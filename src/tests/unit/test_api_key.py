"""Unit tests for opaque API-key values, codecs, and store ports."""

import asyncio
import hashlib
import hmac
import re
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from threading import get_ident
from typing import TYPE_CHECKING

import pytest
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security.config as config_module
from litestar_security.authentication import (
    Authenticated,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
)
from litestar_security.config import BlockingIntegration
from litestar_security.context import CredentialRestrictions, Principal
from litestar_security.providers.api_key import (
    APIKeyClaims,
    APIKeyCodec,
    APIKeyConfig,
    APIKeyProof,
    APIKeyRecord,
    APIKeyService,
    APIKeyStore,
    BufferedAPIKeyUsage,
    IssuedAPIKey,
)

if TYPE_CHECKING:
    from collections.abc import Callable


_NOW = datetime(2026, 7, 28, 19, tzinfo=timezone.utc)
_PEPPER = b"p" * 32
_KEY_ID = "a2tra2tra2tra2tr"


class _MemoryAPIKeyStore:
    """Deterministic atomic store used only by this conformance test."""

    def __init__(self) -> None:
        self.records: dict[str, APIKeyRecord] = {}
        self._lock = asyncio.Lock()
        self.get_calls: list[str] = []
        self.fail_get = False

    async def get(self, key_id: str) -> APIKeyRecord | None:
        self.get_calls.append(key_id)
        if self.fail_get:
            message = "store detail"
            raise RuntimeError(message)
        return self.records.get(key_id)

    async def create(self, record: APIKeyRecord) -> None:
        async with self._lock:
            if record.key_id in self.records:
                message = "duplicate API-key id"
                raise ValueError(message)
            self.records[record.key_id] = record

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyRecord, overlap_until: datetime | None, now: datetime
    ) -> None:
        async with self._lock:
            current = self.records[current_key_id]
            if current.revoked_at is not None:
                message = "API key already rotated"
                raise ValueError(message)
            if replacement.key_id in self.records:
                message = "duplicate API-key id"
                raise ValueError(message)
            bounded_overlap = (
                min(overlap_until, current.expires_at)
                if overlap_until is not None and current.expires_at is not None
                else overlap_until
            )
            self.records[current_key_id] = replace(current, revoked_at=now, overlap_until=bounded_overlap)
            self.records[replacement.key_id] = replacement

    async def revoke(self, *, key_id: str, now: datetime) -> None:
        async with self._lock:
            self.records[key_id] = replace(self.records[key_id], revoked_at=now, overlap_until=None)


class _SyncMemoryAPIKeyStore:
    def __init__(self) -> None:
        self.records: dict[str, APIKeyRecord] = {}
        self.thread_ids: list[int] = []

    def get(self, key_id: str) -> APIKeyRecord | None:
        self.thread_ids.append(get_ident())
        return self.records.get(key_id)

    def create(self, record: APIKeyRecord) -> None:
        self.thread_ids.append(get_ident())
        self.records[record.key_id] = record

    def rotate(
        self, *, current_key_id: str, replacement: APIKeyRecord, overlap_until: datetime | None, now: datetime
    ) -> None:
        self.thread_ids.append(get_ident())
        current = self.records[current_key_id]
        self.records[current_key_id] = replace(current, revoked_at=now, overlap_until=overlap_until)
        self.records[replacement.key_id] = replacement

    def revoke(self, *, key_id: str, now: datetime) -> None:
        self.thread_ids.append(get_ident())
        self.records[key_id] = replace(self.records[key_id], revoked_at=now, overlap_until=None)


class _Resolver:
    def __init__(self) -> None:
        self.claims: list[APIKeyClaims] = []

    async def resolve(self, claims: APIKeyClaims) -> Principal[str]:
        self.claims.append(claims)
        return Principal(id=claims.subject_id, user=claims.subject_id)


class _UsageSink:
    def __init__(self) -> None:
        self.calls: list[tuple[str, datetime]] = []
        self.fail = False

    async def record(self, *, key_id: str, used_at: datetime) -> None:
        self.calls.append((key_id, used_at))
        if self.fail:
            message = "usage detail"
            raise RuntimeError(message)


class _Metrics:
    def __init__(self) -> None:
        self.increments: list[str] = []

    def increment(self, name: str, **_kwargs: object) -> None:
        self.increments.append(name)

    def observe(self, _name: str, _value: float, **_kwargs: object) -> None:
        return None


def _codec(
    *, entropy: "Callable[[int], bytes] | None" = None, comparator: "Callable[[bytes, bytes], bool] | None" = None
) -> APIKeyCodec:
    return APIKeyCodec(
        pepper=_PEPPER,
        entropy=entropy or (lambda length: bytes(range(length))),
        comparator=comparator or hmac.compare_digest,
    )


def _record(**overrides: object) -> APIKeyRecord:
    values: dict[str, object] = {
        "key_id": _KEY_ID,
        "subject_id": "subject-1",
        "digest": b"d" * 32,
        "restrictions": CredentialRestrictions(scopes=frozenset({"read"})),
        "expires_at": _NOW + timedelta(hours=1),
        "revoked_at": None,
        "overlap_until": None,
    }
    values.update(overrides)
    return APIKeyRecord(**values)  # type: ignore[arg-type]


def test_issue_has_exact_canonical_shape_and_storage_safe_record() -> None:
    issued, record = _codec().issue(
        subject_id="subject-1",
        restrictions=CredentialRestrictions(scopes=frozenset({"read"})),
        expires_at=_NOW + timedelta(hours=1),
    )

    assert re.fullmatch(r"lsk_[A-Za-z0-9_-]{16}_[A-Za-z0-9_-]{43}", issued.value)
    assert len(issued.value) == 64
    assert issued.key_id == issued.value.split("_", 2)[1] == record.key_id
    assert record.subject_id == "subject-1"
    assert record.digest != issued.value.encode()
    assert len(record.digest) == hashlib.sha256().digest_size
    assert record.revoked_at is None
    assert record.overlap_until is None


def test_issue_round_trips_to_storage_safe_proof() -> None:
    issued, record = _codec().issue(subject_id="subject-1")

    proof = _codec().proof(issued.value)

    assert proof is not None
    assert proof.key_id == record.key_id
    assert proof.digest == record.digest
    assert issued.value not in repr(proof)


@pytest.mark.parametrize(
    "arguments",
    [
        {"key_id": "not-canonical", "value": "not-a-key"},
        {"key_id": _KEY_ID, "value": 1},
        {"key_id": _KEY_ID, "value": f"bad_prefix_{'A' * 43}"},
        {"key_id": _KEY_ID, "value": f"lsk_bGxsbGxsbGxsbGxs_{'A' * 43}"},
        {"key_id": _KEY_ID, "value": f"lsk_{_KEY_ID}_{'A' * 42}"},
    ],
)
def test_issued_value_rejects_noncanonical_or_mismatched_material(arguments: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="Issued API key"):
        IssuedAPIKey(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "arguments",
    [
        {"key_id": "not-canonical", "digest": b"d" * 32},
        {"key_id": _KEY_ID, "digest": "not-bytes"},
        {"key_id": _KEY_ID, "digest": b"short"},
    ],
)
def test_proof_rejects_invalid_storage_shape(arguments: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="API-key proof"):
        APIKeyProof(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    [
        "",
        "lsk",
        "lsk_key",
        "lsk_key_secret_extra",
        f"other_{_KEY_ID}_{'A' * 43}",
        f"lsk_{'A' * 15}_{'A' * 43}",
        f"lsk_{'A' * 17}_{'A' * 43}",
        f"lsk_{'A' * 16}_{'A' * 42}",
        f"lsk_{'A' * 16}_{'A' * 44}",
        f"lsk_{'!' * 16}_{'A' * 43}",
        f"lsk_{'A' * 16}_{'!' * 43}",
        1,
        None,
    ],
)
def test_proof_rejects_noncanonical_values(value: object) -> None:
    assert _codec().proof(value) is None


def test_issue_uses_independent_entropy_and_is_unique() -> None:
    calls: list[int] = []

    def entropy(length: int) -> bytes:
        calls.append(length)
        return bytes([len(calls)]) * length

    codec = _codec(entropy=entropy)
    first, _ = codec.issue(subject_id="subject-1")
    second, _ = codec.issue(subject_id="subject-1")

    assert calls == [12, 32, 12, 32]
    assert first.key_id != second.key_id
    assert first.value != second.value


def test_digest_is_domain_separated_and_binds_id_and_encoded_secret() -> None:
    issued, record = _codec().issue(subject_id="subject-1")
    _, key_id, secret = issued.value.split("_")
    expected = hmac.new(
        _PEPPER,
        b"litestar-security:api-key:v1\x00" + key_id.encode("ascii") + b"\x00" + secret.encode("ascii"),
        hashlib.sha256,
    ).digest()

    assert record.digest == expected


def test_matches_injects_constant_time_comparator() -> None:
    calls: list[tuple[bytes, bytes]] = []

    def comparator(actual: bytes, expected: bytes) -> bool:
        calls.append((actual, expected))
        return actual == expected

    codec = _codec(comparator=comparator)
    issued, record = codec.issue(subject_id="subject-1")
    proof = codec.proof(issued.value)

    assert proof is not None
    assert codec.matches(proof, record)
    assert calls == [(proof.digest, record.digest)]


@pytest.mark.parametrize(
    ("record", "now", "expected"),
    [
        (_record(expires_at=None), _NOW, True),
        (_record(expires_at=_NOW + timedelta(microseconds=1)), _NOW, True),
        (_record(expires_at=_NOW), _NOW, False),
        (_record(revoked_at=_NOW, overlap_until=None), _NOW, False),
        (_record(revoked_at=_NOW, overlap_until=_NOW), _NOW, True),
        (
            _record(revoked_at=_NOW, overlap_until=_NOW + timedelta(microseconds=1)),
            _NOW + timedelta(microseconds=1),
            True,
        ),
        (
            _record(revoked_at=_NOW, overlap_until=_NOW + timedelta(microseconds=1)),
            _NOW + timedelta(microseconds=2),
            False,
        ),
        (
            _record(
                expires_at=_NOW + timedelta(microseconds=1),
                revoked_at=_NOW,
                overlap_until=_NOW + timedelta(microseconds=1),
            ),
            _NOW + timedelta(microseconds=1),
            False,
        ),
    ],
)
def test_record_validity_has_strict_expiry_and_inclusive_overlap(
    record: APIKeyRecord, now: datetime, expected: int
) -> None:
    assert record.is_valid_at(now) is bool(expected)


@pytest.mark.parametrize(
    "overrides",
    [
        {"key_id": "not-canonical"},
        {"subject_id": ""},
        {"digest": b"short"},
        {"expires_at": datetime(2026, 7, 28)},  # noqa: DTZ001 - intentional naive rejection fixture
        {"revoked_at": datetime(2026, 7, 28)},  # noqa: DTZ001 - intentional naive rejection fixture
        {"overlap_until": datetime(2026, 7, 28)},  # noqa: DTZ001 - intentional naive rejection fixture
        {"overlap_until": _NOW},
        {"revoked_at": _NOW, "overlap_until": _NOW - timedelta(microseconds=1)},
        {"expires_at": _NOW + timedelta(seconds=1), "revoked_at": _NOW, "overlap_until": _NOW + timedelta(seconds=2)},
    ],
)
def test_record_rejects_invalid_storage_state(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="API-key record"):
        _record(**overrides)


@pytest.mark.parametrize(
    "arguments",
    [
        {"pepper": b"short"},
        {"identity_resolver": object()},
        {"prefix": ""},
        {"prefix": "bad_prefix"},
        {"header_name": "bad header"},
        {"usage_write_interval": timedelta(0)},
        {"usage_buffer_capacity": 0},
        {"usage_buffer_capacity": 1_000_001},
    ],
)
def test_config_rejects_unsafe_values(arguments: dict[str, object]) -> None:
    store = _MemoryAPIKeyStore()
    values: dict[str, object] = {"store": store, "pepper": _PEPPER}
    values.update(arguments)

    with pytest.raises(ImproperlyConfiguredException):
        APIKeyConfig(**values)  # type: ignore[arg-type]


def test_secret_bearing_values_are_frozen_and_redacted() -> None:
    issued, record = _codec().issue(subject_id="subject-1")
    config = APIKeyConfig(store=_MemoryAPIKeyStore(), pepper=_PEPPER)

    assert issued.value not in repr(issued)
    assert issued.value not in str(issued)
    assert record.digest.hex() not in repr(record)
    assert _PEPPER.hex() not in repr(config)
    assert issued.as_dict() == {"key_id": issued.key_id, "value": "<redacted>"}
    assert record.as_dict()["digest"] == "<redacted>"
    assert config.as_dict()["pepper"] == "<redacted>"
    with pytest.raises(FrozenInstanceError):
        issued.key_id = "changed"  # type: ignore[misc]


def test_codec_rejects_invalid_entropy_without_leaking_detail() -> None:
    def raises(_length: int) -> bytes:
        message = "entropy detail"
        raise RuntimeError(message)

    for entropy in (lambda _length: b"short", lambda _length: "not-bytes", raises):
        with pytest.raises(RuntimeError, match="API-key generation unavailable"):
            _codec(entropy=entropy).issue(subject_id="subject-1")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "arguments", [{"pepper": b"short"}, {"prefix": "bad_prefix"}, {"entropy": None}, {"comparator": None}]
)
def test_codec_rejects_unsafe_configuration(arguments: dict[str, object]) -> None:
    values: dict[str, object] = {"pepper": _PEPPER}
    values.update(arguments)

    with pytest.raises(ImproperlyConfiguredException):
        APIKeyCodec(**values)  # type: ignore[arg-type]


def test_store_protocol_is_structural() -> None:
    store: APIKeyStore = _MemoryAPIKeyStore()

    assert isinstance(store, APIKeyStore)


@pytest.mark.anyio
async def test_store_conformance_create_duplicate_rotate_overlap_and_revoke() -> None:
    store = _MemoryAPIKeyStore()
    current = _record()
    replacement = _record(key_id="bGxsbGxsbGxsbGxs", digest=b"r" * 32, expires_at=_NOW + timedelta(hours=2))
    await store.create(current)

    with pytest.raises(ValueError, match="duplicate"):
        await store.create(current)

    await store.rotate(
        current_key_id=current.key_id, replacement=replacement, overlap_until=_NOW + timedelta(hours=4), now=_NOW
    )

    assert (await store.get(current.key_id)) == replace(current, revoked_at=_NOW, overlap_until=current.expires_at)
    assert await store.get(replacement.key_id) == replacement
    assert (await store.get(current.key_id)).is_valid_at(current.expires_at) is False  # type: ignore[union-attr]

    await store.revoke(key_id=replacement.key_id, now=_NOW + timedelta(minutes=1))

    revoked = await store.get(replacement.key_id)
    assert revoked is not None
    assert revoked.revoked_at == _NOW + timedelta(minutes=1)
    assert revoked.overlap_until is None


def _api_key_runtime(
    store: _MemoryAPIKeyStore, *, sink: _UsageSink | None = None
) -> tuple[object, object, APIKeyService, _Resolver]:
    resolver = _Resolver()
    entropy_calls = 0

    def entropy(length: int) -> bytes:
        nonlocal entropy_calls
        entropy_calls += 1
        return bytes([entropy_calls]) * length

    slot, mechanism, service = APIKeyConfig(store=store, pepper=_PEPPER, usage_sink=sink).build(
        resolver, clock=lambda: _NOW, entropy=entropy
    )
    return slot, mechanism, service, resolver


@pytest.mark.parametrize(
    ("headers", "outcome"),
    [
        ([], NoCredentials),
        ([(b"x-api-key", b"one"), (b"X-API-Key", b"two")], InvalidCredentials),
        ([(b"x-api-key", b"")], InvalidCredentials),
        ([(b"x-api-key", b"\xff")], InvalidCredentials),
        ([(b"x-api-key", b"has space")], InvalidCredentials),
    ],
)
def test_api_key_slot_rejects_ambiguous_or_malformed_headers(
    headers: list[tuple[bytes, bytes]], outcome: type[object]
) -> None:
    slot, _, _, _ = _api_key_runtime(_MemoryAPIKeyStore())

    extraction = slot.extract(type("Connection", (), {"scope": {"headers": headers}})())

    assert isinstance(extraction, outcome)


def test_api_key_slot_accepts_one_canonical_header() -> None:
    slot, _, _, _ = _api_key_runtime(_MemoryAPIKeyStore())

    extraction = slot.extract(type("Connection", (), {"scope": {"headers": [(b"x-api-key", b"opaque")]}})())

    assert extraction == PresentedCredential("opaque")


@pytest.mark.anyio
@pytest.mark.parametrize("state", ["malformed", "unknown", "mismatch", "expired", "revoked", "unavailable"])
async def test_api_key_authenticator_preserves_structured_failures_and_lookup_bounds(state: str) -> None:
    store = _MemoryAPIKeyStore()
    slot, mechanism, _, _ = _api_key_runtime(store)
    issued, record = _codec().issue(subject_id="subject-1", expires_at=_NOW + timedelta(minutes=5))
    credential = issued.value
    if state not in {"malformed", "unknown"}:
        store.records[record.key_id] = record
    if state == "malformed":
        credential = "not-a-key"
    elif state == "unknown":
        pass
    elif state == "mismatch":
        store.records[record.key_id] = replace(record, digest=b"x" * 32)
    elif state == "expired":
        store.records[record.key_id] = replace(record, expires_at=_NOW)
    elif state == "revoked":
        store.records[record.key_id] = replace(record, revoked_at=_NOW)
    elif state == "unavailable":
        store.fail_get = True

    outcome = await mechanism.authenticator.authenticate(
        credential, type("Connection", (), {"scope": {"headers": []}})()
    )

    assert isinstance(outcome, VerificationUnavailable if state == "unavailable" else InvalidCredentials)
    assert len(store.get_calls) == (0 if state == "malformed" else 1)
    assert slot.name == "api-key"


@pytest.mark.anyio
async def test_api_key_authentication_is_one_lookup_and_defers_usage_persistence() -> None:
    store = _MemoryAPIKeyStore()
    sink = _UsageSink()
    _, mechanism, service, resolver = _api_key_runtime(store, sink=sink)
    issued, record = _codec().issue(
        subject_id="subject-1",
        restrictions=CredentialRestrictions(scopes=frozenset({"reports:read"})),
        expires_at=_NOW + timedelta(minutes=5),
    )
    store.records[record.key_id] = record

    outcome = await mechanism.authenticator.authenticate(
        issued.value, type("Connection", (), {"scope": {"headers": []}})()
    )

    assert isinstance(outcome, Authenticated)
    assert outcome.claims == APIKeyClaims(key_id=record.key_id, subject_id="subject-1")
    assert outcome.restrictions == record.restrictions
    assert outcome.evidence.mechanism == "api-key"
    assert outcome.evidence.slot == "api-key"
    assert outcome.evidence.expires_at == record.expires_at
    assert outcome.evidence.methods == frozenset({"api-key"})
    assert mechanism.scheme_name == "APIKey"
    assert mechanism.security_scheme is not None
    assert mechanism.security_scheme.name == "X-API-Key"
    assert store.get_calls == [record.key_id]
    assert sink.calls == []
    assert await mechanism.resolver.resolve(outcome.claims) == Principal(id="subject-1", user="subject-1")
    assert resolver.claims == [outcome.claims]
    await service.flush_usage()
    assert sink.calls == [(record.key_id, _NOW)]
    await service.close()


@pytest.mark.anyio
async def test_api_key_service_issues_rotates_and_revokes_through_atomic_store_ports() -> None:
    store = _MemoryAPIKeyStore()
    _, _, service, _ = _api_key_runtime(store)
    issued = await service.issue(subject_id="subject-1", expires_at=_NOW + timedelta(hours=1))
    current = store.records[issued.key_id]

    replacement = await service.rotate(
        current_key_id=current.key_id,
        subject_id=current.subject_id,
        restrictions=current.restrictions,
        expires_at=_NOW + timedelta(hours=2),
        overlap=timedelta(minutes=5),
    )

    assert store.records[current.key_id].revoked_at == _NOW
    assert store.records[current.key_id].overlap_until == _NOW + timedelta(minutes=5)
    assert replacement.key_id in store.records
    await service.revoke(replacement.key_id)
    assert store.records[replacement.key_id].revoked_at == _NOW
    assert store.records[replacement.key_id].overlap_until is None


@pytest.mark.anyio
async def test_api_key_rotation_has_one_atomic_winner() -> None:
    store = _MemoryAPIKeyStore()
    _, _, service, _ = _api_key_runtime(store)
    issued = await service.issue(subject_id="subject-1")

    results = await asyncio.gather(
        service.rotate(current_key_id=issued.key_id, subject_id="subject-1"),
        service.rotate(current_key_id=issued.key_id, subject_id="subject-1"),
        return_exceptions=True,
    )

    assert sum(isinstance(result, IssuedAPIKey) for result in results) == 1
    assert sum(isinstance(result, ValueError) for result in results) == 1


@pytest.mark.anyio
async def test_api_key_runtime_defaults_and_absent_usage_are_safe() -> None:
    store = _MemoryAPIKeyStore()
    resolver = _Resolver()
    slot, mechanism, service = APIKeyConfig(store=store, pepper=_PEPPER).build(
        resolver, entropy=lambda length: b"d" * length
    )
    issued = await service.issue(subject_id="subject-1")
    outcome = await mechanism.authenticator.authenticate(
        issued.value, type("Connection", (), {"scope": {"headers": []}})()
    )

    assert isinstance(outcome, Authenticated)
    assert isinstance(
        slot.extract(type("Connection", (), {"scope": {"headers": [(b"x-api-key", issued.value.encode())]}})()),
        PresentedCredential,
    )
    await service.flush_usage()
    await service.close()
    await service.revoke(issued.key_id)


def test_api_key_build_requires_configured_or_explicit_identity_resolver() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="identity resolver"):
        APIKeyConfig(store=_MemoryAPIKeyStore(), pepper=_PEPPER).build()


def test_api_key_round_trip_allows_base64url_underscore_components() -> None:
    codec = _codec(entropy=lambda length: b"\xff" * length)

    issued, _ = codec.issue(subject_id="subject-1")

    assert codec.proof(issued.value) is not None


def test_api_key_config_names_missing_store_capabilities() -> None:
    class CRUDOnlyStore:
        async def add(self, _value: object) -> None:
            return None

        async def update(self, _value: object) -> None:
            return None

        async def delete(self, _value: object) -> None:
            return None

    with pytest.raises(
        ImproperlyConfiguredException,
        match=r"API-key store CRUDOnlyStore is missing capabilities: get, create, rotate, revoke",
    ):
        APIKeyConfig(store=CRUDOnlyStore(), pepper=_PEPPER)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_blocking_api_key_store_is_normalized_once_per_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _SyncMemoryAPIKeyStore()
    config = APIKeyConfig(store=BlockingIntegration(store), pepper=_PEPPER)
    resolver = _Resolver()
    current_thread = get_ident()
    submissions: list[object] = []
    run_sync = config_module.to_thread.run_sync

    async def count_submission(function: object, **kwargs: object) -> object:
        submissions.append(function)
        return await run_sync(function, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(config_module.to_thread, "run_sync", count_submission)

    _, first_mechanism, first_service = config.build(resolver, clock=lambda: _NOW)
    second_service = config.build(resolver, clock=lambda: _NOW)[2]
    first = await first_service.issue(subject_id="subject-1")
    outcome = await first_mechanism.authenticator.authenticate(
        first.value, type("Connection", (), {"scope": {"headers": []}})()
    )
    replacement = await first_service.rotate(current_key_id=first.key_id, subject_id="subject-1")
    await first_service.revoke(replacement.key_id)

    assert isinstance(outcome, Authenticated)
    assert store.thread_ids
    assert all(thread_id != current_thread for thread_id in store.thread_ids)
    assert len(submissions) == len(store.thread_ids) == 4
    assert first_service.config.store is not second_service.config.store
    assert config.store == BlockingIntegration(store)


@pytest.mark.anyio
async def test_direct_async_api_key_store_never_submits_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _MemoryAPIKeyStore()
    config = APIKeyConfig(store=store, pepper=_PEPPER)
    service = config.build(_Resolver(), clock=lambda: _NOW)[2]
    submissions: list[object] = []
    run_sync = config_module.to_thread.run_sync

    async def count_submission(function: object, **kwargs: object) -> object:
        submissions.append(function)
        return await run_sync(function, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(config_module.to_thread, "run_sync", count_submission)

    issued = await service.issue(subject_id="subject-1")
    await service.revoke(issued.key_id)

    assert submissions == []


def test_blocking_api_key_store_rejects_partial_or_async_implementation() -> None:
    class PartialStore:
        def get(self, _key_id: str) -> None:
            return None

    with pytest.raises(
        ImproperlyConfiguredException,
        match=r"API-key store PartialStore is missing capabilities: create, rotate, revoke",
    ):
        APIKeyConfig(store=BlockingIntegration(PartialStore()), pepper=_PEPPER)

    with pytest.raises(ImproperlyConfiguredException, match=r"wrapped by BlockingIntegration must be synchronous"):
        APIKeyConfig(store=BlockingIntegration(_MemoryAPIKeyStore()), pepper=_PEPPER)


@pytest.mark.anyio
async def test_api_key_runtime_rejects_invalid_rotation_clock_and_builder_inputs() -> None:
    store = _MemoryAPIKeyStore()
    _, _, service, resolver = _api_key_runtime(store)

    with pytest.raises(ValueError, match="overlap"):
        await service.rotate(current_key_id="missing", subject_id="subject-1", overlap=timedelta(microseconds=-1))
    with pytest.raises(ImproperlyConfiguredException):
        APIKeyConfig(store=store, pepper=_PEPPER).build(resolver, clock=None)  # type: ignore[arg-type]

    config = APIKeyConfig(store=store, pepper=_PEPPER)
    _, mechanism, _ = config.build(
        resolver,
        clock=lambda: datetime(2026, 7, 28),  # noqa: DTZ001 - intentional naive rejection fixture
        entropy=lambda length: b"e" * length,
    )
    issued, record = APIKeyCodec(pepper=_PEPPER, entropy=lambda length: b"e" * length).issue(subject_id="subject-1")
    store.records[record.key_id] = record
    with pytest.raises(ValueError, match="timezone-aware"):
        await mechanism.authenticator.authenticate(issued.value, type("Connection", (), {"scope": {"headers": []}})())


@pytest.mark.parametrize(
    ("arguments", "error"),
    [
        ({"sink": object()}, ValueError),
        ({"interval": timedelta(0)}, ValueError),
        ({"capacity": 1.5}, TypeError),
        ({"capacity": 0}, ValueError),
        ({"metrics": object()}, TypeError),
    ],
)
def test_usage_buffer_rejects_invalid_configuration(arguments: dict[str, object], error: type[Exception]) -> None:
    values: dict[str, object] = {"sink": _UsageSink(), "interval": timedelta(minutes=5)}
    values.update(arguments)

    with pytest.raises(error):
        BufferedAPIKeyUsage(**values)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_usage_buffer_coalesces_bounds_flushes_and_isolates_sink_failure() -> None:
    sink = _UsageSink()
    metrics = _Metrics()
    usage = BufferedAPIKeyUsage(sink=sink, interval=timedelta(minutes=5), capacity=2, metrics=metrics)
    for _ in range(100):
        usage.observe("key-a", _NOW)
    usage.observe("key-b", _NOW)
    usage.observe("key-c", _NOW)

    await usage.flush()

    assert sink.calls == [("key-a", _NOW), ("key-b", _NOW)]
    assert metrics.increments.count("security.api_key.usage_coalesced") == 99
    assert "security.api_key.usage_dropped" in metrics.increments
    usage.observe("key-a", _NOW + timedelta(minutes=4))
    await usage.flush()
    assert sink.calls == [("key-a", _NOW), ("key-b", _NOW)]
    usage.observe("key-a", _NOW + timedelta(minutes=5))
    sink.fail = True
    await usage.close()
    assert "security.api_key.usage_failure" in metrics.increments
