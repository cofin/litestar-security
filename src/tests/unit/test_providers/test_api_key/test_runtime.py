"""Unit tests for API-key runtime authentication and usage buffering."""

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta
from threading import get_ident

import pytest
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security.workers as workers_module
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
    APIKeyService,
    BufferedAPIKeyUsage,
    IssuedAPIKey,
)
from tests.fixtures.collaborators import RecordingAPIKeyResolver as _Resolver
from tests.fixtures.collaborators import RecordingAPIKeyUsageSink as _UsageSink
from tests.fixtures.collaborators import RecordingAPIMetrics as _Metrics
from tests.fixtures.collaborators import SyncMemoryAPIKeyStore as _SyncMemoryAPIKeyStore
from tests.unit.test_providers.test_api_key.test_api_key import _NOW, _PEPPER, _codec, _MemoryAPIKeyStore


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


async def test_blocking_api_key_store_is_normalized_once_per_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _SyncMemoryAPIKeyStore()
    config = APIKeyConfig(store=BlockingIntegration(store), pepper=_PEPPER)
    resolver = _Resolver()
    current_thread = get_ident()
    submissions: list[object] = []
    run_sync = workers_module.to_thread.run_sync

    async def count_submission(function: object, **kwargs: object) -> object:
        submissions.append(function)
        return await run_sync(function, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(workers_module.to_thread, "run_sync", count_submission)

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


async def test_direct_async_api_key_store_never_submits_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _MemoryAPIKeyStore()
    config = APIKeyConfig(store=store, pepper=_PEPPER)
    service = config.build(_Resolver(), clock=lambda: _NOW)[2]
    submissions: list[object] = []
    run_sync = workers_module.to_thread.run_sync

    async def count_submission(function: object, **kwargs: object) -> object:
        submissions.append(function)
        return await run_sync(function, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(workers_module.to_thread, "run_sync", count_submission)

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
