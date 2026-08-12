"""Unit tests for opaque API-key values, codecs, stores, and runtimes."""

import hashlib
import hmac
import re
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.context import CredentialRestrictions
from litestar_security.providers.api_key import (
    APIKeyCodec,
    APIKeyConfig,
    APIKeyProof,
    APIKeyState,
    APIKeyStore,
    IssuedAPIKey,
)
from tests.fixtures.collaborators import build_api_key_store

if TYPE_CHECKING:
    from collections.abc import Callable


_NOW = datetime(2026, 7, 28, 19, tzinfo=timezone.utc)
_PEPPER = b"p" * 32
_KEY_ID = "a2tra2tra2tra2tr"

_MemoryAPIKeyStore = build_api_key_store


def _codec(
    *, entropy: "Callable[[int], bytes] | None" = None, comparator: "Callable[[bytes, bytes], bool] | None" = None
) -> APIKeyCodec:
    return APIKeyCodec(
        pepper=_PEPPER,
        entropy=entropy or (lambda length: bytes(range(length))),
        comparator=comparator or hmac.compare_digest,
    )


def _record(**overrides: object) -> APIKeyState:
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
    return APIKeyState(**values)  # type: ignore[arg-type]


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
    record: APIKeyState, now: datetime, expected: int
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
    store = build_api_key_store()
    values: dict[str, object] = {"store": store, "pepper": _PEPPER}
    values.update(arguments)

    with pytest.raises(ImproperlyConfiguredException):
        APIKeyConfig(**values)  # type: ignore[arg-type]


def test_secret_bearing_values_are_redacted() -> None:
    issued, record = _codec().issue(subject_id="subject-1")
    config = APIKeyConfig(store=build_api_key_store(), pepper=_PEPPER)

    assert issued.value not in repr(issued)
    assert issued.value not in str(issued)
    assert record.digest.hex() not in repr(record)
    assert _PEPPER.hex() not in repr(config)
    assert issued.as_dict() == {"key_id": issued.key_id, "value": "<redacted>"}
    assert record.as_dict()["digest"] == "<redacted>"
    assert config.as_dict()["pepper"] == "<redacted>"


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
    store: APIKeyStore = build_api_key_store()

    assert isinstance(store, APIKeyStore)


async def test_store_conformance_create_duplicate_rotate_overlap_and_revoke() -> None:
    store = build_api_key_store()
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
