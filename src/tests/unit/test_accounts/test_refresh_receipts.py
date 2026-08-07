from __future__ import annotations

from base64 import urlsafe_b64encode
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone

import msgspec
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security
import litestar_security.accounts as accounts_module
import litestar_security.accounts._receipts as receipts_module
from litestar_security.authentication import InvalidCredentials
from tests.fixtures.accounts import (
    RefreshEntropy,
    RefreshKeyText,
    refresh_idempotency_key,
    refresh_identifier,
    refresh_service,
)

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)

_ACCOUNT_NOW = datetime(2026, 7, 27, tzinfo=timezone.utc)
_REFRESH_ID = "rt_aWlpaWlpaWlpaWlpaWlpaQ"
_REFRESH_SUCCESSOR_ID = "rt_ampqampqampqampqampqag"
_REFRESH_FAMILY_ID = "rf_a2tra2tra2tra2tra2traw"
_REFRESH_TOKEN = f"{_REFRESH_ID}.c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M"
_ACCESS_TOKEN = "e30.e30.YQ"  # noqa: S105


def test_refresh_value_contracts_are_frozen_slotted_and_secret_safe() -> None:
    now = _ACCOUNT_NOW
    entropy_values = iter((b"i" * 16, b"s" * 32))
    codec = accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=lambda _length: next(entropy_values))
    issue = codec.issue()
    proof = codec.verify(issue.refresh_token)
    assert isinstance(proof, accounts_module.RefreshTokenProof)
    response = accounts_module.TokenPair(
        access_token="e30.e30.YQ",  # noqa: S106 - compact public test JWT
        refresh_token=issue.refresh_token,
        expires_in=600,
    )
    receipt_context = accounts_module.RefreshReceiptContext(
        token_id=issue.token_id,
        family_id=_REFRESH_FAMILY_ID,
        account_id="account-1",
        security_epoch=1,
        idempotency_digest=b"k" * 32,
    )
    family_context = accounts_module.RefreshFamilyContext(
        account_id="account-1",
        family_id=_REFRESH_FAMILY_ID,
        security_epoch=1,
        token_expires_at=now + timedelta(days=7),
        family_expires_at=now + timedelta(days=30),
        scopes=frozenset({"read"}),
    )
    create = accounts_module.CreateRefreshFamilyCommand(
        token_id=issue.token_id,
        token_digest=issue.digest,
        account_id="account-1",
        family_id=_REFRESH_FAMILY_ID,
        security_epoch=1,
        created_at=now,
        token_expires_at=now + timedelta(days=7),
        family_expires_at=now + timedelta(days=30),
        scopes=frozenset({"read"}),
    )
    key = accounts_module.RefreshReceiptKey("key-1", b"r" * 32)
    sealer = accounts_module.RefreshReceiptSealer(active_key=key, entropy=lambda _length: b"n" * 12)
    sealed = sealer.seal(response, receipt_context, expires_at=now + timedelta(seconds=30))
    replay = accounts_module.RefreshReceiptReplay(context=family_context, sealed_receipt=sealed)
    values = (codec, issue, proof, response, receipt_context, family_context, replay, create, key, sealer)

    assert sealer.unseal(sealed, receipt_context, now=now) == response
    for value in values:
        assert not hasattr(value, "__dict__")
        if isinstance(value, msgspec.Struct):
            with pytest.raises(AttributeError):
                setattr(value, value.__struct_fields__[0], None)
            continue
        with pytest.raises(FrozenInstanceError):
            setattr(value, fields(value)[0].name, None)
    rendered = " ".join(repr(value) for value in values)
    for secret in (issue.refresh_token, response.access_token, issue.digest.hex(), (b"r" * 32).hex()):
        assert secret not in rendered


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("token_id", refresh_identifier("rt_", 2)),
        ("family_id", refresh_identifier("rf_", 2)),
        ("account_id", "account-2"),
        ("security_epoch", 4),
        ("idempotency_digest", b"z" * 32),
    ],
)
def test_refresh_receipts_bind_all_context_and_support_key_rotation(field: str, replacement: object) -> None:
    codec = accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=RefreshEntropy())
    response = accounts_module.TokenPair(
        access_token="e30.e30.YQ",  # noqa: S106 - compact public test JWT
        refresh_token=codec.issue().refresh_token,
        expires_in=600,
    )
    context = accounts_module.RefreshReceiptContext(
        token_id=refresh_identifier("rt_", 1),
        family_id=refresh_identifier("rf_", 1),
        account_id="account-1",
        security_epoch=3,
        idempotency_digest=b"i" * 32,
    )
    old_key = accounts_module.RefreshReceiptKey("old", b"o" * 32)
    receipt = accounts_module.RefreshReceiptSealer(active_key=old_key, entropy=RefreshEntropy()).seal(
        response, context, expires_at=_JWT_NOW + timedelta(seconds=30)
    )
    rotated = accounts_module.RefreshReceiptSealer(
        active_key=accounts_module.RefreshReceiptKey("new", b"n" * 32),
        retained_keys=(old_key, accounts_module.RefreshReceiptKey("alias", old_key.key)),
    )

    assert rotated.unseal(receipt, context, now=_JWT_NOW) == response
    assert isinstance(
        rotated.unseal(receipt, replace(context, **{field: replacement}), now=_JWT_NOW), InvalidCredentials
    )
    assert isinstance(
        accounts_module.RefreshReceiptSealer(active_key=rotated.active_key).unseal(receipt, context, now=_JWT_NOW),
        InvalidCredentials,
    )
    assert isinstance(
        rotated.unseal(receipt[:-1] + bytes([receipt[-1] ^ 1]), context, now=_JWT_NOW), InvalidCredentials
    )
    assert isinstance(
        rotated.unseal(receipt.replace(b".old.", b".alias.", 1), context, now=_JWT_NOW), InvalidCredentials
    )
    assert isinstance(rotated.unseal(receipt, context, now=_JWT_NOW + timedelta(seconds=30)), InvalidCredentials)
    assert response.access_token.encode() not in receipt
    assert response.refresh_token.encode() not in receipt
    assert response.access_token not in repr(response)
    assert response.refresh_token not in repr(response)


async def test_refresh_receipt_window_preserves_subsecond_precision() -> None:
    service, _store, _accounts, account = refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    key = refresh_idempotency_key()
    rotated_at = _JWT_NOW + timedelta(microseconds=500_000)
    first = await service.rotate(initial.refresh_token, idempotency_key=key, now=rotated_at)
    assert isinstance(first, accounts_module.TokenPair)

    duplicate = await service.rotate(
        initial.refresh_token, idempotency_key=key, now=rotated_at + timedelta(seconds=29, microseconds=750_000)
    )

    assert duplicate == first


def _base_refresh_receipt_context(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "token_id": _REFRESH_ID,
        "family_id": _REFRESH_FAMILY_ID,
        "account_id": "account-1",
        "security_epoch": 1,
        "idempotency_digest": b"k" * 32,
    }
    values.update(overrides)
    return values


def _base_refresh_family_context(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "account_id": "account-1",
        "family_id": _REFRESH_FAMILY_ID,
        "security_epoch": 1,
        "token_expires_at": _ACCOUNT_NOW + timedelta(days=7),
        "family_expires_at": _ACCOUNT_NOW + timedelta(days=30),
        "scopes": frozenset({"read"}),
    }
    values.update(overrides)
    return values


def _base_create_refresh_command(**overrides: object) -> dict[str, object]:
    values = _base_refresh_family_context()
    values.update({"token_id": _REFRESH_ID, "token_digest": b"d" * 32, "created_at": _ACCOUNT_NOW})
    values.update(overrides)
    return values


def _base_rotate_refresh_command(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "token_id": _REFRESH_ID,
        "token_digest": b"d" * 32,
        "account_id": "account-1",
        "family_id": _REFRESH_FAMILY_ID,
        "security_epoch": 1,
        "successor_id": _REFRESH_SUCCESSOR_ID,
        "successor_digest": b"s" * 32,
        "successor_expires_at": _ACCOUNT_NOW + timedelta(days=7),
        "family_expires_at": _ACCOUNT_NOW + timedelta(days=30),
        "sealed_receipt": b"sealed-receipt",
        "receipt_expires_at": _ACCOUNT_NOW + timedelta(seconds=30),
        "idempotency_digest": b"k" * 32,
        "scopes": frozenset({"read"}),
    }
    values.update(overrides)
    return values


def _encode_refresh_test_segment(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _seal_refresh_test_payload(
    payload: bytes,
    *,
    key: accounts_module.RefreshReceiptKey,
    context: accounts_module.RefreshReceiptContext,
    expiry: int,
) -> bytes:
    nonce = b"n" * 12
    ciphertext = AESGCM(key.key).encrypt(
        nonce,
        payload,
        receipts_module._receipt_aad(context, expiry, key.key_id),  # noqa: SLF001 - exercise public unseal validation
    )
    return (
        f"rr1.{key.key_id}.{expiry}.{_encode_refresh_test_segment(nonce)}.{_encode_refresh_test_segment(ciphertext)}"
    ).encode()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: accounts_module.RefreshTokenProof("invalid", b"d" * 32),
        lambda: accounts_module.RefreshTokenProof(_REFRESH_ID, bytearray(b"d" * 32)),
        lambda: accounts_module.RefreshTokenProof(_REFRESH_ID, b"short"),
        lambda: accounts_module.RefreshTokenIssue("invalid", _REFRESH_ID, b"d" * 32),
        lambda: accounts_module.RefreshTokenIssue(_REFRESH_TOKEN, _REFRESH_SUCCESSOR_ID, b"d" * 32),
        lambda: accounts_module.RefreshTokenIssue(_REFRESH_TOKEN, _REFRESH_ID, bytearray(b"d" * 32)),
        lambda: accounts_module.RefreshTokenIssue(_REFRESH_TOKEN, _REFRESH_ID, b"short"),
    ],
)
def test_refresh_proof_and_issue_reject_malformed_storage_material(factory: object) -> None:
    with pytest.raises(ValueError, match="Refresh token"):
        factory()  # type: ignore[operator]


@pytest.mark.parametrize(
    "kwargs", [{"pepper": b"short"}, {"pepper": bytearray(b"p" * 32)}, {"pepper": b"p" * 32, "entropy": None}]
)
def test_refresh_codec_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Refresh token"):
        accounts_module.RefreshTokenCodec(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "entropy",
    [
        lambda _length: b"short",
        lambda length: bytearray(b"x" * length),
        lambda length: b"x" * (16 if length == 16 else 31),
    ],
)
def test_refresh_codec_rejects_invalid_entropy_material(entropy: object) -> None:
    codec = accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=entropy)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="entropy"):
        codec.issue()


@pytest.mark.parametrize(
    ("token_id", "value"),
    [
        ("invalid", "aWlpaWlpaWlpaWlpaWlpaQ"),
        (_REFRESH_ID, object()),
        (_REFRESH_ID, "%"),
        (_REFRESH_ID, RefreshKeyText("aWlpaWlpaWlpaWlpaWlpaQ")),
        (_REFRESH_ID, "YQ"),
        (_REFRESH_ID, _encode_refresh_test_segment(b"x" * 97)),
    ],
)
def test_refresh_idempotency_digest_rejects_noncanonical_or_weak_keys(token_id: str, value: object) -> None:
    codec = accounts_module.RefreshTokenCodec(pepper=b"p" * 32)
    assert isinstance(codec.digest_idempotency_key(token_id, value), litestar_security.InvalidCredentials)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("access_token", "refresh_token", "expires_in"),
    [
        (object(), _REFRESH_TOKEN, 600),
        ("a.b", _REFRESH_TOKEN, 600),
        ("a..c", _REFRESH_TOKEN, 600),
        ("é.e30.YQ", _REFRESH_TOKEN, 600),
        ("e30=.e30.YQ", _REFRESH_TOKEN, 600),
        ("e30.e30.YQ", "invalid", 600),
        ("e30.e30.YQ", _REFRESH_TOKEN, True),
        ("e30.e30.YQ", _REFRESH_TOKEN, 29),
        ("e30.e30.YQ", _REFRESH_TOKEN, 3_601),
        ("a" * 16_385, _REFRESH_TOKEN, 600),
    ],
)
def test_refresh_response_rejects_invalid_credentials_and_expiry(
    access_token: object, refresh_token: str, expires_in: object
) -> None:
    with pytest.raises(ValueError, match="response"):
        accounts_module.TokenPair(  # type: ignore[arg-type]
            access_token=access_token, refresh_token=refresh_token, expires_in=expires_in
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"token_id": "invalid"},
        {"family_id": "invalid"},
        {"account_id": " "},
        {"account_id": "a" * 513},
        {"security_epoch": True},
        {"idempotency_digest": bytearray(b"k" * 32)},
        {"idempotency_digest": b"short"},
    ],
)
def test_refresh_receipt_context_rejects_unbound_values(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="context"):
        accounts_module.RefreshReceiptContext(**_base_refresh_receipt_context(**overrides))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("key_id", "key"),
    [
        ("", b"k" * 32),
        ("bad key", b"k" * 32),
        ("é", b"k" * 32),
        ("k" * 513, b"k" * 32),
        ("key", bytearray(b"k" * 32)),
        ("key", b"short"),
    ],
)
def test_refresh_receipt_key_rejects_unsafe_ids_and_non_aes256_keys(key_id: str, key: object) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="32-byte"):
        accounts_module.RefreshReceiptKey(key_id, key)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"active_key": object()},
        {"active_key": accounts_module.RefreshReceiptKey("key", b"k" * 32), "retained_keys": (object(),)},
        {
            "active_key": accounts_module.RefreshReceiptKey("key", b"k" * 32),
            "retained_keys": (accounts_module.RefreshReceiptKey("key", b"r" * 32),),
        },
        {"active_key": accounts_module.RefreshReceiptKey("key", b"k" * 32), "entropy": None},
    ],
)
def test_refresh_receipt_sealer_rejects_invalid_key_sets_and_entropy(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Refresh receipt"):
        accounts_module.RefreshReceiptSealer(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("nonce", [b"short", bytearray(b"n" * 12)])
def test_refresh_receipt_sealer_rejects_invalid_nonce_material(nonce: object) -> None:
    sealer = accounts_module.RefreshReceiptSealer(
        active_key=accounts_module.RefreshReceiptKey("key", b"k" * 32),
        entropy=lambda _length: nonce,  # type: ignore[return-value]
    )
    response = accounts_module.TokenPair(_ACCESS_TOKEN, _REFRESH_TOKEN, 600)
    context = accounts_module.RefreshReceiptContext(**_base_refresh_receipt_context())  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="nonce"):
        sealer.seal(response, context, expires_at=_ACCOUNT_NOW + timedelta(seconds=30))


@pytest.mark.parametrize(
    "expiry",
    [
        datetime(2026, 7, 27),  # noqa: DTZ001 - explicit rejection fixture
        datetime(1969, 12, 31, tzinfo=timezone.utc),
        object(),
    ],
)
def test_refresh_receipt_sealer_rejects_invalid_expiry(expiry: object) -> None:
    sealer = accounts_module.RefreshReceiptSealer(active_key=accounts_module.RefreshReceiptKey("key", b"k" * 32))
    response = accounts_module.TokenPair(_ACCESS_TOKEN, _REFRESH_TOKEN, 600)
    context = accounts_module.RefreshReceiptContext(**_base_refresh_receipt_context())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="expiry"):
        sealer.seal(response, context, expires_at=expiry)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "receipt",
    [
        "not-bytes",
        b"",
        b"x" * 32_769,
        b"wrong.parts",
        b"rr2.key.1.bm5ubm5ubm5ubm5u.YQ",
        b"rr1..1.bm5ubm5ubm5ubm5u.YQ",
        b"rr1.bad%key.1.bm5ubm5ubm5ubm5u.YQ",
        b"rr1.key.x.bm5ubm5ubm5ubm5u.YQ",
        b"rr1.key.01.bm5ubm5ubm5ubm5u.YQ",
        b"rr1.key.1.bad.YQ",
        b"rr1.key.1.bm5ubm5ubm5ubm5u.",
        b"rr1.key.1.bm5ubm5ubm5ubm5u.%",
        b"\xff",
    ],
)
def test_refresh_receipt_envelope_parser_rejects_malformed_values(receipt: object) -> None:
    assert receipts_module._parse_receipt_envelope(receipt) is None  # noqa: SLF001


@pytest.mark.parametrize(
    "payload",
    [
        b"[]",
        b'{"token_type":"Bearer"}',
        b'{"access_token":"e30.e30.YQ","expires_in":600,"refresh_token":"'
        + _REFRESH_TOKEN.encode()
        + b'","token_type":"Basic"}',
        b'{"access_token":1,"expires_in":600,"refresh_token":"' + _REFRESH_TOKEN.encode() + b'","token_type":"Bearer"}',
        b'{"access_token":"e30.e30.YQ","expires_in":600,"refresh_token":1,"token_type":"Bearer"}',
        b'{"access_token":"e30.e30.YQ","expires_in":true,"refresh_token":"'
        + _REFRESH_TOKEN.encode()
        + b'","token_type":"Bearer"}',
        b'{"access_token":"bad","expires_in":600,"refresh_token":"'
        + _REFRESH_TOKEN.encode()
        + b'","token_type":"Bearer"}',
        b"\xff",
    ],
)
def test_refresh_receipt_unseal_strictly_validates_decrypted_payload(payload: bytes) -> None:
    key = accounts_module.RefreshReceiptKey("key", b"k" * 32)
    context = accounts_module.RefreshReceiptContext(**_base_refresh_receipt_context())  # type: ignore[arg-type]
    expiry = receipts_module._receipt_expiry(_ACCOUNT_NOW + timedelta(seconds=30))  # noqa: SLF001
    sealed = _seal_refresh_test_payload(payload, key=key, context=context, expiry=expiry)
    sealer = accounts_module.RefreshReceiptSealer(active_key=key)
    assert isinstance(sealer.unseal(sealed, context, now=_ACCOUNT_NOW), litestar_security.InvalidCredentials)
    assert isinstance(
        sealer.unseal(sealed, context, now=datetime(2026, 7, 27)),  # noqa: DTZ001
        litestar_security.InvalidCredentials,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"token_expires_at": datetime(2026, 7, 27)},  # noqa: DTZ001
        {"family_expires_at": object()},
        {"account_id": " "},
        {"family_id": "invalid"},
        {"security_epoch": True},
        {"token_expires_at": _ACCOUNT_NOW + timedelta(days=31)},
        {"scopes": frozenset({"bad scope"})},
    ],
)
def test_refresh_family_context_rejects_invalid_state(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="Refresh family"):
        accounts_module.RefreshFamilyContext(**_base_refresh_family_context(**overrides))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"created_at": datetime(2026, 7, 27)},  # noqa: DTZ001
        {"token_expires_at": object()},
        {"family_expires_at": datetime(2026, 7, 27)},  # noqa: DTZ001
        {"token_id": "invalid"},
        {"token_digest": bytearray(b"d" * 32)},
        {"token_digest": b"short"},
        {"account_id": " "},
        {"family_id": "invalid"},
        {"security_epoch": True},
        {"token_expires_at": _ACCOUNT_NOW},
        {"family_expires_at": _ACCOUNT_NOW + timedelta(days=1), "token_expires_at": _ACCOUNT_NOW + timedelta(days=2)},
        {"scopes": frozenset({"bad scope"})},
    ],
)
def test_create_refresh_family_command_rejects_invalid_state(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="Refresh family"):
        accounts_module.CreateRefreshFamilyCommand(**_base_create_refresh_command(**overrides))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"successor_expires_at": datetime(2026, 7, 27)},  # noqa: DTZ001
        {"family_expires_at": object()},
        {"receipt_expires_at": datetime(2026, 7, 27)},  # noqa: DTZ001
        {"token_id": "invalid"},
        {"token_digest": bytearray(b"d" * 32)},
        {"token_digest": b"short"},
        {"account_id": " "},
        {"family_id": "invalid"},
        {"security_epoch": True},
        {"successor_id": "invalid"},
        {"successor_id": _REFRESH_ID},
        {"successor_digest": bytearray(b"s" * 32)},
        {"successor_digest": b"short"},
        {"successor_expires_at": _ACCOUNT_NOW + timedelta(days=31)},
        {"receipt_expires_at": _ACCOUNT_NOW + timedelta(days=31)},
        {"sealed_receipt": bytearray(b"receipt")},
        {"sealed_receipt": b""},
        {"sealed_receipt": b"x" * 32_769},
        {"idempotency_digest": bytearray(b"k" * 32)},
        {"idempotency_digest": b"short"},
        {"scopes": frozenset({"bad scope"})},
    ],
)
def test_rotate_refresh_command_rejects_invalid_state(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="Refresh rotation"):
        accounts_module.RotateRefreshCommand(**_base_rotate_refresh_command(**overrides))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": "rotated"},
        {"status": accounts_module.RefreshRotationStatus.INVALID, "family_revoked": 1},
        {"status": accounts_module.RefreshRotationStatus.ROTATED},
        {"status": accounts_module.RefreshRotationStatus.ROTATED, "sealed_receipt": b"receipt", "family_revoked": True},
        {"status": accounts_module.RefreshRotationStatus.INVALID, "sealed_receipt": bytearray(b"receipt")},
        {"status": accounts_module.RefreshRotationStatus.INVALID, "sealed_receipt": b""},
        {"status": accounts_module.RefreshRotationStatus.INVALID, "sealed_receipt": b"x" * 32_769},
        {"status": accounts_module.RefreshRotationStatus.REVOKED},
        {"status": accounts_module.RefreshRotationStatus.INVALID, "family_revoked": True},
    ],
)
def test_refresh_rotation_outcome_rejects_invalid_state(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match=r"Refresh|Successful|Replay"):
        accounts_module.RefreshRotationOutcome(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"context": object(), "sealed_receipt": b"receipt"},
        {"context": accounts_module.RefreshFamilyContext(**_base_refresh_family_context()), "sealed_receipt": b""},
        {
            "context": accounts_module.RefreshFamilyContext(**_base_refresh_family_context()),
            "sealed_receipt": bytearray(b"receipt"),
        },
        {
            "context": accounts_module.RefreshFamilyContext(**_base_refresh_family_context()),
            "sealed_receipt": b"x" * 32_769,
        },
    ],
)
def test_refresh_receipt_replay_rejects_invalid_state(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="replay"):
        accounts_module.RefreshReceiptReplay(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": "invalid"},
        {"status": accounts_module.RefreshRotationStatus.ROTATED},
        {"status": accounts_module.RefreshRotationStatus.IDEMPOTENT_REPLAY},
        {"status": accounts_module.RefreshRotationStatus.REPLAY_DETECTED},
        {"status": accounts_module.RefreshRotationStatus.REVOKED},
        {"status": accounts_module.RefreshRotationStatus.INVALID, "family_revoked": True},
        {"status": accounts_module.RefreshRotationStatus.INVALID, "family_revoked": 1},
    ],
)
def test_refresh_preflight_outcome_rejects_invalid_state(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="preflight"):
        accounts_module.RefreshPreflightOutcome(**kwargs)  # type: ignore[arg-type]
