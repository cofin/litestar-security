from __future__ import annotations

import asyncio
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import pytest
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security.accounts as accounts_module
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence
from tests.fixtures.accounts import (
    BrokenRefreshScopes,
    RefreshAccessOutcome,
    RefreshEntropy,
    refresh_idempotency_key,
    refresh_identifier,
    refresh_service,
)

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "rt_missing-secret",
        "rt_AAAAAAAAAAAAAAAAAAAAAA.%",
        "rt_AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.extra",
        "xx_AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ],
)
def test_refresh_codec_is_canonical_hmac_only_and_rejects_malformed_tokens(token: str) -> None:
    first = accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=RefreshEntropy())
    second = accounts_module.RefreshTokenCodec(pepper=b"q" * 32, entropy=RefreshEntropy())
    issued = first.issue()

    proof = first.verify(issued.refresh_token)
    other_pepper = second.verify(issued.refresh_token)

    assert issued.refresh_token.startswith("rt_")
    assert len(issued.refresh_token) == 69
    assert isinstance(proof, accounts_module.RefreshTokenProof)
    assert proof.digest == issued.digest
    assert isinstance(other_pepper, accounts_module.RefreshTokenProof)
    assert other_pepper.digest != issued.digest
    assert isinstance(first.verify(token), InvalidCredentials)
    assert isinstance(first.digest_idempotency_key(issued.token_id, "%" * 22), InvalidCredentials)
    assert issued.refresh_token not in repr(issued)
    assert issued.digest.hex() not in repr(issued)


async def test_refresh_known_lookup_with_wrong_digest_is_invalid_without_family_revocation() -> None:
    service, store, _accounts, account = refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    token_id = initial.refresh_token.split(".")[0]
    wrong_secret = base64.urlsafe_b64encode(b"wrong" * 6 + b"!!").rstrip(b"=").decode()

    outcome = await service.rotate(
        f"{token_id}.{wrong_secret}", idempotency_key=refresh_idempotency_key(), now=_JWT_NOW
    )

    assert isinstance(outcome, InvalidCredentials)
    assert not store.revoked_families
    assert store.rotations == []


async def test_refresh_first_rotation_and_same_key_duplicate_return_exact_sealed_result() -> None:
    service, store, _accounts, account = refresh_service()
    initial = await service.issue(account, scopes=frozenset({"reports:read"}), now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    key = refresh_idempotency_key()

    first = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)
    duplicate = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)

    assert isinstance(first, accounts_module.TokenPair)
    assert duplicate == first
    assert store.rotations == [accounts_module.RefreshRotationStatus.ROTATED]
    assert isinstance(store.preparations[-1], accounts_module.RefreshReceiptReplay)
    original = next(iter(store.tokens.values()))
    successor_id = next(token_id for token_id in store.tokens if token_id != initial.refresh_token.split(".")[0])
    successor = store.tokens[successor_id]
    assert original.consumed
    assert successor.scopes == frozenset({"reports:read"})
    assert successor.token_expires_at <= successor.family_expires_at
    stored = repr(store.tokens)
    for plaintext in (initial.refresh_token, first.access_token, first.refresh_token):
        assert plaintext not in stored


async def test_refresh_rotation_preserves_original_passkey_assurance_and_time() -> None:
    service, store, _accounts, account = refresh_service()
    authenticated_at = _JWT_NOW - timedelta(minutes=2)
    evidence = AuthenticationEvidence(
        mechanism="passkey",
        slot="mfa",
        authenticated_at=authenticated_at,
        methods=frozenset({"passkey"}),
        traits=frozenset({"phishing-resistant"}),
        amr=("passkey",),
    )
    initial = await service.issue(account, evidence=evidence, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)

    rotated = await service.rotate(
        initial.refresh_token, idempotency_key=refresh_idempotency_key(), now=_JWT_NOW + timedelta(minutes=1)
    )

    assert isinstance(rotated, accounts_module.TokenPair)
    records = tuple(store.tokens.values())
    assert all(record.evidence == evidence for record in records)
    signer = cast("Any", service.access_tokens.signer)
    assert [claims["auth_time"] for claims in signer.claims] == [
        int(authenticated_at.timestamp()),
        int(authenticated_at.timestamp()),
    ]
    assert all(claims["amr"] == ["passkey"] for claims in signer.claims)


@pytest.mark.parametrize("outage", ["signer", "token_entropy", "receipt_entropy"])
async def test_refresh_same_key_retry_recovers_without_fresh_crypto(outage: str) -> None:
    service, _store, _accounts, account = refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    key = refresh_idempotency_key()
    first = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)
    assert isinstance(first, accounts_module.TokenPair)
    if outage == "signer":
        service = replace(service, access_tokens=RefreshAccessOutcome(VerificationUnavailable(), fail=True))
    elif outage == "token_entropy":
        service = replace(
            service,
            codec=accounts_module.RefreshTokenCodec(pepper=service.codec.pepper, entropy=lambda _length: b"short"),
        )
    else:
        service = replace(service, receipts=replace(service.receipts, entropy=lambda _length: b"short"))

    duplicate = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)

    assert duplicate == first


async def test_refresh_malformed_key_revokes_consumed_token_but_not_active_token() -> None:
    service, store, _accounts, account = refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    assert isinstance(
        await service.rotate(initial.refresh_token, idempotency_key="weak", now=_JWT_NOW), InvalidCredentials
    )
    first = await service.rotate(initial.refresh_token, idempotency_key=refresh_idempotency_key(), now=_JWT_NOW)
    assert isinstance(first, accounts_module.TokenPair)
    assert isinstance(
        await service.rotate(initial.refresh_token, idempotency_key="weak", now=_JWT_NOW), InvalidCredentials
    )
    assert next(iter(store.tokens.values())).family_id in store.revoked_families
    assert store.preparation_events[-1].operation == "local.refresh.prepare"
    assert store.preparation_events[-1].outcome == "attempted"
    assert "weak" not in repr(store.preparation_events[-1])


async def test_refresh_preflight_replay_receipt_failure_revokes_family() -> None:
    service, store, _accounts, account = refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    key = refresh_idempotency_key()
    first = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)
    assert isinstance(first, accounts_module.TokenPair)
    record = store.tokens[initial.refresh_token.partition(".")[0]]
    record.sealed_receipt = b"malformed"

    outcome = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert record.family_id in store.revoked_families


@pytest.mark.parametrize(
    ("second_key", "advance"),
    [
        (None, timedelta(0)),
        (refresh_idempotency_key(2), timedelta(0)),
        (refresh_idempotency_key(1), timedelta(seconds=30)),
    ],
)
async def test_refresh_replay_without_exact_live_key_revokes_family(second_key: str | None, advance: timedelta) -> None:
    service, store, _accounts, account = refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    first = await service.rotate(initial.refresh_token, idempotency_key=refresh_idempotency_key(1), now=_JWT_NOW)
    assert isinstance(first, accounts_module.TokenPair)

    replay = await service.rotate(initial.refresh_token, idempotency_key=second_key, now=_JWT_NOW + advance)

    assert isinstance(replay, InvalidCredentials)
    assert any(
        isinstance(prepared, accounts_module.RefreshPreflightOutcome)
        and prepared.status is accounts_module.RefreshRotationStatus.REPLAY_DETECTED
        and prepared.family_revoked
        for prepared in store.preparations
    )
    family_id = next(iter(store.tokens.values())).family_id
    assert family_id in store.revoked_families
    assert isinstance(
        await service.rotate(first.refresh_token, idempotency_key=second_key, now=_JWT_NOW + advance),
        InvalidCredentials,
    )


@pytest.mark.parametrize("receipt_kind", ["malformed", "expired", "swapped_context"])
async def test_refresh_invalid_store_receipt_fails_closed_and_revokes_family(receipt_kind: str) -> None:
    service, store, _accounts, account = refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    key = refresh_idempotency_key()
    proof = service.codec.verify(initial.refresh_token)
    assert isinstance(proof, accounts_module.RefreshTokenProof)
    digest = service.codec.digest_idempotency_key(proof.token_id, key)
    assert isinstance(digest, bytes)
    record = store.tokens[proof.token_id]
    if receipt_kind == "malformed":
        store.override_receipt = b"rr1.malformed"
    else:
        context = accounts_module.RefreshReceiptContext(
            token_id=proof.token_id,
            family_id=(refresh_identifier("rf_", 2) if receipt_kind == "swapped_context" else record.family_id),
            account_id=record.account_id,
            security_epoch=record.security_epoch,
            idempotency_digest=digest,
        )
        store.override_receipt = service.receipts.seal(
            accounts_module.TokenPair(
                access_token="e30.e30.YQ",  # noqa: S106 - compact public test JWT
                refresh_token=service.codec.issue().refresh_token,
                expires_in=600,
            ),
            context,
            expires_at=_JWT_NOW if receipt_kind == "expired" else _JWT_NOW + timedelta(seconds=30),
        )

    outcome = await service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert record.family_id in store.revoked_families


@pytest.mark.parametrize("condition", ["idle", "absolute", "epoch", "disabled", "account_revoke", "family_revoke"])
async def test_refresh_rotation_rejects_expiry_epoch_and_revocation_boundaries(condition: str) -> None:
    idle = timedelta(days=1)
    absolute = timedelta(days=2)
    service, store, accounts, account = refresh_service(idle_lifetime=idle, absolute_lifetime=absolute)
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    rotate_at = _JWT_NOW
    if condition == "idle":
        rotate_at += idle
    elif condition == "absolute":
        rotate_at += absolute
    elif condition == "epoch":
        accounts.security_epoch += 1
    elif condition == "disabled":
        accounts.account = replace(account, active=False)
    elif condition == "account_revoke":
        await store.revoke_for_account(
            account.account_id,
            event=accounts_module.SecurityEvent(
                "event-revoke", _JWT_NOW, "local.refresh.revoke", "revoked", account_id=account.account_id
            ),
        )
    else:
        family_id = next(iter(store.tokens.values())).family_id
        await store.revoke_family(
            family_id,
            event=accounts_module.SecurityEvent(
                "event-revoke", _JWT_NOW, "local.refresh.revoke", "revoked", family_id=family_id
            ),
        )

    outcome = await service.rotate(initial.refresh_token, idempotency_key=refresh_idempotency_key(), now=rotate_at)

    assert isinstance(outcome, InvalidCredentials)
    assert len(store.tokens) == 1


async def test_refresh_epoch_bump_after_preflight_is_rejected_by_atomic_rotate() -> None:
    accounts_holder: list[Any] = []

    def bump_epoch() -> None:
        accounts_holder[0].security_epoch += 1

    service, store, accounts, account = refresh_service(
        expected_preparations=100, expected_atomic_rotations=100, before_atomic_rotate=bump_epoch
    )
    accounts_holder.append(accounts)
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)

    outcomes = await asyncio.gather(
        *(
            service.rotate(initial.refresh_token, idempotency_key=refresh_idempotency_key(), now=_JWT_NOW)
            for _ in range(100)
        )
    )

    assert all(isinstance(outcome, InvalidCredentials) for outcome in outcomes)
    assert store.rotations == [accounts_module.RefreshRotationStatus.EPOCH_MISMATCH] * 100
    assert len(store.tokens) == 1
    assert not store.revoked_families


async def test_refresh_atomic_rotate_revalidates_preserved_scopes() -> None:
    service, store, _accounts, account = refresh_service()
    initial = await service.issue(account, scopes=frozenset({"read"}), now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    prepare_rotation = store.prepare_rotation

    async def broadened_preflight(
        proof: accounts_module.RefreshTokenProof,
        idempotency_digest: bytes | None,
        *,
        now: datetime,
        event: accounts_module.SecurityEvent,
    ) -> (
        accounts_module.RefreshFamilyContext
        | accounts_module.RefreshReceiptReplay
        | accounts_module.RefreshPreflightOutcome
    ):
        prepared = await prepare_rotation(proof, idempotency_digest, now=now, event=event)
        return (
            replace(prepared, scopes=frozenset({"admin"}))
            if isinstance(prepared, accounts_module.RefreshFamilyContext)
            else prepared
        )

    store.prepare_rotation = broadened_preflight  # type: ignore[method-assign]

    outcome = await service.rotate(initial.refresh_token, idempotency_key=refresh_idempotency_key(), now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert store.rotations == [accounts_module.RefreshRotationStatus.INVALID]
    assert len(store.tokens) == 1


async def test_refresh_presented_token_revoke_is_exact_and_idempotent() -> None:
    service, store, _accounts, account = refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)

    assert not await service.revoke_for_account("account-2", initial.refresh_token, now=_JWT_NOW)
    assert await service.revoke_for_account(account.account_id, initial.refresh_token, now=_JWT_NOW)
    assert not await service.revoke(initial.refresh_token, now=_JWT_NOW)
    assert isinstance(await service.revoke("malformed", now=_JWT_NOW), InvalidCredentials)
    assert len(store.revoked_families) == 1


@pytest.mark.parametrize("mode", ["shared_key", "no_key"])
async def test_refresh_one_hundred_way_races_enforce_one_logical_result(mode: str) -> None:
    service, store, _accounts, account = refresh_service(expected_preparations=100)
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    key = refresh_idempotency_key() if mode == "shared_key" else None

    outcomes = await asyncio.gather(
        *(service.rotate(initial.refresh_token, idempotency_key=key, now=_JWT_NOW) for _ in range(100))
    )

    successes = [outcome for outcome in outcomes if isinstance(outcome, accounts_module.TokenPair)]
    if mode == "shared_key":
        assert len(successes) == 100
        assert all(outcome == successes[0] for outcome in successes)
        assert store.rotations.count(accounts_module.RefreshRotationStatus.ROTATED) == 1
        assert store.rotations.count(accounts_module.RefreshRotationStatus.IDEMPOTENT_REPLAY) == 99
        assert not store.revoked_families
    else:
        assert len(successes) == 1
        assert sum(isinstance(outcome, InvalidCredentials) for outcome in outcomes) == 99
        assert store.rotations.count(accounts_module.RefreshRotationStatus.ROTATED) == 1
        assert accounts_module.RefreshRotationStatus.REPLAY_DETECTED in store.rotations
        assert len(store.revoked_families) == 1
        assert isinstance(await service.rotate(successes[0].refresh_token, now=_JWT_NOW), InvalidCredentials)


def test_refresh_response_headers_are_immutable_no_store_contract() -> None:
    assert accounts_module.REFRESH_RESPONSE_HEADERS == {"Cache-Control": "no-store", "Pragma": "no-cache"}
    with pytest.raises(TypeError):
        accounts_module.REFRESH_RESPONSE_HEADERS["Cache-Control"] = "public"  # type: ignore[index]


def testrefresh_service_rejects_invalid_composition_and_lifetimes() -> None:
    service, _store, _accounts, _account = refresh_service()
    invalid_values = (
        ("accounts", object(), "accounts"),
        ("store", object(), "store"),
        ("codec", object(), "codec"),
        ("receipts", object(), "receipts"),
        ("access_tokens", object(), "issuer"),
        ("idle_lifetime", object(), "lifetimes"),
        ("absolute_lifetime", object(), "lifetimes"),
        ("receipt_window", object(), "lifetimes"),
        ("idle_lifetime", timedelta(0), "lifetimes"),
        ("absolute_lifetime", timedelta(days=1), "lifetimes"),
        ("receipt_window", timedelta(0), "lifetimes"),
        ("receipt_window", timedelta(seconds=31), "lifetimes"),
        ("clock", None, "factories"),
        ("family_ids", None, "factories"),
        ("event_ids", None, "factories"),
    )

    for field_name, value, match in invalid_values:
        with pytest.raises(ImproperlyConfiguredException, match=match):
            replace(service, **{field_name: value})


async def testrefresh_service_default_clock_and_id_factories_issue_valid_family() -> None:
    service, store, accounts, account = refresh_service()
    defaulted = accounts_module.RefreshTokenService(
        accounts=accounts,
        store=store,
        codec=service.codec,
        receipts=service.receipts,
        access_tokens=service.access_tokens,
    )

    outcome = await defaulted.issue(account)

    assert isinstance(outcome, accounts_module.TokenPair)
    assert next(iter(store.tokens.values())).family_id.startswith("rf_")


@pytest.mark.parametrize(
    "mode",
    [
        "not_account",
        "inactive",
        "unverified",
        "clock_failure",
        "epoch_failure",
        "epoch_bool",
        "epoch_mismatch",
        "scopes_type",
        "scopes_broken",
        "scopes_invalid",
        "access_outcome",
        "access_failure",
        "access_shape",
        "bad_family_id",
        "codec_failure",
        "event_failure",
        "create_failure",
        "create_false",
    ],
)
async def test_refresh_issue_sanitizes_invalid_and_unavailable_composition(  # noqa: C901, PLR0912, PLR0915
    mode: str,
) -> None:
    service, store, accounts, account = refresh_service()
    candidate: object = account
    scopes: object = frozenset()
    now: datetime | None = _JWT_NOW
    if mode == "not_account":
        candidate = object()
    elif mode == "inactive":
        candidate = replace(account, active=False)
    elif mode == "unverified":
        candidate = replace(account, verified=False)
    elif mode == "clock_failure":
        service = replace(service, clock=lambda: 1 / 0)
        now = None
    elif mode == "epoch_failure":

        async def current_epoch(_account_id: str) -> int:
            raise OSError

        accounts.current_epoch = current_epoch  # type: ignore[method-assign]
    elif mode == "epoch_bool":

        async def current_epoch(_account_id: str) -> bool:
            return True

        accounts.current_epoch = current_epoch  # type: ignore[method-assign]
    elif mode == "epoch_mismatch":
        accounts.security_epoch += 1
    elif mode == "scopes_type":
        scopes = ["read"]
    elif mode == "scopes_broken":
        scopes = BrokenRefreshScopes()
    elif mode == "scopes_invalid":
        scopes = frozenset({"bad scope"})
    elif mode == "access_outcome":
        service = replace(service, access_tokens=RefreshAccessOutcome(InvalidCredentials()))
    elif mode == "access_failure":
        service = replace(service, access_tokens=RefreshAccessOutcome(VerificationUnavailable(), fail=True))
    elif mode == "access_shape":
        service = replace(service, access_tokens=RefreshAccessOutcome(object()))
    elif mode == "bad_family_id":
        service = replace(service, family_ids=lambda: "invalid")
    elif mode == "codec_failure":
        service = replace(
            service, codec=accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=lambda _length: b"short")
        )
    elif mode == "event_failure":
        service = replace(service, event_ids=lambda: " ")
    elif mode == "create_failure":

        async def create_family(
            _command: accounts_module.CreateRefreshFamilyCommand, *, event: accounts_module.SecurityEvent
        ) -> bool:
            del event
            raise OSError

        store.create_family = create_family  # type: ignore[method-assign]
    else:

        async def create_family(
            _command: accounts_module.CreateRefreshFamilyCommand, *, event: accounts_module.SecurityEvent
        ) -> bool:
            del event
            return False

        store.create_family = create_family  # type: ignore[method-assign]

    outcome = await service.issue(candidate, scopes=scopes, now=now)  # type: ignore[arg-type]

    expected = (
        VerificationUnavailable
        if mode
        in {
            "clock_failure",
            "epoch_failure",
            "access_failure",
            "access_shape",
            "bad_family_id",
            "codec_failure",
            "event_failure",
            "create_failure",
            "create_false",
        }
        else InvalidCredentials
    )
    assert isinstance(outcome, expected)


@pytest.mark.parametrize(
    "mode",
    [
        "malformed",
        "prepare_failure",
        "prepare_shape",
        "expired_context",
        "invalid_idempotency",
        "replay_account_failure",
        "account_failure",
        "access_outcome",
        "access_failure",
        "access_shape",
        "codec_failure",
        "seal_failure",
        "event_failure",
        "rotate_failure",
        "rotate_shape",
        "receipt_revoke_failure",
        "receipt_revoke_false",
    ],
)
async def test_refresh_rotate_sanitizes_invalid_and_unavailable_composition(  # noqa: C901,PLR0912,PLR0915
    mode: str,
) -> None:
    service, store, accounts, account = refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)
    presented = initial.refresh_token
    idempotency_key: str | None = refresh_idempotency_key()
    if mode == "malformed":
        presented = "malformed"
    elif mode == "prepare_failure":

        async def prepare_rotation(
            _proof: accounts_module.RefreshTokenProof,
            _idempotency_digest: bytes | None,
            *,
            now: datetime,
            event: accounts_module.SecurityEvent,
        ) -> accounts_module.RefreshPreflightOutcome:
            del now, event
            raise OSError

        store.prepare_rotation = prepare_rotation  # type: ignore[method-assign]
    elif mode == "prepare_shape":

        async def prepare_rotation(
            _proof: accounts_module.RefreshTokenProof,
            _idempotency_digest: bytes | None,
            *,
            now: datetime,
            event: accounts_module.SecurityEvent,
        ) -> object:
            del now, event
            return object()

        store.prepare_rotation = prepare_rotation  # type: ignore[method-assign]
    elif mode == "expired_context":
        record = next(iter(store.tokens.values()))

        async def prepare_rotation(
            _proof: accounts_module.RefreshTokenProof,
            _idempotency_digest: bytes | None,
            *,
            now: datetime,
            event: accounts_module.SecurityEvent,
        ) -> accounts_module.RefreshFamilyContext:
            del now, event
            return accounts_module.RefreshFamilyContext(
                account_id=record.account_id,
                family_id=record.family_id,
                security_epoch=record.security_epoch,
                token_expires_at=_JWT_NOW,
                family_expires_at=record.family_expires_at,
                scopes=record.scopes,
            )

        store.prepare_rotation = prepare_rotation  # type: ignore[method-assign]
    elif mode == "invalid_idempotency":
        idempotency_key = "weak"
    elif mode == "replay_account_failure":
        first = await service.rotate(presented, idempotency_key=idempotency_key, now=_JWT_NOW)
        assert isinstance(first, accounts_module.TokenPair)

        async def get_by_id(_account_id: str) -> None:
            return None

        accounts.get_by_id = get_by_id  # type: ignore[method-assign]
    elif mode == "account_failure":

        async def get_by_id(_account_id: str) -> accounts_module.LocalAccountState[object] | None:
            raise OSError

        accounts.get_by_id = get_by_id  # type: ignore[method-assign]
    elif mode == "access_outcome":
        service = replace(service, access_tokens=RefreshAccessOutcome(VerificationUnavailable()))
    elif mode == "access_failure":
        service = replace(service, access_tokens=RefreshAccessOutcome(VerificationUnavailable(), fail=True))
    elif mode == "access_shape":
        service = replace(service, access_tokens=RefreshAccessOutcome(object()))
    elif mode == "codec_failure":
        service = replace(
            service,
            codec=accounts_module.RefreshTokenCodec(pepper=service.codec.pepper, entropy=lambda _length: b"short"),
        )
    elif mode == "seal_failure":
        service = replace(
            service,
            receipts=accounts_module.RefreshReceiptSealer(
                active_key=accounts_module.RefreshReceiptKey("key", b"k" * 32), entropy=lambda _length: b"short"
            ),
        )
    elif mode == "event_failure":
        service = replace(service, event_ids=lambda: " ")
    elif mode == "rotate_failure":

        async def rotate(
            _command: accounts_module.RotateRefreshCommand, *, now: datetime, event: accounts_module.SecurityEvent
        ) -> accounts_module.RefreshRotationOutcome:
            del now, event
            raise OSError

        store.rotate = rotate  # type: ignore[method-assign]
    elif mode == "rotate_shape":

        async def rotate(
            _command: accounts_module.RotateRefreshCommand, *, now: datetime, event: accounts_module.SecurityEvent
        ) -> object:
            del now, event
            return object()

        store.rotate = rotate  # type: ignore[method-assign]
    else:
        store.override_receipt = b"malformed"
        if mode == "receipt_revoke_failure":

            async def revoke_family(_family_id: str, *, event: accounts_module.SecurityEvent) -> bool:
                del event
                raise OSError

        else:

            async def revoke_family(_family_id: str, *, event: accounts_module.SecurityEvent) -> bool:
                del event
                return False

        store.revoke_family = revoke_family  # type: ignore[method-assign,possibly-undefined]

    outcome = await service.rotate(presented, idempotency_key=idempotency_key, now=_JWT_NOW)

    unavailable_modes = {
        "prepare_failure",
        "prepare_shape",
        "account_failure",
        "access_outcome",
        "access_failure",
        "access_shape",
        "codec_failure",
        "seal_failure",
        "event_failure",
        "rotate_failure",
        "rotate_shape",
        "receipt_revoke_failure",
        "receipt_revoke_false",
    }
    assert isinstance(outcome, VerificationUnavailable if mode in unavailable_modes else InvalidCredentials)


async def test_refresh_revoke_maps_store_and_clock_failures_to_unavailable() -> None:
    service, store, _accounts, account = refresh_service()
    initial = await service.issue(account, now=_JWT_NOW)
    assert isinstance(initial, accounts_module.TokenPair)

    async def revoke_token(_token_id: str, _token_digest: bytes, *, event: accounts_module.SecurityEvent) -> bool:
        del event
        raise OSError

    store.revoke_token = revoke_token  # type: ignore[method-assign]
    assert isinstance(await service.revoke(initial.refresh_token, now=_JWT_NOW), VerificationUnavailable)

    async def malformed_revoke_token(
        _token_id: str, _token_digest: bytes, *, event: accounts_module.SecurityEvent
    ) -> object:
        del event
        return object()

    store.revoke_token = malformed_revoke_token  # type: ignore[method-assign]
    assert isinstance(await service.revoke(initial.refresh_token, now=_JWT_NOW), VerificationUnavailable)
    assert isinstance(
        await replace(service, clock=lambda: 1 / 0).revoke(initial.refresh_token), VerificationUnavailable
    )
    assert isinstance(await service.revoke_for_account("", initial.refresh_token, now=_JWT_NOW), InvalidCredentials)
    assert isinstance(
        await service.revoke_for_account(account.account_id, "malformed", now=_JWT_NOW), InvalidCredentials
    )

    async def failing_account_revoke(
        _account_id: str, _token_id: str, _token_digest: bytes, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del event
        raise OSError

    store.revoke_token_for_account = failing_account_revoke  # type: ignore[method-assign]
    assert isinstance(
        await service.revoke_for_account(account.account_id, initial.refresh_token, now=_JWT_NOW),
        VerificationUnavailable,
    )

    async def malformed_account_revoke(
        _account_id: str, _token_id: str, _token_digest: bytes, *, event: accounts_module.SecurityEvent
    ) -> object:
        del event
        return object()

    store.revoke_token_for_account = malformed_account_revoke  # type: ignore[method-assign]
    assert isinstance(
        await service.revoke_for_account(account.account_id, initial.refresh_token, now=_JWT_NOW),
        VerificationUnavailable,
    )
    assert isinstance(
        await replace(service, clock=lambda: 1 / 0).revoke_for_account(account.account_id, initial.refresh_token),
        VerificationUnavailable,
    )
