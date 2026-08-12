"""Unit coverage for pre-authentication MFA challenges."""

import hmac
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast

import pytest
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security.accounts as accounts_module
import litestar_security.accounts._mfa_login as mfa_login_module
import litestar_security.accounts._rate_limits as rate_limits_module
import litestar_security.testing as testing_module
from litestar_security.accounts._mfa_login import MFARequired
from litestar_security.accounts._operations import LOGIN_MFA
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence
from tests.fixtures.accounts import (
    FailingMFALoginChallengeStore,
    MFALoginVerificationService,
    MFAProtector,
    MFAStore,
    ScriptedTOTPVerificationService,
    build_mfa_service,
)

_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)


def test_mfa_login_outcome_is_secret_safe_and_rate_limited() -> None:
    outcome = MFARequired(
        challenge="reveal-once-challenge",
        account_id="account-1",
        expires_at=_NOW + timedelta(minutes=5),
        methods=frozenset({"totp", "recovery-code"}),
    )
    assert outcome.code == "mfa_required"
    assert outcome.account_id == "account-1"
    assert "reveal-once-challenge" not in repr(outcome)
    with pytest.raises(FrozenInstanceError):
        outcome.challenge = "replacement"  # type: ignore[misc]
    assert rate_limits_module.DEFAULT_RATE_LIMIT_POLICIES[LOGIN_MFA] == rate_limits_module.RateLimitPolicy(
        limit=10, window=timedelta(minutes=5)
    )


@pytest.mark.parametrize(
    ("lifetime", "valid"),
    [
        (timedelta(microseconds=1), True),
        (timedelta(minutes=10), True),
        (timedelta(), False),
        (timedelta(minutes=10, microseconds=1), False),
    ],
)
def test_mfa_login_challenge_enforces_exact_positive_ten_minute_lifetime(lifetime: timedelta, *, valid: bool) -> None:
    values = {
        "challenge_digest": b"d" * 32,
        "account_id": "account-1",
        "security_epoch": 0,
        "client_key": "client",
        "issued_at": _NOW,
        "expires_at": _NOW + lifetime,
    }
    if valid:
        assert accounts_module.MFALoginChallenge(**values).expires_at == _NOW + lifetime
    else:
        with pytest.raises(ValueError, match="lifetime bindings"):
            accounts_module.MFALoginChallenge(**values)


async def test_mfa_login_issue_derives_a_domain_separated_digest_and_consumes_once() -> None:
    secrets = accounts_module.LocalAuthSecrets.session(purpose_token_pepper=b"p" * 32)
    store = testing_module.InMemoryMFALoginChallengeStore()
    service = mfa_login_module.MFALoginService(
        store=store,
        mfa=build_mfa_service(MFAStore(), MFAProtector(), now=_NOW),
        pepper=secrets.mfa_login_pepper,
        clock=lambda: _NOW,
        entropy=lambda size: b"x" * size,
    )
    issued = await service.issue(
        accounts_module.LocalAccountState(
            account_id="account-1",
            normalized_identifier="person@example.com",
            display_name="Person",
            active=True,
            verified=True,
            security_epoch=0,
            user={"id": "account-1"},
        ),
        client_key="127.0.0.1",
    )
    assert isinstance(issued, MFARequired)
    expected_digest = hmac.digest(secrets.mfa_login_pepper, issued.challenge.encode("ascii"), "sha256")
    assert tuple(store.challenges) == (expected_digest,)
    assert isinstance(
        await service.consume(issued.challenge, account_id="account-1", security_epoch=0, client_key="127.0.0.1"),
        accounts_module.MFALoginChallenge,
    )
    assert (
        await service.consume(issued.challenge, account_id="account-1", security_epoch=0, client_key="127.0.0.1")
        == InvalidCredentials()
    )


async def test_mfa_login_store_burns_expired_and_missing_challenges() -> None:
    store = testing_module.InMemoryMFALoginChallengeStore()
    expired = accounts_module.MFALoginChallenge(
        challenge_digest=b"e" * 32,
        account_id="account-1",
        security_epoch=0,
        client_key=None,
        issued_at=_NOW - timedelta(minutes=1),
        expires_at=_NOW,
    )
    await store.put(expired)
    assert await store.consume(b"e" * 32, account_id="account-1", security_epoch=0, now=_NOW) is None
    assert await store.consume(b"m" * 32, account_id="account-1", security_epoch=0, now=_NOW) is None
    assert store.challenges == {}


@pytest.mark.parametrize(
    ("method", "method_id", "expected_call"),
    [
        ("totp", "method-1", ("totp", "account-1", "method-1", "123456")),
        ("recovery-code", None, ("recovery-code", "account-1", None, "123456")),
    ],
)
async def test_mfa_login_verifies_only_the_selected_factor(
    method: str, method_id: str | None, expected_call: tuple[str, str, str | None, str]
) -> None:
    mfa = MFALoginVerificationService()
    service = mfa_login_module.MFALoginService(
        store=testing_module.InMemoryMFALoginChallengeStore(), mfa=mfa, pepper=b"p" * 32
    )
    record = accounts_module.MFALoginChallenge(
        challenge_digest=b"d" * 32,
        account_id="account-1",
        security_epoch=0,
        client_key=None,
        issued_at=_NOW,
        expires_at=_NOW + timedelta(minutes=5),
    )
    assert isinstance(
        await service.verify(record, method=method, method_id=method_id, code="123456"), AuthenticationEvidence
    )
    assert mfa.calls == [expected_call]
    assert await service.verify(record, method="unknown", method_id=None, code="123456") == InvalidCredentials()
    assert await service.verify(record, method="totp", method_id=None, code="123456") == InvalidCredentials()
    assert mfa.calls == [expected_call]
    unavailable = replace(service, mfa=MFALoginVerificationService(fail=True))
    assert (
        await unavailable.verify(record, method=method, method_id=method_id, code="123456") == VerificationUnavailable()
    )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"store": object()}, "store"),
        ({"mfa": object()}, "MFA capability"),
        ({"pepper": b"short"}, "pepper"),
        ({"methods": frozenset()}, "methods"),
        ({"ttl": timedelta()}, "lifetime"),
        ({"clock": object()}, "callable"),
    ],
)
def test_mfa_login_service_rejects_incomplete_or_unbounded_dependencies(kwargs: dict[str, object], match: str) -> None:
    values: dict[str, object] = {
        "store": testing_module.InMemoryMFALoginChallengeStore(),
        "mfa": build_mfa_service(MFAStore(), MFAProtector()),
        "pepper": b"p" * 32,
    }
    values.update(kwargs)
    with pytest.raises(ImproperlyConfiguredException, match=match):
        mfa_login_module.MFALoginService(**values)  # type: ignore[arg-type]


async def test_mfa_login_service_fail_closes_invalid_inputs_and_collaborators() -> None:
    account = accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=0,
    )
    service = mfa_login_module.MFALoginService(
        store=testing_module.InMemoryMFALoginChallengeStore(),
        mfa=build_mfa_service(MFAStore(), MFAProtector()),
        pepper=b"p" * 32,
        entropy=lambda _size: b"short",
    )
    assert await service.issue(account, client_key="client") == VerificationUnavailable()
    assert await service.issue(replace(account, account_id="\ud800"), client_key="client") == VerificationUnavailable()
    failing = replace(service, store=FailingMFALoginChallengeStore(), entropy=lambda size: b"x" * size)
    assert await failing.issue(account, client_key=None) == VerificationUnavailable()
    assert (
        await failing.consume("challenge", account_id="account-1", security_epoch=0, client_key=None)
        == VerificationUnavailable()
    )


async def test_local_auth_mfa_completion_gates_issuance_and_reuses_one_client_key() -> None:
    account = accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=2,
    )
    challenge = accounts_module.MFALoginChallenge(
        challenge_digest=b"d" * 32,
        account_id=account.account_id,
        security_epoch=account.security_epoch,
        client_key="client",
        issued_at=_NOW,
        expires_at=_NOW + timedelta(minutes=5),
    )
    calls: list[str] = []

    async def get_by_id(_account_id: str) -> object:
        calls.append("account")
        return account

    async def check(*_args: object, **_kwargs: object) -> None:
        calls.append("limit")

    async def consume(*_args: object, **_kwargs: object) -> object:
        calls.append("consume")
        return challenge

    async def verify(*_args: object, **_kwargs: object) -> object:
        calls.append("verify")
        return AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=_NOW, methods=frozenset({"totp"}))

    async def establish(
        _request: object, _account: object, *, evidence: AuthenticationEvidence
    ) -> accounts_module.SessionAuthentication:
        calls.append("establish")
        assert evidence.methods == frozenset({"password", "totp"})
        assert evidence.amr == ("pwd", "otp")
        return accounts_module.SessionAuthentication(
            session_id="c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M",
            binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
            account_id=account.account_id,
            security_epoch=account.security_epoch,
            authenticated_at=_NOW,
            expires_at=_NOW + timedelta(hours=1),
        )

    service = accounts_module.LocalAuthService(
        accounts=cast("Any", SimpleNamespace(get_by_id=get_by_id)),
        password_login=cast("Any", object()),
        password_reauthentication=cast("Any", object()),
        password_change=cast("Any", object()),
        verification=cast("Any", object()),
        recovery=cast("Any", object()),
        session_auth=cast("Any", SimpleNamespace(establish=establish)),
        rate_limits=cast("Any", SimpleNamespace(check=check)),
        mfa_login=cast("Any", SimpleNamespace(consume=consume, verify=verify)),
        client_key=lambda _request: "client",
    )

    outcome = await service.complete_mfa_login(
        cast("Any", object()),
        "challenge",
        account_id=account.account_id,
        method="totp",
        method_id="method-1",
        code="123456",
        transport="session",
    )

    assert isinstance(outcome, accounts_module.LocalAccount)
    assert calls == ["limit", "account", "consume", "verify", "account", "establish"]

    unavailable = replace(service, rate_limits=None)
    assert isinstance(
        await unavailable.complete_mfa_login(
            cast("Any", object()),
            "challenge",
            account_id=account.account_id,
            method="totp",
            method_id="method-1",
            code="123456",
            transport="session",
        ),
        VerificationUnavailable,
    )


@pytest.mark.parametrize("failure", ["limit", "account", "consume", "verify"])
async def test_local_auth_mfa_completion_fail_closes_collaborator_failures(failure: str) -> None:
    account = accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=0,
    )
    challenge = accounts_module.MFALoginChallenge(
        challenge_digest=b"d" * 32,
        account_id=account.account_id,
        security_epoch=account.security_epoch,
        client_key="client",
        issued_at=_NOW,
        expires_at=_NOW + timedelta(minutes=5),
    )

    async def boundary(name: str, result: object = None) -> object:
        if failure == name:
            raise OSError
        return result

    service = accounts_module.LocalAuthService(
        accounts=cast("Any", SimpleNamespace(get_by_id=lambda _account_id: boundary("account", account))),
        password_login=cast("Any", object()),
        password_reauthentication=cast("Any", object()),
        password_change=cast("Any", object()),
        verification=cast("Any", object()),
        recovery=cast("Any", object()),
        rate_limits=cast("Any", SimpleNamespace(check=lambda *_args, **_kwargs: boundary("limit"))),
        mfa_login=cast(
            "Any",
            SimpleNamespace(
                consume=lambda *_args, **_kwargs: boundary("consume", challenge),
                verify=lambda *_args, **_kwargs: boundary("verify", InvalidCredentials()),
            ),
        ),
        client_key=lambda _request: "client",
    )

    assert isinstance(
        await service.complete_mfa_login(
            cast("Any", object()),
            "challenge",
            account_id=account.account_id,
            method="totp",
            method_id="method-1",
            code="123456",
        ),
        VerificationUnavailable,
    )


def test_local_mfa_wire_representations_redact_challenge_and_factor_proof() -> None:
    required = accounts_module.LocalMFAChallenge(
        challenge="challenge-secret", account_id="account-1", expires_at=_NOW, methods=("totp",)
    )
    completion = accounts_module.LocalMFACompletion(
        challenge="challenge-secret", account_id="account-1", method="totp", code="factor-secret"
    )
    assert "challenge-secret" not in repr(required)
    assert "challenge-secret" not in repr(completion)
    assert "factor-secret" not in repr(completion)


async def test_mfa_login_rejects_malformed_challenges_and_burns_client_key_mismatches() -> None:
    """Malformed input does not reach the store, while a binding mismatch burns it."""
    now = _NOW
    store = testing_module.InMemoryMFALoginChallengeStore()
    service = mfa_login_module.MFALoginService(
        store=store,
        mfa=build_mfa_service(MFAStore(), MFAProtector(), now=now),
        pepper=b"p" * 32,
        clock=lambda: now,
        entropy=lambda size: b"x" * size,
    )
    account = accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=0,
    )
    assert (
        await service.consume("not-ascii-\u00e9", account_id="account-1", security_epoch=0, client_key="client")
        == InvalidCredentials()
    )
    issued = await service.issue(account, client_key="client")
    assert isinstance(issued, MFARequired)
    assert (
        await service.consume(issued.challenge, account_id="account-1", security_epoch=0, client_key="other-client")
        == InvalidCredentials()
    )
    assert (
        await service.consume(issued.challenge, account_id="account-1", security_epoch=0, client_key="client")
        == InvalidCredentials()
    )
    unicode_issued = await service.issue(account, client_key="client")
    assert isinstance(unicode_issued, MFARequired)
    assert (
        await service.consume(
            unicode_issued.challenge, account_id="account-1", security_epoch=0, client_key="bad-\ud800"
        )
        == InvalidCredentials()
    )
    assert (
        await service.consume(unicode_issued.challenge, account_id="account-1", security_epoch=0, client_key="client")
        == InvalidCredentials()
    )


@pytest.mark.parametrize(
    ("limited", "account", "expected"),
    [
        (accounts_module.RateLimited(retry_after=3), object(), accounts_module.RateLimited(retry_after=3)),
        (None, None, InvalidCredentials()),
        (
            None,
            accounts_module.LocalAccountState(
                account_id="account-1",
                normalized_identifier="person@example.com",
                display_name="Person",
                active=False,
                verified=True,
                security_epoch=0,
            ),
            InvalidCredentials(),
        ),
    ],
)
async def test_local_auth_mfa_completion_stops_before_challenge_for_limited_or_inactive_accounts(
    limited: object, account: object, expected: object
) -> None:
    async def get_by_id(_account_id: str) -> object:
        return account

    async def check(*_args: object, **_kwargs: object) -> object:
        return limited

    async def consume(*_args: object, **_kwargs: object) -> object:
        pytest.fail("a rate limit or invalid account must not consume the challenge")

    service = accounts_module.LocalAuthService(
        accounts=cast("Any", SimpleNamespace(get_by_id=get_by_id)),
        password_login=cast("Any", object()),
        password_reauthentication=cast("Any", object()),
        password_change=cast("Any", object()),
        verification=cast("Any", object()),
        recovery=cast("Any", object()),
        rate_limits=cast("Any", SimpleNamespace(check=check)),
        mfa_login=cast("Any", SimpleNamespace(consume=consume)),
    )
    assert (
        await service.complete_mfa_login(
            cast("Any", object()),
            "challenge",
            account_id="account-1",
            method="totp",
            method_id="method-1",
            code="123456",
        )
        == expected
    )


async def test_mfa_login_helper_boundaries_fail_closed_without_secret_processing() -> None:
    service = mfa_login_module.MFALoginService(
        store=testing_module.InMemoryMFALoginChallengeStore(),
        mfa=build_mfa_service(MFAStore(), MFAProtector()),
        pepper=b"p" * 32,
    )
    assert (
        await service.issue(cast("Any", SimpleNamespace(account_id="\ud800", security_epoch=0)), client_key=None)
        == VerificationUnavailable()
    )
    assert (
        await service.issue(cast("Any", SimpleNamespace(account_id="account-1", security_epoch=0)), client_key="\ud800")
        == VerificationUnavailable()
    )
    assert mfa_login_module._strict_ascii_context("\ud800") is False  # noqa: SLF001
    assert mfa_login_module._valid_methods({"totp"}) is False  # noqa: SLF001
    assert mfa_login_module._client_keys_match(None, "client") is False  # noqa: SLF001
    assert mfa_login_module._client_keys_match("client", 1) is False  # noqa: SLF001
    assert mfa_login_module._client_keys_match("\ud800", "\ud800") is False  # noqa: SLF001

    record = accounts_module.MFALoginChallenge(b"d" * 32, "account-1", 0, None, _NOW, _NOW + timedelta(minutes=5))
    object.__setattr__(service, "methods", frozenset({"unimplemented"}))
    assert await service.verify(record, method="unimplemented", method_id=None, code="123456") == InvalidCredentials()


async def test_local_auth_mfa_completion_rejects_an_epoch_advance_before_issuance() -> None:
    account = accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=2,
    )
    challenge = accounts_module.MFALoginChallenge(
        b"d" * 32, account.account_id, 2, None, _NOW, _NOW + timedelta(minutes=5)
    )
    reads = 0
    issued = False

    async def get_by_id(_account_id: str) -> object:
        nonlocal reads
        reads += 1
        return account if reads == 1 else replace(account, security_epoch=3)

    async def check(*_args: object, **_kwargs: object) -> None:
        pass

    async def consume(*_args: object, **_kwargs: object) -> object:
        return challenge

    async def verify(*_args: object, **_kwargs: object) -> object:
        return AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=_NOW)

    async def establish(*_args: object, **_kwargs: object) -> object:
        nonlocal issued
        issued = True
        return object()

    service = accounts_module.LocalAuthService(
        accounts=cast("Any", SimpleNamespace(get_by_id=get_by_id)),
        password_login=cast("Any", object()),
        password_reauthentication=cast("Any", object()),
        password_change=cast("Any", object()),
        verification=cast("Any", object()),
        recovery=cast("Any", object()),
        session_auth=cast("Any", SimpleNamespace(establish=establish)),
        rate_limits=cast("Any", SimpleNamespace(check=check)),
        mfa_login=cast("Any", SimpleNamespace(consume=consume, verify=verify)),
    )
    outcome = await service.complete_mfa_login(
        cast("Any", object()),
        "challenge",
        account_id=account.account_id,
        method="totp",
        code="123456",
        transport="session",
    )
    assert isinstance(outcome, InvalidCredentials)
    assert not issued


async def test_local_auth_mfa_completion_burns_a_wrong_factor_before_a_retry() -> None:
    account = accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=0,
    )
    factors = ScriptedTOTPVerificationService(accepted_code="correct", now=_NOW)
    mfa_login = mfa_login_module.MFALoginService(
        store=testing_module.InMemoryMFALoginChallengeStore(),
        mfa=factors,
        pepper=b"p" * 32,
        clock=lambda: _NOW,
        entropy=lambda _size: b"x" * 32,
    )

    async def get_by_id(_account_id: str) -> object:
        return account

    async def check(*_args: object, **_kwargs: object) -> None:
        pass

    service = accounts_module.LocalAuthService(
        accounts=cast("Any", SimpleNamespace(get_by_id=get_by_id)),
        password_login=cast("Any", object()),
        password_reauthentication=cast("Any", object()),
        password_change=cast("Any", object()),
        verification=cast("Any", object()),
        recovery=cast("Any", object()),
        rate_limits=cast("Any", SimpleNamespace(check=check)),
        mfa_login=mfa_login,
        client_key=lambda _request: "client",
    )
    issued = await mfa_login.issue(account, client_key="client")
    assert isinstance(issued, MFARequired)
    for code in ("wrong", "correct"):
        assert isinstance(
            await service.complete_mfa_login(
                cast("Any", object()),
                issued.challenge,
                account_id=account.account_id,
                method="totp",
                method_id="method-1",
                code=code,
            ),
            InvalidCredentials,
        )
    assert factors.codes == ["wrong"]
