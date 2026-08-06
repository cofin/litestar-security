"""Unit coverage for bound, single-use step-up grants."""

from datetime import datetime, timedelta, timezone

import pytest
from anyio import create_task_group

import litestar_security.accounts as accounts_module
import litestar_security.accounts.controllers._mfa as mfa_controllers_module
import litestar_security.testing as testing_module
from litestar_security.authentication import InvalidCredentials
from litestar_security.context import AuthenticationEvidence
from tests.fixtures.accounts import StepUpStore


async def test_step_up_grant_is_exactly_bound_expiring_and_single_use() -> None:
    store = StepUpStore()
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    service = accounts_module.StepUpService(store=store, clock=lambda: now, entropy=lambda _size: b"g" * 32)
    source = AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=now, methods=frozenset({"totp"}))

    grant = await service.issue(
        principal_id="account-1",
        security_epoch=2,
        purpose="password-change",
        transport_binding=b"session-1",
        evidence=source,
    )

    assert isinstance(grant, accounts_module.StepUpCredential)
    assert "gggg" not in repr(grant)
    assert isinstance(
        await service.consume(
            grant.token,
            principal_id="account-1",
            security_epoch=2,
            purpose="different-action",
            transport_binding=b"session-1",
        ),
        InvalidCredentials,
    )
    replay = await service.consume(
        grant.token,
        principal_id="account-1",
        security_epoch=2,
        purpose="password-change",
        transport_binding=b"session-1",
    )
    assert isinstance(replay, InvalidCredentials)


@pytest.mark.parametrize("changed", ["principal", "epoch", "transport", "expiry"])
async def test_step_up_grant_rejects_changed_binding(changed: str) -> None:
    store = StepUpStore()
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    service = accounts_module.StepUpService(store=store, clock=lambda: now)
    source = AuthenticationEvidence(
        mechanism="passkey",
        slot="mfa",
        authenticated_at=now,
        methods=frozenset({"passkey"}),
        traits=frozenset({"phishing-resistant"}),
    )
    grant = await service.issue(
        principal_id="account-1",
        security_epoch=2,
        purpose="credential-remove",
        transport_binding=b"token-1",
        evidence=source,
    )
    assert isinstance(grant, accounts_module.StepUpCredential)
    if changed == "expiry":
        service.clock = lambda: now + timedelta(minutes=6)
    result = await service.consume(
        grant.token,
        principal_id="account-2" if changed == "principal" else "account-1",
        security_epoch=3 if changed == "epoch" else 2,
        purpose="credential-remove",
        transport_binding=b"token-2" if changed == "transport" else b"token-1",
    )
    assert isinstance(result, InvalidCredentials)


def test_public_testing_helpers_are_isolated_structural_conformance_ports() -> None:
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    clock = testing_module.FakeClock(now)

    assert isinstance(testing_module.InMemoryMFAStore(), accounts_module.MFAStore)
    assert isinstance(testing_module.InMemoryMFALoginChallengeStore(), accounts_module.MFALoginChallengeStore)
    assert isinstance(testing_module.InMemorySecurityBackend().mfa_login, accounts_module.MFALoginChallengeStore)
    assert isinstance(testing_module.InMemoryWebAuthnChallengeStore(), accounts_module.WebAuthnChallengeStore)
    assert isinstance(testing_module.InMemoryPasskeyStore(), accounts_module.PasskeyStore)
    assert isinstance(testing_module.InMemoryStepUpStore(), accounts_module.StepUpStore)
    assert clock() == now
    assert clock.advance(timedelta(seconds=1)) == now + timedelta(seconds=1)
    with pytest.raises(ValueError, match="positive"):
        clock.advance(timedelta())


async def test_public_step_up_conformance_store_has_one_atomic_winner() -> None:
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    store = testing_module.InMemoryStepUpStore()
    service = accounts_module.StepUpService(store=store, clock=lambda: now, entropy=lambda _size: b"s" * 32)
    grant = await service.issue(
        principal_id="account-1",
        security_epoch=1,
        purpose="settings",
        transport_binding=b"session",
        evidence=AuthenticationEvidence(
            mechanism="totp", slot="mfa", authenticated_at=now, methods=frozenset({"totp"})
        ),
    )
    assert isinstance(grant, accounts_module.StepUpCredential)
    outcomes: list[object] = []

    async def consume() -> None:
        outcomes.append(
            await service.consume(
                grant.token,
                principal_id="account-1",
                security_epoch=1,
                purpose="settings",
                transport_binding=b"session",
            )
        )

    async with create_task_group() as task_group:
        task_group.start_soon(consume)
        task_group.start_soon(consume)

    assert sum(isinstance(outcome, AuthenticationEvidence) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, InvalidCredentials) for outcome in outcomes) == 1


def test_step_up_purpose_allowlist_covers_every_consumed_purpose_with_strong_factors() -> None:
    purpose_methods = mfa_controllers_module._PURPOSE_METHODS  # noqa: SLF001 - assert the deny-by-default contract

    assert set(purpose_methods) == {
        "totp-enroll",
        "totp-remove",
        "recovery-codes",
        "passkey-register",
        "passkey-remove",
    }
    assert all(methods == frozenset({"password", "passkey"}) for methods in purpose_methods.values())
