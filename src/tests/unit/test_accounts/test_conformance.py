"""Account-store conformance contract tests."""

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import pytest
from litestar.stores.memory import MemoryStore

import litestar_security.testing as testing_module
from litestar_security.accounts import (
    AESGCMSecretProtector,
    RateLimiter,
    RateLimitPolicy,
    SecretProtectorKey,
    StoreRateLimiter,
)
from litestar_security.testing import (
    InMemorySecurityBackend,
    assert_local_account_store_conformance,
    assert_mfa_login_challenge_store_conformance,
    assert_mfa_store_conformance,
    assert_passkey_store_conformance,
    assert_rate_limiter_conformance,
    assert_refresh_family_store_conformance,
    assert_secret_protector_conformance,
    assert_session_registry_conformance,
    assert_step_up_store_conformance,
    assert_webauthn_challenge_store_conformance,
)
from tests.fixtures.accounts_conformance import (
    _AADIgnoringSecretProtector,
    _AlwaysAdvanceMFAStore,
    _AlwaysConsumeRecoveryStore,
    _BrokenAccountStore,
    _BrokenMFALoginChallengeStore,
    _BrokenMFAStore,
    _BrokenPasskeyCloneResultStore,
    _BrokenPasskeyCloneStateStore,
    _BrokenPasskeyStore,
    _BrokenRefreshStore,
    _BrokenSessionStore,
    _BrokenStepUpStore,
    _BrokenWebAuthnChallengeStore,
    _DeterministicSecretProtector,
    _EqualCounterMFAStore,
    _NonAtomicLimiter,
    _NonAtomicPasskeyResultStore,
    _RejectingMFAActivationStore,
    _RejectingPasskeyStore,
    _ReplayingMFAChallengeStore,
    _ReplayingWebAuthnChallengeStore,
    _ReplayStepUpStore,
    _RetainedExpiredMFAStore,
    _RetainedExpiredWebAuthnStore,
    _UnburnedExpiredMFAStore,
    _UnburnedMFAEpochStore,
    _UnburnedWebAuthnPurposeStore,
    _UnderAdmittingLimiter,
    _WrongMFAAccountStore,
    _WrongMFAEpochStore,
    _WrongSecretRoundTripProtector,
    _WrongSecretVersionProtector,
    _WrongWebAuthnBindingStore,
    _WrongWebAuthnPurposeStore,
    _YieldingEpochBumpStore,
    _YieldingPasswordCASStore,
    _YieldingRegistrationStore,
    _YieldingSessionStore,
    _YieldingStepUpStore,
)

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)
_CONFORMANCE_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


async def test_local_account_store_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_local_account_store_conformance(lambda: InMemorySecurityBackend(clock=lambda: _NOW).accounts)


@pytest.mark.parametrize(
    ("toggle", "invariant"),
    [
        ("register_is_atomic", r"RegistrationStore\.register atomicity invariant"),
        ("register_consumes_invitation", r"RegistrationStore\.register partial-write invariant"),
        ("password_cas_is_atomic", r"PasswordCredentialStore\.compare_and_replace_password atomicity invariant"),
        ("cas_persists_winner", r"PasswordCredentialStore\.compare_and_replace_password state invariant"),
        ("cas_preserves_non_password", r"PasswordCredentialStore\.compare_and_replace_password state invariant"),
        ("bump_epoch_is_atomic", r"PasswordCredentialStore\.replace_password_and_bump_epoch epoch invariant"),
        ("bump_epoch_is_exact", r"PasswordCredentialStore\.replace_password_and_bump_epoch epoch invariant"),
        ("bump_persists_winner", r"PasswordCredentialStore\.replace_password_and_bump_epoch state invariant"),
        ("verification_is_single_use", r"VerificationTokenStore\.consume_and_verify replay invariant"),
        ("verification_rejects_expired", r"VerificationTokenStore\.consume_and_verify expiry invariant"),
        ("verification_burns_attempts", r"VerificationTokenStore\.consume_and_verify attempt invariant"),
        ("recovery_checks_epoch", r"RecoveryTokenStore\.consume_and_reset epoch invariant"),
        ("recovery_rejects_expired", r"RecoveryTokenStore\.consume_and_reset expiry invariant"),
        ("recovery_burns_attempts", r"RecoveryTokenStore\.consume_and_reset attempt invariant"),
        ("preserves_final_method", r"LoginMethodStore\.revoke_login_method final-method invariant"),
    ],
)
async def test_local_account_store_conformance_names_each_broken_invariant(toggle: str, invariant: str) -> None:
    def factory() -> _BrokenAccountStore:
        store = _BrokenAccountStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)
        setattr(store, toggle, False)
        return store

    with pytest.raises(AssertionError, match=invariant):
        await assert_local_account_store_conformance(factory)


async def test_local_account_store_conformance_names_partial_registration_exceptions() -> None:
    def factory() -> _BrokenAccountStore:
        return _BrokenAccountStore(
            InMemorySecurityBackend(clock=lambda: _NOW).accounts, registration_partial_raises=True
        )

    with pytest.raises(AssertionError, match=r"RegistrationStore\.register partial-write invariant"):
        await assert_local_account_store_conformance(factory)


async def test_local_account_store_conformance_detects_a_yielding_password_lost_update() -> None:
    def factory() -> _YieldingPasswordCASStore:
        return _YieldingPasswordCASStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)

    with pytest.raises(
        AssertionError, match=r"PasswordCredentialStore\.compare_and_replace_password atomicity invariant"
    ):
        await assert_local_account_store_conformance(factory)


async def test_local_account_store_conformance_detects_a_yielding_registration_lost_update() -> None:
    def factory() -> _YieldingRegistrationStore:
        return _YieldingRegistrationStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)

    with pytest.raises(AssertionError, match=r"RegistrationStore\.register atomicity invariant"):
        await assert_local_account_store_conformance(factory)


async def test_local_account_store_conformance_detects_a_yielding_epoch_lost_update() -> None:
    def factory() -> _YieldingEpochBumpStore:
        return _YieldingEpochBumpStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)

    with pytest.raises(
        AssertionError, match=r"PasswordCredentialStore\.replace_password_and_bump_epoch epoch invariant"
    ):
        await assert_local_account_store_conformance(factory)


async def test_local_account_store_conformance_names_shared_factory_state() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _NOW).accounts

    with pytest.raises(AssertionError, match=r"LocalAccountCapabilities factory invariant"):
        await assert_local_account_store_conformance(lambda: shared)


async def test_local_account_store_conformance_detects_distinct_wrappers_over_shared_storage() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _NOW).accounts

    with pytest.raises(AssertionError, match=r"LocalAccountCapabilities factory isolation invariant"):
        await assert_local_account_store_conformance(lambda: _BrokenAccountStore(shared))


async def test_session_registry_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_session_registry_conformance(
        lambda: InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts, now=_CONFORMANCE_NOW
    )


async def test_session_registry_conformance_rejects_a_shared_factory_instance() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts

    with pytest.raises(AssertionError, match=r"SessionRegistry factory invariant"):
        await assert_session_registry_conformance(lambda: shared, now=_CONFORMANCE_NOW)


async def test_session_registry_conformance_rejects_distinct_wrappers_over_shared_storage() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts
    with pytest.raises(AssertionError, match=r"SessionRegistry factory isolation invariant"):
        await assert_session_registry_conformance(lambda: _BrokenSessionStore(shared), now=_CONFORMANCE_NOW)


@pytest.mark.parametrize(
    ("toggle", "invariant"),
    [
        ("corrupt_created_record", r"SessionRegistry\.create/get state invariant"),
        ("returns_expired_record", r"SessionRegistry\.get expiry invariant"),
        ("rebind_is_atomic", r"SessionRegistry\.rebind atomicity invariant"),
        ("rebind_returns_exact", r"SessionRegistry\.rebind state invariant"),
        ("rebind_commits", r"SessionRegistry\.rebind partial-write invariant"),
        ("checks_ownership", r"SessionRegistry\.revoke_session_for_account ownership invariant"),
        ("keeps_current", r"SessionRegistry\.revoke_other_sessions keep-current invariant"),
    ],
)
async def test_session_registry_conformance_names_each_broken_invariant(toggle: str, invariant: str) -> None:
    def factory() -> _BrokenSessionStore:
        store = _BrokenSessionStore(InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts)
        setattr(store, toggle, False)
        return store

    with pytest.raises(AssertionError, match=invariant):
        await assert_session_registry_conformance(factory, now=_CONFORMANCE_NOW)


async def test_session_registry_conformance_detects_a_yielding_rebind_lost_update() -> None:
    with pytest.raises(AssertionError, match=r"SessionRegistry\.rebind atomicity invariant"):
        await assert_session_registry_conformance(
            lambda: _YieldingSessionStore(InMemorySecurityBackend(clock=lambda: _CONFORMANCE_NOW).accounts),
            now=_CONFORMANCE_NOW,
        )


async def test_refresh_family_store_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_refresh_family_store_conformance(lambda: InMemorySecurityBackend(clock=lambda: _NOW).accounts)


async def test_refresh_family_store_conformance_rejects_a_shared_factory_instance() -> None:
    shared = _BrokenRefreshStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)

    with pytest.raises(AssertionError, match=r"RefreshTokenFamilyStore factory invariant"):
        await assert_refresh_family_store_conformance(lambda: shared)


async def test_refresh_family_store_conformance_rejects_distinct_wrappers_over_shared_storage() -> None:
    shared = InMemorySecurityBackend(clock=lambda: _NOW).accounts

    with pytest.raises(AssertionError, match=r"RefreshTokenFamilyStore factory isolation invariant"):
        await assert_refresh_family_store_conformance(lambda: _BrokenRefreshStore(shared))


@pytest.mark.parametrize(
    ("toggle", "invariant"),
    [
        ("create_rejects_collisions", r"RefreshTokenFamilyStore\.create_family collision invariant"),
        ("rejects_expiry", r"RefreshTokenFamilyStore\.prepare_rotation expiry invariant"),
        ("rotate_is_atomic", r"RefreshTokenFamilyStore\.rotate atomicity invariant"),
        ("rotate_commits", r"RefreshTokenFamilyStore\.rotate partial-write invariant"),
        ("rotate_rejects_expiry", r"RefreshTokenFamilyStore\.rotate late-expiry invariant"),
        ("rotate_revalidates_epoch", r"RefreshTokenFamilyStore\.rotate epoch invariant"),
        ("idempotency_receipt", r"RefreshTokenFamilyStore\.prepare_rotation idempotency invariant"),
        ("replays_revoke", r"RefreshTokenFamilyStore\.prepare_rotation replay invariant"),
        ("checks_ownership", r"RefreshTokenFamilyStore\.revoke_token_for_account ownership invariant"),
    ],
)
async def test_refresh_family_store_conformance_names_each_broken_invariant(toggle: str, invariant: str) -> None:
    def factory() -> _BrokenRefreshStore:
        store = _BrokenRefreshStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)
        setattr(store, toggle, False)
        return store

    with pytest.raises(AssertionError, match=invariant):
        await assert_refresh_family_store_conformance(factory)


@pytest.mark.parametrize(
    ("attribute", "value", "invariant"),
    [
        ("rejected_create_marker", 1, r"create_family state invariant"),
        ("corrupt_context_marker", 1, r"prepare_rotation state invariant"),
        ("rejected_create_marker", 2, r"create_family expiry setup invariant"),
        ("rejected_create_marker", 15, r"prepare_rotation expiry setup invariant"),
        ("accepts_shared_expiry", True, r"prepare_rotation shared-expiry invariant"),
        ("rejected_create_marker", 3, r"rotate atomicity setup invariant"),
        ("durable_rotation_state", False, r"rotate durable-state invariant"),
        ("rejected_create_marker", 6, r"rotate partial-write setup invariant"),
        ("rejected_create_marker", 10, r"rotate late-expiry setup invariant"),
        ("corrupt_context_marker", 10, r"rotate late-expiry setup invariant"),
        ("rejected_create_marker", 13, r"rotate epoch setup invariant"),
        ("has_password_state", False, r"rotate epoch setup invariant"),
        ("rejected_create_marker", 8, r"prepare_rotation replay setup invariant"),
        ("replay_revocation_is_durable", False, r"prepare_rotation replay invariant"),
        ("rejected_create_marker", 11, r"revoke_token_for_account ownership setup invariant"),
        ("ownership_mutates_silently", True, r"revoke_token_for_account ownership invariant"),
    ],
)
async def test_refresh_family_store_conformance_names_setup_and_exact_state_invariants(
    attribute: str, value: object, invariant: str
) -> None:
    def factory() -> _BrokenRefreshStore:
        store = _BrokenRefreshStore(InMemorySecurityBackend(clock=lambda: _NOW).accounts)
        setattr(store, attribute, value)
        return store

    with pytest.raises(AssertionError, match=invariant):
        await assert_refresh_family_store_conformance(factory)


async def test_mfa_store_conformance_rejects_a_non_monotonic_store() -> None:
    with pytest.raises(AssertionError, match="monotonicity invariant"):
        await assert_mfa_store_conformance(_BrokenMFAStore)


@pytest.mark.parametrize(
    ("factory", "invariant"),
    [
        (_AlwaysAdvanceMFAStore, r"MFAStore\.advance_totp_counter atomicity invariant"),
        (_EqualCounterMFAStore, r"MFAStore\.advance_totp_counter monotonicity invariant"),
        (_AlwaysConsumeRecoveryStore, r"MFAStore\.consume_recovery_code atomicity invariant"),
    ],
)
async def test_mfa_store_conformance_names_atomic_invariants(
    factory: Callable[[], testing_module.MFAStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_mfa_store_conformance(factory)


async def test_mfa_store_conformance_names_activation_setup_invariant() -> None:
    with pytest.raises(AssertionError, match=r"MFAStore setup invariant"):
        await assert_mfa_store_conformance(_RejectingMFAActivationStore)


async def test_mfa_login_challenge_conformance_rejects_an_unburned_binding() -> None:
    with pytest.raises(AssertionError, match="account-binding burn invariant"):
        await assert_mfa_login_challenge_store_conformance(_BrokenMFALoginChallengeStore)


@pytest.mark.parametrize(
    ("factory", "invariant"),
    [
        (_WrongMFAAccountStore, r"MFALoginChallengeStore binding invariant"),
        (_WrongMFAEpochStore, r"MFALoginChallengeStore epoch invariant"),
        (_RetainedExpiredMFAStore, r"MFALoginChallengeStore expiry invariant"),
        (_UnburnedMFAEpochStore, r"MFALoginChallengeStore epoch-binding burn invariant"),
        (_ReplayingMFAChallengeStore, r"MFALoginChallengeStore atomicity invariant"),
        (_UnburnedExpiredMFAStore, r"MFALoginChallengeStore expiry burn invariant"),
    ],
)
async def test_mfa_login_challenge_conformance_names_rejected_value_invariants(
    factory: Callable[[], testing_module.MFALoginChallengeStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_mfa_login_challenge_store_conformance(factory)


async def test_webauthn_challenge_conformance_rejects_an_unburned_binding() -> None:
    with pytest.raises(AssertionError, match="binding burn invariant"):
        await assert_webauthn_challenge_store_conformance(_BrokenWebAuthnChallengeStore)


@pytest.mark.parametrize(
    ("factory", "invariant"),
    [
        (_WrongWebAuthnBindingStore, r"WebAuthnChallengeStore binding invariant"),
        (_WrongWebAuthnPurposeStore, r"WebAuthnChallengeStore purpose invariant"),
        (_RetainedExpiredWebAuthnStore, r"WebAuthnChallengeStore expiry invariant"),
        (_UnburnedWebAuthnPurposeStore, r"WebAuthnChallengeStore purpose burn invariant"),
        (_ReplayingWebAuthnChallengeStore, r"WebAuthnChallengeStore atomicity invariant"),
    ],
)
async def test_webauthn_challenge_conformance_names_rejected_value_invariants(
    factory: Callable[[], testing_module.WebAuthnChallengeStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_webauthn_challenge_store_conformance(factory)


async def test_passkey_conformance_rejects_unpersisted_assertion_state() -> None:
    with pytest.raises(AssertionError, match="state invariant"):
        await assert_passkey_store_conformance(_BrokenPasskeyStore)


@pytest.mark.parametrize(
    ("store", "invariant"),
    [
        (_RejectingPasskeyStore, r"PasskeyStore setup invariant"),
        (_NonAtomicPasskeyResultStore, r"PasskeyStore\.record_assertion atomicity invariant"),
    ],
)
async def test_passkey_conformance_names_setup_and_atomicity_invariants(
    store: Callable[[], testing_module.InMemoryPasskeyStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_passkey_store_conformance(store)


@pytest.mark.parametrize(
    ("store", "invariant"),
    [
        (_BrokenPasskeyCloneResultStore, r"clone-risk invariant"),
        (_BrokenPasskeyCloneStateStore, r"clone-state invariant"),
    ],
)
async def test_passkey_conformance_names_clone_risk_invariants(
    store: Callable[[], testing_module.InMemoryPasskeyStore], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_passkey_store_conformance(store)


async def test_step_up_store_conformance_accepts_the_reference_store() -> None:
    await assert_step_up_store_conformance(testing_module.InMemoryStepUpStore)


@pytest.mark.parametrize("binding", ["principal", "epoch", "purpose", "transport", "expiry"])
async def test_step_up_store_conformance_names_each_bound_value(binding: str) -> None:
    with pytest.raises(AssertionError, match=rf"StepUpStore\.consume {binding} invariant"):
        await assert_step_up_store_conformance(lambda: _BrokenStepUpStore(ignored_binding=binding))


async def test_step_up_store_conformance_detects_yielding_double_consume() -> None:
    with pytest.raises(AssertionError, match=r"StepUpStore\.consume atomicity invariant"):
        await assert_step_up_store_conformance(_YieldingStepUpStore)


async def test_step_up_store_conformance_detects_a_replayed_grant() -> None:
    with pytest.raises(AssertionError, match=r"StepUpStore\.consume replay invariant"):
        await assert_step_up_store_conformance(_ReplayStepUpStore)


async def test_rate_limiter_conformance_accepts_the_reference_limiter() -> None:
    await assert_rate_limiter_conformance(
        lambda limit: StoreRateLimiter(
            policies={"conformance.rate_limit": RateLimitPolicy(limit=limit, window=timedelta(minutes=5))},
            store=MemoryStore(),
        )
    )


@pytest.mark.parametrize("limiter", [_NonAtomicLimiter, _UnderAdmittingLimiter])
async def test_rate_limiter_conformance_names_exact_admission_invariant(limiter: Callable[[int], RateLimiter]) -> None:
    with pytest.raises(AssertionError, match=r"RateLimiter\.acquire atomicity invariant: .*admit exactly k"):
        await assert_rate_limiter_conformance(limiter)


@pytest.mark.parametrize(("limit", "concurrency"), [(0, 20), (5, 0), (5, 4), (True, 20), (5, True)])
async def test_rate_limiter_conformance_rejects_invalid_scenario_bounds(limit: object, concurrency: object) -> None:
    with pytest.raises(ValueError, match="conformance"):
        await assert_rate_limiter_conformance(
            lambda valid_limit: StoreRateLimiter(
                policies={"conformance.rate_limit": RateLimitPolicy(limit=valid_limit, window=timedelta(minutes=5))},
                store=MemoryStore(),
            ),
            limit=limit,  # type: ignore[arg-type]  # parametrization proves runtime validation rejects non-integers
            concurrency=concurrency,  # type: ignore[arg-type]  # parametrization proves runtime validation rejects non-integers
        )


async def test_reference_account_conformance_families() -> None:
    await assert_mfa_store_conformance(testing_module.InMemoryMFAStore)
    await assert_mfa_login_challenge_store_conformance(testing_module.InMemoryMFALoginChallengeStore)
    await assert_webauthn_challenge_store_conformance(testing_module.InMemoryWebAuthnChallengeStore)
    await assert_passkey_store_conformance(testing_module.InMemoryPasskeyStore)


async def test_secret_protector_conformance_accepts_the_reference_protector() -> None:
    await assert_secret_protector_conformance(
        lambda: AESGCMSecretProtector(active_key=SecretProtectorKey("v1", b"s" * 32))
    )


async def test_secret_protector_conformance_rejects_ignored_associated_data() -> None:
    with pytest.raises(AssertionError, match="associated data"):
        await assert_secret_protector_conformance(_AADIgnoringSecretProtector)


@pytest.mark.parametrize(
    ("factory", "invariant"),
    [
        (_WrongSecretRoundTripProtector, r"SecretProtector round-trip invariant"),
        (_WrongSecretVersionProtector, r"SecretProtector key-version invariant"),
        (_DeterministicSecretProtector, r"SecretProtector non-determinism invariant"),
    ],
)
async def test_secret_protector_conformance_names_the_remaining_invariants(
    factory: Callable[[], testing_module.SecretProtector], invariant: str
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_secret_protector_conformance(factory)
