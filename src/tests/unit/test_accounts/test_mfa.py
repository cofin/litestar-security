"""Unit coverage for TOTP and recovery-code MFA behavior."""

import base64
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import pyotp
import pytest
from anyio import create_task_group
from cryptography.exceptions import InvalidTag
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security.accounts as accounts_module
import litestar_security.accounts._mfa as mfa_module
import litestar_security.testing as testing_module
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.config import MFAConfig, PasskeyConfig
from litestar_security.context import AuthenticationEvidence
from tests.fixtures.accounts import (
    CombinedMFAStore,
    FailingRecoveryLoginMethods,
    FailingStepUpStore,
    MFAProtector,
    MFAStore,
    PasskeyStore,
    RecoveryLoginMethods,
    RejectActivationMFAStore,
    RejectingTOTPAdvanceStore,
    RejectSingleActivationMFAStore,
    SecurityEvents,
    StepUpStore,
    WebAuthnChallengeStore,
    WebAuthnVerifier,
    WrongVersionMFAProtector,
    build_mfa_service,
)

_MFA_ENCODED_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


@pytest.mark.parametrize(
    ("algorithm", "secret", "code"),
    [
        ("SHA1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "94287082"),
        ("SHA256", base64.b32encode(b"12345678901234567890123456789012").decode(), "46119246"),
        (
            "SHA512",
            base64.b32encode(b"1234567890123456789012345678901234567890123456789012345678901234").decode(),
            "90693936",
        ),
    ],
)
async def test_totp_enrollment_uses_rfc_vectors_and_persists_only_protected_secret(
    algorithm: str, secret: str, code: str
) -> None:
    store = MFAStore()
    protector = MFAProtector()
    service = build_mfa_service(
        store,
        protector,
        policy=accounts_module.TOTPPolicy(digits=8, algorithm=cast("Any", algorithm), allowed_drift_steps=0),
        encoded_seed=secret,
    )
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPProvisioningGrant)
    assert "secret=" in enrollment.provisioning_uri
    assert secret not in repr(enrollment)
    assert secret.encode() not in repr(store.enrollments).encode()
    activated = await service.activate_totp("account-1", enrollment.enrollment_id, code)
    assert isinstance(activated, accounts_module.TOTPMethod)
    assert activated.last_accepted_counter == 1
    assert all(value in protector.associated_data[0] for value in (b"account-1", b"method-1", b"totp", b"test-key"))


async def test_totp_counter_advance_allows_one_concurrent_use_and_rejects_replay() -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    store, protector = MFAStore(), MFAProtector()
    service = build_mfa_service(store, protector, now=now)
    events = SecurityEvents()
    service.events = events
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPProvisioningGrant)
    code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(now)
    assert isinstance(
        await service.activate_totp("account-1", enrollment.enrollment_id, code), accounts_module.TOTPMethod
    )
    next_time = now + timedelta(seconds=30)
    next_code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(next_time)
    service.clock = lambda: next_time
    outcomes: list[object] = []

    async def verify() -> None:
        outcomes.append(await service.verify_totp("account-1", "method-1", next_code))

    async with create_task_group() as task_group:
        task_group.start_soon(verify)
        task_group.start_soon(verify)
    assert sum(isinstance(outcome, AuthenticationEvidence) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, InvalidCredentials) for outcome in outcomes) == 1
    assert isinstance(await service.verify_totp("account-1", "method-1", next_code), InvalidCredentials)


@pytest.mark.parametrize(
    ("policy_kwargs", "match"),
    [
        ({"digits": 7}, "digits"),
        ({"period_seconds": 0}, "period"),
        ({"algorithm": "MD5"}, "algorithm"),
        ({"allowed_drift_steps": -1}, "drift"),
        ({"enrollment_ttl": timedelta()}, "lifetime"),
    ],
)
def test_totp_policy_rejects_unsupported_or_unbounded_profiles(policy_kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.TOTPPolicy(**policy_kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("failure", ["protect", "store", "unprotect"])
async def test_totp_protector_and_store_failures_are_sanitized(failure: str) -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    store = MFAStore()
    protector = MFAProtector(fail=failure == "protect")
    service = build_mfa_service(store, protector, now=now)
    if failure == "store":
        store.fail = True
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    if failure in {"protect", "store"}:
        assert isinstance(enrollment, VerificationUnavailable)
        return
    assert isinstance(enrollment, accounts_module.TOTPProvisioningGrant)
    protector.fail = True
    code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(now)
    assert isinstance(await service.activate_totp("account-1", enrollment.enrollment_id, code), VerificationUnavailable)


async def test_recovery_codes_are_reveal_once_digest_only_and_atomically_consumed() -> None:
    store = MFAStore()
    service = build_mfa_service(store, MFAProtector())
    service.recovery_peppers = (accounts_module.RecoveryCodePepper(key_version="v1", key=b"p" * 32),)
    entropy_counter = iter(range(1, 11))
    service.recovery_entropy = lambda length: next(entropy_counter).to_bytes(length, "big")
    issued = await service.generate_recovery_codes("account-1")
    assert isinstance(issued, accounts_module.RecoveryCodeGrant)
    assert len(issued.codes) == len(set(issued.codes)) == 10
    assert issued.codes[0].encode() not in repr(store.recovery_codes).encode()
    outcomes: list[object] = []

    async def consume() -> None:
        outcomes.append(await service.consume_recovery_code("account-1", issued.codes[0]))

    async with create_task_group() as task_group:
        task_group.start_soon(consume)
        task_group.start_soon(consume)
    assert sum(isinstance(outcome, AuthenticationEvidence) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, InvalidCredentials) for outcome in outcomes) == 1


def test_recovery_code_digest_is_bound_to_its_account() -> None:
    pepper = accounts_module.RecoveryCodePepper(key_version="v1", key=b"p" * 32)
    code = "rc_v1_00000000000000000000000000000001"
    assert mfa_module._recovery_digest(pepper, "account-1", code) != mfa_module._recovery_digest(  # noqa: SLF001
        pepper, "account-2", code
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (accounts_module.RevokeLoginMethodStatus.REVOKED, accounts_module.RevokeLoginMethodStatus.REVOKED),
        (accounts_module.RevokeLoginMethodStatus.FINAL_METHOD, accounts_module.RevokeLoginMethodStatus.FINAL_METHOD),
    ],
)
async def test_totp_removal_delegates_atomic_final_method_safety(
    status: accounts_module.RevokeLoginMethodStatus, expected: accounts_module.RevokeLoginMethodStatus
) -> None:
    login_methods = RecoveryLoginMethods(status)
    service = build_mfa_service(MFAStore(), MFAProtector())
    service.login_methods = login_methods
    outcome = await service.remove_totp_method("account-1", "method-1")
    assert isinstance(outcome, accounts_module.RevokeLoginMethodOutcome)
    assert outcome.status is expected
    assert login_methods.events[0].operation == "local.mfa.totp.remove"


@pytest.mark.parametrize(
    ("case", "expected_type"),
    [
        ("unconfigured", VerificationUnavailable),
        ("duplicate_entropy", VerificationUnavailable),
        ("store_replace", VerificationUnavailable),
        ("malformed", InvalidCredentials),
        ("unknown_version", InvalidCredentials),
        ("store_consume", VerificationUnavailable),
    ],
)
async def test_recovery_failures_are_generic_and_never_leak_codes(case: str, expected_type: type[object]) -> None:
    store = MFAStore()
    service = build_mfa_service(store, MFAProtector())
    pepper = accounts_module.RecoveryCodePepper(key_version="v1", key=b"p" * 32)
    if case != "unconfigured":
        service.recovery_peppers = (pepper,)
    service.recovery_code_count = 1
    service.recovery_entropy = lambda length: b"\x01" * length
    if case == "duplicate_entropy":
        service.recovery_code_count = 2
    if case == "store_replace":
        store.fail = True
    if case in {"unconfigured", "duplicate_entropy", "store_replace"}:
        outcome = await service.generate_recovery_codes("account-1")
    else:
        issued = await service.generate_recovery_codes("account-1")
        assert isinstance(issued, accounts_module.RecoveryCodeGrant)
        code = (
            "malformed"
            if case == "malformed"
            else issued.codes[0].replace("rc_v1_", "rc_old_")
            if case == "unknown_version"
            else issued.codes[0]
        )
        if case == "store_consume":
            store.fail = True
        outcome = await service.consume_recovery_code("account-1", code)

    assert isinstance(outcome, expected_type)
    assert "01010101" not in repr(outcome)


def test_mfa_value_and_service_configuration_rejects_invalid_contracts() -> None:
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)
    protected = accounts_module.ProtectedSecret(b"cipher", "v1")
    with pytest.raises(ValueError, match="Protected secret"):
        accounts_module.ProtectedSecret(b"", "v1")
    with pytest.raises(ValueError, match="Pending TOTP"):
        accounts_module.PendingTOTPEnrollment(
            enrollment_id=" ",
            method_id="m1",
            account_id="a1",
            protected_secret=protected,
            policy=accounts_module.TOTPPolicy(),
            created_at=now,
            expires_at=now + timedelta(minutes=1),
        )
    with pytest.raises(ValueError, match="TOTP method"):
        accounts_module.TOTPMethod(
            method_id="m1",
            account_id="a1",
            protected_secret=protected,
            policy=accounts_module.TOTPPolicy(),
            last_accepted_counter=-1,
            created_at=now,
        )
    with pytest.raises(ValueError, match="Recovery-code digest"):
        accounts_module.RecoveryCodeDigest("a1", "v1", b"short")
    with pytest.raises(ValueError, match="Step-up record"):
        accounts_module.StepUpGrantState(
            grant_digest=b"short",
            transport_digest=b"t" * 32,
            principal_id="a1",
            security_epoch=1,
            purpose="settings",
            methods=frozenset(),
            traits=frozenset(),
            authenticated_at=now,
            expires_at=now + timedelta(minutes=1),
        )
    with pytest.raises(ValueError, match="MFA login challenge"):
        accounts_module.MFALoginChallenge(
            challenge_digest=bytearray(b"d" * 32),
            account_id="a1",
            security_epoch=1,
            client_key=None,
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )
    with pytest.raises(ValueError, match="MFA login challenge"):
        accounts_module.MFALoginChallenge(
            challenge_digest=b"d" * 32,
            account_id="a1",
            security_epoch=1,
            client_key=None,
            issued_at=now,
            expires_at=now + timedelta(minutes=11),
        )
    with pytest.raises(ImproperlyConfiguredException, match="store"):
        accounts_module.MFAService(cast("Any", object()), MFAProtector())
    with pytest.raises(ImproperlyConfiguredException, match="protector"):
        accounts_module.MFAService(MFAStore(), cast("Any", object()))
    with pytest.raises(ImproperlyConfiguredException, match="issuer"):
        accounts_module.MFAService(MFAStore(), MFAProtector(), issuer=" ")
    with pytest.raises(ImproperlyConfiguredException, match="LoginMethodStore"):
        accounts_module.MFAService(MFAStore(), MFAProtector(), login_methods=cast("Any", object()))
    with pytest.raises(ImproperlyConfiguredException, match="store"):
        accounts_module.StepUpService(cast("Any", object()))
    with pytest.raises(ImproperlyConfiguredException, match="lifetime"):
        accounts_module.StepUpService(StepUpStore(), ttl=timedelta())


@pytest.mark.parametrize(("key_version", "key"), [("", b"m" * 32), ("v1", b"m" * 31), ("v1", bytearray(b"m" * 32))])
def test_mfa_secret_protector_key_rejects_invalid_key_material(key_version: str, key: object) -> None:
    """MFA secret encryption only accepts exact versioned AES-256 keys."""
    with pytest.raises(ImproperlyConfiguredException, match="32-byte key"):
        accounts_module.SecretProtectorKey(key_version, key)  # type: ignore[arg-type]


async def test_recovery_regeneration_invalidates_old_codes_and_pepper_versions_are_explicit() -> None:
    entropy_values = iter((b"\x01" * 16, b"\x02" * 16, b"\x03" * 16))
    store = MFAStore()
    service = build_mfa_service(store, MFAProtector())
    v1 = accounts_module.RecoveryCodePepper(key_version="v1", key=b"p" * 32)
    v2 = accounts_module.RecoveryCodePepper(key_version="v2", key=b"q" * 32)
    service.recovery_peppers = (v1,)
    service.recovery_code_count = 1
    service.recovery_entropy = lambda _length: next(entropy_values)
    first = await service.generate_recovery_codes("account-1")
    assert isinstance(first, accounts_module.RecoveryCodeGrant)
    service.recovery_peppers = (v2, v1)
    assert isinstance(await service.consume_recovery_code("account-1", first.codes[0]), AuthenticationEvidence)
    service.recovery_peppers = (v1,)
    stale = await service.generate_recovery_codes("account-1")
    assert isinstance(stale, accounts_module.RecoveryCodeGrant)
    service.recovery_peppers = (v2, v1)
    second = await service.generate_recovery_codes("account-1")
    assert isinstance(second, accounts_module.RecoveryCodeGrant)
    assert second.codes[0].startswith("rc_v2_")
    assert isinstance(await service.consume_recovery_code("account-1", stale.codes[0]), InvalidCredentials)


async def test_mfa_and_step_up_defensive_failures_are_sanitized() -> None:
    now = datetime(2026, 7, 27, tzinfo=timezone.utc)

    service = build_mfa_service(MFAStore(), WrongVersionMFAProtector(), now=now)
    assert isinstance(
        await service.begin_totp_enrollment("account-1", label="person@example.com"), VerificationUnavailable
    )
    service = build_mfa_service(MFAStore(), MFAProtector(), now=now)
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPProvisioningGrant)
    assert isinstance(await service.activate_totp("account-1", enrollment.enrollment_id, "000000"), InvalidCredentials)
    assert isinstance(await service.remove_totp_method("account-1", "method-1"), VerificationUnavailable)
    assert isinstance(await service.consume_recovery_code("account-1", 1), InvalidCredentials)  # type: ignore[arg-type]
    assert isinstance(
        await service.begin_totp_enrollment("bad\x00account", label="person@example.com"), VerificationUnavailable
    )
    service.secret_generator = cast("Any", lambda: b"bytes")
    assert isinstance(
        await service.begin_totp_enrollment("account-1", label="person@example.com"), VerificationUnavailable
    )
    service.secret_generator = lambda: "SHORT"
    assert isinstance(
        await service.begin_totp_enrollment("account-1", label="person@example.com"), VerificationUnavailable
    )

    step_up = accounts_module.StepUpService(
        StepUpStore(), clock=lambda: now, entropy=cast("Any", lambda _size: b"short")
    )
    evidence = AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=now, methods=frozenset({"totp"}))
    assert isinstance(
        await step_up.issue(
            principal_id="account-1",
            security_epoch=1,
            purpose="settings",
            transport_binding=b"session",
            evidence=evidence,
        ),
        VerificationUnavailable,
    )
    assert isinstance(
        await step_up.issue(
            principal_id=" ", security_epoch=1, purpose="settings", transport_binding=b"session", evidence=evidence
        ),
        InvalidCredentials,
    )
    assert isinstance(
        await step_up.consume(
            " ", principal_id="account-1", security_epoch=1, purpose="settings", transport_binding=b"session"
        ),
        InvalidCredentials,
    )


async def test_mfa_operational_and_format_failure_branches_are_sanitized() -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    store = MFAStore()
    protector = MFAProtector()
    service = build_mfa_service(store, protector, now=now)
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPProvisioningGrant)
    code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").at(now)
    method = await service.activate_totp("account-1", enrollment.enrollment_id, code)
    assert isinstance(method, accounts_module.TOTPMethod)
    next_time = now + timedelta(seconds=30)
    next_code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").at(next_time)
    service.clock = lambda: next_time
    store.fail = True
    assert isinstance(await service.verify_totp("account-1", method.method_id, next_code), VerificationUnavailable)

    service.login_methods = cast("Any", FailingRecoveryLoginMethods(accounts_module.RevokeLoginMethodStatus.REVOKED))
    assert isinstance(await service.remove_totp_method("account-1", method.method_id), VerificationUnavailable)

    failing_step_store = StepUpStore()
    step_up = accounts_module.StepUpService(failing_step_store, clock=lambda: now)
    failing_step_store.consume = cast("Any", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
    assert isinstance(
        await step_up.consume(
            "token", principal_id="account-1", security_epoch=1, purpose="settings", transport_binding=b"session"
        ),
        VerificationUnavailable,
    )

    for invalid_secret in (1, "!!!!", "GEZA", base64.b32encode(b"x").decode()):
        invalid = build_mfa_service(MFAStore(), MFAProtector(), now=now)
        invalid.secret_generator = cast("Any", lambda value=invalid_secret: value)
        assert isinstance(
            await invalid.begin_totp_enrollment("account-1", label="person@example.com"), VerificationUnavailable
        )
    invalid = build_mfa_service(MFAStore(), MFAProtector(), now=now)
    invalid.recovery_peppers = (accounts_module.RecoveryCodePepper("v1", b"p" * 32),)
    invalid.recovery_entropy = cast("Any", lambda _size: b"short")
    assert isinstance(await invalid.generate_recovery_codes("account-1"), VerificationUnavailable)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"key_version": " ", "key": b"p" * 32},
        {"key_version": "bad_version", "key": b"p" * 32},
        {"key_version": "v1", "key": b"short"},
    ],
)
def test_recovery_pepper_rejects_ambiguous_or_short_keys(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Recovery-code pepper"):
        accounts_module.RecoveryCodePepper(**kwargs)  # type: ignore[arg-type]


async def test_mfa_atomic_rejection_and_step_up_storage_failure_are_sanitized() -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    store = RejectingTOTPAdvanceStore()
    service = build_mfa_service(store, MFAProtector(), now=now)
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPProvisioningGrant)
    activation_code = pyotp.TOTP(_MFA_ENCODED_SEED).at(now)
    method = await service.activate_totp("account-1", enrollment.enrollment_id, activation_code)
    assert isinstance(method, accounts_module.TOTPMethod)
    next_time = now + timedelta(seconds=30)
    service.clock = lambda: next_time
    assert isinstance(
        await service.verify_totp("account-1", method.method_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(next_time)),
        InvalidCredentials,
    )
    assert isinstance(
        await service.verify_totp("account-1", method.method_id, "１２３４５６"),  # noqa: RUF001 - non-ASCII digits
        InvalidCredentials,
    )
    assert isinstance(await service.verify_totp("account-1", method.method_id, "ABCDEF"), InvalidCredentials)

    invalid_context = build_mfa_service(MFAStore(), MFAProtector(), now=now)
    invalid_context.identifiers = iter(("enrollment", "bad\x00method")).__next__
    assert isinstance(
        await invalid_context.begin_totp_enrollment("account-1", label="person@example.com"), VerificationUnavailable
    )

    step_up = accounts_module.StepUpService(FailingStepUpStore(), clock=lambda: now)
    evidence = AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=now, methods=frozenset({"totp"}))
    assert isinstance(
        await step_up.issue(
            principal_id="account-1",
            security_epoch=1,
            purpose="settings",
            transport_binding=b"session",
            evidence=evidence,
        ),
        VerificationUnavailable,
    )

    atomic_store = MFAStore()
    atomic = build_mfa_service(atomic_store, MFAProtector(), now=now)
    atomic.recovery_peppers = (accounts_module.RecoveryCodePepper("v1", b"p" * 32),)
    atomic.recovery_code_count = 1
    atomic.recovery_entropy = lambda length: b"r" * length
    pending = await atomic.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(pending, accounts_module.TOTPProvisioningGrant)
    assert isinstance(
        await atomic.activate_totp_with_recovery_codes("account-1", pending.enrollment_id, "000000"), InvalidCredentials
    )
    atomic_store.fail = True
    assert isinstance(
        await atomic.activate_totp_with_recovery_codes(
            "account-1", pending.enrollment_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(now)
        ),
        VerificationUnavailable,
    )
    atomic_store.fail = False
    activated = await atomic.activate_totp_with_recovery_codes(
        "account-1", pending.enrollment_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(now)
    )
    assert isinstance(activated, accounts_module.RecoveryCodeGrant)
    assert atomic_store.methods
    assert atomic_store.recovery_codes
    assert isinstance(
        await atomic.activate_totp_with_recovery_codes(
            "account-1", pending.enrollment_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(now)
        ),
        InvalidCredentials,
    )

    rejecting = build_mfa_service(RejectActivationMFAStore(), MFAProtector(), now=now)
    rejecting.recovery_peppers = atomic.recovery_peppers
    rejecting.recovery_code_count = 1
    rejected_pending = await rejecting.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(rejected_pending, accounts_module.TOTPProvisioningGrant)
    assert isinstance(
        await rejecting.activate_totp_with_recovery_codes(
            "account-1", rejected_pending.enrollment_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(now)
        ),
        InvalidCredentials,
    )

    single = build_mfa_service(RejectSingleActivationMFAStore(), MFAProtector(), now=now)
    single_pending = await single.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(single_pending, accounts_module.TOTPProvisioningGrant)
    assert isinstance(
        await single.activate_totp("account-1", single_pending.enrollment_id, pyotp.TOTP(_MFA_ENCODED_SEED).at(now)),
        InvalidCredentials,
    )


@pytest.mark.parametrize(
    "value",
    [
        accounts_module.TOTPEnrollment(label="User", step_up_grant="grant-secret"),
        accounts_module.TOTPProvisioning(
            enrollment_id="e1",
            method_id="m1",
            provisioning_uri="otpauth://secret",
            expires_at=datetime(2026, 7, 27, tzinfo=timezone.utc),
        ),
        accounts_module.TOTPVerification(enrollment_id="e1", code="123456"),
        accounts_module.StepUpAuthorization(step_up_grant="grant-secret"),
        accounts_module.StepUpVerification(method="totp", credential="123456", method_id="m1"),
        accounts_module.StepUpGrant(
            grant="grant-secret", purpose="settings", expires_at=datetime(2026, 7, 27, tzinfo=timezone.utc)
        ),
        accounts_module.RecoveryCodes(codes=("rc_v1_SECRET",)),
        accounts_module.PasskeyVerification(account_id="account-1", response="browser-secret"),
        accounts_module.PasskeyRegistrationStart(user_name="person@example.com", step_up_grant="grant-secret"),
        accounts_module.PasskeyOptions(
            options="challenge-secret", expires_at=datetime(2026, 7, 27, tzinfo=timezone.utc)
        ),
    ],
)
def test_mfa_route_dto_representations_redact_secret_material(value: object) -> None:
    rendered = repr(value)

    assert "<redacted>" in rendered
    assert all(
        secret not in rendered
        for secret in (
            "123456",
            "grant-secret",
            "rc_v1_SECRET",
            "browser-secret",
            "otpauth://secret",
            "challenge-secret",
        )
    )


async def test_recovery_audit_failure_cannot_reverse_settled_generation_or_consumption() -> None:
    store = MFAStore()
    service = build_mfa_service(store, MFAProtector())
    service.events = SecurityEvents(fail=True)
    service.recovery_peppers = (accounts_module.RecoveryCodePepper(key_version="v1", key=b"p" * 32),)
    service.recovery_code_count = 1
    service.recovery_entropy = lambda length: b"\x01" * length

    issued = await service.generate_recovery_codes("account-1")

    assert isinstance(issued, accounts_module.RecoveryCodeGrant)
    assert isinstance(await service.consume_recovery_code("account-1", issued.codes[0]), AuthenticationEvidence)


async def test_totp_drift_account_and_expiry_failures_are_generic() -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    store = MFAStore()
    protector = MFAProtector()
    service = build_mfa_service(store, protector, now=now)
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPProvisioningGrant)
    code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(now)

    assert isinstance(await service.activate_totp("account-2", enrollment.enrollment_id, code), InvalidCredentials)
    service.clock = lambda: enrollment.expires_at
    assert isinstance(await service.activate_totp("account-1", enrollment.enrollment_id, code), InvalidCredentials)

    service = build_mfa_service(store := MFAStore(), protector := MFAProtector(), now=now)
    enrollment = await service.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPProvisioningGrant)
    future_code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(now + timedelta(seconds=30))
    activated = await service.activate_totp("account-1", enrollment.enrollment_id, future_code)
    assert isinstance(activated, accounts_module.TOTPMethod)
    service.clock = lambda: now + timedelta(seconds=60)
    too_far_code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=30).at(now + timedelta(seconds=120))
    assert isinstance(await service.verify_totp("account-1", activated.method_id, too_far_code), InvalidCredentials)
    assert isinstance(await service.verify_totp("account-2", activated.method_id, future_code), InvalidCredentials)


@pytest.mark.parametrize("account_id", ["", " ", "account\x00id"])
def test_recovery_code_digest_rejects_invalid_account_binding(account_id: str) -> None:
    """Recovery-code HMACs never accept blank or NUL-delimited account bindings."""
    pepper = accounts_module.RecoveryCodePepper(key_version="v1", key=b"p" * 32)

    with pytest.raises(ValueError):  # noqa: PT011 - private helper intentionally raises a bare ValueError
        mfa_module._recovery_digest(pepper, account_id, "rc_v1_00000000000000000000000000000001")  # noqa: SLF001


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (accounts_module.RevokeLoginMethodStatus.REVOKED, accounts_module.RevokeLoginMethodStatus.REVOKED),
        (accounts_module.RevokeLoginMethodStatus.FINAL_METHOD, accounts_module.RevokeLoginMethodStatus.FINAL_METHOD),
    ],
)
async def test_totp_removal_delegates_atomic_final_method_safety_and_redacts_events(
    status: accounts_module.RevokeLoginMethodStatus, expected: accounts_module.RevokeLoginMethodStatus
) -> None:
    login_methods = RecoveryLoginMethods(status)
    service = build_mfa_service(MFAStore(), MFAProtector())
    service.login_methods = login_methods

    outcome = await service.remove_totp_method("account-1", "method-1")

    assert isinstance(outcome, accounts_module.RevokeLoginMethodOutcome)
    assert outcome.status is expected
    assert len(login_methods.events) == 1
    assert login_methods.events[0].operation == "local.mfa.totp.remove"
    assert "secret" not in repr(login_methods.events[0]).lower()


async def test_public_conformance_helpers_execute_factor_atomicity_matrix() -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    clock = testing_module.FakeClock(now)
    mfa_store = testing_module.InMemoryMFAStore()
    protector = MFAProtector()
    recovery_values = iter(range(10))
    mfa = accounts_module.MFAService(
        store=mfa_store,
        secret_protector=protector,
        clock=clock,
        secret_generator=lambda: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        identifiers=iter(("enrollment-1", "method-1")).__next__,
        recovery_peppers=(accounts_module.RecoveryCodePepper("v1", b"p" * 32),),
        recovery_entropy=lambda _size: next(recovery_values).to_bytes(16, "big"),
    )
    enrollment = await mfa.begin_totp_enrollment("account-1", label="person@example.com")
    assert isinstance(enrollment, accounts_module.TOTPProvisioningGrant)
    code = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").at(now)
    method = await mfa.activate_totp("account-1", enrollment.enrollment_id, code)
    assert isinstance(method, accounts_module.TOTPMethod)
    assert await mfa_store.get_totp_method("other", method.method_id) is None
    assert not await mfa_store.advance_totp_counter(method.method_id, accepted_counter=1, now=now)
    recovery = await mfa.generate_recovery_codes("account-1")
    assert isinstance(recovery, accounts_module.RecoveryCodeGrant)
    assert isinstance(await mfa.consume_recovery_code("account-1", recovery.codes[0]), AuthenticationEvidence)
    assert isinstance(await mfa.consume_recovery_code("account-1", recovery.codes[0]), InvalidCredentials)

    challenge_store = testing_module.InMemoryWebAuthnChallengeStore()
    passkey_store = testing_module.InMemoryPasskeyStore()
    verifier = WebAuthnVerifier()
    passkeys = accounts_module.PasskeyService(
        store=passkey_store,
        challenge_store=challenge_store,
        verifier=verifier,
        rp_id="example.com",
        rp_name="Example",
        origins=("https://example.com",),
        clock=clock,
        challenge_entropy=lambda size: b"c" * size,
    )
    options = await passkeys.begin_registration("account-1", user_name="person@example.com", binding=b"session")
    assert isinstance(options, accounts_module.WebAuthnOptions)
    credential = await passkeys.verify_registration("account-1", binding=b"session", response="{}")
    assert isinstance(credential, accounts_module.PasskeyCredential)
    assert not await passkey_store.add_credential(
        credential,
        login_method=accounts_module.LoginMethod("pk_duplicate", "passkey", now),
        event=accounts_module.SecurityEvent(
            event_id="event-duplicate",
            occurred_at=now,
            operation="passkey.register.verify",
            outcome="created",
            account_id="account-1",
        ),
    )
    assert await passkey_store.get_credential(b"absent") is None
    assert (
        await passkey_store.record_assertion(
            credential.credential_id,
            expected_version=99,
            sign_count=1,
            backup_eligible=False,
            backup_state=False,
            clone_risk=False,
            now=now,
        )
        is accounts_module.PasskeyAssertionStatus.CONFLICT
    )
    assert len(await passkey_store.list_credentials("account-1")) == 1
    assert await passkey_store.rename_credential("other", credential.credential_id, "No") is None
    renamed = await passkey_store.rename_credential("account-1", credential.credential_id, "Laptop")
    assert renamed is not None
    assert renamed.display_name == "Laptop"
    assert await challenge_store.consume(b"x" * 32, binding_digest=b"y" * 32, purpose="registration", now=now) is None


async def test_aesgcm_mfa_secret_protector_rejects_invalid_configuration_entropy_and_envelopes() -> None:
    """MFA AES-GCM protection rejects malformed material before decrypting it."""
    mfa_key = accounts_module.SecretProtectorKey("v1", b"m" * 32)
    mfa_protector = accounts_module.AESGCMSecretProtector(active_key=mfa_key)
    protected_mfa_secret = await mfa_protector.protect(b"secret", associated_data=b"bound")

    assert mfa_protector.active_key_version == "v1"
    assert await mfa_protector.unprotect(protected_mfa_secret, associated_data=b"bound") == b"secret"
    with pytest.raises(InvalidTag):
        await mfa_protector.unprotect(protected_mfa_secret, associated_data=b"other-binding")

    with pytest.raises(ImproperlyConfiguredException, match="unique keys"):
        accounts_module.AESGCMSecretProtector(active_key=mfa_key, retained_keys=(mfa_key,))
    protector = accounts_module.AESGCMSecretProtector(active_key=mfa_key, entropy=lambda _size: b"short")
    with pytest.raises(ValueError, match="entropy"):
        await protector.protect(b"secret", associated_data=b"bound")

    protector = accounts_module.AESGCMSecretProtector(active_key=mfa_key)
    for protected in (
        accounts_module.ProtectedSecret(ciphertext=b"x" * 12, key_version="unknown"),
        accounts_module.ProtectedSecret(ciphertext=b"x" * 12, key_version="v1"),
    ):
        with pytest.raises(ValueError, match="envelope"):
            await protector.unprotect(protected, associated_data=b"bound")


def test_mfa_and_passkey_feature_configs_build_services_and_validate_route_controls() -> None:
    combined = CombinedMFAStore()
    login_methods = RecoveryLoginMethods()
    events = SecurityEvents()
    policy = accounts_module.TOTPPolicy(algorithm="SHA256")
    pepper = accounts_module.RecoveryCodePepper("v1", b"p" * 32)
    mfa = MFAConfig(
        store=combined,
        secret_protector=MFAProtector(),
        policy=policy,
        recovery_peppers=(pepper,),
        login_methods=login_methods,
        events=events,
        route_prefix="/security/",
        register_routes=False,
    )
    assert isinstance(mfa.mfa_service, accounts_module.MFAService)
    assert isinstance(mfa.step_up_service, accounts_module.StepUpService)
    assert mfa.mfa_service.policy is policy
    assert mfa.mfa_service.recovery_peppers == (pepper,)
    assert mfa.mfa_service.login_methods is login_methods
    assert mfa.mfa_service.events is events
    assert mfa.route_prefix == "/security"

    passkeys = PasskeyConfig(
        store=PasskeyStore(),
        challenge_store=WebAuthnChallengeStore(),
        rp_id="example.com",
        origins=("https://example.com",),
        login_methods=login_methods,
        events=events,
        step_up_store=StepUpStore(),
        register_routes=False,
    )
    assert isinstance(passkeys.passkey_service, accounts_module.PasskeyService)
    assert isinstance(passkeys.step_up_service, accounts_module.StepUpService)
    assert passkeys.passkey_service.login_methods is login_methods
    assert passkeys.passkey_service.events is events

    with pytest.raises(ImproperlyConfiguredException, match="recovery-code pepper"):
        MFAConfig(store=combined, secret_protector=MFAProtector())
    with pytest.raises(ImproperlyConfiguredException, match="login-method"):
        PasskeyConfig(
            store=PasskeyStore(),
            challenge_store=WebAuthnChallengeStore(),
            rp_id="example.com",
            origins=("https://example.com",),
        )

    for config in (
        lambda: MFAConfig(MFAStore(), MFAProtector(), route_prefix="relative"),
        lambda: MFAConfig(MFAStore(), MFAProtector(), route_prefix=cast("Any", 1)),
        lambda: MFAConfig(MFAStore(), MFAProtector(), register_routes=cast("Any", 1)),
        lambda: PasskeyConfig(
            PasskeyStore(),
            WebAuthnChallengeStore(),
            "example.com",
            ("https://example.com",),
            register_routes=cast("Any", 1),
        ),
    ):
        with pytest.raises(ImproperlyConfiguredException):
            config()
