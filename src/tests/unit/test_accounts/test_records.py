"""Unit tests for local account records, protocols, and atomic outcomes."""

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from functools import partial

import pytest

import litestar_security.accounts as accounts_module

_ACCOUNT_NOW = datetime(2026, 7, 27, tzinfo=timezone.utc)
_SESSION_ID = "c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M"
_BINDING_ID = "sb_aWlpaWlpaWlpaWlpaWlpaQ"
_REFRESH_ID = "rt_aWlpaWlpaWlpaWlpaWlpaQ"
_REFRESH_SUCCESSOR_ID = "rt_ampqampqampqampqampqag"
_REFRESH_FAMILY_ID = "rf_a2tra2tra2tra2tra2traw"
_CONTRADICTORY_ACCOUNT: accounts_module.LocalAccountState[object] = accounts_module.LocalAccountState(
    account_id="account-1",
    normalized_identifier="user@example.com",
    display_name=None,
    active=True,
    verified=True,
    security_epoch=1,
)

_BASE_LOCAL_CAPABILITIES = {
    "compare_and_replace_password",
    "consume_and_reset",
    "consume_and_verify",
    "current_epoch",
    "find_for_login",
    "get_by_id",
    "get_password_state",
    "issue",
    "issue_absent",
    "list_methods",
    "register_login_method",
    "replace_password_and_bump_epoch",
    "revoke_login_method",
}
_SESSION_CAPABILITIES = {
    "create",
    "get",
    "list_for_account",
    "rebind",
    "revoke_other_sessions",
    "revoke_session_for_account",
    "revoke_sessions_for_account",
    "touch",
}
_REFRESH_CAPABILITIES = {
    "create_family",
    "prepare_rotation",
    "revoke_family",
    "revoke_for_account",
    "revoke_token",
    "revoke_token_for_account",
    "rotate",
}


def _structural_capabilities(*method_names: str) -> object:
    def method(*_args: object, **_kwargs: object) -> None:
        return None

    return type("StructuralCapabilities", (), dict.fromkeys(method_names, method))()


@pytest.mark.parametrize(
    ("protocol", "methods"),
    [
        (accounts_module.AccountLookup, {"find_for_login", "get_by_id"}),
        (accounts_module.LocalAccountCapabilities, _BASE_LOCAL_CAPABILITIES),
        (
            accounts_module.PasswordCredentialStore,
            {"get_password_state", "compare_and_replace_password", "replace_password_and_bump_epoch"},
        ),
        (accounts_module.LoginMethodStore, {"list_methods", "register_login_method", "revoke_login_method"}),
        (accounts_module.RegistrationStore, {"register"}),
        (accounts_module.VerificationTokenStore, {"issue", "issue_absent", "consume_and_verify"}),
        (accounts_module.RecoveryTokenStore, {"issue", "issue_absent", "consume_and_reset"}),
        (accounts_module.SecurityEpochStore, {"current_epoch"}),
        (accounts_module.SessionRegistry, _SESSION_CAPABILITIES),
        (accounts_module.RefreshTokenFamilyStore, _REFRESH_CAPABILITIES),
    ],
)
def test_account_capabilities_are_runtime_structural(protocol: type[object], methods: set[str]) -> None:
    implementation = _structural_capabilities(*methods)

    assert isinstance(implementation, protocol)
    assert protocol not in type(implementation).__mro__
    if methods:
        incomplete = _structural_capabilities(*tuple(methods)[1:])
        assert not isinstance(incomplete, protocol)


def test_local_account_commands_and_results_are_secret_safe() -> None:
    now = datetime(2026, 7, 26, 23, tzinfo=timezone.utc)
    event_correlation = {"request_id": "request-1"}
    event = accounts_module.SecurityEvent(
        event_id="event-1",
        occurred_at=now,
        operation="local.login",
        outcome="accepted",
        account_id="account-1",
        correlation=event_correlation,
    )

    event_correlation["request_id"] = "changed"
    assert event.correlation == {"request_id": "request-1"}


@pytest.mark.parametrize(
    "secret",
    [
        "binding-secret-digest",
        "destination-secret",
        "raw-notification-secret",
        "encoded-secret-hash",
        "sealed-secret-receipt",
        "successor-secret-digest",
        "token-secret-digest",
    ],
)
def test_local_account_commands_and_results_redact_secret_fields(secret: str) -> None:
    assert secret not in _rendered_secret_safe_records()


@pytest.mark.parametrize(
    "result_factory",
    [
        partial(accounts_module.PasswordChangeOutcome, accounts_module.PasswordChangeStatus.CHANGED),
        partial(accounts_module.PasswordChangeOutcome, accounts_module.PasswordChangeStatus.CONFLICT, 2),
        partial(accounts_module.RegistrationOutcome, accounts_module.RegistrationStatus.CREATED),
        partial(
            accounts_module.RegistrationOutcome, accounts_module.RegistrationStatus.DUPLICATE, _CONTRADICTORY_ACCOUNT
        ),
        partial(accounts_module.VerificationOutcome, accounts_module.VerificationStatus.CONSUMED),
        partial(
            accounts_module.VerificationOutcome,
            accounts_module.VerificationStatus.INVALID,
            _CONTRADICTORY_ACCOUNT.account_id,
            1,
        ),
        partial(accounts_module.PasswordResetOutcome, accounts_module.PasswordResetStatus.RESET),
        partial(
            accounts_module.PasswordResetOutcome,
            accounts_module.PasswordResetStatus.INVALID,
            _CONTRADICTORY_ACCOUNT.account_id,
            1,
        ),
        partial(accounts_module.RefreshRotationOutcome, accounts_module.RefreshRotationStatus.ROTATED),
        partial(
            accounts_module.RefreshRotationOutcome,
            accounts_module.RefreshRotationStatus.ROTATED,
            sealed_receipt=b"receipt",
            family_revoked=True,
        ),
        partial(accounts_module.RefreshRotationOutcome, accounts_module.RefreshRotationStatus.REPLAY_DETECTED),
        partial(
            accounts_module.RefreshRotationOutcome, accounts_module.RefreshRotationStatus.INVALID, family_revoked=True
        ),
    ],
    ids=[
        "password-changed-missing-epoch",
        "password-conflict-with-epoch",
        "registration-created-missing-account",
        "registration-duplicate-with-account",
        "verification-consumed-missing-fields",
        "verification-invalid-with-fields",
        "reset-missing-fields",
        "reset-invalid-with-fields",
        "refresh-rotated-missing-receipt",
        "refresh-rotated-family-revoked",
        "refresh-replay-not-revoked",
        "refresh-invalid-family-revoked",
    ],
)
def test_atomic_results_reject_contradictory_status_payloads(result_factory: Callable[[], object]) -> None:
    with pytest.raises(ValueError, match=r"require|must report"):
        result_factory()


def test_atomic_results_preserve_optional_fields_when_unpopulated() -> None:
    assert accounts_module.PasswordChangeOutcome(accounts_module.PasswordChangeStatus.CONFLICT).security_epoch is None
    assert accounts_module.RegistrationOutcome(accounts_module.RegistrationStatus.DUPLICATE).account is None
    assert accounts_module.VerificationOutcome(accounts_module.VerificationStatus.INVALID).account_id is None
    assert accounts_module.PasswordResetOutcome(accounts_module.PasswordResetStatus.EXPIRED).account_id is None
    assert (
        accounts_module.RefreshRotationOutcome(
            accounts_module.RefreshRotationStatus.IDEMPOTENT_REPLAY, b"receipt"
        ).sealed_receipt
        == b"receipt"
    )
    assert accounts_module.RefreshRotationOutcome(
        accounts_module.RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True
    ).family_revoked
    assert accounts_module.RefreshRotationOutcome(
        accounts_module.RefreshRotationStatus.REVOKED, family_revoked=True
    ).family_revoked
    assert not accounts_module.RefreshRotationOutcome(accounts_module.RefreshRotationStatus.EXPIRED).family_revoked


@pytest.mark.parametrize("epoch", [-1, True, 9_223_372_036_854_775_808])
@pytest.mark.parametrize(
    "factory",
    [
        lambda epoch: accounts_module.LocalAccountState(
            account_id="account-1",
            normalized_identifier="user@example.com",
            display_name=None,
            active=True,
            verified=True,
            security_epoch=epoch,
        ),
        lambda epoch: accounts_module.PasswordCredentialState("encoded-hash", epoch, active=True, verified=True),
        lambda epoch: accounts_module.PasswordReauthenticationProof(
            "account-1", epoch, _ACCOUNT_NOW, _ACCOUNT_NOW + timedelta(minutes=5)
        ),
        lambda epoch: accounts_module.PasswordChangeOutcome(accounts_module.PasswordChangeStatus.CHANGED, epoch),
        lambda epoch: accounts_module.PasswordResetOutcome(
            accounts_module.PasswordResetStatus.RESET, "account-1", epoch
        ),
        lambda epoch: accounts_module.SessionAuthentication(
            _SESSION_ID, _BINDING_ID, "account-1", epoch, _ACCOUNT_NOW, _ACCOUNT_NOW + timedelta(hours=1)
        ),
        lambda epoch: accounts_module.UserAuthSession(
            _SESSION_ID,
            _BINDING_ID,
            b"d" * 32,
            "account-1",
            epoch,
            _ACCOUNT_NOW,
            _ACCOUNT_NOW,
            _ACCOUNT_NOW,
            _ACCOUNT_NOW + timedelta(hours=1),
        ),
        lambda epoch: accounts_module.CreateSessionCommand(
            _SESSION_ID,
            _BINDING_ID,
            b"d" * 32,
            "account-1",
            epoch,
            _ACCOUNT_NOW,
            _ACCOUNT_NOW,
            _ACCOUNT_NOW + timedelta(hours=1),
        ),
        lambda epoch: accounts_module.RotateRefreshCommand(
            _REFRESH_ID,
            b"d" * 32,
            "account-1",
            _REFRESH_FAMILY_ID,
            epoch,
            _REFRESH_SUCCESSOR_ID,
            b"s" * 32,
            _ACCOUNT_NOW,
            _ACCOUNT_NOW,
            b"receipt",
            _ACCOUNT_NOW,
        ),
    ],
    ids=[
        "local-account",
        "password-credential",
        "reauth-proof",
        "password-change-outcome",
        "password-reset-outcome",
        "session-authentication",
        "user-auth-session",
        "create-session-command",
        "rotate-refresh-command",
    ],
)
def test_account_password_session_and_refresh_contracts_share_one_strict_epoch_domain(
    epoch: object, factory: Callable[[object], object]
) -> None:
    with pytest.raises(ValueError, match="epoch"):
        factory(epoch)


@pytest.mark.parametrize(("field_name", "value"), [("active", 1), ("verified", "false")])
def test_local_account_requires_exact_boolean_state(field_name: str, value: object) -> None:
    values = {
        "account_id": "account-1",
        "normalized_identifier": "user@example.com",
        "display_name": None,
        "active": True,
        "verified": True,
        "security_epoch": 1,
    }
    values[field_name] = value

    with pytest.raises(ValueError, match="Local account"):
        accounts_module.LocalAccountState(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(("field_name", "value"), [("active", 1), ("verified", "false")])
def test_password_credential_state_requires_exact_boolean_account_state(field_name: str, value: object) -> None:
    values = {"password_hash": "encoded-hash", "security_epoch": 1, "active": True, "verified": True}
    values[field_name] = value

    with pytest.raises(ValueError, match="boolean account state"):
        accounts_module.PasswordCredentialState(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("authenticated_at", "expires_at", "match"),
    [
        (_ACCOUNT_NOW.replace(tzinfo=None), _ACCOUNT_NOW + timedelta(minutes=5), "timezone-aware"),
        (_ACCOUNT_NOW, _ACCOUNT_NOW.replace(tzinfo=None), "timezone-aware"),
        (object(), _ACCOUNT_NOW + timedelta(minutes=5), "timezone-aware"),
        (_ACCOUNT_NOW, _ACCOUNT_NOW + timedelta(minutes=5, microseconds=1), "valid lifetime"),
    ],
)
def test_password_reauthentication_proof_requires_aware_timestamps(
    authenticated_at: datetime, expires_at: datetime, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        accounts_module.PasswordReauthenticationProof("account-1", 1, authenticated_at, expires_at)


def _rendered_secret_safe_records() -> str:
    now = datetime(2026, 7, 26, 23, tzinfo=timezone.utc)
    account = accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="user@example.com",
        display_name="User",
        active=True,
        verified=True,
        security_epoch=1,
        user=object(),
    )
    binding_digest = b"binding-secret-digest".ljust(32, b"b")
    token_digest = b"token-secret-digest".ljust(32, b"d")
    successor_digest = b"successor-secret-digest".ljust(32, b"x")
    receipt = b"sealed-secret-receipt"
    lookup_id = "verification_aWlpaWlpaWlpaWlpaWlpaQ"
    notification_value = "raw-notification-secret"
    values = (
        account,
        accounts_module.LoginMethod(method_id="password-1", kind="password", created_at=now),
        accounts_module.SecurityEvent(
            event_id="event-1",
            occurred_at=now,
            operation="local.login",
            outcome="accepted",
            account_id=account.account_id,
        ),
        accounts_module.TokenIssue(
            token_id=lookup_id,
            digest=token_digest,
            purpose=accounts_module.TokenPurpose.VERIFICATION,
            account_id=account.account_id,
            expires_at=now + timedelta(hours=1),
            maximum_attempts=5,
        ),
        accounts_module.NotificationCommand(
            template="verify",
            destination="destination-secret",
            token=notification_value,
            expires_at=now + timedelta(hours=1),
        ),
        accounts_module.RegistrationCommand(normalized_identifier="user@example.com"),
        accounts_module.PasswordCredentialState("encoded-secret-hash", 1, active=True, verified=True),
        accounts_module.PasswordReauthenticationProof(
            account_id=account.account_id, security_epoch=1, authenticated_at=now, expires_at=now + timedelta(minutes=5)
        ),
        accounts_module.PasswordChangeOutcome(accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2),
        accounts_module.RevokeLoginMethodOutcome(accounts_module.RevokeLoginMethodStatus.REVOKED),
        accounts_module.RegistrationOutcome(accounts_module.RegistrationStatus.CREATED, account),
        accounts_module.VerificationOutcome(accounts_module.VerificationStatus.CONSUMED, account.account_id, 1),
        accounts_module.PasswordResetOutcome(accounts_module.PasswordResetStatus.RESET, account.account_id, 2),
        accounts_module.RegistrationPolicy.disabled(),
        accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        accounts_module.SessionAuthentication(
            session_id=_SESSION_ID,
            binding_id=_BINDING_ID,
            account_id=account.account_id,
            security_epoch=1,
            authenticated_at=now,
            expires_at=now + timedelta(hours=1),
        ),
        accounts_module.SessionBindingProof(binding_id=_BINDING_ID, digest=binding_digest),
        accounts_module.UserAuthSession(
            session_id=_SESSION_ID,
            binding_id=_BINDING_ID,
            binding_digest=binding_digest,
            account_id=account.account_id,
            security_epoch=1,
            created_at=now,
            authenticated_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(hours=1),
        ),
        accounts_module.CreateSessionCommand(
            session_id=_SESSION_ID,
            binding_id=_BINDING_ID,
            binding_digest=binding_digest,
            account_id=account.account_id,
            security_epoch=1,
            created_at=now,
            authenticated_at=now,
            expires_at=now + timedelta(hours=1),
        ),
        accounts_module.SessionSummary(
            session_id=_SESSION_ID, current=True, created_at=now, last_seen_at=now, expires_at=now + timedelta(hours=1)
        ),
        accounts_module.RotateRefreshCommand(
            token_id=_REFRESH_ID,
            token_digest=token_digest,
            account_id=account.account_id,
            family_id=_REFRESH_FAMILY_ID,
            security_epoch=1,
            successor_id=_REFRESH_SUCCESSOR_ID,
            successor_digest=successor_digest,
            successor_expires_at=now + timedelta(days=7),
            family_expires_at=now + timedelta(days=30),
            sealed_receipt=receipt,
            receipt_expires_at=now + timedelta(seconds=30),
        ),
        accounts_module.RefreshRotationOutcome(accounts_module.RefreshRotationStatus.ROTATED, receipt),
    )
    return " ".join(repr(value) for value in values)
