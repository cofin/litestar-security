"""Local account models, security event records, operation constants, and outcomes."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from logging import getLogger
from types import MappingProxyType
from typing import Generic, Protocol, TypeVar, runtime_checkable
from unicodedata import normalize

from litestar_security.accounts._internal import aware_utc_time, strict_text, valid_security_epoch
from litestar_security.schema import WireStruct

__all__ = (
    "LOGIN",
    "LOGIN_MFA",
    "MFA_RECOVERY_CONSUME",
    "MFA_RECOVERY_REPLACE",
    "MFA_TOTP_ENROLL",
    "MFA_TOTP_REMOVE",
    "MFA_TOTP_VERIFY",
    "OUTCOME_ATTEMPTED",
    "OUTCOME_CHANGED",
    "OUTCOME_CLONE_RISK",
    "OUTCOME_CREATED",
    "OUTCOME_ISSUED",
    "OUTCOME_MALFORMED_HASH",
    "OUTCOME_RATE_LIMITED",
    "OUTCOME_REBOUND",
    "OUTCOME_RESET",
    "OUTCOME_REVOKED",
    "OUTCOME_UPDATED",
    "OUTCOME_VERIFIED",
    "PASSKEY_ASSERT",
    "PASSKEY_AUTH_OPTIONS",
    "PASSKEY_REGISTER_OPTIONS",
    "PASSKEY_REGISTER_VERIFY",
    "PASSKEY_REMOVE",
    "PASSWORD_CHANGE",
    "PASSWORD_FORCE_RESET",
    "PASSWORD_REFRESH_REVOKE",
    "PASSWORD_REHASH",
    "PASSWORD_RESET",
    "PASSWORD_SESSION_REBIND",
    "PASSWORD_SESSION_REVOKE_OTHERS",
    "PASSWORD_VERIFY",
    "RATE_LIMITED_OPERATIONS",
    "RECOVERY",
    "RECOVERY_CONSUME",
    "RECOVERY_ISSUE",
    "REFRESH_CREATE",
    "REFRESH_PREPARE",
    "REFRESH_RECEIPT",
    "REFRESH_REVOKE",
    "REFRESH_ROTATE",
    "REGISTRATION",
    "SESSION_LOGOUT",
    "SESSION_REBIND",
    "SESSION_REVOKE",
    "SESSION_REVOKE_ALL_SUFFIX",
    "VERIFICATION_CONSUME",
    "VERIFICATION_ISSUE",
    "VERIFICATION_RESEND",
    "InvalidInvitation",
    "LifecycleAccepted",
    "LifecycleRejected",
    "LocalAccountState",
    "LocalAuthMode",
    "LoginMethod",
    "NoOpSecurityEventSink",
    "PasswordChangeOutcome",
    "PasswordChangeStatus",
    "PasswordCredentialState",
    "PasswordPolicyViolation",
    "PasswordReauthenticationProof",
    "PasswordResetOutcome",
    "PasswordResetStatus",
    "PasswordVerificationStatus",
    "RegistrationMode",
    "RegistrationOutcome",
    "RegistrationStatus",
    "RevokeLoginMethodOutcome",
    "RevokeLoginMethodStatus",
    "SecurityEvent",
    "SecurityEventSink",
    "TokenPurpose",
    "VerificationOutcome",
    "VerificationStatus",
    "emit_security_event",
    "lifecycle_event",
    "normalize_identifier",
)

UserT = TypeVar("UserT")
_EMPTY_CORRELATION: Mapping[str, str] = MappingProxyType({})
_DEFAULT_REAUTHENTICATION_TTL = timedelta(minutes=5)
_LOGGER = getLogger(__name__)

PASSWORD_CHANGE = "local.password.change"
PASSWORD_FORCE_RESET = "local.password.force_reset"
PASSWORD_REFRESH_REVOKE = "local.password.refresh_revoke"
PASSWORD_REHASH = "local.password.rehash"
PASSWORD_SESSION_REBIND = "local.password.session_rebind"
PASSWORD_SESSION_REVOKE_OTHERS = "local.password.session_revoke_others"
PASSWORD_VERIFY = "local.password.verify"
RECOVERY = "local.recovery"
RECOVERY_CONSUME = "local.recovery.consume"
RECOVERY_ISSUE = "local.recovery.issue"
REFRESH_CREATE = "local.refresh.create"
REFRESH_PREPARE = "local.refresh.prepare"
REFRESH_RECEIPT = "local.refresh.receipt"
REFRESH_REVOKE = "local.refresh.revoke"
REFRESH_ROTATE = "local.refresh.rotate"
REGISTRATION = "local.registration"
SESSION_LOGOUT = "local.session.logout"
SESSION_REBIND = "local.session.rebind"
SESSION_REVOKE = "local.session.revoke"
VERIFICATION_CONSUME = "local.verification.consume"
VERIFICATION_ISSUE = "local.verification.issue"

SESSION_REVOKE_ALL_SUFFIX = ".session_revoke_all"

LOGIN = "local.login"
LOGIN_MFA = "local.login.mfa"
MFA_RECOVERY_CONSUME = "local.mfa.recovery.consume"
MFA_RECOVERY_REPLACE = "local.mfa.recovery.replace"
MFA_TOTP_ENROLL = "local.mfa.totp.enroll"
MFA_TOTP_REMOVE = "local.mfa.totp.remove"
MFA_TOTP_VERIFY = "local.mfa.totp.verify"
PASSKEY_ASSERT = "local.passkey.assert"
PASSKEY_AUTH_OPTIONS = "local.passkey.authentication.options"
PASSKEY_REGISTER_OPTIONS = "local.passkey.registration.options"
PASSKEY_REGISTER_VERIFY = "local.passkey.registration.verify"
PASSKEY_REMOVE = "local.passkey.remove"
PASSWORD_RESET = "local.password.reset"
VERIFICATION_RESEND = "local.verification.resend"

RATE_LIMITED_OPERATIONS = frozenset({
    LOGIN,
    LOGIN_MFA,
    REGISTRATION,
    RECOVERY,
    PASSWORD_RESET,
    PASSWORD_VERIFY,
    VERIFICATION_RESEND,
    VERIFICATION_CONSUME,
    REFRESH_ROTATE,
    MFA_TOTP_ENROLL,
    MFA_TOTP_VERIFY,
    MFA_TOTP_REMOVE,
    MFA_RECOVERY_CONSUME,
    MFA_RECOVERY_REPLACE,
    PASSKEY_REGISTER_OPTIONS,
    PASSKEY_REGISTER_VERIFY,
    PASSKEY_AUTH_OPTIONS,
    PASSKEY_ASSERT,
    PASSKEY_REMOVE,
})

OUTCOME_ATTEMPTED = "attempted"
OUTCOME_CHANGED = "changed"
OUTCOME_CLONE_RISK = "clone_risk"
OUTCOME_CREATED = "created"
OUTCOME_ISSUED = "issued"
OUTCOME_MALFORMED_HASH = "malformed_hash"
OUTCOME_RATE_LIMITED = "rate_limited"
OUTCOME_REBOUND = "rebound"
OUTCOME_RESET = "reset"
OUTCOME_REVOKED = "revoked"
OUTCOME_UPDATED = "updated"
OUTCOME_VERIFIED = "verified"


class LocalAuthMode(str, Enum):
    """Visible local-authentication transport selection."""

    SESSION = "session"
    TOKENS = "tokens"
    HYBRID = "hybrid"


class RegistrationMode(str, Enum):
    """Supported self-service registration policies."""

    DISABLED = "disabled"
    PUBLIC = "public"
    INVITE_ONLY = "invite_only"


class TokenPurpose(str, Enum):
    """Closed namespaces for one-time local-account tokens."""

    INVITATION = "invitation"
    VERIFICATION = "verification"
    RECOVERY = "recovery"


class PasswordChangeStatus(str, Enum):
    """Atomic password-change outcomes."""

    CHANGED = "changed"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"
    EPOCH_EXHAUSTED = "epoch_exhausted"


class PasswordPolicyViolation(str, Enum):
    """Secret-free reasons a candidate password does not satisfy policy."""

    TOO_SHORT = "too_short"
    TOO_LONG = "too_long"
    TOO_MANY_BYTES = "too_many_bytes"
    INVALID_TEXT = "invalid_text"
    MATCHES_IDENTIFIER = "matches_identifier"
    COMPROMISED = "compromised"


class PasswordVerificationStatus(str, Enum):
    """Sanitized outcomes from one constant-work password verification."""

    VERIFIED = "verified"
    INVALID = "invalid"
    MALFORMED = "malformed"
    TOO_LONG = "too_long"


class RevokeLoginMethodStatus(str, Enum):
    """Atomic login-method revocation outcomes."""

    REVOKED = "revoked"
    NOT_FOUND = "not_found"
    FINAL_METHOD = "final_method"


class RegistrationStatus(str, Enum):
    """Atomic registration outcomes."""

    CREATED = "created"
    DUPLICATE = "duplicate"
    INVALID_INVITATION = "invalid_invitation"


class VerificationStatus(str, Enum):
    """Atomic purpose-token consumption outcomes."""

    CONSUMED = "consumed"
    INVALID = "invalid"
    EXPIRED = "expired"
    USED = "used"


class PasswordResetStatus(str, Enum):
    """Atomic recovery-token/password-reset outcomes."""

    RESET = "reset"
    INVALID = "invalid"
    EXPIRED = "expired"
    USED = "used"
    CONFLICT = "conflict"
    EPOCH_EXHAUSTED = "epoch_exhausted"


@dataclass(frozen=True, slots=True)
class LocalAccountState(Generic[UserT]):
    """Application-owned account projection needed by local authentication."""

    account_id: str
    normalized_identifier: str
    display_name: str | None
    active: bool
    verified: bool
    security_epoch: int
    user: UserT | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Validate the stable account and strict epoch projection."""
        if (
            not strict_text(self.account_id)
            or not strict_text(self.normalized_identifier)
            or not valid_security_epoch(self.security_epoch)
            or type(self.active) is not bool
            or type(self.verified) is not bool
        ):
            msg = "Local account requires stable identifiers and a valid security epoch"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class LoginMethod:
    """One application-owned viable login method."""

    method_id: str
    kind: str
    created_at: datetime
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class PasswordCredentialState:
    """Atomic password hash, account-state, and epoch snapshot for reauthentication."""

    password_hash: str = field(repr=False)
    security_epoch: int
    active: bool
    verified: bool

    def __post_init__(self) -> None:
        """Require one encoded hash bound to an eligible account and strict current epoch."""
        if (
            not strict_text(self.password_hash)
            or not valid_security_epoch(self.security_epoch)
            or type(self.active) is not bool
            or type(self.verified) is not bool
        ):
            msg = "Password credential state requires a hash, valid security epoch, and boolean account state"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class PasswordReauthenticationProof:
    """Account- and epoch-bound recent password proof for sensitive mutation."""

    account_id: str
    security_epoch: int
    authenticated_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        """Require a strict identity, epoch, and forward-moving proof window."""
        try:
            authenticated_at = aware_utc_time(self.authenticated_at)
            expires_at = aware_utc_time(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Password reauthentication proof timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not strict_text(self.account_id)
            or not valid_security_epoch(self.security_epoch)
            or expires_at <= authenticated_at
            or expires_at - authenticated_at > _DEFAULT_REAUTHENTICATION_TTL
        ):
            msg = "Password reauthentication proof requires an account, epoch, and valid lifetime"
            raise ValueError(msg)
        object.__setattr__(self, "authenticated_at", authenticated_at)
        object.__setattr__(self, "expires_at", expires_at)


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Secret-free event committed with a security decision or mutation."""

    event_id: str
    occurred_at: datetime
    operation: str
    outcome: str
    account_id: str | None = None
    principal_id: str | None = None
    mechanism: str | None = None
    session_id: str | None = None
    family_id: str | None = None
    correlation: Mapping[str, str] = field(default_factory=lambda: _EMPTY_CORRELATION)

    def __post_init__(self) -> None:
        """Freeze caller-supplied correlation fields."""
        object.__setattr__(self, "correlation", MappingProxyType(dict(self.correlation)))


@runtime_checkable
class SecurityEventSink(Protocol):
    """Application-owned sink for secret-free, non-transactional decisions."""

    async def emit(self, event: SecurityEvent) -> None:
        """Record one sanitized security decision.

        Events are secret-free by construction, so a sink may forward them
        anywhere. Observational events cannot change the decision they describe;
        raising from one is logged and dropped.

        Args:
            event: The event to record.
        """
        ...


@dataclass(frozen=True, slots=True)
class NoOpSecurityEventSink:
    """Accept security events when an application has not configured a sink."""

    async def emit(self, event: SecurityEvent) -> None:
        """Discard one already-sanitized observational event.

        Args:
            event: The event to discard.
        """
        del event


class LifecycleAccepted(WireStruct, frozen=True):
    """Shared enumeration-resistant response body for lifecycle requests."""

    detail: str = "If eligible, the request will be processed."


@dataclass(frozen=True, slots=True)
class InvalidInvitation:
    """Generic invalid-invitation response without expiry or replay details."""

    detail: str = "Invitation is invalid or unavailable."


@dataclass(frozen=True, slots=True)
class LifecycleRejected:
    """Generic malformed lifecycle request response."""

    detail: str = "The request is invalid."


@dataclass(frozen=True, slots=True)
class PasswordChangeOutcome:
    """Atomic password replacement and security-epoch outcome."""

    status: PasswordChangeStatus
    security_epoch: int | None = None

    def __post_init__(self) -> None:
        """Require an epoch only for a successful atomic replacement."""
        changed = self.status is PasswordChangeStatus.CHANGED
        if (
            type(self.status) is not PasswordChangeStatus
            or changed != (self.security_epoch is not None)
            or (changed and not valid_security_epoch(self.security_epoch))
        ):
            msg = "Changed password outcomes require exactly one security epoch"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RevokeLoginMethodOutcome:
    """Atomic login-method revocation outcome."""

    status: RevokeLoginMethodStatus


@dataclass(frozen=True, slots=True)
class RegistrationOutcome(Generic[UserT]):
    """Atomic registration outcome."""

    status: RegistrationStatus
    account: LocalAccountState[UserT] | None = None

    def __post_init__(self) -> None:
        """Require an account projection only for a created registration."""
        if (self.status is RegistrationStatus.CREATED) != (self.account is not None):
            msg = "Created registration outcomes require exactly one account"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    """Atomic verification-token consumption outcome."""

    status: VerificationStatus
    account_id: str | None = None
    security_epoch: int | None = None

    def __post_init__(self) -> None:
        """Require account and epoch payload only for successful consumption."""
        consumed = self.status is VerificationStatus.CONSUMED
        has_payload = self.account_id is not None and self.security_epoch is not None
        if consumed != has_payload or (
            not consumed and (self.account_id is not None or self.security_epoch is not None)
        ):
            msg = "Consumed verification outcomes require exactly one account and security epoch"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class PasswordResetOutcome:
    """Atomic recovery-token consumption and password-reset outcome."""

    status: PasswordResetStatus
    account_id: str | None = None
    security_epoch: int | None = None

    def __post_init__(self) -> None:
        """Require account and epoch payload only for a completed reset."""
        reset = self.status is PasswordResetStatus.RESET
        has_payload = self.account_id is not None and self.security_epoch is not None
        if (
            type(self.status) is not PasswordResetStatus
            or reset != has_payload
            or (not reset and (self.account_id is not None or self.security_epoch is not None))
            or (reset and (not strict_text(self.account_id) or not valid_security_epoch(self.security_epoch)))
        ):
            msg = "Reset password outcomes require exactly one account and security epoch"
            raise ValueError(msg)


def normalize_identifier(value: str) -> str:
    """Apply the default compatibility, whitespace, and case normalization.

    Args:
        value: The submitted identifier.

    Returns:
        The NFKC-normalized, stripped, case-folded identifier.

    Raises:
        ValueError: If the value is not text.
    """
    if type(value) is not str:
        msg = "Identifier normalization requires text"
        raise ValueError(msg)
    return normalize("NFKC", value).strip().casefold()


async def emit_security_event(sink: SecurityEventSink, event: SecurityEvent) -> None:
    """Offer one observational event to an application sink without letting it fail.

    Observational events report a decision that has already been made. A sink
    that raises must not change that decision or surface its exception to the
    caller, so the failure is logged without the untrusted detail and dropped.
    Durable mutation events do not come through here: those are passed into the
    atomic store operation itself, so a rejected event fails the mutation.
    """
    try:
        await sink.emit(event)
    except Exception:
        _LOGGER.error("Security event sink failed for %s", event.operation)


def lifecycle_event(
    event_ids: Callable[[], str], occurred_at: datetime, *, operation: str, outcome: str, account_id: str | None = None
) -> SecurityEvent:
    """Build one standard lifecycle security event."""
    event_id = event_ids()
    if not strict_text(event_id):
        raise ValueError
    return SecurityEvent(
        event_id=event_id.strip(),
        occurred_at=occurred_at,
        operation=operation,
        outcome=outcome,
        account_id=account_id,
        mechanism="password",
    )
