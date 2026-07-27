"""Backend-agnostic local-account contracts and explicit transport profiles."""

from collections.abc import Mapping  # noqa: TC003 - Litestar resolves public annotations at runtime
from dataclasses import dataclass, field
from datetime import datetime  # noqa: TC003 - Litestar resolves public annotations at runtime
from enum import Enum
from types import MappingProxyType
from typing import Any, Generic, Protocol, TypeVar, runtime_checkable

from litestar.config.csrf import CSRFConfig
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts.sessions import RefreshTokenFamilyStore, SessionBindingConfig, SessionRegistry
from litestar_security.config import ExternalCSRF
from litestar_security.providers.jwt import LocalKeyRing

__all__ = (
    "AccountLookup",
    "ConsumeResult",
    "ConsumeStatus",
    "LocalAccount",
    "LocalAccountCapabilities",
    "LocalAuth",
    "LocalAuthConfig",
    "LocalAuthMode",
    "LoginMethod",
    "LoginMethodStore",
    "NotificationCommand",
    "PasswordChangeResult",
    "PasswordChangeStatus",
    "PasswordCredentialStore",
    "PasswordResetResult",
    "PasswordResetStatus",
    "RecoveryTokenStore",
    "RegistrationCommand",
    "RegistrationMode",
    "RegistrationPolicy",
    "RegistrationResult",
    "RegistrationStatus",
    "RegistrationStore",
    "RevokeLoginMethodResult",
    "RevokeLoginMethodStatus",
    "SecurityEpochStore",
    "SecurityEvent",
    "TokenIssue",
    "VerificationTokenStore",
)

UserT = TypeVar("UserT")
_EMPTY_CORRELATION: "Mapping[str, str]" = MappingProxyType({})
_ASCII_CONTROL_LIMIT = 32


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


class PasswordChangeStatus(str, Enum):
    """Atomic password-change outcomes."""

    CHANGED = "changed"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"


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


class ConsumeStatus(str, Enum):
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


@dataclass(frozen=True, slots=True)
class LocalAccount(Generic[UserT]):
    """Application-owned account projection needed by local authentication."""

    account_id: str
    normalized_identifier: str
    display_name: str | None
    active: bool
    verified: bool
    security_epoch: int
    user: UserT | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class LoginMethod:
    """One application-owned viable login method."""

    method_id: str
    kind: str
    created_at: "datetime"
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Secret-free event committed with a security decision or mutation."""

    event_id: str
    occurred_at: "datetime"
    operation: str
    outcome: str
    account_id: str | None = None
    principal_id: str | None = None
    mechanism: str | None = None
    session_id: str | None = None
    family_id: str | None = None
    correlation: "Mapping[str, str]" = field(default=_EMPTY_CORRELATION)

    def __post_init__(self) -> None:
        """Freeze caller-supplied correlation fields."""
        object.__setattr__(self, "correlation", MappingProxyType(dict(self.correlation)))


@dataclass(frozen=True, slots=True)
class TokenIssue:
    """Hashed, purpose-bound token material accepted by an atomic store."""

    token_id: str
    digest: bytes = field(repr=False)
    purpose: str
    account_id: str
    expires_at: "datetime"
    maximum_attempts: int


@dataclass(frozen=True, slots=True)
class NotificationCommand:
    """Delivery-neutral notification data with a one-time opaque token."""

    template: str
    destination: str = field(repr=False)
    token: str = field(repr=False)
    expires_at: "datetime"
    return_url: str | None = None


@dataclass(frozen=True, slots=True)
class RegistrationCommand:
    """Application-neutral local registration input."""

    normalized_identifier: str = field(repr=False)
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class PasswordChangeResult:
    """Atomic password replacement and security-epoch outcome."""

    status: PasswordChangeStatus
    security_epoch: int | None = None

    def __post_init__(self) -> None:
        """Require an epoch only for a successful atomic replacement."""
        changed = self.status is PasswordChangeStatus.CHANGED
        if changed != (self.security_epoch is not None):
            msg = "Changed password results require exactly one security epoch"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RevokeLoginMethodResult:
    """Atomic login-method revocation outcome."""

    status: RevokeLoginMethodStatus


@dataclass(frozen=True, slots=True)
class RegistrationResult(Generic[UserT]):
    """Atomic registration outcome."""

    status: RegistrationStatus
    account: LocalAccount[UserT] | None = None

    def __post_init__(self) -> None:
        """Require an account projection only for a created registration."""
        if (self.status is RegistrationStatus.CREATED) != (self.account is not None):
            msg = "Created registration results require exactly one account"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ConsumeResult:
    """Atomic verification-token consumption outcome."""

    status: ConsumeStatus
    account_id: str | None = None
    security_epoch: int | None = None

    def __post_init__(self) -> None:
        """Require account and epoch payload only for successful consumption."""
        consumed = self.status is ConsumeStatus.CONSUMED
        has_payload = self.account_id is not None and self.security_epoch is not None
        if consumed != has_payload or (
            not consumed and (self.account_id is not None or self.security_epoch is not None)
        ):
            msg = "Consumed verification results require exactly one account and security epoch"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class PasswordResetResult:
    """Atomic recovery-token consumption and password-reset outcome."""

    status: PasswordResetStatus
    account_id: str | None = None
    security_epoch: int | None = None

    def __post_init__(self) -> None:
        """Require account and epoch payload only for a completed reset."""
        reset = self.status is PasswordResetStatus.RESET
        has_payload = self.account_id is not None and self.security_epoch is not None
        if reset != has_payload or (not reset and (self.account_id is not None or self.security_epoch is not None)):
            msg = "Reset password results require exactly one account and security epoch"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RegistrationPolicy:
    """Explicit self-service registration policy."""

    mode: RegistrationMode
    require_verification: bool = True

    @classmethod
    def disabled(cls) -> "RegistrationPolicy":
        """Disable self-service registration."""
        return cls(mode=RegistrationMode.DISABLED)

    @classmethod
    def public(cls, *, require_verification: bool = True) -> "RegistrationPolicy":
        """Enable public self-service registration."""
        return cls(mode=RegistrationMode.PUBLIC, require_verification=require_verification)

    @classmethod
    def invite_only(cls, *, require_verification: bool = True) -> "RegistrationPolicy":
        """Require an atomic invitation consume during registration."""
        return cls(mode=RegistrationMode.INVITE_ONLY, require_verification=require_verification)


@runtime_checkable
class AccountLookup(Protocol[UserT]):
    """Resolve the minimal application account projection."""

    async def find_for_login(self, normalized_identifier: str) -> "LocalAccount[UserT] | None":
        """Find an account through an already-normalized identifier."""
        ...  # pragma: no cover

    async def get_by_id(self, account_id: str) -> "LocalAccount[UserT] | None":
        """Resolve an account by its stable security identifier."""
        ...  # pragma: no cover


@runtime_checkable
class PasswordCredentialStore(Protocol):
    """Store password credentials through atomic security operations."""

    async def get_password_hash(self, account_id: str) -> str | None:
        """Load the current encoded password hash."""
        ...  # pragma: no cover

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, *, event: SecurityEvent
    ) -> bool:
        """Atomically replace a hash only when its expected value is current."""
        ...  # pragma: no cover

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeResult:
        """Atomically replace a password and increment the security epoch."""
        ...  # pragma: no cover


@runtime_checkable
class LoginMethodStore(Protocol):
    """Maintain viable login methods through guarded atomic operations."""

    async def register_login_method(self, account_id: str, method: LoginMethod, *, event: SecurityEvent) -> None:
        """Register one login method and its durable event."""
        ...  # pragma: no cover

    async def revoke_login_method(
        self, account_id: str, method_id: str, *, require_remaining: bool = True, event: SecurityEvent
    ) -> RevokeLoginMethodResult:
        """Revoke a method without removing the final viable method by default."""
        ...  # pragma: no cover


@runtime_checkable
class RegistrationStore(Protocol[UserT]):
    """Create an account and consume any invitation atomically."""

    async def register(  # noqa: PLR0913
        self,
        command: RegistrationCommand,
        password_hash: str,
        *,
        invitation_digest: bytes | None,
        verification: TokenIssue,
        notification: NotificationCommand,
        event: SecurityEvent,
    ) -> RegistrationResult[UserT]:
        """Commit registration, invitation, verification, notification, and event."""
        ...  # pragma: no cover


@runtime_checkable
class VerificationTokenStore(Protocol):
    """Issue and atomically consume account-verification tokens."""

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        """Commit a verification issue, notification, and durable event."""
        ...  # pragma: no cover

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: "datetime", event: SecurityEvent
    ) -> ConsumeResult:
        """Consume a verification token and verify its account atomically."""
        ...  # pragma: no cover


@runtime_checkable
class RecoveryTokenStore(Protocol):
    """Issue and atomically consume password-recovery tokens."""

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        """Commit a recovery issue, notification, and durable event."""
        ...  # pragma: no cover

    async def consume_and_reset(
        self, token_id: str, digest: bytes, new_password_hash: str, *, now: "datetime", event: SecurityEvent
    ) -> PasswordResetResult:
        """Consume a recovery token and reset password/epoch atomically."""
        ...  # pragma: no cover


@runtime_checkable
class SecurityEpochStore(Protocol):
    """Resolve the exact current account security epoch."""

    async def current_epoch(self, account_id: str) -> int | None:
        """Return the current epoch or ``None`` for an absent account."""
        ...  # pragma: no cover


@runtime_checkable
class LocalAccountCapabilities(
    AccountLookup[UserT],
    PasswordCredentialStore,
    LoginMethodStore,
    VerificationTokenStore,
    RecoveryTokenStore,
    SecurityEpochStore,
    Protocol[UserT],
):
    """Structural account capabilities required by every local-auth profile."""


@dataclass(frozen=True, slots=True)
class LocalAuthConfig(Generic[UserT]):
    """Explicit local-authentication transport and capability selection."""

    mode: LocalAuthMode
    accounts: LocalAccountCapabilities[UserT] = field(repr=False)
    registration: RegistrationPolicy
    route_prefix: str
    csrf: CSRFConfig | ExternalCSRF | None = field(default=None, repr=False)
    binding: SessionBindingConfig | None = field(default=None, repr=False)
    key_ring: LocalKeyRing | None = field(default=None, repr=False)
    token_audience: str | None = None

    def __post_init__(self) -> None:
        """Validate transport-specific values and structural capabilities."""
        if self.mode.__class__ is not LocalAuthMode:
            msg = "Local authentication mode must be a LocalAuthMode"
            raise ImproperlyConfiguredException(detail=msg)
        if self.registration.__class__ is not RegistrationPolicy:
            msg = "Local authentication registration must be a RegistrationPolicy"
            raise ImproperlyConfiguredException(detail=msg)
        if self.route_prefix.__class__ is not str:
            msg = "Local authentication route prefix must be an absolute non-root path"
            raise ImproperlyConfiguredException(detail=msg)
        route_prefix = self.route_prefix.rstrip("/")
        if (
            not route_prefix.startswith("/")
            or route_prefix == ""
            or "//" in route_prefix
            or any(value in route_prefix for value in ("\\", "{", "}", "?", "#"))
            or any(segment in {".", ".."} for segment in route_prefix.split("/"))
            or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in route_prefix)
        ):
            msg = "Local authentication route prefix must be an absolute non-root path"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "route_prefix", route_prefix)
        if self.mode in {LocalAuthMode.SESSION, LocalAuthMode.HYBRID} and (
            not isinstance(self.csrf, (CSRFConfig, ExternalCSRF)) or not isinstance(self.binding, SessionBindingConfig)
        ):
            msg = "Session local authentication requires explicit CSRF and binding configuration"
            raise ImproperlyConfiguredException(detail=msg)
        if self.mode in {LocalAuthMode.TOKENS, LocalAuthMode.HYBRID}:
            audience = self.token_audience.strip() if isinstance(self.token_audience, str) else ""
            if not isinstance(self.key_ring, LocalKeyRing) or not audience:
                msg = "Token local authentication requires an explicit key ring and audience"
                raise ImproperlyConfiguredException(detail=msg)
            object.__setattr__(self, "token_audience", audience)
        self._validate_capabilities()

    def _validate_capabilities(self) -> None:
        required: list[type[Any]] = [
            AccountLookup,
            PasswordCredentialStore,
            LoginMethodStore,
            VerificationTokenStore,
            RecoveryTokenStore,
            SecurityEpochStore,
        ]
        if self.registration.mode is not RegistrationMode.DISABLED:
            required.append(RegistrationStore)
        if self.mode in {LocalAuthMode.SESSION, LocalAuthMode.HYBRID}:
            required.append(SessionRegistry)
        if self.mode in {LocalAuthMode.TOKENS, LocalAuthMode.HYBRID}:
            required.append(RefreshTokenFamilyStore)
        missing = tuple(protocol.__name__ for protocol in required if not isinstance(self.accounts, protocol))
        if missing:
            msg = f"Local authentication account capabilities missing for {self.mode.value}: {', '.join(missing)}"
            raise ImproperlyConfiguredException(detail=msg)


_DISABLED_REGISTRATION = RegistrationPolicy.disabled()


class LocalAuth:
    """Construct explicit session, token, or hybrid local-auth profiles."""

    @classmethod
    def session(
        cls,
        *,
        accounts: LocalAccountCapabilities[UserT],
        csrf: CSRFConfig | ExternalCSRF,
        binding: SessionBindingConfig,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
    ) -> "LocalAuthConfig[UserT]":
        """Select native-session local authentication."""
        return LocalAuthConfig(
            mode=LocalAuthMode.SESSION,
            accounts=accounts,
            csrf=csrf,
            binding=binding,
            registration=registration,
            route_prefix=route_prefix,
        )

    @classmethod
    def tokens(
        cls,
        *,
        accounts: LocalAccountCapabilities[UserT],
        key_ring: LocalKeyRing,
        token_audience: str,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
    ) -> "LocalAuthConfig[UserT]":
        """Select bearer access/refresh-token local authentication."""
        return LocalAuthConfig(
            mode=LocalAuthMode.TOKENS,
            accounts=accounts,
            key_ring=key_ring,
            token_audience=token_audience,
            registration=registration,
            route_prefix=route_prefix,
        )

    @classmethod
    def hybrid(  # noqa: PLR0913
        cls,
        *,
        accounts: LocalAccountCapabilities[UserT],
        csrf: CSRFConfig | ExternalCSRF,
        binding: SessionBindingConfig,
        key_ring: LocalKeyRing,
        token_audience: str,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
    ) -> "LocalAuthConfig[UserT]":
        """Select distinct native-session and bearer-token local transports."""
        return LocalAuthConfig(
            mode=LocalAuthMode.HYBRID,
            accounts=accounts,
            csrf=csrf,
            binding=binding,
            key_ring=key_ring,
            token_audience=token_audience,
            registration=registration,
            route_prefix=route_prefix,
        )
