"""Consolidated account storage contracts and capability protocols."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, TypeVar, runtime_checkable

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security._typing import import_optional_attribute
from litestar_security.accounts._internal import strict_text, valid_security_epoch
from litestar_security.accounts._rate_limits import RateLimiter
from litestar_security.accounts.models import (
    LocalAccountState,
    LoginMethod,
    PasswordChangeOutcome,
    PasswordCredentialState,
    PasswordResetOutcome,
    RegistrationMode,
    RegistrationOutcome,
    RevokeLoginMethodOutcome,
    SecurityEvent,
    VerificationOutcome,
)
from litestar_security.accounts.sessions import NativeSessionStore, SessionRegistry, UserAuthSessionResolver
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from litestar_security.accounts._passkeys import PasskeyStore, WebAuthnChallengeStore
    from litestar_security.accounts.mfa import MFALoginChallengeStore, MFAStore, SecretProtector, StepUpStore, TOTPStore
    from litestar_security.accounts.passwords import PasswordPolicy
    from litestar_security.accounts.tokens import (
        NotificationCommand,
        PurposeTokenDelivery,
        RefreshTokenFamilyStore,
        RegistrationCommand,
        TokenIssue,
    )

UserT = TypeVar("UserT")


@dataclass(frozen=True, slots=True)
class RegistrationPolicy:
    """Explicit self-service registration policy."""

    mode: RegistrationMode
    require_verification: bool = True
    password_policy: PasswordPolicy | None = None

    @classmethod
    def disabled(cls) -> RegistrationPolicy:
        """Disable self-service registration."""
        return cls(mode=RegistrationMode.DISABLED)

    @classmethod
    def public(
        cls, *, require_verification: bool = True, password_policy: PasswordPolicy | None = None
    ) -> RegistrationPolicy:
        """Enable public self-service registration."""
        return cls(
            mode=RegistrationMode.PUBLIC, require_verification=require_verification, password_policy=password_policy
        )

    @classmethod
    def invite_only(
        cls, *, require_verification: bool = True, password_policy: PasswordPolicy | None = None
    ) -> RegistrationPolicy:
        """Require an atomic invitation consume during registration."""
        return cls(
            mode=RegistrationMode.INVITE_ONLY,
            require_verification=require_verification,
            password_policy=password_policy,
        )


@runtime_checkable
class AccountLookup(Protocol[UserT]):
    """Resolve the minimal application account projection."""

    async def find_for_login(self, normalized_identifier: str) -> LocalAccountState[UserT] | None:
        """Find an account through an already-normalized identifier."""
        ...

    async def get_by_id(self, account_id: str) -> LocalAccountState[UserT] | None:
        """Resolve an account by its stable security identifier."""
        ...


@runtime_checkable
class PasswordCredentialStore(Protocol):
    """Store password credentials through atomic security operations."""

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        """Load one atomic password hash, account-state, and security-epoch snapshot."""
        ...

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, *, event: SecurityEvent
    ) -> bool:
        """Atomically replace a hash only when its expected value is current."""
        ...

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeOutcome:
        """Atomically replace a password and increment the security epoch."""
        ...


@runtime_checkable
class LoginMethodStore(Protocol):
    """Maintain viable login methods through guarded atomic operations."""

    async def list_methods(self, account_id: str) -> tuple[LoginMethod, ...]:
        """Return every login method currently viable for one account."""
        ...

    async def register_login_method(self, account_id: str, method: LoginMethod, *, event: SecurityEvent) -> None:
        """Register one login method and its durable event."""
        ...

    async def revoke_login_method(
        self, account_id: str, method_id: str, *, require_remaining: bool = True, event: SecurityEvent
    ) -> RevokeLoginMethodOutcome:
        """Revoke a method without removing the final viable method by default."""
        ...


@runtime_checkable
class RegistrationStore(Protocol[UserT]):
    """Create an account and consume any invitation atomically."""

    async def register(
        self,
        command: RegistrationCommand,
        password_hash: str,
        *,
        invitation_digest: bytes | None,
        verification: PurposeTokenDelivery | None,
        now: datetime,
        event: SecurityEvent,
    ) -> RegistrationOutcome[UserT]:
        """Commit registration, invitation, verification, notification, and event."""
        ...


@runtime_checkable
class VerificationTokenStore(Protocol):
    """Issue and atomically consume account-verification tokens."""

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        """Commit a verification issue, notification, and durable event."""
        ...

    async def issue_absent(self) -> None:
        """Perform one durable round trip that commits nothing."""
        ...

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: datetime, event: SecurityEvent
    ) -> VerificationOutcome:
        """Consume a verification token and verify its account atomically."""
        ...


@runtime_checkable
class RecoveryTokenStore(Protocol):
    """Issue and atomically consume password-recovery tokens."""

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        """Commit a recovery issue, notification, and durable event."""
        ...

    async def issue_absent(self) -> None:
        """Perform one durable round trip that commits nothing."""
        ...

    async def consume_and_reset(
        self, token_id: str, digest: bytes, new_password_hash: str, *, now: datetime, event: SecurityEvent
    ) -> PasswordResetOutcome:
        """Consume only at its issued epoch, then reset password and advance epoch atomically."""
        ...


@runtime_checkable
class SecurityEpochStore(Protocol):
    """Resolve the exact current account security epoch."""

    async def current_epoch(self, account_id: str) -> int | None:
        """Return the current epoch or None for an absent account."""
        ...


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
class SecurityEpochValidator:
    """Validate one presented epoch against authoritative application state."""

    store: SecurityEpochStore = field(repr=False)

    def __post_init__(self) -> None:
        """Require the exact epoch lookup capability."""
        if not isinstance(object.__getattribute__(self, "store"), SecurityEpochStore):
            msg = "Security epoch validator store must implement SecurityEpochStore"
            raise ImproperlyConfiguredException(detail=msg)

    async def validate(
        self, account_id: str, presented_epoch: int
    ) -> InvalidCredentials | VerificationUnavailable | None:
        """Return None only when the exact current epoch matches."""
        if not strict_text(account_id) or not valid_security_epoch(presented_epoch):
            return InvalidCredentials()
        try:
            current_epoch = await self.store.current_epoch(account_id)
        except Exception:
            return VerificationUnavailable()
        if not valid_security_epoch(current_epoch) or current_epoch != presented_epoch:
            return InvalidCredentials()
        return None


SessionStore = NativeSessionStore
RateLimiterStore = RateLimiter

__all__ = (
    "AccountLookup",
    "LocalAccountCapabilities",
    "LoginMethodStore",
    "MFALoginChallengeStore",
    "MFAStore",
    "NativeSessionStore",
    "PasskeyStore",
    "PasswordCredentialStore",
    "RateLimiter",
    "RateLimiterStore",
    "RecoveryTokenStore",
    "RefreshTokenFamilyStore",
    "RegistrationPolicy",
    "RegistrationStore",
    "SecretProtector",
    "SecurityEpochStore",
    "SecurityEpochValidator",
    "SessionRegistry",
    "SessionStore",
    "StepUpStore",
    "TOTPStore",
    "UserAuthSessionResolver",
    "VerificationTokenStore",
    "WebAuthnChallengeStore",
)

_OPTIONAL_PROTOCOLS: Mapping[str, tuple[str, str, frozenset[str]]] = {
    "TOTPStore": ("litestar_security.accounts.mfa", "mfa", frozenset({"pyotp"})),
    "MFAStore": ("litestar_security.accounts.mfa", "mfa", frozenset({"pyotp"})),
    "StepUpStore": ("litestar_security.accounts.mfa", "mfa", frozenset({"pyotp"})),
    "SecretProtector": ("litestar_security.accounts.mfa", "mfa", frozenset({"pyotp"})),
    "MFALoginChallengeStore": ("litestar_security.accounts.mfa", "mfa", frozenset({"pyotp"})),
    "PasskeyStore": ("litestar_security.accounts._passkeys", "passkeys", frozenset({"webauthn"})),
    "WebAuthnChallengeStore": ("litestar_security.accounts._passkeys", "passkeys", frozenset({"webauthn"})),
}


def __getattr__(name: str) -> object:
    """Resolve optional storage protocols only when feature dependencies are available."""
    if name == "RefreshTokenFamilyStore":
        from litestar_security.accounts.tokens import RefreshTokenFamilyStore

        return RefreshTokenFamilyStore

    target = _OPTIONAL_PROTOCOLS.get(name)
    if target is not None:
        module_name, extras, dependencies = target
        return import_optional_attribute(module_name, name, extras=extras, dependencies=dependencies)
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
