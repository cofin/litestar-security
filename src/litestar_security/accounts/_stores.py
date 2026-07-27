"""Persistence and capability protocols implemented by applications."""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, TypeVar, runtime_checkable

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import strict_text, valid_security_epoch
from litestar_security.accounts._purpose_tokens import (
    NotificationCommand,
    PurposeTokenDelivery,
    RegistrationCommand,
    TokenIssue,
)
from litestar_security.accounts._records import (
    ConsumeResult,
    LocalAccount,
    LoginMethod,
    PasswordChangeResult,
    PasswordCredentialState,
    PasswordResetResult,
    RegistrationMode,
    RegistrationResult,
    RevokeLoginMethodResult,
    SecurityEvent,
)
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable

if TYPE_CHECKING:
    from datetime import datetime

__all__ = (
    "AccountLookup",
    "LocalAccountCapabilities",
    "LoginMethodStore",
    "PasswordCredentialStore",
    "RecoveryTokenStore",
    "RegistrationPolicy",
    "RegistrationStore",
    "SecurityEpochStore",
    "SecurityEpochValidator",
    "VerificationTokenStore",
)

UserT = TypeVar("UserT")


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

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        """Load one atomic encoded-password and security-epoch snapshot."""
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

    async def register(  # noqa: PLR0913 - explicit configuration surface; every input is named
        self,
        command: RegistrationCommand,
        password_hash: str,
        *,
        invitation_digest: bytes | None,
        verification: PurposeTokenDelivery | None,
        now: "datetime",
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
        """Consume only at its issued epoch, then reset password and advance epoch atomically."""
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
        """Return ``None`` only when the exact current epoch matches."""
        if not strict_text(account_id) or not valid_security_epoch(presented_epoch):
            return InvalidCredentials()
        try:
            current_epoch = await self.store.current_epoch(account_id)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if not valid_security_epoch(current_epoch) or current_epoch != presented_epoch:
            return InvalidCredentials()
        return None
