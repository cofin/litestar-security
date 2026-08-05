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
    ConsumeOutcome,
    LocalAccountRecord,
    LoginMethod,
    PasswordChangeOutcome,
    PasswordCredentialState,
    PasswordResetOutcome,
    RegistrationMode,
    RegistrationOutcome,
    RevokeLoginMethodOutcome,
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
        """Disable self-service registration.

        Returns:
            A policy that generates no registration route.
        """
        return cls(mode=RegistrationMode.DISABLED)

    @classmethod
    def public(cls, *, require_verification: bool = True) -> "RegistrationPolicy":
        """Enable public self-service registration.

        Args:
            require_verification: Issue a verification token with the account and
                leave the account unverified until that token is consumed.

        Returns:
            A policy that generates an open registration route.
        """
        return cls(mode=RegistrationMode.PUBLIC, require_verification=require_verification)

    @classmethod
    def invite_only(cls, *, require_verification: bool = True) -> "RegistrationPolicy":
        """Require an atomic invitation consume during registration.

        Args:
            require_verification: Issue a verification token with the account and
                leave the account unverified until that token is consumed.

        Returns:
            A policy whose registration route additionally requires an invitation token.
        """
        return cls(mode=RegistrationMode.INVITE_ONLY, require_verification=require_verification)


@runtime_checkable
class AccountLookup(Protocol[UserT]):
    """Resolve the minimal application account projection."""

    async def find_for_login(self, normalized_identifier: str) -> "LocalAccountRecord[UserT] | None":
        """Find an account through an already-normalized identifier.

        The caller normalizes before calling, so match the stored value exactly
        rather than normalizing again.

        Args:
            normalized_identifier: The identifier as normalized by the configured normalizer.

        Returns:
            The account projection, or ``None`` when no account matches.
        """
        ...  # pragma: no cover

    async def get_by_id(self, account_id: str) -> "LocalAccountRecord[UserT] | None":
        """Resolve an account by its stable security identifier.

        Args:
            account_id: The stable account identifier carried on credentials.

        Returns:
            The account projection, or ``None`` when the account no longer exists.
        """
        ...  # pragma: no cover


@runtime_checkable
class PasswordCredentialStore(Protocol):
    """Store password credentials through atomic security operations."""

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        """Load one atomic password hash, account-state, and security-epoch snapshot.

        Read the hash, active/verified projection, and epoch in one operation.
        Values read separately can describe a state that never existed during
        a concurrent deactivation or verification-state change.

        Args:
            account_id: The account whose credential state to read.

        Returns:
            The paired hash, account-state projection, and epoch, or ``None``
            when the account has no password.
        """
        ...  # pragma: no cover

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, *, event: SecurityEvent
    ) -> bool:
        """Atomically replace a hash only when its expected value is current.

        The comparison is what makes concurrent changes safe, so it must happen
        inside the same operation as the write.

        Args:
            account_id: The account whose password to replace.
            expected_hash: The hash the caller read and expects to still be stored.
            password_hash: The replacement hash.
            event: The audit event to commit with the replacement. Rejecting it
                must fail the replacement.

        Returns:
            ``True`` when the stored hash matched and was replaced, ``False`` when
            it had already changed.
        """
        ...  # pragma: no cover

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeOutcome:
        """Atomically replace a password and increment the security epoch.

        Advancing the epoch is what invalidates credentials issued before the
        change, so it must commit with the new hash or not at all.

        Args:
            account_id: The account whose password to replace.
            password_hash: The replacement hash.
            expected_epoch: The epoch the caller read; a different stored epoch is a conflict.
            event: The audit event to commit with the replacement. Rejecting it
                must fail the replacement.

        Returns:
            The outcome, carrying the new epoch only when the replacement committed.
        """
        ...  # pragma: no cover


@runtime_checkable
class LoginMethodStore(Protocol):
    """Maintain viable login methods through guarded atomic operations."""

    async def register_login_method(self, account_id: str, method: LoginMethod, *, event: SecurityEvent) -> None:
        """Register one login method and its durable event.

        Args:
            account_id: The account gaining the method.
            method: The method to record.
            event: The audit event to commit with the registration. Rejecting it
                must fail the registration.
        """
        ...  # pragma: no cover

    async def revoke_login_method(
        self, account_id: str, method_id: str, *, require_remaining: bool = True, event: SecurityEvent
    ) -> RevokeLoginMethodOutcome:
        """Revoke a method without removing the final viable method by default.

        Args:
            account_id: The account owning the method.
            method_id: The method to revoke.
            require_remaining: Refuse the revocation when it would leave the
                account with no way to sign in.
            event: The audit event to commit with the revocation. Rejecting it
                must fail the revocation.

        Returns:
            The outcome, distinguishing an absent method from a refused final one.
        """
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
    ) -> RegistrationOutcome[UserT]:
        """Commit registration, invitation, verification, notification, and event.

        Every part commits together. Creating the account but failing to consume
        the invitation would let one invitation create unlimited accounts.

        Args:
            command: The normalized identifier and display name to register.
            password_hash: The encoded hash for the new account.
            invitation_digest: The digest of the presented invitation to consume,
                or ``None`` under a policy that requires no invitation.
            verification: The verification token and notification to store with the
                account, or ``None`` when the policy requires no verification.
            now: The commit timestamp.
            event: The audit event to commit with the registration. Rejecting it
                must fail the registration.

        Returns:
            The outcome, carrying the account projection only when it was created.
        """
        ...  # pragma: no cover


@runtime_checkable
class VerificationTokenStore(Protocol):
    """Issue and atomically consume account-verification tokens."""

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        """Commit a verification issue, notification, and durable event.

        Store the digest the issue carries, never the token itself: the token is
        the secret sent to the account holder.

        Args:
            issue: The token digest, account binding, and expiry to store.
            notification: The delivery the application should send.
            event: The audit event to commit with the issue. Rejecting it must
                fail the issue.
        """
        ...  # pragma: no cover

    async def issue_absent(self) -> None:
        """Perform one durable round trip that commits nothing.

        Called instead of :meth:`issue` when the identifier resolves to no
        eligible account. The durable step MUST cost the same whether or not the
        identifier resolves: an implementation that answers quickly for unknown
        accounts makes a present account measurably slower to probe, defeating
        the shared-response guarantee. Commit, notify, and mutate nothing.
        """
        ...  # pragma: no cover

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: "datetime", event: SecurityEvent
    ) -> ConsumeOutcome:
        """Consume a verification token and verify its account atomically.

        Marking the token used and marking the account verified must commit
        together, so one token can never verify twice.

        Args:
            token_id: The identifier carried by the presented token.
            digest: The digest to compare against the stored one.
            now: The timestamp to evaluate expiry against.
            event: The audit event to commit with the consumption. Rejecting it
                must fail the consumption.

        Returns:
            The outcome, carrying the account and its epoch only when consumed.
        """
        ...  # pragma: no cover


@runtime_checkable
class RecoveryTokenStore(Protocol):
    """Issue and atomically consume password-recovery tokens."""

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        """Commit a recovery issue, notification, and durable event.

        Store the digest the issue carries, never the token itself: the token is
        the secret sent to the account holder.

        Args:
            issue: The token digest, account binding, and expiry to store.
            notification: The delivery the application should send.
            event: The audit event to commit with the issue. Rejecting it must
                fail the issue.
        """
        ...  # pragma: no cover

    async def issue_absent(self) -> None:
        """Perform one durable round trip that commits nothing.

        Called instead of :meth:`issue` when the identifier resolves to no
        eligible account. The durable step MUST cost the same whether or not the
        identifier resolves: an implementation that answers quickly for unknown
        accounts makes a present account measurably slower to probe, defeating
        the shared-response guarantee. Commit, notify, and mutate nothing.
        """
        ...  # pragma: no cover

    async def consume_and_reset(
        self, token_id: str, digest: bytes, new_password_hash: str, *, now: "datetime", event: SecurityEvent
    ) -> PasswordResetOutcome:
        """Consume only at its issued epoch, then reset password and advance epoch atomically.

        The epoch check is what stops a stale recovery token from undoing a
        password change made after the token was issued.

        Args:
            token_id: The identifier carried by the presented token.
            digest: The digest to compare against the stored one.
            new_password_hash: The encoded replacement hash.
            now: The timestamp to evaluate expiry against.
            event: The audit event to commit with the reset. Rejecting it must
                fail the reset.

        Returns:
            The outcome, carrying the account and its new epoch only when reset.
        """
        ...  # pragma: no cover


@runtime_checkable
class SecurityEpochStore(Protocol):
    """Resolve the exact current account security epoch."""

    async def current_epoch(self, account_id: str) -> int | None:
        """Return the current epoch or ``None`` for an absent account.

        Read authoritative state rather than a cache: a stale epoch keeps
        revoked credentials working.

        Args:
            account_id: The account whose epoch to read.

        Returns:
            The current epoch, or ``None`` when the account does not exist.
        """
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
        """Return ``None`` only when the exact current epoch matches.

        Args:
            account_id: The account named by the presented credential.
            presented_epoch: The epoch the credential was issued at.

        Returns:
            ``None`` when the credential is still current, ``InvalidCredentials``
            when the epoch has moved on, and ``VerificationUnavailable`` when the
            store could not be read.
        """
        if not strict_text(account_id) or not valid_security_epoch(presented_epoch):
            return InvalidCredentials()
        try:
            current_epoch = await self.store.current_epoch(account_id)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if not valid_security_epoch(current_epoch) or current_epoch != presented_epoch:
            return InvalidCredentials()
        return None
