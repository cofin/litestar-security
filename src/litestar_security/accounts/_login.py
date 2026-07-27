"""Password login and reauthentication services."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from logging import getLogger
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import aware_utc_time, new_event_id, utc_now
from litestar_security.accounts._passwords import PasswordHasher
from litestar_security.accounts._records import (
    LocalAccount,
    NoOpSecurityEventSink,
    PasswordReauthenticationProof,
    PasswordVerificationStatus,
    SecurityEvent,
    SecurityEventSink,
    normalize_identifier,
)
from litestar_security.accounts._stores import AccountLookup, PasswordCredentialStore
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable

if TYPE_CHECKING:
    from collections.abc import Callable


__all__ = ("PasswordLoginService", "PasswordReauthenticationService")

UserT = TypeVar("UserT")
_DEFAULT_REAUTHENTICATION_TTL = timedelta(minutes=5)
_LOGGER = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PasswordReauthenticationService:
    """Verify a current password and emit short-lived password evidence."""

    accounts: PasswordCredentialStore = field(repr=False)
    hasher: PasswordHasher = field(repr=False)
    evidence_ttl: timedelta = _DEFAULT_REAUTHENTICATION_TTL
    clock: "Callable[[], datetime]" = field(default=utc_now, repr=False, compare=False)
    events: SecurityEventSink = field(default_factory=NoOpSecurityEventSink, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate structural ports and the bounded evidence lifetime."""
        accounts_value: object = object.__getattribute__(self, "accounts")
        hasher_value: object = object.__getattribute__(self, "hasher")
        evidence_ttl_value: object = object.__getattribute__(self, "evidence_ttl")
        clock_value: object = object.__getattribute__(self, "clock")
        events_value: object = object.__getattribute__(self, "events")
        event_ids_value: object = object.__getattribute__(self, "event_ids")
        if not isinstance(accounts_value, PasswordCredentialStore):
            msg = "Password reauthentication accounts must implement PasswordCredentialStore"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(hasher_value, PasswordHasher):
            msg = "Password reauthentication hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if (
            not isinstance(evidence_ttl_value, timedelta)
            or evidence_ttl_value <= timedelta(0)
            or evidence_ttl_value > _DEFAULT_REAUTHENTICATION_TTL
        ):
            msg = "Password reauthentication evidence lifetime must be positive and at most five minutes"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(clock_value):
            msg = "Password reauthentication clock must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(events_value, SecurityEventSink):
            msg = "Password reauthentication events must implement SecurityEventSink"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(event_ids_value):
            msg = "Password reauthentication event id factory must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    async def verify(  # noqa: PLR0911 - preserve explicit sanitized outcomes at each security boundary
        self, account_id: str, password: str, *, now: datetime | None = None
    ) -> PasswordReauthenticationProof | InvalidCredentials | VerificationUnavailable:
        """Return an account- and epoch-bound proof or one sanitized domain outcome."""
        account_value: object = account_id
        if account_value.__class__ is not str or not (normalized_account_id := account_id.strip()):
            return InvalidCredentials()
        try:
            authenticated_at = aware_utc_time(self.clock() if now is None else now)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        read_unavailable = False
        try:
            state = await self.accounts.get_password_state(normalized_account_id)
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            state = None
            read_unavailable = True
        encoded_hash = state.password_hash if state is not None else None
        try:
            result = await self.hasher.verify(encoded_hash, password)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if read_unavailable:
            return VerificationUnavailable()
        if not result.verified or encoded_hash is None or state is None:
            if result.status is PasswordVerificationStatus.MALFORMED:
                await self._emit_malformed(normalized_account_id, authenticated_at)
            return InvalidCredentials()
        if result.replacement_hash is not None and not await self._rehash(
            normalized_account_id, encoded_hash, result.replacement_hash, authenticated_at
        ):
            return VerificationUnavailable()
        return PasswordReauthenticationProof(
            account_id=normalized_account_id,
            security_epoch=state.security_epoch,
            authenticated_at=authenticated_at,
            expires_at=authenticated_at + self.evidence_ttl,
        )

    async def _rehash(self, account_id: str, expected_hash: str, replacement_hash: str, occurred_at: datetime) -> bool:
        try:
            event = self._event(account_id, occurred_at, operation="local.password.rehash", outcome="updated")
            replaced: object = await self.accounts.compare_and_replace_password(
                account_id, expected_hash, replacement_hash, event=event
            )
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            return False
        return replaced is True

    def _event(self, account_id: str, occurred_at: datetime, *, operation: str, outcome: str) -> SecurityEvent:
        event_id = self.event_ids().strip()
        if not event_id:
            raise ValueError
        return SecurityEvent(
            event_id=event_id,
            occurred_at=occurred_at,
            operation=operation,
            outcome=outcome,
            account_id=account_id,
            mechanism="password",
        )

    async def _emit_malformed(self, account_id: str, occurred_at: datetime) -> None:
        try:
            await self.events.emit(
                self._event(account_id, occurred_at, operation="local.password.verify", outcome="malformed_hash")
            )
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            _LOGGER.error("Security event sink failed")  # noqa: TRY400 - omit untrusted exception details


@dataclass(frozen=True, slots=True)
class PasswordLoginService(Generic[UserT]):
    """Authenticate one normalized identifier with exactly one password-work class."""

    accounts: AccountLookup[UserT] = field(repr=False)
    hasher: PasswordHasher = field(repr=False)
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    _reauthentication: PasswordReauthenticationService = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate the minimal lookup and password capabilities once."""
        accounts_value: object = object.__getattribute__(self, "accounts")
        hasher_value: object = object.__getattribute__(self, "hasher")
        normalizer_value: object = object.__getattribute__(self, "normalizer")
        if not isinstance(accounts_value, AccountLookup) or not isinstance(accounts_value, PasswordCredentialStore):
            msg = "Password login accounts must implement AccountLookup and PasswordCredentialStore"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(hasher_value, PasswordHasher):
            msg = "Password login hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(normalizer_value):
            msg = "Password login normalizer must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(
            self,
            "_reauthentication",
            PasswordReauthenticationService(
                accounts=cast("PasswordCredentialStore", accounts_value), hasher=self.hasher
            ),
        )

    async def authenticate(
        self, identifier: str, password: str, *, now: datetime | None = None
    ) -> LocalAccount[UserT] | InvalidCredentials | VerificationUnavailable:
        """Return an active verified account after lookup and constant password work."""
        account: LocalAccount[UserT] | None = None
        lookup_unavailable = False
        try:
            normalized_identifier = self.normalizer(identifier)
            if normalized_identifier:
                account = await self.accounts.find_for_login(normalized_identifier)
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            lookup_unavailable = True
        if account is None:
            try:
                await self.hasher.verify(None, password)
            except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
                return VerificationUnavailable()
            return VerificationUnavailable() if lookup_unavailable else InvalidCredentials()
        password_result = await self._reauthentication.verify(account.account_id, password, now=now)
        if not isinstance(password_result, PasswordReauthenticationProof):
            return password_result
        if (
            not account.active
            or not account.verified
            or password_result.account_id != account.account_id
            or password_result.security_epoch != account.security_epoch
        ):
            return InvalidCredentials()
        return account
