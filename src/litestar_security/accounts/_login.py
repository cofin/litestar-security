"""Password login and reauthentication services."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from logging import getLogger
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import aware_utc_time, new_event_id, utc_now
from litestar_security.accounts._operations import (
    LOGIN,
    OUTCOME_ATTEMPTED,
    OUTCOME_MALFORMED_HASH,
    OUTCOME_UPDATED,
    OUTCOME_VERIFIED,
    PASSWORD_REHASH,
    PASSWORD_VERIFY,
)
from litestar_security.accounts._passwords import PasswordHasher
from litestar_security.accounts._rate_limits import RateLimited, RateLimitGuard
from litestar_security.accounts._records import (
    LocalAccountRecord,
    NoOpSecurityEventSink,
    PasswordReauthenticationProof,
    PasswordVerificationStatus,
    SecurityEvent,
    SecurityEventSink,
    emit_security_event,
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
        """Return an account- and epoch-bound proof or one sanitized domain outcome.

        Args:
            account_id: The authenticated caller's account.
            password: The current password to re-verify.
            now: Override the clock, for tests and replayable proofs.

        Returns:
            Short-lived evidence bound to the account and its epoch,
            ``InvalidCredentials`` when the password is rejected, or
            ``VerificationUnavailable`` when a dependency failed.
        """
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
        if not state.active or not state.verified:
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
            event = self._event(account_id, occurred_at, operation=PASSWORD_REHASH, outcome=OUTCOME_UPDATED)
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
            event = self._event(account_id, occurred_at, operation=PASSWORD_VERIFY, outcome=OUTCOME_MALFORMED_HASH)
        except ValueError:
            _LOGGER.error("Security event could not be built for %s", PASSWORD_VERIFY)  # noqa: TRY400 - omit details
            return
        await emit_security_event(self.events, event)


@dataclass(frozen=True, slots=True)
class PasswordLoginService(Generic[UserT]):
    """Authenticate one normalized identifier with exactly one password-work class."""

    accounts: AccountLookup[UserT] = field(repr=False)
    hasher: PasswordHasher = field(repr=False)
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    rate_limits: RateLimitGuard | None = field(default=None, repr=False, compare=False)
    clock: "Callable[[], datetime]" = field(default=utc_now, repr=False, compare=False)
    events: SecurityEventSink = field(default_factory=NoOpSecurityEventSink, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=new_event_id, repr=False, compare=False)
    _reauthentication: PasswordReauthenticationService = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate the minimal lookup, password, limiting, and audit capabilities once."""
        accounts_value: object = object.__getattribute__(self, "accounts")
        hasher_value: object = object.__getattribute__(self, "hasher")
        normalizer_value: object = object.__getattribute__(self, "normalizer")
        rate_limits_value: object = object.__getattribute__(self, "rate_limits")
        events_value: object = object.__getattribute__(self, "events")
        if not isinstance(accounts_value, AccountLookup) or not isinstance(accounts_value, PasswordCredentialStore):
            msg = "Password login accounts must implement AccountLookup and PasswordCredentialStore"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(hasher_value, PasswordHasher):
            msg = "Password login hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(normalizer_value):
            msg = "Password login normalizer must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        if rate_limits_value is not None and rate_limits_value.__class__ is not RateLimitGuard:
            msg = "Password login rate limits must be a RateLimitGuard"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(events_value, SecurityEventSink):
            msg = "Password login events must implement SecurityEventSink"
            raise ImproperlyConfiguredException(detail=msg)
        clock_value: object = object.__getattribute__(self, "clock")
        event_ids_value: object = object.__getattribute__(self, "event_ids")
        if not callable(clock_value) or not callable(event_ids_value):
            msg = "Password login clock and event id factory must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(
            self,
            "_reauthentication",
            PasswordReauthenticationService(
                accounts=cast("PasswordCredentialStore", accounts_value),
                hasher=self.hasher,
                clock=self.clock,
                events=self.events,
                event_ids=self.event_ids,
            ),
        )

    async def authenticate(
        self, identifier: str, password: str, *, now: datetime | None = None, client_key: str | None = None
    ) -> LocalAccountRecord[UserT] | RateLimited | InvalidCredentials | VerificationUnavailable:
        """Return an active verified account after limiting, lookup, and constant password work.

        The limiter runs before the store lookup and before Argon2, so a denied
        attempt costs neither. An absent account still pays for a hash, so a
        missing account is not measurably faster to probe than a present one.

        Args:
            identifier: The submitted identifier, normalized before lookup.
            password: The submitted password.
            now: Override the clock, for tests and replayable authentication.
            client_key: The caller identity for the rate-limit client bucket.

        Returns:
            The authenticated account, ``RateLimited`` when the budget is spent,
            ``InvalidCredentials`` when the credentials are rejected, or
            ``VerificationUnavailable`` when a dependency failed. A rejected
            identifier and a rejected password are not distinguished.
        """
        normalized_identifier = ""
        lookup_unavailable = False
        try:
            normalized_identifier = self.normalizer(identifier)
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            lookup_unavailable = True
        limited = await self._check_rate_limit(client_key, normalized_identifier)
        if limited is not None:
            return limited
        account, lookup_unavailable = await self._find_account(normalized_identifier, unavailable=lookup_unavailable)
        if account is None:
            return await self._absent_account_outcome(password, unavailable=lookup_unavailable)
        password_result = await self._reauthentication.verify(account.account_id, password, now=now)
        if not isinstance(password_result, PasswordReauthenticationProof):
            if isinstance(password_result, InvalidCredentials):
                await self._emit_decision(account.account_id, OUTCOME_ATTEMPTED)
            return password_result
        if (
            not account.active
            or not account.verified
            or password_result.account_id != account.account_id
            or password_result.security_epoch != account.security_epoch
        ):
            await self._emit_decision(account.account_id, OUTCOME_ATTEMPTED)
            return InvalidCredentials()
        await self._emit_decision(account.account_id, OUTCOME_VERIFIED)
        return account

    async def _find_account(
        self, normalized_identifier: str, *, unavailable: bool
    ) -> "tuple[LocalAccountRecord[UserT] | None, bool]":
        if unavailable or not normalized_identifier:
            return None, unavailable
        try:
            return await self.accounts.find_for_login(normalized_identifier), False
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            return None, True

    async def _absent_account_outcome(
        self, password: str, *, unavailable: bool
    ) -> "InvalidCredentials | VerificationUnavailable":
        # Hash against nothing anyway: skipping the work here would make a missing
        # account measurably faster to probe than a present one.
        try:
            await self.hasher.verify(None, password)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if unavailable:
            return VerificationUnavailable()
        await self._emit_decision(None, OUTCOME_ATTEMPTED)
        return InvalidCredentials()

    async def _check_rate_limit(
        self, client_key: str | None, normalized_identifier: str
    ) -> "RateLimited | VerificationUnavailable | None":
        rate_limits = self.rate_limits
        if rate_limits is None:
            return None
        return await rate_limits.check(LOGIN, client_key=client_key, identifier=normalized_identifier or None)

    async def _emit_decision(self, account_id: str | None, outcome: str) -> None:
        try:
            event = SecurityEvent(
                event_id=self.event_ids(),
                occurred_at=aware_utc_time(self.clock()),
                operation=LOGIN,
                outcome=outcome,
                account_id=account_id,
                mechanism="password",
            )
        except Exception:  # noqa: BLE001 - a failed clock or id factory cannot change a settled decision
            _LOGGER.error("Security event could not be built for %s", LOGIN)  # noqa: TRY400 - omit untrusted details
            return
        await emit_security_event(self.events, event)
