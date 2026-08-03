"""Password change, recovery, and epoch-invalidation services."""

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from hmac import compare_digest
from logging import getLogger
from typing import TYPE_CHECKING, Generic, TypeVar

from anyio import CancelScope
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import (
    aware_utc_time,
    new_event_id,
    strict_text,
    utc_now,
    valid_security_epoch,
)
from litestar_security.accounts._operations import (
    OUTCOME_CHANGED,
    OUTCOME_ISSUED,
    OUTCOME_REBOUND,
    OUTCOME_RESET,
    OUTCOME_REVOKED,
    PASSWORD_CHANGE,
    PASSWORD_FORCE_RESET,
    PASSWORD_REFRESH_REVOKE,
    PASSWORD_RESET,
    PASSWORD_SESSION_REBIND,
    PASSWORD_SESSION_REVOKE_OTHERS,
    RECOVERY,
    RECOVERY_CONSUME,
    RECOVERY_ISSUE,
    SESSION_REVOKE_ALL_SUFFIX,
)
from litestar_security.accounts._passwords import PasswordHasher, PasswordPolicy, PasswordPolicyResult
from litestar_security.accounts._purpose_tokens import PurposeTokenCodec, approved_return_url
from litestar_security.accounts._rate_limits import RateLimited, RateLimitGuard, validate_rate_limits
from litestar_security.accounts._records import (
    InvalidLifecycleRequest,
    LifecycleAccepted,
    PasswordChangeResult,
    PasswordChangeStatus,
    PasswordReauthenticationProof,
    PasswordResetResult,
    PasswordResetStatus,
    TokenPurpose,
    lifecycle_event,
    normalize_identifier,
)
from litestar_security.accounts._refresh import RefreshTokenFamilyStore
from litestar_security.accounts._sessions import CreateSessionCommand, SessionRegistry
from litestar_security.accounts._stores import AccountLookup, PasswordCredentialStore, RecoveryTokenStore
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable

if TYPE_CHECKING:
    from collections.abc import Callable


__all__ = ("PasswordChangeService", "RecoveryTokenService")


UserT = TypeVar("UserT")


_DEFAULT_REAUTHENTICATION_TTL = timedelta(minutes=5)


_DEFAULT_TOKEN_ATTEMPTS = 5


_MAXIMUM_TOKEN_ATTEMPTS = 100


_MAXIMUM_SECURITY_EPOCH = 9_223_372_036_854_775_807


_RECOVERY_TOKEN_LIFETIME = timedelta(minutes=30)


_LOGGER = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PasswordChangeService:
    """Apply authenticated or administrative password changes and epoch invalidation."""

    accounts: PasswordCredentialStore = field(repr=False)
    hasher: PasswordHasher = field(repr=False)
    password_policy: PasswordPolicy = field(default_factory=PasswordPolicy, repr=False)
    sessions: SessionRegistry | None = field(default=None, repr=False)
    refresh_tokens: RefreshTokenFamilyStore | None = field(default=None, repr=False)
    evidence_ttl: timedelta = _DEFAULT_REAUTHENTICATION_TTL
    clock: "Callable[[], datetime]" = field(default=utc_now, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate atomic mutation, hashing, and optional transport cleanup ports."""
        if not isinstance(object.__getattribute__(self, "accounts"), PasswordCredentialStore):
            msg = "Password change accounts must implement PasswordCredentialStore"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(object.__getattribute__(self, "hasher"), PasswordHasher):
            msg = "Password change hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if object.__getattribute__(self, "password_policy").__class__ is not PasswordPolicy:
            msg = "Password change policy must be PasswordPolicy"
            raise ImproperlyConfiguredException(detail=msg)
        if self.sessions is not None and not isinstance(object.__getattribute__(self, "sessions"), SessionRegistry):
            msg = "Password change sessions must implement SessionRegistry"
            raise ImproperlyConfiguredException(detail=msg)
        if self.refresh_tokens is not None and not isinstance(
            object.__getattribute__(self, "refresh_tokens"), RefreshTokenFamilyStore
        ):
            msg = "Password change refresh tokens must implement RefreshTokenFamilyStore"
            raise ImproperlyConfiguredException(detail=msg)
        if (
            self.evidence_ttl.__class__ is not timedelta
            or self.evidence_ttl <= timedelta(0)
            or self.evidence_ttl > _DEFAULT_REAUTHENTICATION_TTL
            or not callable(self.clock)
            or not callable(self.event_ids)
        ):
            msg = "Password change evidence lifetime and hooks must be valid"
            raise ImproperlyConfiguredException(detail=msg)

    async def change(  # noqa: PLR0913 - explicit configuration surface; every input is named
        self,
        account_id: str,
        password: str,
        *,
        proof: PasswordReauthenticationProof,
        normalized_identifier: str | None = None,
        current_session_id: str | None = None,
        replacement_session: CreateSessionCommand | None = None,
        compromise: bool = False,
        now: datetime | None = None,
    ) -> (
        PasswordChangeResult
        | PasswordPolicyResult
        | InvalidCredentials
        | InvalidLifecycleRequest
        | VerificationUnavailable
    ):
        """Change a password after recent proof and preserve only an explicitly rebound session.

        Args:
            account_id: The account whose password to replace.
            password: The replacement password, checked against policy first.
            proof: Recent password evidence, bound to the account and its epoch.
            normalized_identifier: The identifier, rejected as a password.
            current_session_id: The caller's session, kept when a replacement is supplied.
            replacement_session: The prepared rebind, so the caller keeps a usable session.
            compromise: Revoke the caller's own session with the others instead of rebinding.
            now: Override the clock, for tests and replayable changes.

        Returns:
            The change outcome, a policy violation, or a sanitized failure. A
            successful change advances the security epoch, which invalidates every
            credential issued before it.
        """
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
        except (AttributeError, TypeError, ValueError):
            return InvalidLifecycleRequest()
        if not self._recent_password_proof(account_id, proof, occurred_at):
            return InvalidCredentials()
        return await self._replace(
            account_id,
            password,
            expected_epoch=proof.security_epoch,
            normalized_identifier=normalized_identifier,
            current_session_id=current_session_id,
            replacement_session=replacement_session,
            compromise=compromise,
            occurred_at=occurred_at,
            operation=PASSWORD_CHANGE,
        )

    async def force_reset(
        self,
        account_id: str,
        password: str,
        *,
        expected_epoch: int,
        normalized_identifier: str | None = None,
        now: datetime | None = None,
    ) -> PasswordChangeResult | PasswordPolicyResult | InvalidLifecycleRequest | VerificationUnavailable:
        """Perform an application-authorized reset without registering an admin route.

        No generated route reaches this. The library ships no administrative
        endpoint, so an application that needs one authorizes it itself and calls
        this directly.

        Args:
            account_id: The account whose password to replace.
            password: The replacement password, checked against policy first.
            expected_epoch: The epoch the caller read; a different stored epoch is a conflict.
            normalized_identifier: The identifier, rejected as a password.
            now: Override the clock, for tests and replayable resets.

        Returns:
            The change outcome, a policy violation, or a sanitized failure.
        """
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
        except (AttributeError, TypeError, ValueError):
            return InvalidLifecycleRequest()
        return await self._replace(
            account_id,
            password,
            expected_epoch=expected_epoch,
            normalized_identifier=normalized_identifier,
            current_session_id=None,
            replacement_session=None,
            compromise=True,
            occurred_at=occurred_at,
            operation=PASSWORD_FORCE_RESET,
        )

    async def _replace(  # noqa: PLR0911, PLR0913 - preserve explicit sanitized outcomes at each security boundary
        self,
        account_id: str,
        password: str,
        *,
        expected_epoch: int,
        normalized_identifier: str | None,
        current_session_id: str | None,
        replacement_session: CreateSessionCommand | None,
        compromise: bool,
        occurred_at: datetime,
        operation: str,
    ) -> PasswordChangeResult | PasswordPolicyResult | InvalidLifecycleRequest | VerificationUnavailable:
        if (
            not strict_text(account_id)
            or not valid_security_epoch(expected_epoch)
            or not self._valid_rebind(
                account_id,
                occurred_at,
                current_session_id=current_session_id,
                replacement_session=replacement_session,
                compromise=compromise,
            )
        ):
            return InvalidLifecycleRequest()
        if expected_epoch == _MAXIMUM_SECURITY_EPOCH:
            return PasswordChangeResult(PasswordChangeStatus.EPOCH_EXHAUSTED)
        try:
            policy_result = self.password_policy.check(password, normalized_identifier=normalized_identifier)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if not policy_result.accepted:
            return policy_result
        try:
            password_hash = await self.hasher.hash(password)
            result = await self.accounts.replace_password_and_bump_epoch(
                account_id,
                password_hash,
                expected_epoch=expected_epoch,
                event=lifecycle_event(
                    self.event_ids, occurred_at, operation=operation, outcome=OUTCOME_CHANGED, account_id=account_id
                ),
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if result.status is not PasswordChangeStatus.CHANGED:
            return result
        new_epoch = result.security_epoch
        if new_epoch is None or new_epoch != expected_epoch + 1:
            return VerificationUnavailable()
        with CancelScope(shield=True):
            await self._cleanup_after_change(
                account_id,
                new_epoch,
                occurred_at,
                current_session_id=current_session_id,
                replacement_session=replacement_session,
                compromise=compromise,
            )
        return result

    def _valid_rebind(
        self,
        account_id: str,
        occurred_at: datetime,
        *,
        current_session_id: str | None,
        replacement_session: CreateSessionCommand | None,
        compromise: bool,
    ) -> bool:
        if compromise and (current_session_id is not None or replacement_session is not None):
            return False
        if (current_session_id is None) != (replacement_session is None):
            return False
        if current_session_id is None:
            return True
        if self.sessions is None or not strict_text(current_session_id) or replacement_session is None:
            return False
        try:
            expires_at = aware_utc_time(replacement_session.expires_at)
        except (AttributeError, ValueError):
            return False
        return (
            replacement_session.__class__ is CreateSessionCommand
            and replacement_session.account_id == account_id
            and strict_text(replacement_session.session_id)
            and replacement_session.session_id != current_session_id
            and expires_at > occurred_at
        )

    def _recent_password_proof(self, account_id: str, proof: object, occurred_at: datetime) -> bool:
        if (
            not isinstance(proof, PasswordReauthenticationProof)
            or proof.__class__ is not PasswordReauthenticationProof
            or not strict_text(account_id)
        ):
            return False
        return (
            compare_digest(proof.account_id.encode("utf-8"), account_id.encode("utf-8"))
            and proof.authenticated_at <= occurred_at
            and occurred_at - proof.authenticated_at <= self.evidence_ttl
            and occurred_at <= proof.expires_at
        )

    async def _cleanup_after_change(  # noqa: PLR0913 - explicit configuration surface; every input is named
        self,
        account_id: str,
        security_epoch: int,
        occurred_at: datetime,
        *,
        current_session_id: str | None,
        replacement_session: CreateSessionCommand | None,
        compromise: bool,
    ) -> None:
        if self.refresh_tokens is not None:
            try:
                await self.refresh_tokens.revoke_for_account(
                    account_id,
                    event=lifecycle_event(
                        self.event_ids,
                        occurred_at,
                        operation=PASSWORD_REFRESH_REVOKE,
                        outcome=OUTCOME_REVOKED,
                        account_id=account_id,
                    ),
                )
            except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
                _LOGGER.error("Password refresh cleanup failed")  # noqa: TRY400 - omit untrusted exception details
        if self.sessions is None:
            return
        if compromise or current_session_id is None or replacement_session is None:
            await _revoke_all_sessions(self.sessions, account_id, occurred_at, self.event_ids)
            return
        try:
            await self.sessions.revoke_other_sessions(
                account_id,
                current_session_id,
                event=lifecycle_event(
                    self.event_ids,
                    occurred_at,
                    operation=PASSWORD_SESSION_REVOKE_OTHERS,
                    outcome=OUTCOME_REVOKED,
                    account_id=account_id,
                ),
            )
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            _LOGGER.error("Password session cleanup failed")  # noqa: TRY400 - omit untrusted exception details
        try:
            await self.sessions.rebind(
                current_session_id,
                replace(replacement_session, account_id=account_id, security_epoch=security_epoch),
                event=lifecycle_event(
                    self.event_ids,
                    occurred_at,
                    operation=PASSWORD_SESSION_REBIND,
                    outcome=OUTCOME_REBOUND,
                    account_id=account_id,
                ),
            )
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            _LOGGER.error("Password session rebind failed")  # noqa: TRY400 - omit untrusted exception details


@dataclass(frozen=True, slots=True)
class RecoveryTokenService(Generic[UserT]):
    """Issue enumeration-resistant password-recovery notification commands."""

    accounts: AccountLookup[UserT] = field(repr=False)
    store: RecoveryTokenStore = field(repr=False)
    tokens: PurposeTokenCodec = field(repr=False)
    hasher: PasswordHasher = field(repr=False)
    password_policy: PasswordPolicy = field(default_factory=PasswordPolicy, repr=False)
    sessions: SessionRegistry | None = field(default=None, repr=False)
    refresh_tokens: RefreshTokenFamilyStore | None = field(default=None, repr=False)
    lifetime: timedelta = _RECOVERY_TOKEN_LIFETIME
    maximum_attempts: int = _DEFAULT_TOKEN_ATTEMPTS
    return_url: str | None = None
    clock: "Callable[[], datetime]" = field(default=utc_now, repr=False, compare=False)
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=new_event_id, repr=False, compare=False)
    rate_limits: RateLimitGuard | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate lookup, atomic recovery store, and deterministic hooks."""
        validate_rate_limits(self.rate_limits, name="Recovery token service")
        if not isinstance(object.__getattribute__(self, "accounts"), AccountLookup):
            msg = "Recovery token accounts must implement AccountLookup"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(object.__getattribute__(self, "store"), RecoveryTokenStore):
            msg = "Recovery token store must implement RecoveryTokenStore"
            raise ImproperlyConfiguredException(detail=msg)
        if object.__getattribute__(self, "tokens").__class__ is not PurposeTokenCodec:
            msg = "Recovery token codec must be PurposeTokenCodec"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(object.__getattribute__(self, "hasher"), PasswordHasher):
            msg = "Recovery token hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if object.__getattribute__(self, "password_policy").__class__ is not PasswordPolicy:
            msg = "Recovery token password policy must be PasswordPolicy"
            raise ImproperlyConfiguredException(detail=msg)
        if self.sessions is not None and not isinstance(object.__getattribute__(self, "sessions"), SessionRegistry):
            msg = "Recovery token sessions must implement SessionRegistry"
            raise ImproperlyConfiguredException(detail=msg)
        if self.refresh_tokens is not None and not isinstance(
            object.__getattribute__(self, "refresh_tokens"), RefreshTokenFamilyStore
        ):
            msg = "Recovery token refresh tokens must implement RefreshTokenFamilyStore"
            raise ImproperlyConfiguredException(detail=msg)
        validate_lifecycle_configuration(
            lifetime=self.lifetime,
            attempts=self.maximum_attempts,
            return_url=self.return_url,
            clock=self.clock,
            normalizer=self.normalizer,
            event_ids=self.event_ids,
            name="Recovery token service",
        )

    async def request(
        self, identifier: str, *, now: datetime | None = None, client_key: str | None = None
    ) -> LifecycleAccepted | RateLimited | VerificationUnavailable:
        """Always return the shared response after one token-HMAC work class.

        Denial is safe to report here even though every other outcome is
        deliberately identical: the budget is consumed for unknown identifiers
        too, so being limited reveals nothing about whether an account exists.

        Every request pays one durable store round trip: an eligible account
        commits through :meth:`RecoveryTokenStore.issue`, any other identifier
        probes through :meth:`RecoveryTokenStore.issue_absent`, so a present
        account is not measurably slower to probe than an absent one.

        Args:
            identifier: The submitted identifier.
            now: Override the clock, for tests and replayable requests.
            client_key: The caller identity for the rate-limit bucket.

        Returns:
            The same acceptance for every identifier, ``RateLimited`` when the
            budget is spent, or ``VerificationUnavailable`` when a dependency failed.
        """
        limited = await self._check_request_rate_limit(identifier, client_key)
        if limited is not None:
            return limited
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            normalized_identifier = self.normalizer(identifier)
            issued = self.tokens.issue(
                TokenPurpose.RECOVERY,
                now=occurred_at,
                lifetime=self.lifetime,
                template="local.recovery",
                destination=normalized_identifier,
                return_url=self.return_url,
                maximum_attempts=self.maximum_attempts,
            )
            account = await self.accounts.find_for_login(normalized_identifier) if normalized_identifier else None
            if account is not None and account.active:
                issue, notification = issued.bind(account.account_id, security_epoch=account.security_epoch)
                await self.store.issue(
                    issue,
                    notification,
                    event=lifecycle_event(
                        self.event_ids,
                        occurred_at,
                        operation=RECOVERY_ISSUE,
                        outcome=OUTCOME_ISSUED,
                        account_id=account.account_id,
                    ),
                )
            else:
                await self.store.issue_absent()
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            _LOGGER.error("Recovery token request failed")  # noqa: TRY400 - omit untrusted exception details
        return LifecycleAccepted()

    async def reset(
        self, token: object, password: str, *, now: datetime | None = None, client_key: str | None = None
    ) -> PasswordResetResult | PasswordPolicyResult | RateLimited | VerificationUnavailable:
        """Apply policy and delegate token consumption and password replacement atomically.

        Only the client bucket applies: the presented value is a recovery token,
        and digesting it into a bucket key would let a limiter backend become a
        record of which tokens were attempted.

        Args:
            token: The presented recovery token.
            password: The replacement password, checked against policy first.
            now: Override the clock, for tests and replayable resets.
            client_key: The caller identity for the rate-limit bucket.

        Returns:
            The reset outcome, a policy violation, ``RateLimited`` when the budget
            is spent, or ``VerificationUnavailable`` when a dependency failed. An
            expired, used, and unknown token are not distinguished.
        """
        limited = await self._check_reset_rate_limit(client_key)
        if limited is not None:
            return limited
        proof = self.tokens.proof(token, expected_purpose=TokenPurpose.RECOVERY)
        if proof is None:
            return PasswordResetResult(PasswordResetStatus.INVALID)
        try:
            policy_result = self.password_policy.check(password)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if not policy_result.accepted:
            return policy_result
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            password_hash = await self.hasher.hash(password)
            result = await self.store.consume_and_reset(
                proof.token_id,
                proof.digest,
                password_hash,
                now=occurred_at,
                event=lifecycle_event(self.event_ids, occurred_at, operation=RECOVERY_CONSUME, outcome=OUTCOME_RESET),
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if result.status is PasswordResetStatus.RESET and result.account_id is not None:
            with CancelScope(shield=True):
                await _revoke_all_credentials(
                    account_id=result.account_id,
                    sessions=self.sessions,
                    refresh_tokens=self.refresh_tokens,
                    occurred_at=occurred_at,
                    event_ids=self.event_ids,
                    operation=RECOVERY,
                )
        return result

    async def _check_request_rate_limit(
        self, identifier: str, client_key: str | None
    ) -> "RateLimited | VerificationUnavailable | None":
        rate_limits = self.rate_limits
        if rate_limits is None:
            return None
        try:
            normalized_identifier = self.normalizer(identifier) or None
        except Exception:  # noqa: BLE001 - a failed normalizer still consumes the client budget
            normalized_identifier = None
        return await rate_limits.check(RECOVERY, client_key=client_key, identifier=normalized_identifier)

    async def _check_reset_rate_limit(self, client_key: str | None) -> "RateLimited | VerificationUnavailable | None":
        rate_limits = self.rate_limits
        if rate_limits is None:
            return None
        return await rate_limits.check(PASSWORD_RESET, client_key=client_key)


def validate_lifecycle_configuration(  # noqa: PLR0913 - explicit configuration surface; every input is named
    *,
    lifetime: timedelta,
    attempts: int,
    return_url: str | None,
    clock: object,
    normalizer: object,
    event_ids: object,
    name: str,
) -> None:
    if lifetime.__class__ is not timedelta or lifetime <= timedelta(0):
        msg = f"{name} lifetime must be positive"
        raise ImproperlyConfiguredException(detail=msg)
    if attempts.__class__ is not int or not 1 <= attempts <= _MAXIMUM_TOKEN_ATTEMPTS:
        msg = f"{name} attempts must be a positive bounded integer"
        raise ImproperlyConfiguredException(detail=msg)
    if return_url is not None and not approved_return_url(return_url):
        msg = f"{name} return URL must be an approved absolute HTTP(S) URL"
        raise ImproperlyConfiguredException(detail=msg)
    if not callable(clock) or not callable(normalizer) or not callable(event_ids):
        msg = f"{name} hooks must be callable"
        raise ImproperlyConfiguredException(detail=msg)


async def _revoke_all_sessions(
    sessions: SessionRegistry,
    account_id: str,
    occurred_at: datetime,
    event_ids: "Callable[[], str]",
    *,
    operation: str = "local.password.session_revoke_all",
) -> None:
    try:
        await sessions.revoke_sessions_for_account(
            account_id,
            event=lifecycle_event(
                event_ids, occurred_at, operation=operation, outcome=OUTCOME_REVOKED, account_id=account_id
            ),
        )
    except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
        _LOGGER.error("Password session cleanup failed")  # noqa: TRY400 - omit untrusted exception details


async def _revoke_all_credentials(  # noqa: PLR0913 - explicit configuration surface; every input is named
    *,
    account_id: str,
    sessions: SessionRegistry | None,
    refresh_tokens: RefreshTokenFamilyStore | None,
    occurred_at: datetime,
    event_ids: "Callable[[], str]",
    operation: str,
) -> None:
    if sessions is not None:
        await _revoke_all_sessions(
            sessions, account_id, occurred_at, event_ids, operation=f"{operation}{SESSION_REVOKE_ALL_SUFFIX}"
        )
    if refresh_tokens is not None:
        try:
            await refresh_tokens.revoke_for_account(
                account_id,
                event=lifecycle_event(
                    event_ids,
                    occurred_at,
                    operation=f"{operation}.refresh_revoke",
                    outcome=OUTCOME_REVOKED,
                    account_id=account_id,
                ),
            )
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            _LOGGER.error("Password refresh cleanup failed")  # noqa: TRY400 - omit untrusted exception details
