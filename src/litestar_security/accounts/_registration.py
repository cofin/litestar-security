"""Registration and verification-token lifecycle services."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from logging import getLogger
from typing import TYPE_CHECKING, Generic, TypeVar

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import aware_utc_time, new_event_id, strict_text, utc_now
from litestar_security.accounts._operations import (
    OUTCOME_CREATED,
    OUTCOME_ISSUED,
    OUTCOME_VERIFIED,
    REGISTRATION,
    VERIFICATION_CONSUME,
    VERIFICATION_ISSUE,
    VERIFICATION_RESEND,
)
from litestar_security.accounts._passwords import PasswordHasher, PasswordPolicy, PasswordPolicyDecision
from litestar_security.accounts._purpose_tokens import PurposeTokenCodec, PurposeTokenDelivery, RegistrationCommand
from litestar_security.accounts._rate_limits import RateLimited, RateLimitGuard, validate_rate_limits
from litestar_security.accounts._records import (
    ConsumeOutcome,
    ConsumeStatus,
    InvalidInvitation,
    LifecycleAccepted,
    LifecycleRejected,
    RegistrationMode,
    RegistrationStatus,
    TokenPurpose,
    lifecycle_event,
    normalize_identifier,
)
from litestar_security.accounts._recovery import validate_lifecycle_configuration
from litestar_security.accounts._stores import (
    AccountLookup,
    RegistrationPolicy,
    RegistrationStore,
    VerificationTokenStore,
)
from litestar_security.authentication import VerificationUnavailable

if TYPE_CHECKING:
    from collections.abc import Callable


__all__ = ("RegistrationService", "VerificationTokenService")

UserT = TypeVar("UserT")
_DEFAULT_TOKEN_ATTEMPTS = 5
_VERIFICATION_TOKEN_LIFETIME = timedelta(hours=24)
_LOGGER = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RegistrationService(Generic[UserT]):
    """Apply policy and commit one atomic enumeration-resistant registration."""

    accounts: RegistrationStore[UserT] = field(repr=False)
    hasher: PasswordHasher = field(repr=False)
    tokens: PurposeTokenCodec = field(repr=False)
    registration: RegistrationPolicy
    password_policy: PasswordPolicy = field(default_factory=PasswordPolicy)
    verification_lifetime: timedelta = _VERIFICATION_TOKEN_LIFETIME
    verification_attempts: int = _DEFAULT_TOKEN_ATTEMPTS
    verification_return_url: str | None = None
    clock: "Callable[[], datetime]" = field(default=utc_now, repr=False, compare=False)
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=new_event_id, repr=False, compare=False)
    rate_limits: RateLimitGuard | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate the selected registration policy and injected boundaries."""
        validate_rate_limits(self.rate_limits, name="Registration service")
        accounts_value: object = object.__getattribute__(self, "accounts")
        hasher_value: object = object.__getattribute__(self, "hasher")
        tokens_value: object = object.__getattribute__(self, "tokens")
        if not isinstance(accounts_value, RegistrationStore):
            msg = "Registration service accounts must implement RegistrationStore"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(hasher_value, PasswordHasher):
            msg = "Registration service hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if tokens_value.__class__ is not PurposeTokenCodec:
            msg = "Registration service tokens must be PurposeTokenCodec"
            raise ImproperlyConfiguredException(detail=msg)
        if self.registration.__class__ is not RegistrationPolicy or self.registration.mode is RegistrationMode.DISABLED:
            msg = "Registration service requires an enabled RegistrationPolicy"
            raise ImproperlyConfiguredException(detail=msg)
        validate_lifecycle_configuration(
            lifetime=self.verification_lifetime,
            attempts=self.verification_attempts,
            return_url=self.verification_return_url,
            clock=self.clock,
            normalizer=self.normalizer,
            event_ids=self.event_ids,
            name="Registration service",
        )

    async def register(  # noqa: PLR0911, PLR0913 - one named input per registration policy input; explicit outcomes
        self,
        identifier: str,
        password: str,
        *,
        display_name: str | None = None,
        invitation_token: str | None = None,
        now: datetime | None = None,
        client_key: str | None = None,
    ) -> (
        LifecycleAccepted
        | InvalidInvitation
        | LifecycleRejected
        | PasswordPolicyDecision
        | RateLimited
        | VerificationUnavailable
    ):
        """Hash and pass one complete candidate registration to the atomic store.

        The hash and the atomic ``register`` call both run unconditionally, so
        the constant-time obligation for a taken versus a new identifier lives
        in the application's :meth:`RegistrationStore.register` implementation.

        Args:
            identifier: The submitted identifier, normalized before use.
            password: The submitted password, checked against policy first.
            display_name: An optional human-readable name to store.
            invitation_token: The invitation to consume under an invite-only
                policy, or ``None`` under a public one.
            now: Override the clock, for tests and replayable registration.
            client_key: The caller identity for the rate-limit client bucket.

        Returns:
            The same acceptance whether or not the identifier was taken, a policy
            violation, an invitation rejection, ``RateLimited`` when the budget is
            spent, or ``VerificationUnavailable`` when a dependency failed.
        """
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            normalized_identifier = self.normalizer(identifier)
        except (TypeError, UnicodeError, ValueError):
            return LifecycleRejected()
        if not strict_text(normalized_identifier):
            return LifecycleRejected()
        limited = await self._check_rate_limit(normalized_identifier, client_key)
        if limited is not None:
            return limited
        try:
            password_result = self.password_policy.check(password, normalized_identifier=normalized_identifier)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if not password_result.accepted:
            return password_result
        invitation_digest: bytes | None = None
        if self.registration.mode is RegistrationMode.INVITE_ONLY:
            invitation = self.tokens.proof(invitation_token, expected_purpose=TokenPurpose.INVITATION)
            if invitation is None:
                return InvalidInvitation()
            invitation_digest = invitation.digest
        try:
            password_hash = await self.hasher.hash(password)
            verification = self._verification_plan(normalized_identifier, occurred_at)
            event = lifecycle_event(self.event_ids, occurred_at, operation=REGISTRATION, outcome=OUTCOME_CREATED)
            result = await self.accounts.register(
                RegistrationCommand(normalized_identifier=normalized_identifier, display_name=display_name),
                password_hash,
                invitation_digest=invitation_digest,
                verification=verification,
                now=occurred_at,
                event=event,
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if result.status is RegistrationStatus.INVALID_INVITATION:
            return InvalidInvitation()
        return LifecycleAccepted()

    async def _check_rate_limit(
        self, normalized_identifier: str, client_key: str | None
    ) -> "RateLimited | VerificationUnavailable | None":
        rate_limits = self.rate_limits
        if rate_limits is None:
            return None
        return await rate_limits.check(REGISTRATION, client_key=client_key, identifier=normalized_identifier)

    def _verification_plan(self, destination: str, occurred_at: datetime) -> PurposeTokenDelivery | None:
        if not self.registration.require_verification:
            return None
        return self.tokens.issue(
            TokenPurpose.VERIFICATION,
            now=occurred_at,
            lifetime=self.verification_lifetime,
            template="local.verify",
            destination=destination,
            return_url=self.verification_return_url,
            maximum_attempts=self.verification_attempts,
        )


@dataclass(frozen=True, slots=True)
class VerificationTokenService(Generic[UserT]):
    """Issue generic verification resends and atomically consume confirmations."""

    accounts: AccountLookup[UserT] = field(repr=False)
    store: VerificationTokenStore = field(repr=False)
    tokens: PurposeTokenCodec = field(repr=False)
    lifetime: timedelta = _VERIFICATION_TOKEN_LIFETIME
    maximum_attempts: int = _DEFAULT_TOKEN_ATTEMPTS
    return_url: str | None = None
    clock: "Callable[[], datetime]" = field(default=utc_now, repr=False, compare=False)
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=new_event_id, repr=False, compare=False)
    rate_limits: RateLimitGuard | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate lookup, atomic token store, and deterministic hooks."""
        validate_rate_limits(self.rate_limits, name="Verification token service")
        if not isinstance(object.__getattribute__(self, "accounts"), AccountLookup):
            msg = "Verification token accounts must implement AccountLookup"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(object.__getattribute__(self, "store"), VerificationTokenStore):
            msg = "Verification token store must implement VerificationTokenStore"
            raise ImproperlyConfiguredException(detail=msg)
        if object.__getattribute__(self, "tokens").__class__ is not PurposeTokenCodec:
            msg = "Verification token codec must be PurposeTokenCodec"
            raise ImproperlyConfiguredException(detail=msg)
        validate_lifecycle_configuration(
            lifetime=self.lifetime,
            attempts=self.maximum_attempts,
            return_url=self.return_url,
            clock=self.clock,
            normalizer=self.normalizer,
            event_ids=self.event_ids,
            name="Verification token service",
        )

    async def resend(
        self, identifier: str, *, now: datetime | None = None, client_key: str | None = None
    ) -> LifecycleAccepted | RateLimited | VerificationUnavailable:
        """Always return the shared response after one token-HMAC work class.

        Denial is safe to report here even though every other outcome is
        deliberately identical: the budget is consumed for unknown identifiers
        too, so being limited reveals nothing about whether an account exists.

        Every request pays one durable store round trip: an eligible account
        commits through :meth:`VerificationTokenStore.issue`, any other
        identifier probes through :meth:`VerificationTokenStore.issue_absent`,
        so a present account is not measurably slower to probe than an absent
        one.

        Args:
            identifier: The submitted identifier.
            now: Override the clock, for tests and replayable requests.
            client_key: The caller identity for the rate-limit client bucket.

        Returns:
            The same acceptance for every identifier, ``RateLimited`` when the
            budget is spent, or ``VerificationUnavailable`` when a dependency failed.
        """
        limited = await self._check_rate_limit(identifier, client_key)
        if limited is not None:
            return limited
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            normalized_identifier = self.normalizer(identifier)
            issued = self.tokens.issue(
                TokenPurpose.VERIFICATION,
                now=occurred_at,
                lifetime=self.lifetime,
                template="local.verify",
                destination=normalized_identifier,
                return_url=self.return_url,
                maximum_attempts=self.maximum_attempts,
            )
            account = await self.accounts.find_for_login(normalized_identifier) if normalized_identifier else None
            if account is not None and account.active and not account.verified:
                issue, notification = issued.bind(account.account_id)
                await self.store.issue(
                    issue,
                    notification,
                    event=lifecycle_event(
                        self.event_ids,
                        occurred_at,
                        operation=VERIFICATION_ISSUE,
                        outcome=OUTCOME_ISSUED,
                        account_id=account.account_id,
                    ),
                )
            else:
                await self.store.issue_absent()
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            _LOGGER.error("Verification token request failed")  # noqa: TRY400 - omit untrusted exception details
        return LifecycleAccepted()

    async def consume(
        self, token: object, *, now: datetime | None = None, client_key: str | None = None
    ) -> "ConsumeOutcome | RateLimited | VerificationUnavailable":
        """Verify purpose locally and delegate single-use mutation atomically.

        The budget is keyed on the client bucket only: the route consumes a
        token, and digesting tokens into a subject bucket would turn the limiter
        backend into a record of attempted tokens.

        Args:
            token: The presented verification token.
            now: Override the clock, for tests and replayable consumption.
            client_key: The caller identity for the rate-limit client bucket.

        Returns:
            The consumption outcome, ``RateLimited`` when the budget is spent, or
            ``VerificationUnavailable`` when the store failed. An expired, used,
            and unknown token are not distinguished.
        """
        rate_limits = self.rate_limits
        if rate_limits is not None:
            limited = await rate_limits.check(VERIFICATION_CONSUME, client_key=client_key)
            if limited is not None:
                return limited
        proof = self.tokens.proof(token, expected_purpose=TokenPurpose.VERIFICATION)
        if proof is None:
            return ConsumeOutcome(ConsumeStatus.INVALID)
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            return await self.store.consume_and_verify(
                proof.token_id,
                proof.digest,
                now=occurred_at,
                event=lifecycle_event(
                    self.event_ids, occurred_at, operation=VERIFICATION_CONSUME, outcome=OUTCOME_VERIFIED
                ),
            )
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()

    async def _check_rate_limit(
        self, identifier: str, client_key: str | None
    ) -> "RateLimited | VerificationUnavailable | None":
        rate_limits = self.rate_limits
        if rate_limits is None:
            return None
        try:
            normalized_identifier = self.normalizer(identifier) or None
        except Exception:  # noqa: BLE001 - a failed normalizer still consumes the client budget
            normalized_identifier = None
        return await rate_limits.check(VERIFICATION_RESEND, client_key=client_key, identifier=normalized_identifier)
