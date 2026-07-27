"""Operation-scoped rate limiting for abuse-prone local-account entry points.

Local login, registration, recovery, verification, and refresh routes are
unauthenticated and deliberately expensive: password verification runs Argon2,
which costs the server real CPU on every attempt. That combination makes them
both a password-guessing surface and an amplification lever, so each one
consumes a budget before it does any credential work.

Two buckets guard every limited operation. The client bucket uses a key the
application supplies, because only the application knows which proxy headers it
trusts. The subject bucket uses a peppered digest of the normalized identifier,
which is what stops one account being targeted from many addresses. Neither
bucket ever receives a raw identifier, password, or token.

:class:`RateLimiter` is a port. :class:`StoreRateLimiter` is the bundled
implementation over a native Litestar :class:`~litestar.stores.base.Store`,
resolved by name from the application store registry, so pointing that name at a
shared backend makes limiting correct across worker processes.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha256
from hmac import digest as hmac_digest
from logging import getLogger
from math import ceil
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from litestar.exceptions import ImproperlyConfiguredException
from litestar.stores.base import Store

from litestar_security.accounts._internal import (
    MINIMUM_PEPPER_BYTES,
    aware_utc_time,
    new_event_id,
    strict_text,
    utc_now,
)
from litestar_security.accounts._operations import (
    LOGIN,
    OUTCOME_RATE_LIMITED,
    PASSWORD_RESET,
    RECOVERY,
    REFRESH_ROTATE,
    REGISTRATION,
    VERIFICATION_RESEND,
)
from litestar_security.accounts._records import (
    NoOpSecurityEventSink,
    SecurityEvent,
    SecurityEventSink,
    emit_security_event,
)
from litestar_security.authentication import VerificationUnavailable

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


__all__ = (
    "DEFAULT_RATE_LIMIT_POLICIES",
    "RATE_LIMIT_STORE_NAME",
    "RateLimitDecision",
    "RateLimitGuard",
    "RateLimitPolicy",
    "RateLimitRequest",
    "RateLimited",
    "RateLimiter",
    "StoreRateLimiter",
    "UnlimitedRateLimiter",
    "validate_rate_limits",
)

_LOGGER = getLogger(__name__)

RATE_LIMIT_STORE_NAME = "litestar_security.rate_limits"

_SUBJECT_DIGEST_LABEL = b"litestar-security/rate-limit/subject"
_MAXIMUM_WINDOW = timedelta(days=1)
_MAXIMUM_LIMIT = 1_000_000
_MAXIMUM_COST = 1_000
_MAXIMUM_KEY_TEXT = 512


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """One operation's budget, applied to each bucket independently.

    Args:
        limit: Attempts allowed per window in a single bucket.
        window: Length of the fixed window the limit applies to.
    """

    limit: int
    window: timedelta

    def __post_init__(self) -> None:
        """Require a bounded positive limit and a whole-second window."""
        limit_value: object = self.limit
        window_value: object = self.window
        if limit_value.__class__ is not int or not 1 <= self.limit <= _MAXIMUM_LIMIT:
            msg = "Rate limit must be a positive bounded integer"
            raise ImproperlyConfiguredException(detail=msg)
        if (
            not isinstance(window_value, timedelta)  # pyright: ignore[reportUnnecessaryIsInstance] - runtime port
            or self.window <= timedelta(0)
            or self.window > _MAXIMUM_WINDOW
            or self.window.microseconds
        ):
            msg = "Rate limit window must be positive whole seconds of at most one day"
            raise ImproperlyConfiguredException(detail=msg)


DEFAULT_RATE_LIMIT_POLICIES: "Mapping[str, RateLimitPolicy]" = MappingProxyType({
    LOGIN: RateLimitPolicy(limit=10, window=timedelta(minutes=5)),
    REGISTRATION: RateLimitPolicy(limit=5, window=timedelta(hours=1)),
    RECOVERY: RateLimitPolicy(limit=5, window=timedelta(hours=1)),
    PASSWORD_RESET: RateLimitPolicy(limit=10, window=timedelta(hours=1)),
    VERIFICATION_RESEND: RateLimitPolicy(limit=5, window=timedelta(hours=1)),
    REFRESH_ROTATE: RateLimitPolicy(limit=60, window=timedelta(minutes=5)),
})


@dataclass(frozen=True, slots=True)
class RateLimitRequest:
    """One bucketed attempt presented to a limiter.

    Args:
        operation: Canonical ``local.*`` name of the entry point being consumed.
        client_key: Application-supplied trusted client identity, or ``None`` to
            skip the client bucket.
        subject_digest: Peppered digest of the normalized identifier, or ``None``
            when the operation carries no identifier. Never a raw identifier.
        cost: Units this attempt consumes from each bucket.
    """

    operation: str
    client_key: str | None = None
    subject_digest: str | None = None
    cost: int = 1

    def __post_init__(self) -> None:
        """Require a named operation, bounded bucket keys, and a positive cost."""
        cost_value: object = self.cost
        if not strict_text(self.operation):
            msg = "Rate limit request operation must be non-empty text"
            raise ValueError(msg)
        for value in (self.client_key, self.subject_digest):
            if value is not None and (not strict_text(value) or len(value) > _MAXIMUM_KEY_TEXT):
                msg = "Rate limit bucket keys must be bounded non-empty text"
                raise ValueError(msg)
        if cost_value.__class__ is not int or not 1 <= self.cost <= _MAXIMUM_COST:
            msg = "Rate limit cost must be a positive bounded integer"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """One limiter verdict for a single attempt.

    Args:
        allowed: Whether the attempt may proceed.
        retry_after: Whole seconds until the caller may retry, reported only
            when the attempt was denied.
    """

    allowed: bool
    retry_after: int | None = None

    def __post_init__(self) -> None:
        """Require a positive retry hint, and only on denial."""
        allowed_value: object = self.allowed
        retry_value: object = self.retry_after
        if allowed_value.__class__ is not bool:
            msg = "Rate limit decision must be boolean"
            raise ValueError(msg)
        if retry_value is not None and (retry_value.__class__ is not int or retry_value < 1):
            msg = "Rate limit retry-after must be a positive whole number of seconds"
            raise ValueError(msg)
        if self.allowed and retry_value is not None:
            msg = "Allowed rate limit decisions cannot carry a retry-after"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RateLimited:
    """Sanitized outcome returned when an operation exhausted its budget.

    Args:
        retry_after: Whole seconds until the caller may retry, when the limiter
            reported one.
        code: Stable machine-readable reason.
    """

    retry_after: int | None = None
    code: str = "rate_limited"


@runtime_checkable
class RateLimiter(Protocol):
    """Application-owned budget for one abuse-prone operation.

    Implementations should consume atomically where their backend allows it. A
    limiter that raises is treated as unavailable and fails closed, so raising is
    the correct response to a backend outage.
    """

    async def acquire(self, request: RateLimitRequest) -> RateLimitDecision:
        """Consume one attempt's cost and report whether it may proceed."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class UnlimitedRateLimiter:
    """Allow every attempt, for deployments that limit at the edge instead."""

    async def acquire(self, request: RateLimitRequest) -> RateLimitDecision:
        """Allow one attempt without consuming any budget."""
        del request
        return RateLimitDecision(allowed=True)


@dataclass(slots=True)
class StoreRateLimiter:
    """Fixed-window limiter over a native Litestar store.

    The store is resolved by name from the application registry during startup,
    so an unconfigured name yields Litestar's in-memory default and registering a
    shared backend under the same name makes counting correct across worker
    processes.

    Counting is read-modify-write rather than atomic, because the native store
    contract exposes no compare-and-increment. Concurrent attempts can therefore
    undercount slightly; supply a limiter backed by an atomic primitive through
    :class:`RateLimiter` where exactness matters.

    Args:
        policies: Budget per operation. Operations absent from the mapping are
            not limited by this limiter.
        store_name: Registry name resolved during application startup.
        store: Pre-resolved store, bypassing registry resolution.
        clock: Source of the current time.
    """

    policies: "Mapping[str, RateLimitPolicy]" = DEFAULT_RATE_LIMIT_POLICIES
    store_name: str = RATE_LIMIT_STORE_NAME
    store: Store | None = field(default=None, repr=False)
    clock: "Callable[[], datetime]" = field(default=utc_now, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate the store name, policies, and clock, then freeze the mapping."""
        store_value: object = self.store
        if not strict_text(self.store_name):
            msg = "Rate limit store name must be non-empty text"
            raise ImproperlyConfiguredException(detail=msg)
        if store_value is not None and not isinstance(store_value, Store):  # pyright: ignore[reportUnnecessaryIsInstance] - runtime port
            msg = "Rate limit store must be a Litestar Store"
            raise ImproperlyConfiguredException(detail=msg)
        clock_value: object = self.clock
        if not callable(clock_value):
            msg = "Rate limit clock must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        policies = dict(self.policies)
        if any(not strict_text(name) or policy.__class__ is not RateLimitPolicy for name, policy in policies.items()):
            msg = "Rate limit policies must map operation names to RateLimitPolicy values"
            raise ImproperlyConfiguredException(detail=msg)
        self.policies = MappingProxyType(policies)

    def bind(self, store: Store) -> None:
        """Attach the store resolved from the application registry at startup."""
        store_value: object = store
        if not isinstance(store_value, Store):  # pyright: ignore[reportUnnecessaryIsInstance] - runtime port
            msg = "Rate limit store must be a Litestar Store"
            raise ImproperlyConfiguredException(detail=msg)
        self.store = store

    async def acquire(self, request: RateLimitRequest) -> RateLimitDecision:
        """Consume one attempt from every configured bucket for the operation."""
        policy = self.policies.get(request.operation)
        if policy is None:
            return RateLimitDecision(allowed=True)
        store = self.store
        if store is None:
            msg = "Rate limit store has not been resolved"
            raise RuntimeError(msg)
        now = self.clock()
        retry_after = 0
        for kind, value in (("c", request.client_key), ("s", request.subject_digest)):
            if value is None:
                continue
            exhausted = await self._consume(store, request, policy, kind=kind, value=value, now=now)
            if exhausted is not None:
                retry_after = max(retry_after, exhausted)
        if retry_after:
            return RateLimitDecision(allowed=False, retry_after=retry_after)
        return RateLimitDecision(allowed=True)

    async def _consume(  # noqa: PLR0913 - one bucket read/write; every input is named
        self, store: Store, request: RateLimitRequest, policy: RateLimitPolicy, *, kind: str, value: str, now: datetime
    ) -> int | None:
        window = int(policy.window.total_seconds())
        elapsed = now.timestamp()
        slot = int(elapsed // window)
        bucket = sha256(f"{request.operation}\x00{kind}\x00{value}".encode()).hexdigest()
        key = f"{self.store_name}:{slot}:{bucket}"
        raw = await store.get(key)
        try:
            used = int(raw) if raw is not None else 0
        except ValueError:
            msg = "Rate limit counter is unreadable"
            raise RuntimeError(msg) from None
        used += request.cost
        await store.set(key, str(used).encode("ascii"), expires_in=window)
        if used <= policy.limit:
            return None
        return max(1, ceil((slot + 1) * window - elapsed))


@dataclass(frozen=True, slots=True)
class RateLimitGuard:
    """Bucket one operation's attempts without exposing the identifier.

    Every service that limits an entry point shares one guard, so denial audit
    events are constructed the same way everywhere instead of once per service.

    Args:
        limiter: The configured budget implementation.
        pepper: Secret used to derive subject digests; at least 32 bytes.
        events: Sink notified when an attempt is denied.
        clock: Source of the current time for denial events.
        event_ids: Factory for unique denial event identifiers.
    """

    limiter: RateLimiter = field(repr=False)
    pepper: bytes = field(repr=False)
    events: SecurityEventSink = field(default_factory=NoOpSecurityEventSink, repr=False, compare=False)
    clock: "Callable[[], datetime]" = field(default=utc_now, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Require a limiter, a long enough digest pepper, and a usable sink."""
        limiter_value: object = object.__getattribute__(self, "limiter")
        pepper_value: object = object.__getattribute__(self, "pepper")
        events_value: object = object.__getattribute__(self, "events")
        if not isinstance(limiter_value, RateLimiter):
            msg = "Rate limit guard limiter must implement RateLimiter"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(pepper_value, bytes) or len(pepper_value) < MINIMUM_PEPPER_BYTES:
            msg = "Rate limit guard pepper must be at least 32 bytes"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(events_value, SecurityEventSink):
            msg = "Rate limit guard events must implement SecurityEventSink"
            raise ImproperlyConfiguredException(detail=msg)
        clock_value: object = object.__getattribute__(self, "clock")
        event_ids_value: object = object.__getattribute__(self, "event_ids")
        if not callable(clock_value) or not callable(event_ids_value):
            msg = "Rate limit guard clock and event id factory must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    async def check(
        self, operation: str, *, client_key: str | None = None, identifier: str | None = None
    ) -> "RateLimited | VerificationUnavailable | None":
        """Consume one attempt, returning ``None`` when the caller may proceed."""
        try:
            request = RateLimitRequest(
                operation=operation,
                client_key=client_key,
                subject_digest=self.subject_digest(identifier) if identifier is not None else None,
            )
            decision: object = await self.limiter.acquire(request)
        except Exception:  # noqa: BLE001 - an unavailable limiter must fail closed, not open
            _LOGGER.error("Rate limiter unavailable for %s", operation)  # noqa: TRY400 - omit untrusted details
            return VerificationUnavailable()
        if not isinstance(decision, RateLimitDecision):  # pyright: ignore[reportUnnecessaryIsInstance] - runtime port
            _LOGGER.error("Rate limiter returned an unusable decision for %s", operation)
            return VerificationUnavailable()
        if decision.allowed:
            return None
        await self._emit_denial(operation)
        return RateLimited(retry_after=decision.retry_after)

    def subject_digest(self, identifier: str) -> str:
        """Derive the stable peppered bucket digest for one normalized identifier."""
        return hmac_digest(self.pepper, _SUBJECT_DIGEST_LABEL + identifier.encode("utf-8"), sha256).hex()

    async def _emit_denial(self, operation: str) -> None:
        # The account is deliberately absent: a denial is keyed on a digest, and
        # resolving it back to an account would defeat the point of digesting it.
        try:
            event = SecurityEvent(
                event_id=self.event_ids(),
                occurred_at=aware_utc_time(self.clock()),
                operation=operation,
                outcome=OUTCOME_RATE_LIMITED,
            )
        except Exception:  # noqa: BLE001 - a failed clock or id factory cannot change a settled denial
            _LOGGER.error("Rate limit event could not be built for %s", operation)  # noqa: TRY400 - omit details
            return
        await emit_security_event(self.events, event)


def validate_rate_limits(value: object, *, name: str) -> None:
    """Require an optional rate-limit guard to be exactly a :class:`RateLimitGuard`.

    Args:
        value: The configured guard, or ``None`` when the service is unlimited.
        name: Service name used in the configuration error.

    Raises:
        ImproperlyConfiguredException: If a guard is supplied but is the wrong type.
    """
    if value is not None and value.__class__ is not RateLimitGuard:
        msg = f"{name} rate limits must be a RateLimitGuard"
        raise ImproperlyConfiguredException(detail=msg)
