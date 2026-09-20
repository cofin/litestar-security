"""Deterministic fakes, mocks, and test clocks for security test suites."""

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Generic, TypeVar
from urllib.parse import parse_qsl

import httpx
from anyio import Event

from litestar_security.authentication import AuthorizationResolution, IdentityResolution
from litestar_security.clock import SecurityClock
from litestar_security.context import AuthorizationSnapshot, Principal
from litestar_security.providers.oauth import (
    OAuthTransaction,
    OAuthTransactionStart,
    ProviderIdentity,
    ProviderTokenSet,
    SecretStr,
)
from litestar_security.websocket import WebSocketBinding

__all__ = (
    "BackendBarrier",
    "BackendEvent",
    "FakeClock",
    "FakeOAuthHTTPTransport",
    "FakeOAuthProvider",
    "FakeSecurityClock",
    "InMemoryWebSocketRevocationSource",
    "OAuthRequestObservation",
    "StaticAuthorizationResolver",
    "StaticAuthorizationSnapshotRefresher",
    "StaticIdentityResolver",
)

ClaimsT = TypeVar("ClaimsT")
UserT = TypeVar("UserT")


@dataclass(frozen=True, slots=True)
class OAuthRequestObservation:
    """Secret-free projection of one provider HTTP request."""

    method: str
    url: str
    header_names: frozenset[str]
    form_fields: frozenset[str]


class FakeOAuthHTTPTransport(httpx.AsyncBaseTransport):
    """Deterministic queued HTTPX transport for provider conformance tests."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        """Initialize with responses consumed in order.

        Args:
            responses: Provider responses to return.
        """
        self.responses = list(responses)
        self.requests: list[OAuthRequestObservation] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Record one request and return the next response."""
        self.requests.append(
            OAuthRequestObservation(
                method=request.method,
                url=str(request.url),
                header_names=frozenset(name.lower() for name in request.headers if name.lower() != "authorization"),
                form_fields=frozenset(
                    key for key, _value in parse_qsl(request.content.decode(), keep_blank_values=True)
                ),
            )
        )
        if not self.responses:
            message = "Fake OAuth HTTP responses exhausted"
            raise AssertionError(message)
        response = self.responses.pop(0)
        return httpx.Response(response.status_code, headers=response.headers, content=response.content, request=request)


class FakeOAuthProvider:
    """Deterministic async provider with public lifecycle call history."""

    def __init__(self, *, name: str, tokens: ProviderTokenSet, identity: ProviderIdentity) -> None:
        """Initialize fixed provider results."""
        self.name = name
        self.tokens = tokens
        self.identity = identity
        self.calls: list[str] = []

    def build_authorization_url(self, start: OAuthTransactionStart) -> str:
        """Return a deterministic URL."""
        self.calls.append("authorize")
        return f"https://provider.example/authorize?state={start.state.get_secret_value()}"

    async def exchange_code(
        self, *, code: SecretStr, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Return configured exchange tokens."""
        del code, transaction, now
        self.calls.append("exchange")
        return self.tokens

    async def resolve_identity(
        self, tokens: ProviderTokenSet, *, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderIdentity:
        """Return the configured identity."""
        del tokens, transaction, now
        self.calls.append("identity")
        return self.identity

    async def refresh(
        self, refresh_token: SecretStr, *, current_scopes: frozenset[str] | None = None, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Return configured refresh tokens."""
        del refresh_token, current_scopes, now
        self.calls.append("refresh")
        return self.tokens

    async def revoke(self, token: SecretStr, *, token_type_hint: str | None) -> None:
        """Record deterministic revocation."""
        del token, token_type_hint
        self.calls.append("revoke")


class FakeClock(SecurityClock):
    """Deterministic wall and monotonic clock owned by one test."""

    __slots__ = ("_monotonic", "_now")

    def __init__(self, now: datetime, monotonic_start: float = 0.0) -> None:
        """Initialize at one timezone-aware instant.

        Args:
            now: Initial time.
            monotonic_start: Initial monotonic reading in seconds.

        Raises:
            ValueError: If ``now`` is naive.
        """
        if now.tzinfo is None or now.utcoffset() is None:
            message = "FakeClock requires a timezone-aware datetime"
            raise ValueError(message)
        self._now = now.astimezone(timezone.utc)
        self._monotonic = float(monotonic_start)

    def __call__(self) -> datetime:
        """Return the current instant.

        Returns:
            The current UTC datetime.
        """
        return self._now

    def advance(self, delta: timedelta) -> datetime:
        """Advance both sources by a positive duration.

        Args:
            delta: Positive duration to add.

        Returns:
            The updated UTC datetime.

        Raises:
            ValueError: If ``delta`` is not positive.
        """
        if delta <= timedelta():
            message = "FakeClock advance must be positive"
            raise ValueError(message)
        self._now += delta
        self._monotonic += delta.total_seconds()
        return self._now

    def now(self) -> datetime:
        """Return the current UTC wall clock instant.

        Returns:
            The deterministic UTC datetime.
        """
        return self._now

    def monotonic(self) -> float:
        """Return the current monotonic reading.

        Returns:
            Deterministic elapsed seconds plus the initial reading.
        """
        return self._monotonic

    def step_wall(self, delta: timedelta) -> datetime:
        """Adjust wall time without changing the monotonic reading.

        Args:
            delta: Signed adjustment, including zero or a backward step.

        Returns:
            The updated UTC wall clock datetime.
        """
        self._now += delta
        return self._now


class FakeSecurityClock(FakeClock):
    """Named dual-clock fake retaining the existing testing API."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class StaticIdentityResolver(Generic[ClaimsT, UserT]):
    """Identity resolver that returns one configured outcome without retaining claims."""

    resolution: IdentityResolution[UserT]

    async def resolve(self, claims: ClaimsT) -> IdentityResolution[UserT]:
        """Return the configured identity-resolution outcome.

        Args:
            claims: Ignored verified claims, which are never retained.

        Returns:
            The configured principal or sanitized identity-resolution outcome.

        Raises:
            None.
        """
        del claims
        return self.resolution


@dataclass(frozen=True, slots=True)
class StaticAuthorizationResolver(Generic[UserT]):
    """Authorization resolver that returns one configured detached outcome."""

    resolution: AuthorizationResolution

    async def resolve(self, principal: Principal[UserT]) -> AuthorizationResolution:
        """Return the configured authorization-resolution outcome.

        Args:
            principal: Ignored authenticated principal, which is never mutated.

        Returns:
            The configured immutable snapshot or sanitized authorization-resolution outcome.

        Raises:
            None.
        """
        del principal
        return self.resolution


class InMemoryWebSocketRevocationSource:
    """Deterministic per-binding WebSocket revocation source for tests."""

    __slots__ = ("_events",)

    def __init__(self) -> None:
        """Initialize an isolated set of per-binding revocation events."""
        self._events: dict[WebSocketBinding, Event] = {}

    def _event(self, binding: WebSocketBinding) -> Event:
        """Return the private revocation event for one complete binding."""
        return self._events.setdefault(binding, Event())

    async def wait(self, binding: WebSocketBinding) -> None:
        """Block until the exact binding has been revoked.

        Args:
            binding: The complete secret-free binding to supervise.
        """
        await self._event(binding).wait()

    def revoke(self, binding: WebSocketBinding) -> None:
        """Release waiters for one exact binding.

        Args:
            binding: The complete secret-free binding to revoke.
        """
        self._event(binding).set()


@dataclass(frozen=True, slots=True)
class StaticAuthorizationSnapshotRefresher(Generic[UserT]):
    """WebSocket snapshot refresher that returns one configured immutable snapshot."""

    snapshot: AuthorizationSnapshot

    async def refresh(
        self, *, principal: Principal[UserT], previous: AuthorizationSnapshot, route_name: str
    ) -> AuthorizationSnapshot:
        """Return the configured immutable authorization snapshot.

        Args:
            principal: Ignored authenticated principal, which is never mutated.
            previous: Ignored prior snapshot, which is never mutated or returned.
            route_name: Ignored bound route name.

        Returns:
            The configured immutable authorization snapshot.
        """
        del principal, previous, route_name
        return self.snapshot


@dataclass(frozen=True, slots=True)
class BackendEvent:
    """One secret-free deterministic reference-backend operation."""

    sequence: int
    operation: str
    details: Mapping[str, str]

    def __post_init__(self) -> None:
        """Freeze copied diagnostic details."""
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))


@dataclass(slots=True)
class BackendBarrier:
    """Deterministically pause one named backend operation."""

    reached: Event = dataclass_field(default_factory=Event)
    release: Event = dataclass_field(default_factory=Event)
