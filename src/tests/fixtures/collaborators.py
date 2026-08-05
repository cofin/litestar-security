"""Shared test collaborators, so a fake is defined once and found by the next test.

Two kinds of thing live here.

**Kit-backed builders.** Where ``litestar_security.testing`` already ships a
double, the builder is a thin wrapper over it and adds only defaults. Where the
kit ships a *production* adapter -- ``MemoryOAuthAccountStore``,
``MemoryTokenVault``, ``MemoryOAuthTransactionStore``, ``AESGCMSecretProtector``,
``StoreRateLimiter`` -- the builder returns the real thing, so a test using it
exercises real code rather than a double.

**Hand-written collaborators.** The kit covers stores, not the runtime seams:
nothing in it fakes a JWKS fetcher, a JWT verifier or signer, a Litestar guard,
a controller, a metrics sink, or an event sink. Those are exactly the names that
were being redefined inside individual test functions, so they are written once
here.

Every hand-written collaborator keeps a public call history -- ``calls``,
``requests``, ``events`` -- matching the shape ``FakeOAuthProvider.calls``
already uses, so a test asserts on what was received rather than on a private
attribute. ``ProbeController`` is the one non-dataclass: a Litestar
``Controller`` subclass has to be a plain class.
"""

from __future__ import annotations

import json
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from litestar import Controller, get
from litestar.exceptions import PermissionDeniedException
from litestar.stores.memory import MemoryStore

from litestar_security import testing as kit
from litestar_security.accounts import (
    AESGCMSecretProtector,
    RateLimited,
    RateLimitPolicy,
    RefreshTokenCodec,
    SecretProtectorKey,
    StoreRateLimiter,
    TokenPair,
)
from litestar_security.providers.oauth import ProviderIdentity, ProviderTokenSet, SecretStr

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from threading import Event

    import httpx

    from litestar_security.providers.jwks import JWKSFetchRequest, JWKSFetchResponse

# A function-parameter default, so the dataclass-default rule in patterns.md does
# not apply and no mutable-default suppression is needed.
_NO_ATTRIBUTES: Mapping[str, str] = MappingProxyType({})

# The kit's own default instant (``_DEFAULT_NOW``, testing.py:150), restated
# because the kit's constant is private. A clock-driven backend and a
# default-constructed one therefore agree on now.
FIXED_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

# Every store ``InMemorySecurityBackend`` owns, read from its ``__slots__``. The
# OIDC session-logout store is deliberately absent: the backend cannot reach it,
# which is what ``build_security_environment`` exists to work around.
BACKEND_STORE_ATTRIBUTES: tuple[str, ...] = (
    "accounts",
    "api_keys",
    "challenges",
    "mfa",
    "mfa_login",
    "oauth_accounts",
    "oauth_tokens",
    "oauth_transactions",
    "passkeys",
    "step_up",
    "websocket_connect_tokens",
)

_TOKEN_PEPPER = b"t" * 32
_DEFAULT_EXPIRES_IN = 300


@dataclass(frozen=True, slots=True)
class SecurityEnvironment:
    """One aggregate backend and the OIDC logout store it cannot reach.

    ``InMemoryOIDCSessionLogoutStore`` is absent from
    ``InMemorySecurityBackend.__slots__``, so a test needing both would
    otherwise construct two objects with independent clocks. Both here share
    ``clock``.
    """

    backend: kit.InMemorySecurityBackend
    clock: kit.FakeClock
    oidc_session_logout: kit.InMemoryOIDCSessionLogoutStore


def build_security_environment(
    *,
    now: datetime | None = None,
    session_mappings: tuple[tuple[str, str, str | None, str | None], ...] = (),
    frontchannel_bindings: Mapping[tuple[str, str, str], str] | None = None,
) -> SecurityEnvironment:
    """Build the aggregate backend and the OIDC logout store on one clock.

    Args:
        now: The instant the shared clock starts at. Defaults to ``FIXED_NOW``.
        session_mappings: Session mappings the OIDC logout store starts with.
        frontchannel_bindings: Front-channel bindings the logout store starts with.

    Returns:
        The backend, the clock both share, and the OIDC session-logout store.
    """
    clock = kit.FakeClock(FIXED_NOW if now is None else now)
    return SecurityEnvironment(
        backend=kit.InMemorySecurityBackend(clock=clock),
        clock=clock,
        oidc_session_logout=kit.InMemoryOIDCSessionLogoutStore(
            session_mappings=session_mappings,
            frontchannel_bindings={} if frontchannel_bindings is None else frontchannel_bindings,
        ),
    )


def build_compact_jwt(*, claims: Mapping[str, object] | None = None, signature: bytes = b"signature") -> str:
    """Build a structurally valid compact JWT.

    ``TokenPair`` validates the *shape* of its access token -- three non-empty
    base64url-decodable segments within a length bound -- and never verifies a
    signature, so this is sufficient wherever only construction matters. A test
    that verifies the signature passes a really-signed token instead.

    Args:
        claims: Payload claims. Defaults to a minimal subject claim.
        signature: Raw signature bytes to encode as the third segment.

    Returns:
        The encoded ``header.payload.signature`` string.
    """
    payload = {"sub": "acct-1"} if claims is None else dict(claims)
    return ".".join((
        _segment({"alg": "EdDSA", "typ": "JWT"}),
        _segment(payload),
        urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    ))


def build_token_pair(
    *,
    access_token: str | None = None,
    refresh_token: str | None = None,
    expires_in: int = _DEFAULT_EXPIRES_IN,
    codec: RefreshTokenCodec | None = None,
) -> TokenPair:
    """Build a valid ``TokenPair``.

    ``TokenPair`` is the one public wire struct polyfactory cannot build: its
    ``__post_init__`` demands a compact JWT, an ``rt_<identifier>.<secret>``
    refresh token whose secret decodes, and an ``expires_in`` inside the
    configured bounds. The refresh token here comes from the real
    ``RefreshTokenCodec``, so it is a genuinely well-formed credential.

    Args:
        access_token: Overrides the generated compact JWT.
        refresh_token: Overrides the codec-issued refresh token.
        expires_in: Access-token lifetime in seconds. Values outside the
            library's bounds are passed through so a test can assert rejection.
        codec: The codec issuing the refresh token. Defaults to a test pepper.

    Returns:
        The constructed token pair.
    """
    issuer = RefreshTokenCodec(pepper=_TOKEN_PEPPER) if codec is None else codec
    return TokenPair(
        access_token=build_compact_jwt() if access_token is None else access_token,
        refresh_token=issuer.issue().refresh_token if refresh_token is None else refresh_token,
        expires_in=expires_in,
    )


def build_oauth_provider(
    *,
    name: str = "example",
    issuer: str = "https://issuer.example",
    subject: str = "subject-1",
    scopes: frozenset[str] = frozenset({"openid"}),
    expires_at: datetime | None = None,
) -> kit.FakeOAuthProvider:
    """Build the kit's recording OAuth provider with usable defaults.

    Args:
        name: The provider name.
        issuer: The issuer the returned identity carries.
        subject: The subject the returned identity carries.
        scopes: Scopes on the returned token set.
        expires_at: Token expiry. Defaults to one hour after ``FIXED_NOW``.

    Returns:
        A provider recording every exchange on ``calls``.
    """
    return kit.FakeOAuthProvider(
        name=name,
        tokens=ProviderTokenSet(
            access_token=SecretStr("provider-access-token"),
            token_type="Bearer",  # noqa: S106 - the RFC 6749 token type, not a credential
            scopes=scopes,
            expires_at=FIXED_NOW + timedelta(hours=1) if expires_at is None else expires_at,
        ),
        identity=ProviderIdentity(
            provider=name,
            issuer=issuer,
            subject=subject,
            display_name="Example Person",
            email="person@example.com",
            email_verified=True,
            raw_claims={},
        ),
    )


def build_oauth_transport(responses: Sequence[httpx.Response] = ()) -> kit.FakeOAuthHTTPTransport:
    """Build the kit's OAuth transport over a queued response list.

    Args:
        responses: ``httpx.Response`` values the transport returns in order.

    Returns:
        A transport consuming the queue one response per request.
    """
    return kit.FakeOAuthHTTPTransport(list(responses))


def build_revocation_source() -> kit.InMemoryWebSocketRevocationSource:
    """Build the kit's WebSocket revocation source.

    Returns:
        An empty in-memory revocation source.
    """
    return kit.InMemoryWebSocketRevocationSource()


def build_secret_protector(*, key_version: str = "v1", key: bytes = b"k" * 32) -> AESGCMSecretProtector:
    """Build the production AES-GCM secret protector.

    This is real library code, not a double: the kit ships no protector fake
    because none is needed. The value is frozen, so it is safe at session scope.

    Args:
        key_version: The active key version label.
        key: The 32-byte active key.

    Returns:
        A protector sealing with the given active key.
    """
    return AESGCMSecretProtector(active_key=SecretProtectorKey(key_version=key_version, key=key))


def build_rate_limiter(
    *, policies: Mapping[str, RateLimitPolicy] | None = None, store: MemoryStore | None = None
) -> StoreRateLimiter:
    """Build the production store-backed rate limiter over an in-memory store.

    Args:
        policies: Operation-to-policy mapping. Defaults to one permissive policy
            under ``"conformance.rate_limit"``.
        store: The backing store. Defaults to a fresh ``MemoryStore``.

    Returns:
        A limiter whose counters live only for the test.
    """
    resolved = (
        {"conformance.rate_limit": RateLimitPolicy(limit=5, window=timedelta(minutes=5))}
        if policies is None
        else policies
    )
    return StoreRateLimiter(policies=resolved, store=MemoryStore() if store is None else store)


@dataclass(slots=True)
class RecordingJWKSFetcher:
    """Async JWKS fetcher replaying a queued script and recording every request.

    A queued entry is returned as-is, raised if it is an exception, or called
    with the request if it is callable. Running out of entries is an error, not
    a silent empty response.
    """

    responses: list[object] = field(default_factory=list)
    requests: list[JWKSFetchRequest] = field(default_factory=list)
    closes: int = 0

    async def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        """Return the next scripted response.

        Args:
            request: The recorded fetch request.

        Returns:
            The next queued response.

        Raises:
            AssertionError: If the script is exhausted.
        """
        return _next_response(self.responses, self.requests, request)

    async def aclose(self) -> None:
        """Record one close."""
        self.closes += 1


@dataclass(slots=True)
class SyncRecordingJWKSFetcher:
    """Synchronous twin of ``RecordingJWKSFetcher``, for the worker-normalization paths."""

    responses: list[object] = field(default_factory=list)
    requests: list[JWKSFetchRequest] = field(default_factory=list)
    closes: int = 0

    def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        """Return the next scripted response.

        Args:
            request: The recorded fetch request.

        Returns:
            The next queued response.

        Raises:
            AssertionError: If the script is exhausted.
        """
        return _next_response(self.responses, self.requests, request)

    def close(self) -> None:
        """Record one close."""
        self.closes += 1


@dataclass(slots=True)
class BlockingJWKSFetcher:
    """Synchronous fetcher that blocks until released, for saturation and timeout paths.

    ``started`` is set on entry and ``release`` gates the return, so a test can
    observe a fetch in flight without sleeping.
    """

    response: JWKSFetchResponse
    started: Event
    release: Event
    timeout: float = 1.0
    requests: list[JWKSFetchRequest] = field(default_factory=list)

    def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        """Block until released, then return the configured response.

        Args:
            request: The recorded fetch request.

        Returns:
            The configured response.
        """
        self.requests.append(request)
        self.started.set()
        self.release.wait(timeout=self.timeout)
        return self.response


@dataclass(slots=True)
class RecordingJWTVerifier:
    """JWT verifier recording every token it is asked about and returning a scripted outcome."""

    outcome: object
    config: object = None
    calls: list[tuple[str, datetime]] = field(default_factory=list)

    def verify(self, token: str, *, now: datetime) -> object:
        """Record the call and return the configured outcome.

        Args:
            token: The presented token.
            now: The verification instant.

        Returns:
            The configured outcome.
        """
        self.calls.append((token, now))
        return self.outcome


@dataclass(slots=True)
class FailingJWTVerifier:
    """JWT verifier that raises, for the fail-closed ``VerificationUnavailable`` paths."""

    error: Exception = field(default_factory=lambda: RuntimeError("verifier unavailable"))
    config: object = None
    calls: list[tuple[str, datetime]] = field(default_factory=list)

    def verify(self, token: str, *, now: datetime) -> object:
        """Record the call and raise.

        Args:
            token: The presented token.
            now: The verification instant.

        Returns:
            Never returns.

        Raises:
            Exception: Always, with the configured error.
        """
        self.calls.append((token, now))
        raise self.error


@dataclass(slots=True)
class RecordingSigner:
    """JWT signer recording claims and returning a fixed token."""

    token: str = "signed-token"  # noqa: S105 - a placeholder token value, not a credential
    calls: list[tuple[Mapping[str, object], datetime]] = field(default_factory=list)

    def sign(self, claims: Mapping[str, object], *, now: datetime) -> str:
        """Record the call and return the configured token.

        Args:
            claims: The claims to sign.
            now: The signing instant.

        Returns:
            The configured token.
        """
        self.calls.append((claims, now))
        return self.token


@dataclass(slots=True)
class RecordingRateLimitGuard:
    """Rate-limit guard that admits every operation and records the admission."""

    calls: list[tuple[str, str | None, str | None]] = field(default_factory=list)

    async def check(self, operation: str, *, client_key: str | None = None, identifier: str | None = None) -> None:
        """Record one admitted operation.

        Args:
            operation: The rate-limited operation name.
            client_key: The caller's client key, when one is bound.
            identifier: The account identifier, when one is known.
        """
        self.calls.append((operation, client_key, identifier))


@dataclass(slots=True)
class DenyingRateLimitGuard:
    """Rate-limit guard that denies every operation with a retry hint."""

    retry_after: int = 2
    calls: list[tuple[str, str | None, str | None]] = field(default_factory=list)

    async def check(
        self, operation: str, *, client_key: str | None = None, identifier: str | None = None
    ) -> RateLimited:
        """Record one denied operation.

        Args:
            operation: The rate-limited operation name.
            client_key: The caller's client key, when one is bound.
            identifier: The account identifier, when one is known.

        Returns:
            The denial carrying ``retry_after``.
        """
        self.calls.append((operation, client_key, identifier))
        return RateLimited(retry_after=self.retry_after)


@dataclass(slots=True)
class RecordingRouteGuard:
    """Native Litestar guard that permits every connection and records it."""

    calls: list[tuple[object, object]] = field(default_factory=list)

    def __call__(self, connection: object, handler: object) -> None:
        """Record one permitted connection.

        Args:
            connection: The ASGI connection under check.
            handler: The route handler under check.
        """
        self.calls.append((connection, handler))


@dataclass(slots=True)
class DenyingRouteGuard:
    """Native Litestar guard that denies every connection."""

    detail: str = "denied by test guard"
    calls: list[tuple[object, object]] = field(default_factory=list)

    def __call__(self, connection: object, handler: object) -> None:
        """Record one denied connection and refuse it.

        Args:
            connection: The ASGI connection under check.
            handler: The route handler under check.

        Raises:
            PermissionDeniedException: Always.
        """
        self.calls.append((connection, handler))
        raise PermissionDeniedException(detail=self.detail)


@dataclass(slots=True)
class RecordingMetricsSink:
    """``SecurityMetrics`` sink keeping counters and observations apart.

    ``name in sink`` answers "was this metric touched at all", which is what
    most assertions want.
    """

    increments: list[tuple[str, dict[str, str]]] = field(default_factory=list)
    observations: list[tuple[str, float, dict[str, str]]] = field(default_factory=list)

    def increment(self, name: str, *, attributes: Mapping[str, str] = _NO_ATTRIBUTES) -> None:
        """Record one counter increment.

        Args:
            name: The counter name.
            attributes: Dimensions recorded with the increment.
        """
        self.increments.append((name, dict(attributes)))

    def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = _NO_ATTRIBUTES) -> None:
        """Record one observation.

        Args:
            name: The measurement name.
            value: The observed value.
            attributes: Dimensions recorded with the observation.
        """
        self.observations.append((name, value, dict(attributes)))

    def __contains__(self, name: object) -> bool:
        """Report whether a metric of this name was recorded at all.

        Args:
            name: The metric name to look for.

        Returns:
            ``True`` when the name was incremented or observed.
        """
        return any(recorded == name for recorded, _ in self.increments) or any(
            recorded == name for recorded, _, _ in self.observations
        )


@dataclass(slots=True)
class RecordingEventSink:
    """``SecurityEventSink`` collecting every emitted event."""

    events: list[object] = field(default_factory=list)

    async def emit(self, event: object) -> None:
        """Collect one event.

        Args:
            event: The emitted security event.
        """
        self.events.append(event)


@dataclass(slots=True)
class FailingEventSink:
    """``SecurityEventSink`` that raises, proving an observational failure is dropped."""

    error: Exception = field(default_factory=lambda: RuntimeError("sink unavailable"))
    events: list[object] = field(default_factory=list)

    async def emit(self, event: object) -> None:
        """Collect one event, then raise.

        Args:
            event: The emitted security event.

        Raises:
            Exception: Always, with the configured error.
        """
        self.events.append(event)
        raise self.error


@dataclass(slots=True)
class FailingStore:
    """Store whose named methods raise, for the fail-closed port paths.

    Any attribute is callable. Methods named in ``failing`` raise ``error``;
    every other call is recorded and returns ``None``, which is what the
    read-then-write halves of an atomic port contract expect. This replaces the
    per-test ``BrokenStore`` definitions across the account and WebSocket suites.
    """

    failing: tuple[str, ...] = ()
    error: Exception = field(default_factory=lambda: RuntimeError("store unavailable"))
    calls: list[tuple[str, dict[str, object]]] = field(default_factory=list)

    def __getattr__(self, name: str) -> Callable[..., Any]:
        """Return an async stub for any port method.

        Args:
            name: The port method being reached for.

        Returns:
            An async callable recording the call, raising for named methods.

        Raises:
            AttributeError: For dunder lookups, so protocol checks stay honest.
        """
        if name.startswith("__"):
            raise AttributeError(name)

        async def call(*args: object, **kwargs: object) -> None:
            self.calls.append((name, {**{str(index): value for index, value in enumerate(args)}, **kwargs}))
            if name in self.failing:
                raise self.error

        return call


class ProbeController(Controller):
    """Minimal controller for route-registration and guard-layering assertions.

    Not a dataclass: a Litestar ``Controller`` subclass must stay a plain class.
    """

    path = "/probe"

    @get("/", name="probe", sync_to_thread=False)
    def probe(self) -> dict[str, str]:
        """Return one constant body.

        Returns:
            A marker payload proving the route ran.
        """
        return {"probe": "ok"}


def _segment(value: Mapping[str, object]) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _next_response(responses: list[object], requests: list[JWKSFetchRequest], request: object) -> object:
    requests.append(request)
    if not responses:
        message = "Unexpected JWKS fetch"
        raise AssertionError(message)
    response = responses.pop(0)
    if isinstance(response, Exception):
        raise response
    return response(request) if callable(response) else response


class NotifyingLocalAccountStore(kit.InMemoryLocalAccountStore):
    """A kit account store that keeps the one-time tokens it was asked to deliver.

    The bundled store discards the delivery command deliberately: a real adapter
    hands it to an email service rather than storing it. A test driving the
    generated routes through registration, verification, or recovery needs the
    token those routes never return, so this subclass records each command it
    receives and delegates the rest unchanged.
    """

    __slots__ = ("delivered",)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Record deliveries alongside the store's own state.

        Args:
            *args: Positional arguments for the bundled store.
            **kwargs: Keyword arguments for the bundled store.
        """
        super().__init__(*args, **kwargs)
        self.delivered: list[Any] = []

    async def issue(self, issue: Any, notification: Any, *, event: Any) -> None:
        """Record one delivery command, then store the issue as the kit does.

        Args:
            issue: The purpose-token issue to store.
            notification: The delivery command carrying the one-time token.
            event: The durable security event committed with the issue.
        """
        self.delivered.append(notification)
        await super().issue(issue, notification, event=event)

    async def register(self, command: Any, password_hash: str, **kwargs: Any) -> Any:
        """Record the verification delivery registration commits alongside the account.

        Registration is one atomic call rather than an account write followed by
        an issue, so the delivery command reaches the store only here.

        Args:
            command: The registration command.
            password_hash: The hash to store for the new account.
            **kwargs: The remaining registration inputs, passed through.

        Returns:
            The registration outcome the kit produced.
        """
        verification = kwargs.get("verification")
        if verification is not None:
            self.delivered.append(verification.notification)
        return await super().register(command, password_hash, **kwargs)

    def token_for(self, template: str) -> str:
        """Return the most recent one-time token issued under one template.

        Args:
            template: The delivery template, such as ``"verification"``.

        Returns:
            The token the route delivered but never returned.

        Raises:
            AssertionError: If no delivery under that template was recorded.
        """
        tokens = [command.token for command in self.delivered if command.template == template]
        assert tokens, f"no {template} token was delivered"
        return tokens[-1]
