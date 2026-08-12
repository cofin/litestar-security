"""Shared test collaborators, so a fake is defined once and found by the next test.

Two kinds of thing live here.

**Kit-backed builders.** Where ``litestar_security.testing`` already ships a
double, the builder is a thin wrapper over it and adds only defaults. Where the
kit ships a *production* adapter -- ``MemoryOAuthAccountStore``,
``MemoryOAuthTransactionStore``, ``AESGCMSecretProtector``,
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

import asyncio
import json
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from threading import get_ident
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

import httpx
from litestar import Controller, get
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
from litestar_security.context import Principal
from litestar_security.providers.jwt import JWTValidationConfig
from litestar_security.providers.oauth import ProtectedOAuthSecret, ProviderIdentity, ProviderTokenSet, SecretStr

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Mapping, Sequence

    from litestar_security.providers.api_key import APIKeyClaims, APIKeyState
    from litestar_security.providers.jwks import JWKSFetchOutcome, JWKSFetchTarget

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
    "oauth_transactions",
    "passkeys",
    "step_up",
    "websocket_connect_tokens",
)

_TOKEN_PEPPER = b"t" * 32
_DEFAULT_EXPIRES_IN = 300


class MemoryAPIKeyStore:
    """Mutable atomic API-key store supporting runtime fault scripting."""

    def __init__(self) -> None:
        self.records: dict[str, APIKeyState] = {}
        self._lock = asyncio.Lock()
        self.get_calls: list[str] = []
        self.fail_get = False

    async def get(self, key_id: str) -> APIKeyState | None:
        """Return and record one lookup."""
        self.get_calls.append(key_id)
        if self.fail_get:
            msg = "store detail"
            raise RuntimeError(msg)
        return self.records.get(key_id)

    async def create(self, record: APIKeyState) -> None:
        """Create one unique record atomically."""
        async with self._lock:
            if record.key_id in self.records:
                msg = "duplicate API-key id"
                raise ValueError(msg)
            self.records[record.key_id] = record

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyState, overlap_until: datetime | None, now: datetime
    ) -> None:
        """Rotate one current record atomically."""
        async with self._lock:
            current = self.records[current_key_id]
            if current.revoked_at is not None or replacement.key_id in self.records:
                msg = "API key rotation conflict"
                raise ValueError(msg)
            bounded = (
                min(overlap_until, current.expires_at)
                if overlap_until is not None and current.expires_at is not None
                else overlap_until
            )
            self.records[current_key_id] = replace(current, revoked_at=now, overlap_until=bounded)
            self.records[replacement.key_id] = replacement

    async def revoke(self, *, key_id: str, now: datetime) -> None:
        """Revoke one record atomically."""
        async with self._lock:
            self.records[key_id] = replace(self.records[key_id], revoked_at=now, overlap_until=None)


def build_api_key_store() -> MemoryAPIKeyStore:
    """Build an isolated mutable API-key store."""
    return MemoryAPIKeyStore()


@dataclass(slots=True)
class RecordingOAuthProtector:
    """Deterministic OAuth transaction protector with an optional failure switch."""

    fail: bool = False
    active_key_version: str = "test-key"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        """Protect deterministically or raise the configured operational failure."""
        del associated_data
        if self.fail:
            msg = "secret protect detail"
            raise RuntimeError(msg)
        return ProtectedOAuthSecret(
            ciphertext=bytes(value ^ 0xA5 for value in secret), key_version=self.active_key_version
        )

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        """Recover deterministically or raise the configured operational failure."""
        del associated_data
        if self.fail:
            msg = "secret unprotect detail"
            raise RuntimeError(msg)
        return bytes(value ^ 0xA5 for value in protected.ciphertext)


class RecordingAPIKeyResolver:
    """Resolve API-key claims and record each normalized claim."""

    def __init__(self) -> None:
        self.claims: list[APIKeyClaims] = []

    async def resolve(self, claims: APIKeyClaims) -> Principal[str]:
        """Resolve one API-key subject."""
        self.claims.append(claims)
        return Principal(id=claims.subject_id, user=claims.subject_id)


class RecordingAPIKeyUsageSink:
    """Record usage observations with an optional operational failure."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, datetime]] = []
        self.fail = False

    async def record(self, *, key_id: str, used_at: datetime) -> None:
        """Record one observation or raise the configured failure."""
        self.calls.append((key_id, used_at))
        if self.fail:
            msg = "usage detail"
            raise RuntimeError(msg)


class RecordingAPIMetrics:
    """Record metric increments while accepting observations."""

    def __init__(self) -> None:
        self.increments: list[str] = []

    def increment(self, name: str, **_kwargs: object) -> None:
        """Record one counter name."""
        self.increments.append(name)

    def observe(self, _name: str, _value: float, **_kwargs: object) -> None:
        """Accept one observation."""


class SyncMemoryAPIKeyStore:
    """Synchronous API-key store recording worker thread identities."""

    def __init__(self) -> None:
        self.records: dict[str, APIKeyState] = {}
        self.thread_ids: list[int] = []

    def get(self, key_id: str) -> APIKeyState | None:
        """Return a record and capture the executing thread."""
        self.thread_ids.append(get_ident())
        return self.records.get(key_id)

    def create(self, record: APIKeyState) -> None:
        """Create a record and capture the executing thread."""
        self.thread_ids.append(get_ident())
        self.records[record.key_id] = record

    def rotate(
        self, *, current_key_id: str, replacement: APIKeyState, overlap_until: datetime | None, now: datetime
    ) -> None:
        """Rotate a record and capture the executing thread."""
        self.thread_ids.append(get_ident())
        current = self.records[current_key_id]
        self.records[current_key_id] = replace(current, revoked_at=now, overlap_until=overlap_until)
        self.records[replacement.key_id] = replacement

    def revoke(self, *, key_id: str, now: datetime) -> None:
        """Revoke a record and capture the executing thread."""
        self.thread_ids.append(get_ident())
        self.records[key_id] = replace(self.records[key_id], revoked_at=now, overlap_until=None)


class RecordingDNSResolver:
    """Return fixed DNS answers and record every lookup."""

    def __init__(self, answers: Mapping[str, tuple[str, ...]]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, int]] = []

    async def __call__(self, hostname: str, port: int) -> tuple[str, ...]:
        """Resolve one configured host."""
        self.calls.append((hostname, port))
        if hostname not in self.answers:
            msg = f"Unexpected DNS lookup for {hostname}:{port}"
            raise AssertionError(msg)
        return self.answers[hostname]


class RecordingMockTransport(httpx.MockTransport):
    """HTTPX mock transport recording requests and close state."""

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        super().__init__(handler)
        self.requests: list[httpx.Request] = []
        self.was_closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Record and dispatch one request."""
        self.requests.append(request)
        return await super().handle_async_request(request)

    async def aclose(self) -> None:
        """Record and perform closure."""
        self.was_closed = True
        await super().aclose()


class ChunkedByteStream(httpx.AsyncByteStream):
    """Deterministic async response stream exposing configured chunks."""

    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.was_iterated = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield configured chunks in order."""
        self.was_iterated = True
        for chunk in self.chunks:
            yield chunk


class ProviderPrincipalResolver:
    """Resolve a text claim into a principal with the same identifier."""

    async def resolve(self, claims: str) -> Principal[object]:
        """Build the principal."""
        return Principal(id=claims)


class AsyncRecordingJWTVerifier:
    """JWT verifier returning one configured outcome and recording calls."""

    def __init__(self, outcome: object, config: JWTValidationConfig) -> None:
        self.outcome = outcome
        self.config = config
        self.calls: list[tuple[str, datetime]] = []

    async def verify(self, token: str, *, now: datetime) -> object:
        """Record and return the configured outcome."""
        self.calls.append((token, now))
        return self.outcome


def build_recording_jwt_verifier(
    outcome: object,
    *,
    issuer: str = "https://issuer.example",
    audiences: frozenset[str] = frozenset({"litestar-security"}),
) -> AsyncRecordingJWTVerifier:
    """Build a recording verifier with a safe fixed validation policy."""
    return AsyncRecordingJWTVerifier(
        outcome, JWTValidationConfig(issuer=issuer, audiences=audiences, algorithms=frozenset({"HS256"}))
    )


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
    requests: list[JWKSFetchTarget] = field(default_factory=list)
    closes: int = 0

    async def fetch(self, request: JWKSFetchTarget) -> JWKSFetchOutcome:
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


def _next_response(responses: list[object], requests: list[JWKSFetchTarget], request: object) -> object:
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
