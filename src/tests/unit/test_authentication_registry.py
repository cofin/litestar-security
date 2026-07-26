"""Unit tests for authentication outcomes and registry compilation."""

import asyncio
import base64
import gzip
import json
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from math import inf, nan
from pathlib import Path
from threading import Event as ThreadEvent
from threading import Lock as ThreadLock
from time import perf_counter, perf_counter_ns, sleep
from types import SimpleNamespace
from typing import Any, cast

import httpx
import jwt
import pytest
from anyio import CancelScope, CapacityLimiter, Event, create_task_group, fail_after, get_cancelled_exc_class
from anyio.lowlevel import checkpoint
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi.spec import SecurityScheme

from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationPolicy,
    AuthenticationRegistry,
    InvalidCredentials,
    MechanismRequirement,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
    all_of,
    any_of,
    at_least,
    mechanism,
    optional,
    public,
    required,
    security,
)
from litestar_security.config import ExternalCSRF, SecurityConfig
from litestar_security.context import AuthenticationEvidence, AuthorizationSnapshot, CredentialRestrictions, Principal
from litestar_security.providers import jwks as jwks_provider
from litestar_security.providers import jwt as jwt_provider
from litestar_security.providers import oidc as oidc_provider
from litestar_security.providers.jwks import (
    AsyncJWKSFetcher,
    CachedJWKSProvider,
    JWKSCacheEntry,
    JWKSCachePolicy,
    JWKSFetchRequest,
    JWKSFetchResponse,
    NoOpSecurityMetrics,
    SecurityMetrics,
    SyncJWKSFetcher,
    WorkerLimits,
    normalize_fetcher,
)
from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JWTClaims,
    JWTValidationConfig,
    LocalKeyRing,
    PyJWTVerifier,
    SigningKey,
    SyncJWTVerifier,
    SyncTokenSigner,
    TokenSigner,
    UnverifiedJWTRoute,
    VerificationKey,
    VerificationKeySet,
    build_access_token_claims,
    normalize_signer,
    normalize_verifier,
    parse_unverified_jwt_route,
)
from litestar_security.providers.oidc import DiscoveryPolicy, OIDCDiscoveryClient, OIDCDiscoveryError, OIDCMetadata

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
_NAIVE_JWT_NOW = datetime(2026, 7, 26)  # noqa: DTZ001 - explicit rejection fixture
_JWT_ISSUER = "https://issuer.example"
_JWT_AUDIENCE = "litestar-security"
_OIDC_ISSUER = "https://issuer.example/tenant"
_OIDC_DISCOVERY_URL = f"{_OIDC_ISSUER}/.well-known/openid-configuration"
_OIDC_PUBLIC_IP = "93.184.216.34"
_JWKS_URI = f"{_JWT_ISSUER}/.well-known/jwks.json"


def test_jwks_worker_and_metrics_contracts_are_safe_by_default() -> None:
    limits = WorkerLimits()
    metrics = NoOpSecurityMetrics()

    assert limits.network_tokens == 8
    assert limits.crypto_tokens == 32
    assert limits.timeout == 10.0
    assert limits.network_limiter.total_tokens == 8
    assert limits.crypto_limiter.total_tokens == 32
    assert limits.network_limiter is not limits.crypto_limiter
    assert isinstance(metrics, SecurityMetrics)
    metrics.increment("security.jwks.fresh_hit")
    metrics.observe("security.jwks.fetch_duration", 0.1)


@pytest.mark.parametrize(
    "kwargs", [{"network_tokens": 0}, {"crypto_tokens": True}, {"timeout": 0}, {"timeout": inf}, {"timeout": nan}]
)
def test_jwks_worker_limits_reject_invalid_capacity(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        WorkerLimits(**kwargs)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_jwks_fetcher_normalization_selects_async_or_bounded_sync_once() -> None:
    response = JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')
    metrics: list[str] = []

    class Metrics:
        def increment(self, name: str, *, attributes: Mapping[str, str] = {}) -> None:
            del attributes
            metrics.append(name)

        def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = {}) -> None:
            del name, value, attributes

    class AsyncFetcher:
        async def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return response

    class SyncFetcher:
        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return response

    request = JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI)
    async_fetcher = AsyncFetcher()
    normalized_async = normalize_fetcher(async_fetcher, limiter=CapacityLimiter(1))
    normalized_sync = normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(2), metrics=Metrics())

    assert normalized_async is async_fetcher
    assert isinstance(normalized_sync, AsyncJWKSFetcher)
    assert isinstance(SyncFetcher(), SyncJWKSFetcher)
    assert await normalized_async.fetch(request) is response
    assert await normalized_sync.fetch(request) is response
    assert "security.worker.saturation" not in metrics


def test_jwks_fetcher_normalization_rejects_invalid_configuration() -> None:
    cases = (
        (object(), 1.0, None, "must define fetch"),
        (_RecordingJWKSFetcher(), 0.0, None, "timeout must be finite and positive"),
        (_RecordingJWKSFetcher(), 1.0, object(), "must implement SecurityMetrics"),
        (_RecordingJWKSFetcher(), 1.0, None, "limiter must have finite bounded capacity"),
    )
    for index, (fetcher, timeout, metrics, match) in enumerate(cases):
        with pytest.raises(ImproperlyConfiguredException, match=match):
            normalize_fetcher(  # type: ignore[arg-type]
                fetcher,
                limiter=CapacityLimiter(inf if index == 3 else 1),
                timeout=timeout,
                metrics=metrics,  # type: ignore[arg-type]
            )


@pytest.mark.anyio
async def test_jwks_sync_fetcher_is_bounded_without_blocking_the_event_loop() -> None:
    started = ThreadEvent()
    release = ThreadEvent()
    calls: list[JWKSFetchResponse] = []

    class SyncFetcher:
        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            started.set()
            release.wait(timeout=1)
            return JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')

    normalized = normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(1))
    request = JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI)

    async def fetch() -> None:
        calls.append(await normalized.fetch(request))

    async with create_task_group() as task_group:
        task_group.start_soon(fetch)
        with fail_after(1):
            while not started.is_set():
                await checkpoint()
        task_group.start_soon(fetch)
        await checkpoint()
        assert calls == []
        release.set()

    assert len(calls) == 2


@pytest.mark.anyio
async def test_sync_crypto_normalization_is_bounded_and_keeps_the_event_loop_live() -> None:  # noqa: C901, PLR0915
    release = ThreadEvent()
    saturated = ThreadEvent()
    lock = ThreadLock()
    active = 0
    maximum_active = 0
    outcomes: list[InvalidCredentials] = []
    records: list[tuple[str, float | None]] = []
    stop_ticker = Event()
    ticker_count = 0

    class Metrics:
        def increment(self, name: str, *, attributes: Mapping[str, str] = {}) -> None:
            del attributes
            records.append((name, None))

        def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = {}) -> None:
            del attributes
            records.append((name, value))

    class SyncVerifier:
        config = _jwt_config("EdDSA")

        def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            nonlocal active, maximum_active
            assert now is _JWT_NOW
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
                if active == 2:
                    saturated.set()
            release.wait(timeout=1)
            with lock:
                active -= 1
            return InvalidCredentials()

    class AsyncVerifier:
        config = _jwt_config("EdDSA")

        async def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            assert now is _JWT_NOW
            return InvalidCredentials()

    class AsyncSigner:
        async def sign(self, _claims: Mapping[str, object], *, now: datetime) -> str:
            assert now is _JWT_NOW
            return "async"

    class SyncSigner:
        def sign(self, _claims: Mapping[str, object], *, now: datetime) -> str:
            assert now is _JWT_NOW
            return "sync"

    workers = WorkerLimits(crypto_tokens=2)
    metrics = Metrics()
    verifier = normalize_verifier(SyncVerifier(), worker_limits=workers, metrics=metrics)
    async_verifier = AsyncVerifier()
    async_signer = AsyncSigner()
    normalized_async_signer = normalize_signer(async_signer, worker_limits=workers, metrics=metrics)
    normalized_sync_signer = normalize_signer(SyncSigner(), worker_limits=workers, metrics=metrics)

    async def verify() -> None:
        outcomes.append(cast("InvalidCredentials", await verifier.verify("token", now=_JWT_NOW)))

    async def ticker() -> None:
        nonlocal ticker_count
        while not stop_ticker.is_set():
            ticker_count += 1
            await checkpoint()

    async with create_task_group() as task_group:
        task_group.start_soon(ticker)
        for _ in range(2):
            task_group.start_soon(verify)
        with fail_after(1):
            while not saturated.is_set():
                await checkpoint()
        for _ in range(98):
            task_group.start_soon(verify)
        with fail_after(1):
            while not any(name == "security.worker.saturation" for name, _ in records):
                await checkpoint()
        observed_ticks = ticker_count
        release.set()
        with fail_after(1):
            while len(outcomes) != 100:
                await checkpoint()
        stop_ticker.set()

    assert observed_ticks > 0
    assert maximum_active == 2
    assert len(outcomes) == 100
    assert isinstance(SyncVerifier(), SyncJWTVerifier)
    assert isinstance(SyncSigner(), SyncTokenSigner)
    assert normalize_verifier(async_verifier, worker_limits=workers, metrics=metrics) is async_verifier
    assert normalized_async_signer is async_signer
    assert await normalized_sync_signer.sign({}, now=_JWT_NOW) == "sync"
    names = [name for name, _ in records]
    assert {
        "security.worker.saturation",
        "security.worker.wait",
        "security.worker.duration",
        "security.jwt.verify_duration",
        "security.jwt.sign_duration",
    } <= set(names)
    assert all(value is None or value >= 0 for _, value in records)


@pytest.mark.anyio
async def test_sync_crypto_timeout_is_sanitized() -> None:
    release = ThreadEvent()

    class SyncVerifier:
        config = _jwt_config("EdDSA")

        def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            del now
            release.wait(timeout=1)
            return InvalidCredentials()

    class SyncSigner:
        def sign(self, _claims: Mapping[str, object], *, now: datetime) -> str:
            del now
            release.wait(timeout=1)
            return "token"

    workers = WorkerLimits(crypto_tokens=1, timeout=0.01)
    verifier = normalize_verifier(SyncVerifier(), worker_limits=workers)
    signer = normalize_signer(SyncSigner(), worker_limits=workers)

    outcome = await verifier.verify("token", now=_JWT_NOW)
    with pytest.raises(RuntimeError, match="Token signing unavailable"):
        await signer.sign({}, now=_JWT_NOW)
    release.set()

    assert isinstance(outcome, VerificationUnavailable)


def test_crypto_worker_configuration_rejects_invalid_values(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key = SigningKey(key_id="active", algorithm="EdDSA", private_key=jwt_key_material["EdDSA"][0])
    verification_key = VerificationKey(key_id="active", algorithm="EdDSA", key=jwt_key_material["EdDSA"][1])

    class SyncSigner:
        def sign(self, _claims: Mapping[str, object], *, now: datetime) -> str:
            del now
            return "token"

    class SyncVerifier:
        config = _jwt_config("EdDSA")

        def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            del now
            return InvalidCredentials()

    cases = (
        (lambda: normalize_signer(object()), "must define sign"),
        (lambda: normalize_signer(SyncSigner(), worker_limits=object()), "worker limits must be WorkerLimits"),
        (lambda: normalize_signer(SyncSigner(), metrics=object()), "metrics must implement SecurityMetrics"),
        (lambda: normalize_verifier(object()), "must define verify"),
        (lambda: normalize_verifier(SyncVerifier(), worker_limits=object()), "worker limits must be WorkerLimits"),
        (
            lambda: VerificationKeySet(issuer=_JWT_ISSUER, keys=(verification_key,)).build_verifier(
                _jwt_config("EdDSA"),
                worker_limits=object(),  # type: ignore[arg-type]
            ),
            "worker limits must be WorkerLimits",
        ),
        (
            lambda: LocalKeyRing(
                issuer=_JWT_ISSUER,
                active_signing_key=signing_key,
                worker_limits=object(),  # type: ignore[arg-type]
            ),
            "worker limits must be WorkerLimits",
        ),
        (
            lambda: PyJWTVerifier(config=_jwt_config("EdDSA"), key=verification_key, limiter=CapacityLimiter(inf)),
            "limiter must have finite bounded capacity",
        ),
        (
            lambda: PyJWTVerifier(config=_jwt_config("EdDSA"), key=verification_key, worker_timeout=inf),
            "timeout must be finite and positive",
        ),
        (
            lambda: jwt_provider._LocalJWTSigner(  # noqa: SLF001
                issuer=_JWT_ISSUER, signing_key=signing_key, worker_timeout=inf
            ),
            "timeout must be finite and positive",
        ),
    )
    for factory, match in cases:
        with pytest.raises(ImproperlyConfiguredException, match=match):
            factory()


@pytest.mark.anyio
async def test_jwks_sync_fetcher_timeout_maps_to_unavailable(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    release = ThreadEvent()

    class SyncFetcher:
        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            release.wait(timeout=1)
            return _jwks_response(_verification_jwk(jwt_key_material))

    normalized = normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(1), timeout=0.01)
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=normalized)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    release.set()

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_metrics_are_vendor_neutral_and_redacted(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    records: list[tuple[str, float | None, dict[str, str]]] = []

    class Metrics:
        def increment(self, name: str, *, attributes: Mapping[str, str] = {}) -> None:
            records.append((name, None, dict(attributes)))

        def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = {}) -> None:
            records.append((name, value, dict(attributes)))

    known = _verification_jwk(jwt_key_material, key_id="known")
    fetcher = _RecordingJWKSFetcher(_jwks_response(known, cache_control="max-age=60"), OSError("operational-detail"))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, metrics=Metrics())

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW)
    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "attacker-kid", "EdDSA", now=_JWT_NOW)
    rendered = repr(records)

    assert {"security.jwks.refresh_success", "security.jwks.unknown_key", "security.jwks.refresh_failure"} <= {
        name for name, _, _ in records
    }
    assert all(value is None or value >= 0 for _, value, _ in records)
    assert all(secret not in rendered for secret in (_JWT_ISSUER, _JWKS_URI, "attacker-kid", "operational-detail"))


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"metrics": object()}, "must implement SecurityMetrics"),
        ({"fetcher_owned": 1}, "ownership must be boolean"),
        ({"worker_limits": object()}, "worker limits must be WorkerLimits"),
    ],
)
def test_jwks_provider_rejects_invalid_runtime_configuration(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        CachedJWKSProvider(
            entries=(_jwks_entry(),),
            fetcher=_RecordingJWKSFetcher(),
            **kwargs,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(("fetcher_owned", "expected_closes"), [(False, 0), (True, 1)])
@pytest.mark.anyio
async def test_jwks_provider_closes_only_owned_fetchers(
    *, fetcher_owned: bool, expected_closes: int, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    class Fetcher:
        def __init__(self) -> None:
            self.closes = 0

        async def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return _jwks_response(_verification_jwk(jwt_key_material))

        async def aclose(self) -> None:
            self.closes += 1

    fetcher = Fetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, fetcher_owned=fetcher_owned)

    await provider.aclose()
    await provider.aclose()

    assert fetcher.closes == expected_closes


@pytest.mark.anyio
async def test_jwks_provider_closes_owned_sync_fetcher_in_worker() -> None:
    class SyncFetcher:
        def __init__(self) -> None:
            self.closes = 0

        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')

        def close(self) -> None:
            self.closes += 1

    source = SyncFetcher()
    normalized = normalize_fetcher(source, limiter=CapacityLimiter(1))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=normalized, fetcher_owned=True)

    await provider.aclose()

    assert source.closes == 1


@pytest.mark.anyio
async def test_jwks_provider_accepts_owned_sync_fetcher_without_close() -> None:
    class SyncFetcher:
        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')

    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),),
        fetcher=normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(1)),
        fetcher_owned=True,
    )

    await provider.aclose()


@pytest.mark.parametrize("close_mode", ["absent", "sync"])
@pytest.mark.anyio
async def test_jwks_provider_accepts_owned_fetchers_without_async_close(close_mode: str) -> None:
    class Fetcher:
        async def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')

    class SyncCloseFetcher(Fetcher):
        def aclose(self) -> None:
            return None

    fetcher = Fetcher() if close_mode == "absent" else SyncCloseFetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, fetcher_owned=True)

    await provider.aclose()


def _jwt_claims(**overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": _JWT_ISSUER,
        "sub": "user-1",
        "aud": _JWT_AUDIENCE,
        "exp": int((_JWT_NOW + timedelta(minutes=10)).timestamp()),
        "iat": int(_JWT_NOW.timestamp()),
        "nbf": int((_JWT_NOW - timedelta(seconds=1)).timestamp()),
        "client_id": "client-1",
        "jti": "token-1",
        "scope": "reports:read profile",
        "metadata": {"groups": ["finance", "operations"]},
    }
    claims.update(overrides)
    return claims


def _jwt_config(
    algorithm: str,
    *,
    access_token_profile: bool = True,
    required_claims: frozenset[str] = frozenset({"iss", "sub", "aud", "exp", "iat"}),
    maximum_lifetime: timedelta | None = timedelta(hours=1),
) -> JWTValidationConfig:
    return JWTValidationConfig(
        issuer=_JWT_ISSUER,
        audiences=frozenset({_JWT_AUDIENCE}),
        algorithms=frozenset({algorithm}),
        required_claims=required_claims,
        access_token_profile=access_token_profile,
        maximum_lifetime=maximum_lifetime,
    )


def _encode_jwt(
    signing_key: bytes,
    algorithm: str,
    *,
    claims: Mapping[str, object] | None = None,
    headers: Mapping[str, object] | None = None,
    include_key_id: bool = True,
) -> str:
    protected: dict[str, object] = {"typ": "at+jwt"}
    if include_key_id:
        protected["kid"] = "key-1"
    if headers:
        protected.update(headers)
    encoded = jwt.encode(dict(claims or _jwt_claims()), signing_key, algorithm=algorithm, headers=protected)
    return encoded.decode() if isinstance(encoded, bytes) else encoded


def _jwt_segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _compact_jwt(header: bytes, payload: bytes, signature: bytes = b"signature") -> str:
    return ".".join((_jwt_segment(header), _jwt_segment(payload), _jwt_segment(signature)))


class _Slot:
    def __init__(self, name: str) -> None:
        self.name = name

    def extract(self, _connection: object) -> NoCredentials:
        return NoCredentials()


class _Authenticator:
    def __init__(self, name: str, slot: str, *, participates_by_default: bool = True) -> None:
        self.name = name
        self.slot = slot
        self.participates_by_default = participates_by_default

    async def authenticate(self, _credential: str, _connection: object) -> NoCredentials:
        return NoCredentials()


class _Resolver:
    async def resolve(self, claims: str) -> Principal[object]:
        return Principal(id=claims)


class _RecordingJWTVerifier:
    def __init__(self, outcome: object, config: JWTValidationConfig) -> None:
        self.outcome = outcome
        self.config = config
        self.calls: list[tuple[str, datetime]] = []

    async def verify(self, token: str, *, now: datetime) -> object:
        self.calls.append((token, now))
        return self.outcome


def _recording_jwt_verifier(
    outcome: object, *, issuer: str = _JWT_ISSUER, audiences: frozenset[str] = frozenset({_JWT_AUDIENCE})
) -> _RecordingJWTVerifier:
    return _RecordingJWTVerifier(
        outcome, JWTValidationConfig(issuer=issuer, audiences=audiences, algorithms=frozenset({"HS256"}))
    )


class _FakeOIDCResolver:
    def __init__(self, answers: Mapping[str, tuple[str, ...]]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, int]] = []

    async def __call__(self, hostname: str, port: int) -> tuple[str, ...]:
        self.calls.append((hostname, port))
        if hostname not in self.answers:
            msg = f"Unexpected DNS lookup for {hostname}:{port}"
            raise AssertionError(msg)
        return self.answers[hostname]


class _RecordingMockTransport(httpx.MockTransport):
    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        super().__init__(handler)
        self.requests: list[httpx.Request] = []
        self.was_closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return await super().handle_async_request(request)

    async def aclose(self) -> None:
        self.was_closed = True
        await super().aclose()


class _ChunkedOIDCStream(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.was_iterated = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.was_iterated = True
        for chunk in self.chunks:
            yield chunk


def _oidc_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "issuer": _OIDC_ISSUER,
        "jwks_uri": f"{_OIDC_ISSUER}/jwks",
        "authorization_endpoint": f"{_OIDC_ISSUER}/authorize",
        "token_endpoint": f"{_OIDC_ISSUER}/token",
        "end_session_endpoint": f"{_OIDC_ISSUER}/logout",
        "id_token_signing_alg_values_supported": ["EdDSA", "RS256"],
    }
    document.update(overrides)
    return document


def _oidc_response(
    document: Mapping[str, object] | None = None,
    *,
    status_code: int = 200,
    content: bytes | None = None,
    content_type: str | None = "application/json",
) -> httpx.Response:
    headers = {} if content_type is None else {"content-type": content_type}
    body = (
        json.dumps(dict(document if document is not None else _oidc_document()), separators=(",", ":")).encode()
        if content is None
        else content
    )
    return httpx.Response(status_code, content=body, headers=headers)


def _oidc_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    policy: DiscoveryPolicy | None = None,
    algorithms: frozenset[str] = frozenset({"EdDSA", "ES256"}),
    answers: Mapping[str, tuple[str, ...]] | None = None,
) -> tuple[OIDCDiscoveryClient, _RecordingMockTransport, _FakeOIDCResolver]:
    transport = _RecordingMockTransport(handler)
    resolver = _FakeOIDCResolver(
        {"issuer.example": (_OIDC_PUBLIC_IP,), "keys.example": (_OIDC_PUBLIC_IP,)} if answers is None else answers
    )
    client = OIDCDiscoveryClient(
        policy=policy or DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
        algorithms=algorithms,
        transport=transport,
        resolver=resolver,
    )
    return client, transport, resolver


async def _discover_and_close(client: OIDCDiscoveryClient, issuer: str = _OIDC_ISSUER) -> OIDCMetadata:
    try:
        return await client.discover(issuer)
    finally:
        await client.aclose()


class _RecordingJWKSFetcher:
    def __init__(
        self, *responses: JWKSFetchResponse | Exception | Callable[[JWKSFetchRequest], JWKSFetchResponse]
    ) -> None:
        self.responses = list(responses)
        self.requests: list[JWKSFetchRequest] = []

    async def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        self.requests.append(request)
        if not self.responses:
            message = "Unexpected JWKS fetch"
            raise AssertionError(message)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response(request) if callable(response) else response


class _BlockingJWKSFetcher:
    def __init__(
        self,
        *responses: JWKSFetchResponse | Exception | Callable[[JWKSFetchRequest], JWKSFetchResponse],
        immediate_calls: int = 0,
        maximum_calls: int = 1,
        issuers: tuple[str, ...] = (),
    ) -> None:
        self.responses = responses
        self.immediate_calls = immediate_calls
        self.maximum_calls = maximum_calls
        self.requests: list[JWKSFetchRequest] = []
        self.started = Event()
        self.started_by_issuer = {issuer: Event() for issuer in issuers}
        self.release = Event()
        self.finished = Event()
        self.active = 0
        self.cancelled = 0

    async def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        self.requests.append(request)
        call_number = len(self.requests)
        if call_number > self.maximum_calls:
            message = "Concurrent JWKS fetch escaped single-flight coordination"
            raise AssertionError(message)
        if call_number > self.immediate_calls:
            self.active += 1
            self.started.set()
            if issuer_started := self.started_by_issuer.get(request.issuer):
                issuer_started.set()
            try:
                await self.release.wait()
            except get_cancelled_exc_class():
                self.cancelled += 1
                raise
            finally:
                self.active -= 1
                if self.active == 0:
                    self.finished.set()
        response = self.responses[call_number - 1]
        if isinstance(response, Exception):
            raise response
        return response(request) if callable(response) else response


def _verification_jwk(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], algorithm: str = "EdDSA", key_id: str = "key-1"
) -> dict[str, object]:
    key = VerificationKey(key_id=key_id, algorithm=algorithm, key=jwt_key_material[algorithm][1])  # type: ignore[arg-type]
    return dict(cast("Mapping[str, object]", key.public_jwk))


def _raw_public_jwk(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], source_algorithm: str, algorithm: str, key_id: str
) -> dict[str, object]:
    public_key = serialization.load_pem_public_key(jwt_key_material[source_algorithm][1])
    serializer_algorithm = {"ES384": "ES256", "RS1024": "RS256"}.get(source_algorithm, source_algorithm)
    jwk = cast("dict[str, object]", jwt.get_algorithm_by_name(serializer_algorithm).to_jwk(public_key, as_dict=True))
    jwk.update({"alg": algorithm, "kid": key_id, "key_ops": ["verify"], "use": "sig"})
    return jwk


def _jwks_body(*keys: Mapping[str, object]) -> bytes:
    return json.dumps({"keys": [dict(key) for key in keys]}, separators=(",", ":")).encode()


def _jwks_response(
    *keys: Mapping[str, object],
    status_code: int = 200,
    body: bytes | None = None,
    cache_control: str | None = None,
    etag: str | None = None,
) -> JWKSFetchResponse:
    headers: dict[str, str] = {"content-type": "application/json"}
    if cache_control is not None:
        headers["cache-control"] = cache_control
    if etag is not None:
        headers["etag"] = etag
    return JWKSFetchResponse(status_code=status_code, body=_jwks_body(*keys) if body is None else body, headers=headers)


def _jwks_entry(
    issuer: str = _JWT_ISSUER, jwks_uri: str = _JWKS_URI, algorithms: frozenset[str] = frozenset({"EdDSA"})
) -> JWKSCacheEntry:
    return JWKSCacheEntry(issuer=issuer, jwks_uri=jwks_uri, algorithms=algorithms)


def _jwks_performance_baseline() -> dict[str, Any]:
    baseline_path = Path(__file__).parents[3] / "benchmarks" / "jwks-runtime-v1.json"
    return cast("dict[str, Any]", json.loads(baseline_path.read_text(encoding="utf-8")))


def _p95(values: list[float]) -> float:
    return sorted(values)[max(0, (len(values) * 95 + 99) // 100 - 1)]


@pytest.mark.performance
def test_jwks_performance_baseline_has_relative_budget_schema() -> None:
    baseline = _jwks_performance_baseline()

    assert baseline["schema_version"] == 1
    assert baseline["benchmark"] == "jwks-runtime-foundation"
    assert baseline["interpretation"] == "relative regression gates; not absolute cross-machine claims"
    assert baseline["budgets"] == {
        "fresh_hit_p95_ratio": {"comparison": "fresh_selection_and_verify/direct_lookup_and_verify", "maximum": 1.2},
        "sync_ticker_delay_p95_ms": {"comparison": "event_loop_tick_overshoot", "maximum": 10.0},
    }
    assert set(baseline["observed"]) == {"fresh_hit_p95_ratio", "sync_ticker_delay_p95_ms"}
    assert all(baseline["observed"][name] <= budget["maximum"] for name, budget in baseline["budgets"].items())


@pytest.mark.performance
@pytest.mark.anyio
async def test_jwks_performance_fresh_issuer_path_is_lock_and_fetch_free(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    second_issuer = "https://fresh.example"
    second_uri = f"{second_issuer}/jwks"
    first = _jwks_response(_verification_jwk(jwt_key_material, key_id="first"), cache_control="max-age=30")
    second = _jwks_response(_verification_jwk(jwt_key_material, key_id="second"), cache_control="max-age=300")
    fetcher = _BlockingJWKSFetcher(first, second, first, immediate_calls=2, maximum_calls=3)

    class FailingLock:
        async def __aenter__(self) -> None:
            message = "fresh selection acquired the entry lock"
            raise AssertionError(message)

        async def __aexit__(self, *_args: object) -> None:
            return None

    provider = CachedJWKSProvider(entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri)), fetcher=fetcher)
    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "first", "EdDSA", now=_JWT_NOW)
    await provider.select_key(second_issuer, second_uri, "second", "EdDSA", now=_JWT_NOW)
    state = cast("Any", provider)._entries[(second_issuer, second_uri)]  # noqa: SLF001
    state.lock = FailingLock()
    fresh_result: list[object] = []

    async def refresh_expired() -> None:
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "first", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))

    async with create_task_group() as task_group:
        task_group.start_soon(refresh_expired)
        await fetcher.started.wait()
        with fail_after(0.1):
            fresh_result.append(
                await provider.select_key(
                    second_issuer, second_uri, "second", "EdDSA", now=_JWT_NOW + timedelta(seconds=30)
                )
            )
        fetcher.release.set()

    assert isinstance(fresh_result[0], VerificationKey)
    assert len(fetcher.requests) == 3


@pytest.mark.performance
@pytest.mark.anyio
async def test_jwks_performance_single_flight_and_cache_bounds(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    keys = tuple(_verification_jwk(jwt_key_material, key_id=f"known-{index}") for index in range(4))
    response = _jwks_response(*keys, cache_control="max-age=60")
    blocking_fetcher = _BlockingJWKSFetcher(response)
    cold_provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=blocking_fetcher)
    cold_results: list[object | None] = [None] * 100

    async def select_cold(index: int) -> None:
        cold_results[index] = await cold_provider.select_key(_JWT_ISSUER, _JWKS_URI, "known-0", "EdDSA", now=_JWT_NOW)

    async with create_task_group() as task_group:
        for index in range(len(cold_results)):
            task_group.start_soon(select_cold, index)
        await blocking_fetcher.started.wait()
        await checkpoint()
        blocking_fetcher.release.set()

    policy = JWKSCachePolicy(maximum_keys=4, maximum_unknown_keys=64)
    not_modified = JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"})
    bounded_fetcher = _RecordingJWKSFetcher(response, not_modified)
    bounded_provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=bounded_fetcher, policy=policy)
    await bounded_provider.select_key(_JWT_ISSUER, _JWKS_URI, "known-0", "EdDSA", now=_JWT_NOW)
    for _ in range(1_000):
        await bounded_provider.select_key(
            _JWT_ISSUER, _JWKS_URI, "repeated-unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=1)
        )
    for index in range(1_000):
        await bounded_provider.select_key(
            _JWT_ISSUER, _JWKS_URI, f"unknown-{index}", "EdDSA", now=_JWT_NOW + timedelta(seconds=1)
        )
    state = cast("Any", bounded_provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001

    assert len(blocking_fetcher.requests) == 1
    assert all(result is cold_results[0] for result in cold_results)
    assert len(bounded_fetcher.requests) == 2
    assert len(cast("Any", bounded_provider)._entries) == 1  # noqa: SLF001
    assert len(state.snapshot.keys) <= policy.maximum_keys
    assert len(state.negative) <= policy.maximum_unknown_keys


@pytest.mark.performance
@pytest.mark.anyio
async def test_jwks_performance_fresh_hit_p95_is_relative_to_direct_verification(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    private_key, _public_key = jwt_key_material["EdDSA"]
    token = _encode_jwt(private_key, "EdDSA")
    fetcher = _RecordingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material), cache_control="max-age=300"))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    selected = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    assert isinstance(selected, VerificationKey)
    decode_options = {"verify_exp": False, "verify_iat": False, "verify_nbf": False}

    def verify(key: bytes) -> None:
        jwt.decode(token, key, algorithms=["EdDSA"], audience=_JWT_AUDIENCE, issuer=_JWT_ISSUER, options=decode_options)

    for _ in range(20):
        verify(selected.key)
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    direct_samples: list[float] = []
    fresh_samples: list[float] = []
    direct = {("key-1", "EdDSA"): selected}
    for index in range(300):
        if index % 2:
            started = perf_counter_ns()
            fresh = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
            assert isinstance(fresh, VerificationKey)
            verify(fresh.key)
            fresh_samples.append(float(perf_counter_ns() - started))
        started = perf_counter_ns()
        verify(direct[("key-1", "EdDSA")].key)
        direct_samples.append(float(perf_counter_ns() - started))
        if not index % 2:
            started = perf_counter_ns()
            fresh = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
            assert isinstance(fresh, VerificationKey)
            verify(fresh.key)
            fresh_samples.append(float(perf_counter_ns() - started))

    ratio = _p95(fresh_samples) / _p95(direct_samples)
    maximum = _jwks_performance_baseline()["budgets"]["fresh_hit_p95_ratio"]["maximum"]

    assert ratio <= maximum


@pytest.mark.performance
@pytest.mark.anyio
async def test_jwks_performance_saturated_sync_verification_keeps_ticker_under_budget() -> None:
    pending = 100
    tick_overshoots_ms: list[float] = []

    class SyncVerifier:
        config = _jwt_config("EdDSA")

        def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            assert now is _JWT_NOW
            sleep(0.002)
            return InvalidCredentials()

    verifier = normalize_verifier(SyncVerifier(), worker_limits=WorkerLimits(crypto_tokens=2))

    async def verify() -> None:
        nonlocal pending
        await verifier.verify("token", now=_JWT_NOW)
        pending -= 1

    async def ticker() -> None:
        interval = 0.001
        last_tick = perf_counter()
        while pending:
            await asyncio.sleep(interval)
            tick = perf_counter()
            tick_overshoots_ms.append(max(0.0, tick - last_tick - interval) * 1_000)
            last_tick = tick

    async with create_task_group() as task_group:
        task_group.start_soon(ticker)
        for _ in range(pending):
            task_group.start_soon(verify)

    maximum = _jwks_performance_baseline()["budgets"]["sync_ticker_delay_p95_ms"]["maximum"]
    observed_p95 = _p95(tick_overshoots_ms)

    assert len(tick_overshoots_ms) >= 10
    assert observed_p95 <= maximum


def _mechanism(
    name: str, slot: str, *, participates_by_default: bool = True
) -> AuthenticationMechanism[str, str, object]:
    return AuthenticationMechanism(
        authenticator=_Authenticator(name, slot, participates_by_default=participates_by_default),  # type: ignore[arg-type]
        resolver=_Resolver(),
    )


def test_outcomes_are_distinct_immutable_and_secret_safe() -> None:
    evidence = AuthenticationEvidence(
        mechanism="local", slot="authorization.bearer", authenticated_at=datetime(2026, 7, 26, tzinfo=timezone.utc)
    )
    presented = PresentedCredential("secret-token")
    outcomes = (
        NoCredentials(),
        Authenticated(claims={"sub": "user-1"}, evidence=evidence),
        InvalidCredentials(),
        VerificationUnavailable(retry_after=30),
    )

    assert tuple(type(outcome) for outcome in outcomes) == (
        NoCredentials,
        Authenticated,
        InvalidCredentials,
        VerificationUnavailable,
    )
    assert "secret-token" not in repr(presented)
    with pytest.raises(FrozenInstanceError):
        outcomes[2].code = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("slots", "mechanisms", "match"),
    [
        ([_Slot(" ")], [], "slot name"),
        ([_Slot("cookie"), _Slot(" cookie ")], [], "Duplicate credential slot"),
        ([_Slot("cookie")], [_mechanism(" ", "cookie")], "mechanism name"),
        (
            [_Slot("cookie"), _Slot("header")],
            [_mechanism("local", "cookie"), _mechanism(" local ", "header")],
            "Duplicate authentication mechanism",
        ),
        ([_Slot("cookie")], [_mechanism("local", "missing")], "undefined credential slot"),
        (
            [_Slot("cookie")],
            [_mechanism("local", "cookie"), _mechanism("backup", "cookie")],
            "Duplicate owner for credential slot",
        ),
        (
            [_Slot("authorization.bearer")],
            [_mechanism("local-jwt", "authorization.bearer"), _mechanism("oidc", "authorization.bearer")],
            "authorization.bearer",
        ),
    ],
)
def test_registry_rejects_invalid_or_ambiguous_ownership(
    slots: list[_Slot], mechanisms: list[AuthenticationMechanism[str, str, object]], match: str
) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        AuthenticationRegistry(slots=slots, mechanisms=mechanisms)  # type: ignore[arg-type]


def test_registry_normalizes_order_and_default_participation() -> None:
    registry = AuthenticationRegistry(
        slots=[_Slot(" cookie "), _Slot(" x-api-key ")],  # type: ignore[list-item]
        mechanisms=[
            _mechanism(" local ", " cookie "),
            _mechanism(" api-key ", " x-api-key ", participates_by_default=False),
        ],
    )

    assert registry.slot_names == ("cookie", "x-api-key")
    assert registry.mechanism_names == ("local", "api-key")
    assert registry.default_mechanism_names == ("local",)
    assert registry.get_slot(" cookie ").name == " cookie "
    assert registry.get_mechanism(" api-key ").authenticator.name == " api-key "
    assert registry.get_mechanism_for_slot("cookie") is registry.get_mechanism("local")
    assert registry.get_mechanism_for_slot("unused") is None


def test_required_default_plan_rejects_zero_participants() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="required default authentication"):
        AuthenticationRegistry(
            slots=[_Slot("x-api-key")],  # type: ignore[list-item]
            mechanisms=[_mechanism("api-key", "x-api-key", participates_by_default=False)],
            require_default=True,
        )


def test_policy_helpers_are_immutable_hashable_and_deterministic() -> None:
    oidc = mechanism(" oidc ", " reports:read ", "profile")
    policies = (
        public(),
        required(),
        required("session"),
        any_of("session", oidc),
        all_of("session", oidc),
        at_least(2, "session", oidc, "api-key"),
        optional(all_of("session", oidc)),
    )

    assert oidc == MechanismRequirement("oidc", ("reports:read", "profile"))
    assert required("session") == any_of("session")
    assert policies == tuple(policies)
    assert len(set(policies)) == len(policies)
    with pytest.raises(FrozenInstanceError):
        oidc.name = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (AuthenticationPolicy, "policy helper"),
        (lambda: security(cast("AuthenticationPolicy", object())), "policy helper"),
        (lambda: mechanism(" "), "mechanism name"),
        (lambda: mechanism("oidc", " "), "scope"),
        (lambda: mechanism("oidc", "read", " read "), "Duplicate scope"),
        (any_of, "at least one"),
        (lambda: any_of("session", " session "), "Duplicate mechanism"),
        (all_of, "at least one"),
        (lambda: all_of("session", mechanism("session")), "Duplicate mechanism"),
        (lambda: optional(public()), "positive"),
        (lambda: optional(optional(required("session"))), "nested optional"),
        (lambda: at_least(0, "a"), "between 1 and"),
        (lambda: at_least(2, "a"), "between 1 and"),
        (lambda: at_least(1, "a", " a "), "Duplicate mechanism"),
    ],
)
def test_policy_helpers_reject_invalid_or_unfaithful_expressions(factory: Callable[[], object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        factory()


def test_required_without_arguments_is_the_implicit_secure_default() -> None:
    config = SecurityConfig()

    assert isinstance(config.default_policy, AuthenticationPolicy)
    assert config.default_policy == required()
    assert config.default_policy != public()
    assert required() != required("session")


@pytest.mark.parametrize(
    "kwargs", [{"scheme_name": "bearer"}, {"security_scheme": SecurityScheme(type="http", scheme="bearer")}]
)
def test_authentication_mechanism_requires_complete_openapi_scheme_pair(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="configured together"):
        AuthenticationMechanism(
            authenticator=_Authenticator("a", "slot-a"),  # type: ignore[arg-type]
            resolver=_Resolver(),
            **kwargs,
        )


def test_authentication_mechanism_declares_session_capability() -> None:
    mechanism_value = AuthenticationMechanism(
        authenticator=_Authenticator("session", "session"),  # type: ignore[arg-type]
        resolver=_Resolver(),
        session_capable=True,
    )

    assert mechanism_value.session_capable is True


def test_external_csrf_requires_a_named_integration() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="name must not be blank"):
        ExternalCSRF(name=" ", validate=lambda _path, _method, _policy: True)


@pytest.mark.parametrize("limit", [0, -1])
def test_security_config_requires_positive_openapi_combination_limit(limit: int) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=r"max_openapi_combinations.*positive"):
        SecurityConfig(max_openapi_combinations=limit)


@pytest.mark.parametrize("case", [(None,), (True,), (False,)])
def test_security_returns_fresh_route_metadata_without_changing_policy(case: tuple[bool | None]) -> None:
    csrf_required = case[0]
    policy = optional(required(mechanism("oidc", "profile")))

    first = security(policy, csrf_required=csrf_required)
    second = security(policy, csrf_required=csrf_required)
    first_declaration = next(iter(first.values()))
    second_declaration = next(iter(second.values()))

    assert first is not second
    assert first == second
    assert first_declaration.policy is policy
    assert first_declaration.csrf_required is csrf_required
    assert first_declaration == second_declaration
    with pytest.raises(FrozenInstanceError):
        first_declaration.csrf_required = not csrf_required  # type: ignore[misc]


@pytest.mark.anyio
async def test_composite_bearer_dispatcher_selects_only_one_verifier() -> None:
    calls: list[tuple[str, str]] = []

    class _CompositeBearer(_Authenticator):
        async def authenticate(self, credential: str, _connection: object) -> Authenticated[str]:
            issuer, claims = credential.split(":", maxsplit=1)
            calls.append((issuer, claims))
            return Authenticated(
                claims=claims,
                evidence=AuthenticationEvidence(
                    mechanism=f"bearer:{issuer}",
                    slot=self.slot,
                    authenticated_at=datetime(2026, 7, 26, tzinfo=timezone.utc),
                ),
            )

    authenticator = _CompositeBearer("bearer", "authorization.bearer")
    registry = AuthenticationRegistry(
        slots=[_Slot("authorization.bearer")],  # type: ignore[list-item]
        mechanisms=[AuthenticationMechanism(authenticator=authenticator, resolver=_Resolver())],
    )

    outcome = await registry.get_mechanism("bearer").authenticator.authenticate(
        "local:user-1",
        None,  # type: ignore[arg-type]
    )

    assert isinstance(outcome, Authenticated)
    assert calls == [("local", "user-1")]


@pytest.mark.parametrize(
    ("headers", "expected_type", "expected_value"),
    [
        ([], NoCredentials, None),
        ([(b"authorization", b"Bearer compact.jwt.value")], PresentedCredential, "compact.jwt.value"),
        ([(b"authorization", b"bEaReR compact.jwt.value")], PresentedCredential, "compact.jwt.value"),
        (
            [(b"authorization", b"Bearer one.two.three"), (b"Authorization", b"Bearer four.five.six")],
            InvalidCredentials,
            None,
        ),
        ([(b"authorization", b"")], InvalidCredentials, None),
        ([(b"authorization", b"Basic credential")], InvalidCredentials, None),
        ([(b"authorization", b" Bearer one.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer  one.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer\tone.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer one.two.three\x7f")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer \xff")], InvalidCredentials, None),
    ],
    ids=[
        "absent",
        "bearer",
        "case-insensitive-scheme",
        "duplicate",
        "empty",
        "wrong-scheme",
        "leading-space",
        "double-space",
        "tab",
        "control",
        "non-ascii",
    ],
)
def test_composite_bearer_extracts_the_raw_authorization_namespace_once(
    headers: list[tuple[bytes, bytes]],
    expected_type: type[NoCredentials] | type[PresentedCredential[object]] | type[InvalidCredentials],
    expected_value: str | None,
) -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    )
    physical_slot, _ = composite.build(_Resolver())

    extraction = physical_slot.extract(SimpleNamespace(scope={"headers": headers}))  # type: ignore[arg-type]

    assert isinstance(extraction, expected_type)
    assert getattr(extraction, "value", None) == expected_value


def test_composite_bearer_rejects_oversized_credentials_during_extraction() -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
        maximum_token_bytes=5,
    )
    physical_slot, _ = composite.build(_Resolver())

    extraction = physical_slot.extract(
        SimpleNamespace(scope={"headers": [(b"authorization", b"Bearer longer")]})  # type: ignore[arg-type]
    )

    assert extraction == InvalidCredentials()


def _routing_token(*, issuer: str, audiences: str | list[str], token_type: str | None = None) -> str:
    return _compact_jwt(
        json.dumps({"alg": "RS256", "kid": "shared", "typ": token_type or "at+jwt"}, separators=(",", ":")).encode(),
        json.dumps({"iss": issuer, "aud": audiences}, separators=(",", ":")).encode(),
    )


@pytest.mark.parametrize(
    ("issuer", "audience", "selected_name"),
    [("https://local.example", "local-api", "local"), ("https://oidc.example", "oidc-api", "oidc")],
)
@pytest.mark.anyio
async def test_composite_bearer_selects_exactly_one_trust_slot(issuer: str, audience: str, selected_name: str) -> None:
    grants = AuthorizationSnapshot(
        scopes=frozenset({"reports:read"}),
        roles=frozenset({"analyst"}),
        capabilities=frozenset({"reports"}),
        team_roles={"team-1": frozenset({"viewer"})},
        tenant_ids=frozenset({"tenant-1"}),
        attributes={"region": "north"},
    )
    restrictions = CredentialRestrictions(
        scopes=frozenset({"reports:read"}), roles=frozenset({"analyst"}), tenant_ids=frozenset({"tenant-1"})
    )
    authenticated = Authenticated(
        claims="user-1",
        evidence=AuthenticationEvidence(
            mechanism="provider",
            slot="provider-slot",
            authenticated_at=_JWT_NOW,
            expires_at=_JWT_NOW + timedelta(1),
            methods=frozenset({"jwt"}),
            traits=frozenset({"phishing-resistant"}),
            acr="urn:example:acr:2",
            amr=("pwd", "otp"),
        ),
        grants=grants,
        restrictions=restrictions,
    )
    local = _recording_jwt_verifier(authenticated, issuer="https://local.example", audiences=frozenset({"local-api"}))
    oidc = _recording_jwt_verifier(authenticated, issuer="https://oidc.example", audiences=frozenset({"oidc-api"}))
    token = _routing_token(issuer=issuer, audiences=audience)
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(
                    issuers=frozenset({"https://local.example"}), audiences=frozenset({"local-api"})
                ),
                verifier=local,  # type: ignore[arg-type]
            ),
            BearerTokenSlot(
                name="oidc",
                selector=BearerSlotSelector(
                    issuers=frozenset({"https://oidc.example"}), audiences=frozenset({"oidc-api"})
                ),
                verifier=oidc,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

    assert isinstance(outcome, Authenticated)
    assert outcome.evidence.mechanism == "bearer"
    assert outcome.evidence.slot == selected_name
    assert outcome.evidence == AuthenticationEvidence(
        mechanism="bearer",
        slot=selected_name,
        authenticated_at=_JWT_NOW,
        expires_at=_JWT_NOW + timedelta(1),
        methods=frozenset({"jwt"}),
        traits=frozenset({"phishing-resistant"}),
        acr="urn:example:acr:2",
        amr=("pwd", "otp"),
    )
    assert outcome.grants == grants
    assert outcome.restrictions == restrictions
    assert len(local.calls) + len(oidc.calls) == 1
    assert (local.calls if selected_name == "local" else oidc.calls) == [(token, _JWT_NOW)]


@pytest.mark.anyio
async def test_composite_bearer_cryptographically_isolates_same_kid_trust_domains(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    local_signing_key, local_verification_key = jwt_key_material["RS256"]
    oidc_signing_key, oidc_verification_key = jwt_key_material["RS256_ALT"]
    profiles = (
        ("local", "https://local.example", "local-api", local_signing_key, local_verification_key),
        ("oidc", "https://oidc.example", "oidc-api", oidc_signing_key, oidc_verification_key),
    )
    slots = tuple(
        BearerTokenSlot(
            name=name,
            selector=BearerSlotSelector(issuers=frozenset({issuer}), audiences=frozenset({audience})),
            verifier=PyJWTVerifier(
                config=JWTValidationConfig(
                    issuer=issuer, audiences=frozenset({audience}), algorithms=frozenset({"RS256"})
                ),
                key=verification_key,
                require_key_id=True,
            ),
        )
        for name, issuer, audience, _signing_key, verification_key in profiles
    )
    _, mechanism_value = CompositeBearerConfig(mechanism_name="bearer", slots=slots).build(
        _Resolver(), clock=lambda: _JWT_NOW
    )

    for name, issuer, audience, signing_key, _verification_key in profiles:
        token = _encode_jwt(signing_key, "RS256", claims=_jwt_claims(iss=issuer, aud=audience))
        outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

        assert isinstance(outcome, Authenticated)
        assert outcome.claims.issuer == issuer
        assert outcome.evidence.slot == name

    cross_domain_token = _encode_jwt(
        local_signing_key, "RS256", claims=_jwt_claims(iss="https://oidc.example", aud="oidc-api")
    )
    cross_domain_outcome = await mechanism_value.authenticator.authenticate(
        cross_domain_token,
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert cross_domain_outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("selectors", "audiences"),
    [
        (
            (
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"one", "two"})),
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"one"})),
            ),
            "one",
        ),
        (
            (
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"one"})),
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"two"})),
            ),
            ["one", "two"],
        ),
        (
            (
                BearerSlotSelector(issuers=frozenset({"https://one.example"})),
                BearerSlotSelector(issuers=frozenset({"https://other.example"})),
            ),
            "unknown",
        ),
    ],
    ids=["overlapping-audience-ambiguity", "multi-audience-ambiguity", "unknown"],
)
@pytest.mark.anyio
async def test_composite_bearer_rejects_unknown_or_ambiguous_routes_without_verification(
    selectors: tuple[BearerSlotSelector, BearerSlotSelector], audiences: str | list[str]
) -> None:
    verifiers = tuple(
        _recording_jwt_verifier(
            InvalidCredentials(),
            issuer=next(iter(selector.issuers)),
            audiences=selector.audiences
            or (frozenset({audiences}) if isinstance(audiences, str) else frozenset(audiences)),
        )
        for selector in selectors
    )
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=tuple(
            BearerTokenSlot(name=f"slot-{index}", selector=selector, verifier=verifiers[index])  # type: ignore[arg-type]
            for index, selector in enumerate(selectors)
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate(
        _routing_token(issuer="https://issuer.example", audiences=audiences),
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert outcome == InvalidCredentials(code="unknown_or_ambiguous_bearer_slot")
    assert not verifiers[0].calls
    assert not verifiers[1].calls


@pytest.mark.parametrize(
    ("verifier_outcome", "expected"),
    [
        (InvalidCredentials(code="provider_invalid"), InvalidCredentials(code="provider_invalid")),
        (
            VerificationUnavailable(code="provider_unavailable", retry_after=2),
            VerificationUnavailable(code="provider_unavailable", retry_after=2),
        ),
        (NoCredentials(), InvalidCredentials()),
    ],
    ids=["invalid", "unavailable", "unexpected-no-credentials"],
)
@pytest.mark.anyio
async def test_composite_bearer_preserves_selected_terminal_outcomes(
    verifier_outcome: InvalidCredentials | VerificationUnavailable | NoCredentials,
    expected: InvalidCredentials | VerificationUnavailable,
) -> None:
    verifier = _recording_jwt_verifier(verifier_outcome)
    token = _routing_token(issuer=_JWT_ISSUER, audiences=_JWT_AUDIENCE)
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

    assert outcome == expected
    assert verifier.calls == [(token, _JWT_NOW)]


@pytest.mark.anyio
async def test_composite_bearer_rejects_malformed_routes_before_verification() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate("malformed", SimpleNamespace())  # type: ignore[arg-type]

    assert outcome == InvalidCredentials()
    assert not verifier.calls


@pytest.mark.anyio
async def test_composite_bearer_uses_an_aware_utc_clock_by_default() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver())

    await mechanism_value.authenticator.authenticate(
        _routing_token(issuer=_JWT_ISSUER, audiences=_JWT_AUDIENCE),
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert verifier.calls[0][1].tzinfo is timezone.utc


def test_composite_bearer_builds_one_native_registry_mechanism() -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    )

    physical_slot, mechanism_value = composite.build(_Resolver())
    registry = AuthenticationRegistry(slots=(physical_slot,), mechanisms=(mechanism_value,))  # type: ignore[arg-type]

    assert registry.slot_names == ("authorization.bearer",)
    assert registry.mechanism_names == ("bearer",)
    assert mechanism_value.scheme_name == "bearer"
    assert mechanism_value.security_scheme == SecurityScheme(type="http", scheme="bearer", bearer_format="JWT")


@pytest.mark.anyio
async def test_composite_bearer_never_retains_or_represents_the_raw_token() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    physical_slot, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)
    token = _routing_token(issuer=_JWT_ISSUER, audiences=_JWT_AUDIENCE)
    extraction = physical_slot.extract(
        SimpleNamespace(scope={"headers": [(b"authorization", f"Bearer {token}".encode())]})  # type: ignore[arg-type]
    )
    outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

    assert isinstance(extraction, PresentedCredential)
    assert outcome == InvalidCredentials()
    assert all(
        token not in repr(value)
        for value in (composite, physical_slot, mechanism_value, mechanism_value.authenticator, extraction, outcome)
    )


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: BearerSlotSelector(issuers=frozenset()), "issuer"),
        (lambda: BearerSlotSelector(issuers=frozenset({_JWT_ISSUER}), token_types=frozenset()), "token types"),
        (lambda: CompositeBearerConfig(mechanism_name="bearer", slots=()), "at least one"),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=(
                    BearerTokenSlot(
                        name="duplicate",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    ),
                    BearerTokenSlot(
                        name="duplicate",
                        selector=BearerSlotSelector(issuers=frozenset({"https://other.example"})),
                        verifier=_recording_jwt_verifier(InvalidCredentials(), issuer="https://other.example"),  # type: ignore[arg-type]
                    ),
                ),
            ),
            "Duplicate bearer slot",
        ),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=tuple(
                    BearerTokenSlot(
                        name=f"slot-{index}",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    )
                    for index in range(2)
                ),
            ),
            "identical selector",
        ),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=(
                    BearerTokenSlot(
                        name="local",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    ),
                ),
                maximum_token_bytes=0,
            ),
            "maximum token bytes",
        ),
        (
            lambda: BearerTokenSlot(
                name="missing-config",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=cast("Any", SimpleNamespace()),
            ),
            "must expose JWTValidationConfig",
        ),
        (
            lambda: BearerTokenSlot(
                name="issuer-mismatch",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials(), issuer="https://other.example"),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
        (
            lambda: BearerTokenSlot(
                name="audience-mismatch",
                selector=BearerSlotSelector(
                    issuers=frozenset({_JWT_ISSUER}), audiences=frozenset({"another-audience"})
                ),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
        (
            lambda: BearerTokenSlot(
                name="type-mismatch",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER}), token_types=frozenset({"id+jwt"})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
    ],
)
def test_composite_bearer_configuration_rejects_ambiguous_or_unsafe_values(
    factory: Callable[[], object], match: str
) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        factory()


def test_composite_bearer_requires_a_callable_clock() -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    )

    with pytest.raises(ImproperlyConfiguredException, match="clock must be callable"):
        composite.build(_Resolver(), clock=None)  # type: ignore[arg-type]


@pytest.mark.parametrize("algorithm", ["EdDSA", "ES256", "RS256", "HS256"])
@pytest.mark.anyio
async def test_local_key_ring_signs_and_verifies_every_supported_algorithm(
    algorithm: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    private_key, _public_key = jwt_key_material[algorithm]
    signing_key = SigningKey(key_id=f"{algorithm.lower()}-active", algorithm=algorithm, private_key=private_key)
    ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=signing_key)
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=3,
        scopes=frozenset({"profile", "reports:read"}),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=10),
        jti="token-1",
        not_before=_JWT_NOW - timedelta(seconds=1),
    )

    token = await ring.build_signer().sign(claims, now=_JWT_NOW)
    outcome = await ring.build_verifier(_jwt_config(algorithm)).verify(token, now=_JWT_NOW)

    assert jwt.get_unverified_header(token) == {"alg": algorithm, "kid": f"{algorithm.lower()}-active", "typ": "at+jwt"}
    assert isinstance(outcome, Authenticated)
    assert outcome.claims.raw["se"] == 3
    assert outcome.claims.scopes == frozenset({"profile", "reports:read"})
    assert (
        signing_key.public_jwk is None if algorithm == "HS256" else signing_key.public_jwk["kid"] == signing_key.key_id
    )


@pytest.mark.anyio
async def test_local_key_ring_rotation_accepts_retained_keys_and_rejects_removed_keys(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    old_private, old_public = jwt_key_material["RS256"]
    new_private, _new_public = jwt_key_material["RS256_ALT"]
    old_ring = LocalKeyRing(
        issuer=_JWT_ISSUER, active_signing_key=SigningKey(key_id="old", algorithm="RS256", private_key=old_private)
    )
    new_active = SigningKey(key_id="new", algorithm="RS256", private_key=new_private)
    retained = VerificationKey(key_id="old", algorithm="RS256", key=old_public)
    rotated_ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=new_active, verification_keys=(retained,))
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=1,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=10),
        jti="rotation-token",
    )
    old_token = await old_ring.build_signer().sign(claims, now=_JWT_NOW)
    new_token = await rotated_ring.build_signer().sign(claims, now=_JWT_NOW)
    config = _jwt_config("RS256")

    assert isinstance(await rotated_ring.build_verifier(config).verify(old_token, now=_JWT_NOW), Authenticated)
    assert isinstance(await rotated_ring.build_verifier(config).verify(new_token, now=_JWT_NOW), Authenticated)
    assert rotated_ring.verification_key_set.keys == rotated_ring.all_verification_keys
    replacement_without_old = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=new_active)
    assert await replacement_without_old.build_verifier(config).verify(old_token, now=_JWT_NOW) == InvalidCredentials()
    verifier = rotated_ring.build_verifier(config)
    assert await verifier.verify("malformed", now=_JWT_NOW) == InvalidCredentials()
    missing_algorithm = _compact_jwt(
        b'{"kid":"old","typ":"at+jwt"}', json.dumps(dict(claims), separators=(",", ":")).encode()
    )
    assert await verifier.verify(missing_algorithm, now=_JWT_NOW) == InvalidCredentials()


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("blank-kid", "key id"),
        ("public-signing-key", "signing key"),
        ("weak-rsa", "RS256"),
        ("wrong-curve", "ES256"),
        ("wrong-ed-key", "EdDSA"),
        ("short-hmac", "HS256"),
        ("short-hmac-verification", "HS256"),
        ("mismatched-jwk", "correspond"),
        ("private-jwk", "public JWK"),
        ("wrong-jwk-alg", "public JWK"),
        ("wrong-jwk-use", "public JWK"),
        ("wrong-jwk-ops", "public JWK"),
        ("private-verification-key", "verification key"),
        ("wrong-verification-type", "verification key"),
        ("non-bytes-signing-key", "signing key"),
        ("non-bytes-verification-key", "verification key"),
        ("unsupported-signing-algorithm", "Unsupported local signing algorithm"),
        ("unsupported-verification-algorithm", "Unsupported local verification algorithm"),
        ("empty-key-set", "at least one key"),
        ("hmac-public-jwk", "public JWK"),
        ("mismatched-jwk-kid", "public JWK"),
        ("duplicate-kid", "Duplicate local key id"),
        ("issuer-mismatch", "issuer"),
        ("active-algorithm-excluded", "active signing algorithm"),
        ("no-compatible-key-set", "no key accepted"),
    ],
)
def test_local_key_ring_rejects_unsafe_startup_configuration(  # noqa: C901
    case: str, match: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    rsa_private, rsa_public = jwt_key_material["RS256"]
    alt_private, _alt_public = jwt_key_material["RS256_ALT"]
    valid = SigningKey(key_id="valid", algorithm="RS256", private_key=rsa_private)
    public_jwk = dict(cast("Mapping[str, object]", valid.public_jwk))

    def build_invalid() -> object:  # noqa: C901, PLR0911, PLR0912
        if case == "blank-kid":
            return SigningKey(key_id=" ", algorithm="RS256", private_key=rsa_private)
        if case == "public-signing-key":
            return SigningKey(key_id="public", algorithm="RS256", private_key=rsa_public)
        if case == "weak-rsa":
            return SigningKey(key_id="weak", algorithm="RS256", private_key=jwt_key_material["RS1024"][0])
        if case == "wrong-curve":
            return SigningKey(key_id="curve", algorithm="ES256", private_key=jwt_key_material["ES384"][0])
        if case == "wrong-ed-key":
            return SigningKey(key_id="wrong-ed", algorithm="EdDSA", private_key=rsa_private)
        if case == "short-hmac":
            return SigningKey(key_id="short", algorithm="HS256", private_key=b"too-short")
        if case == "short-hmac-verification":
            return VerificationKey(key_id="short", algorithm="HS256", key=b"too-short")
        if case == "mismatched-jwk":
            return SigningKey(key_id="valid", algorithm="RS256", private_key=alt_private, public_jwk=public_jwk)
        if case == "private-jwk":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "d": "secret"}
            )
        if case == "wrong-jwk-alg":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "alg": "ES256"}
            )
        if case == "wrong-jwk-use":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "use": "enc"}
            )
        if case == "wrong-jwk-ops":
            return SigningKey(
                key_id="valid",
                algorithm="RS256",
                private_key=rsa_private,
                public_jwk={**public_jwk, "key_ops": ["sign"]},
            )
        if case == "private-verification-key":
            return VerificationKey(key_id="private", algorithm="RS256", key=rsa_private)
        if case == "wrong-verification-type":
            return VerificationKey(key_id="wrong-type", algorithm="ES256", key=rsa_public)
        if case == "non-bytes-signing-key":
            return SigningKey(key_id="type", algorithm="RS256", private_key=cast("Any", "not-bytes"))
        if case == "non-bytes-verification-key":
            return VerificationKey(key_id="type", algorithm="RS256", key=cast("Any", "not-bytes"))
        if case == "unsupported-signing-algorithm":
            return SigningKey(key_id="unsupported", algorithm=cast("Any", "ES384"), private_key=rsa_private)
        if case == "unsupported-verification-algorithm":
            return VerificationKey(key_id="unsupported", algorithm=cast("Any", "ES384"), key=rsa_public)
        if case == "empty-key-set":
            return VerificationKeySet(issuer=_JWT_ISSUER, keys=())
        if case == "hmac-public-jwk":
            return SigningKey(
                key_id="hmac", algorithm="HS256", private_key=jwt_key_material["HS256"][0], public_jwk=public_jwk
            )
        if case == "mismatched-jwk-kid":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "kid": "other"}
            )
        if case == "duplicate-kid":
            return LocalKeyRing(
                issuer=_JWT_ISSUER,
                active_signing_key=valid,
                verification_keys=(VerificationKey(key_id="valid", algorithm="RS256", key=rsa_public),),
            )
        ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=valid)
        if case == "issuer-mismatch":
            return ring.build_verifier(
                JWTValidationConfig(
                    issuer="https://other.example",
                    audiences=frozenset({_JWT_AUDIENCE}),
                    algorithms=frozenset({"RS256"}),
                )
            )
        if case == "active-algorithm-excluded":
            retained = VerificationKey(key_id="retained-ec", algorithm="ES256", key=jwt_key_material["ES256"][1])
            return LocalKeyRing(
                issuer=_JWT_ISSUER, active_signing_key=valid, verification_keys=(retained,)
            ).build_verifier(_jwt_config("ES256"))
        return VerificationKeySet(
            issuer=_JWT_ISSUER, keys=(VerificationKey(key_id="rsa-only", algorithm="RS256", key=rsa_public),)
        ).build_verifier(_jwt_config("ES256"))

    with pytest.raises(ImproperlyConfiguredException, match=match):
        build_invalid()


def test_access_token_claim_builder_is_deterministic_minimal_and_validated() -> None:
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=7,
        scopes=frozenset({"z:write", "a:read"}),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=5),
        jti="token-1",
        not_before=_JWT_NOW + timedelta(seconds=2),
    )

    assert dict(claims) == {
        "iss": _JWT_ISSUER,
        "sub": "user-1",
        "aud": _JWT_AUDIENCE,
        "exp": int((_JWT_NOW + timedelta(minutes=5)).timestamp()),
        "iat": int(_JWT_NOW.timestamp()),
        "nbf": int((_JWT_NOW + timedelta(seconds=2)).timestamp()),
        "client_id": "client-1",
        "jti": "token-1",
        "scope": "a:read z:write",
        "se": 7,
    }
    assert not {"email", "password", "roles", "teams", "user"}.intersection(claims)
    with pytest.raises(TypeError):
        claims["sub"] = "changed"  # type: ignore[index]
    random_one = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=0,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=1),
    )
    random_two = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=0,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=1),
    )
    assert random_one["jti"] != random_two["jti"]
    assert "scope" not in random_one


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"issuer": " "}, "identifier"),
        ({"audience": " "}, "identifier"),
        ({"subject": " "}, "identifier"),
        ({"client_id": " "}, "identifier"),
        ({"security_epoch": -1}, "security epoch"),
        ({"security_epoch": True}, "security epoch"),
        ({"lifetime": timedelta(0)}, "lifetime"),
        ({"lifetime": timedelta(milliseconds=500)}, "whole second"),
        ({"now": _NAIVE_JWT_NOW}, "timezone-aware"),
        ({"not_before": _NAIVE_JWT_NOW}, "timezone-aware"),
        ({"not_before": _JWT_NOW + timedelta(minutes=6)}, "expiry"),
        ({"jti": " "}, "identifier"),
        ({"scopes": frozenset({" "})}, "identifier"),
    ],
)
def test_access_token_claim_builder_rejects_invalid_inputs(overrides: dict[str, object], match: str) -> None:
    kwargs: dict[str, object] = {
        "issuer": _JWT_ISSUER,
        "audience": _JWT_AUDIENCE,
        "subject": "user-1",
        "client_id": "client-1",
        "security_epoch": 0,
        "scopes": frozenset({"profile"}),
        "now": _JWT_NOW,
        "lifetime": timedelta(minutes=5),
        "jti": "token-1",
    }
    kwargs.update(overrides)

    with pytest.raises(ValueError, match=match):
        build_access_token_claims(**kwargs)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_local_signer_runs_crypto_in_a_worker_and_supports_custom_signers(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []
    observations: list[str] = []

    async def run_sync(function: Callable[[], object], **kwargs: object) -> object:
        calls.append(kwargs)
        return function()

    class Metrics:
        def increment(self, name: str, *, attributes: Mapping[str, str] = {}) -> None:
            del name, attributes

        def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = {}) -> None:
            del value, attributes
            observations.append(name)

    monkeypatch.setattr(jwt_provider.to_thread, "run_sync", run_sync)
    ring = LocalKeyRing(
        issuer=_JWT_ISSUER,
        active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=jwt_key_material["EdDSA"][0]),
        metrics=Metrics(),
    )
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=0,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=5),
        jti="worker-token",
    )

    token = await ring.build_signer().sign(claims, now=_JWT_NOW)

    class _CustomSigner:
        async def sign(self, custom_claims: Mapping[str, object], *, now: datetime) -> str:
            assert custom_claims is claims
            assert now is _JWT_NOW
            encoded = jwt.encode(
                dict(custom_claims),
                jwt_key_material["EdDSA"][0],
                algorithm="EdDSA",
                headers={"kid": "kms", "typ": "at+jwt"},
            )
            return encoded.decode() if isinstance(encoded, bytes) else encoded

    custom_signer: TokenSigner = _CustomSigner()  # type: ignore[assignment]
    custom_token = await custom_signer.sign(claims, now=_JWT_NOW)  # type: ignore[arg-type]
    custom_keys = VerificationKeySet(
        issuer=_JWT_ISSUER, keys=(VerificationKey(key_id="kms", algorithm="EdDSA", key=jwt_key_material["EdDSA"][1]),)
    )

    assert token.count(".") == 2
    assert len(calls) == 1
    assert calls[0]["abandon_on_cancel"] is True
    assert cast("CapacityLimiter", calls[0]["limiter"]).total_tokens == 32
    assert isinstance(await ring.build_verifier(_jwt_config("EdDSA")).verify(token, now=_JWT_NOW), Authenticated)
    assert {"security.jwt.sign_duration", "security.jwt.verify_duration"} <= set(observations)
    assert isinstance(custom_signer, TokenSigner)
    assert isinstance(
        await custom_keys.build_verifier(_jwt_config("EdDSA")).verify(custom_token, now=_JWT_NOW), Authenticated
    )

    async def unavailable(_function: Callable[[], object], **_kwargs: object) -> object:
        message = "private failure detail"
        raise OSError(message)

    monkeypatch.setattr(jwt_provider.to_thread, "run_sync", unavailable)
    with pytest.raises(RuntimeError, match="Token signing unavailable") as exc_info:
        await ring.build_signer().sign(claims, now=_JWT_NOW)
    assert "private failure detail" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("missing", "sub"),
        ("forbidden", ("email", "private@example.com")),
        ("issuer", "https://other.example"),
        ("issued_at", int(_JWT_NOW.timestamp()) + 1),
        ("not_before", int((_JWT_NOW + timedelta(hours=1)).timestamp())),
        ("scope", "profile  reports:read"),
    ],
)
@pytest.mark.anyio
async def test_local_signer_rejects_nonconforming_access_claims(
    mutation: str, value: object, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    ring = LocalKeyRing(
        issuer=_JWT_ISSUER,
        active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=jwt_key_material["EdDSA"][0]),
    )
    claims = dict(
        build_access_token_claims(
            issuer=_JWT_ISSUER,
            audience=_JWT_AUDIENCE,
            subject="user-1",
            client_id="client-1",
            security_epoch=0,
            scopes=frozenset({"profile"}),
            now=_JWT_NOW,
            lifetime=timedelta(minutes=5),
            jti="invalid-shape",
        )
    )
    if mutation == "missing":
        claims.pop(cast("str", value))
    elif mutation == "forbidden":
        key, item = cast("tuple[str, object]", value)
        claims[key] = item
    elif mutation == "issuer":
        claims["iss"] = value
    elif mutation == "issued_at":
        claims["iat"] = value
    elif mutation == "not_before":
        claims["nbf"] = value
    else:
        claims["scope"] = value

    with pytest.raises(ValueError, match="Invalid local access-token claims"):
        await ring.build_signer().sign(cast("Mapping[str, object]", claims), now=_JWT_NOW)  # type: ignore[arg-type]


def test_local_key_material_is_secret_safe(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    private_key, public_key = jwt_key_material["RS256"]
    signing_key = SigningKey(key_id="active", algorithm="RS256", private_key=private_key)
    verification_key = VerificationKey(key_id="retained", algorithm="RS256", key=public_key)
    ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=signing_key, verification_keys=(verification_key,))

    assert all(
        private_key.decode() not in repr(value) and public_key.decode() not in repr(value)
        for value in (signing_key, verification_key, ring, ring.build_signer())
    )
    for public_jwk in (signing_key.public_jwk, verification_key.public_jwk):
        assert public_jwk is not None
        assert not {"d", "dp", "dq", "k", "oth", "p", "q", "qi"}.intersection(public_jwk)


def test_local_keys_canonicalize_null_public_jwk_metadata(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    private_key, public_key = jwt_key_material["RS256"]
    generated = SigningKey(key_id="generated", algorithm="RS256", private_key=private_key)
    null_metadata = {
        **dict(cast("Mapping[str, object]", generated.public_jwk)),
        "alg": None,
        "key_ops": None,
        "kid": None,
        "use": None,
    }

    signing_key = SigningKey(
        key_id="active", algorithm="RS256", private_key=private_key, public_jwk=cast("Any", null_metadata)
    )
    verification_key = VerificationKey(
        key_id="retained", algorithm="RS256", key=public_key, public_jwk=cast("Any", null_metadata)
    )

    for public_jwk, key_id in ((signing_key.public_jwk, "active"), (verification_key.public_jwk, "retained")):
        assert public_jwk is not None
        assert public_jwk["alg"] == "RS256"
        assert public_jwk["key_ops"] == ("verify",)
        assert public_jwk["kid"] == key_id
        assert public_jwk["use"] == "sig"


@pytest.mark.parametrize(
    ("algorithm", "require_key_id"), [("EdDSA", True), ("ES256", True), ("RS256", True), ("HS256", False)]
)
@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_supported_algorithms_and_normalizes_claims(
    algorithm: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]], *, require_key_id: bool
) -> None:
    signing_key, verification_key = jwt_key_material[algorithm]
    token = _encode_jwt(signing_key, algorithm, claims=_jwt_claims(sub="user-\u0430"), include_key_id=require_key_id)
    verifier = PyJWTVerifier(config=_jwt_config(algorithm), key=verification_key, require_key_id=require_key_id)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)
    claims = outcome.claims
    assert isinstance(claims, JWTClaims)
    assert claims.issuer == _JWT_ISSUER
    assert claims.subject == "user-\u0430"
    assert claims.audiences == frozenset({_JWT_AUDIENCE})
    assert claims.scopes == frozenset({"reports:read", "profile"})
    assert claims.client_id == "client-1"
    assert claims.token_id == "token-1"  # noqa: S105 - public token identifier, not a credential
    assert claims.expires_at == _JWT_NOW + timedelta(minutes=10)


@pytest.mark.parametrize(
    ("scope_claims", "expected"),
    [
        ({"scope": "reports:read profile"}, frozenset({"reports:read", "profile"})),
        ({"scp": ["reports:read", "profile"]}, frozenset({"reports:read", "profile"})),
        ({"aud": [_JWT_AUDIENCE]}, frozenset()),
    ],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_only_documented_scope_shapes(
    scope_claims: dict[str, object], expected: frozenset[str], jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    claims = _jwt_claims()
    claims.pop("scope")
    claims.update(scope_claims)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=claims, include_key_id=False), now=_JWT_NOW
    )

    assert isinstance(outcome, Authenticated)
    assert outcome.claims.scopes == expected


def test_unverified_jwt_route_is_explicit_and_immutable() -> None:
    token = _compact_jwt(
        json.dumps({"alg": "HS256", "typ": "at+jwt"}, separators=(",", ":")).encode(),
        json.dumps({"iss": _JWT_ISSUER, "aud": [_JWT_AUDIENCE]}, separators=(",", ":")).encode(),
    )

    route = parse_unverified_jwt_route(token)

    assert isinstance(route, UnverifiedJWTRoute)
    assert route.header == {"alg": "HS256", "typ": "at+jwt"}
    assert route.payload == {"iss": _JWT_ISSUER, "aud": (_JWT_AUDIENCE,)}
    with pytest.raises(TypeError):
        route.header["alg"] = "none"  # type: ignore[index]


@pytest.mark.parametrize(
    "token",
    [
        "",
        "one.two",
        "one.two.three.four",
        "one..three",
        _compact_jwt(b"[]", b"{}"),
        _compact_jwt(b"{}", b"[]"),
        _compact_jwt(b"\xff", b"{}"),
        _compact_jwt(b'{"alg":"HS256","alg":"none"}', b"{}"),
        _compact_jwt(b"{}", b'{"iss":"one","iss":"two"}'),
        _compact_jwt(b"{}", b'{"value":NaN}'),
        _compact_jwt(b"{}", (b'{"nested":' * 33) + b"null" + (b"}" * 33)),
        _compact_jwt(b"{}", json.dumps({"value": "x" * 16_384}).encode()),
        "*.e30.c2ln",
        "é.e30.c2ln",
        "e30.e30.A",
        "e30.e30.AB",
    ],
    ids=[
        "empty",
        "two-segments",
        "four-segments",
        "empty-segment",
        "header-not-object",
        "payload-not-object",
        "invalid-utf8",
        "duplicate-header-member",
        "duplicate-payload-member",
        "non-finite-number",
        "excessive-json-depth",
        "excessive-token-size",
        "invalid-base64url",
        "non-ascii",
        "invalid-base64url-length",
        "non-canonical-base64url",
    ],
)
def test_unverified_jwt_route_rejects_malformed_or_ambiguous_json(token: str) -> None:
    assert parse_unverified_jwt_route(token) == InvalidCredentials()


@pytest.mark.parametrize("limits", [{"maximum_token_bytes": 0}, {"maximum_json_depth": 0}])
def test_unverified_jwt_route_rejects_invalid_parser_limits(limits: dict[str, int]) -> None:
    assert parse_unverified_jwt_route("e30.e30.c2ln", **limits) == InvalidCredentials()  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "protected_header",
    [
        {"crit": ["unknown"]},
        {"b64": True},
        {"jwk": {"kty": "oct", "k": "embedded"}},
        {"jku": "https://attacker.invalid/jwks"},
        {"x5u": "https://attacker.invalid/certificate"},
        {"x5c": ["certificate"]},
        {"x5t": "certificate-thumbprint"},
        {"x5t#S256": "certificate-thumbprint"},
    ],
    ids=["crit", "b64", "jwk", "jku", "x5u", "x5c", "x5t", "x5t-s256"],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_forbidden_jose_headers(
    protected_header: dict[str, object], jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)
    if "b64" in protected_header:
        header = {"alg": "HS256", "typ": "at+jwt", **protected_header}
        token = _compact_jwt(
            json.dumps(header, separators=(",", ":")).encode(),
            json.dumps(_jwt_claims(), separators=(",", ":")).encode(),
        )
    else:
        token = _encode_jwt(signing_key, "HS256", headers=protected_header, include_key_id=False)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("header", "algorithm"),
    [
        ({"alg": "none", "typ": "at+jwt"}, "none"),
        ({"typ": "at+jwt"}, "missing"),
        ({"alg": "HS256", "typ": "JWT"}, "HS256"),
        ({"alg": "HS256"}, "HS256"),
        ({"alg": "RS256", "typ": "at+jwt"}, "RS256"),
        ({"alg": "HS256", "typ": "at+jwt", "kid": 7}, "HS256"),
    ],
    ids=["none", "missing-alg", "id-token-type", "missing-type", "missing-asymmetric-kid", "malformed-key-id"],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_algorithm_type_and_key_id_confusion(
    header: dict[str, object], algorithm: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    verification_algorithm = "RS256" if algorithm == "RS256" else "HS256"
    verification_key = jwt_key_material[verification_algorithm][1]
    verifier = PyJWTVerifier(
        config=_jwt_config(verification_algorithm),
        key=verification_key,
        require_key_id=verification_algorithm == "RS256",
    )
    token = _compact_jwt(
        json.dumps(header, separators=(",", ":")).encode(), json.dumps(_jwt_claims(), separators=(",", ":")).encode()
    )

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_hmac_rsa_algorithm_confusion(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    token = _encode_jwt(jwt_key_material["HS256"][0], "HS256", include_key_id=False)
    verifier = PyJWTVerifier(config=_jwt_config("RS256"), key=jwt_key_material["RS256"][1], require_key_id=True)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("overrides", "removed"),
    [
        ({"iss": "https://issuer.examp\u043be"}, frozenset()),
        ({"aud": "another-service"}, frozenset()),
        ({"aud": []}, frozenset()),
        ({"aud": 7}, frozenset()),
        ({"aud": [_JWT_AUDIENCE, 7]}, frozenset()),
        ({"aud": [_JWT_AUDIENCE, " "]}, frozenset()),
        ({"aud": [_JWT_AUDIENCE, _JWT_AUDIENCE]}, frozenset()),
        ({"exp": int((_JWT_NOW - timedelta(seconds=31)).timestamp())}, frozenset()),
        ({"nbf": int((_JWT_NOW + timedelta(seconds=31)).timestamp())}, frozenset()),
        ({"iat": int((_JWT_NOW + timedelta(seconds=31)).timestamp())}, frozenset()),
        (
            {
                "nbf": int((_JWT_NOW + timedelta(seconds=5)).timestamp()),
                "exp": int((_JWT_NOW + timedelta(seconds=5)).timestamp()),
            },
            frozenset(),
        ),
        ({"exp": True}, frozenset()),
        ({"iat": 1.5}, frozenset()),
        ({"exp": 10**100}, frozenset()),
        (
            {
                "iat": int((_JWT_NOW - timedelta(hours=2)).timestamp()),
                "exp": int((_JWT_NOW + timedelta(minutes=1)).timestamp()),
            },
            frozenset(),
        ),
        ({"sub": ""}, frozenset()),
        ({"client_id": ""}, frozenset()),
        ({"jti": ""}, frozenset()),
        ({"scope": 7}, frozenset()),
        ({"scope": "reports:read reports:read"}, frozenset()),
        ({"scp": "reports:read"}, frozenset({"scope"})),
        ({"scp": ["reports:read", 7]}, frozenset({"scope"})),
        ({"scp": ["reports:read"], "scope": "profile"}, frozenset()),
        ({}, frozenset({"iss"})),
        ({}, frozenset({"sub"})),
        ({}, frozenset({"exp"})),
        ({}, frozenset({"iat"})),
    ],
    ids=[
        "issuer-unicode-lookalike",
        "audience-mismatch",
        "audience-empty",
        "audience-malformed",
        "audience-member-malformed",
        "audience-member-blank",
        "audience-duplicate",
        "expired",
        "not-before-in-future",
        "issued-at-in-future",
        "not-before-at-expiry",
        "boolean-numeric-date",
        "float-numeric-date",
        "numeric-date-overflow",
        "excessive-lifetime",
        "empty-subject",
        "empty-client-id",
        "empty-token-id",
        "scalar-scope",
        "duplicate-scope",
        "string-scp",
        "mixed-scp",
        "ambiguous-scope-claims",
        "missing-issuer",
        "missing-subject",
        "missing-expiry",
        "missing-issued-at",
    ],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_invalid_rfc_9068_claims(
    overrides: dict[str, object], removed: frozenset[str], jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    claims = _jwt_claims(**overrides)
    for claim in removed:
        claims.pop(claim)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=claims, include_key_id=False), now=_JWT_NOW
    )

    assert outcome == InvalidCredentials()


@pytest.mark.anyio
async def test_pyjwt_verifier_enforces_explicit_non_access_token_required_claims(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    verifier = PyJWTVerifier(
        config=_jwt_config(
            "HS256",
            access_token_profile=False,
            required_claims=frozenset({"iss", "sub", "aud", "exp", "iat", "tenant"}),
        ),
        key=verification_key,
        require_key_id=False,
    )

    outcome = await verifier.verify(_encode_jwt(signing_key, "HS256", include_key_id=False), now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_non_access_profile_without_optional_access_claims(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    claims = _jwt_claims()
    claims.pop("client_id")
    claims.pop("jti")
    verifier = PyJWTVerifier(
        config=_jwt_config("HS256", access_token_profile=False, maximum_lifetime=None),
        key=verification_key,
        require_key_id=False,
    )

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=claims, include_key_id=False), now=_JWT_NOW
    )

    assert isinstance(outcome, Authenticated)
    assert outcome.claims.client_id is None
    assert outcome.claims.token_id is None


@pytest.mark.parametrize("claim", ["client_id", "jti"])
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_malformed_optional_access_claims_in_non_access_profiles(
    claim: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    verifier = PyJWTVerifier(
        config=_jwt_config("HS256", access_token_profile=False), key=verification_key, require_key_id=False
    )

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=_jwt_claims(**{claim: 7}), include_key_id=False), now=_JWT_NOW
    )

    assert outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("token", "now"),
    [("malformed", _JWT_NOW), ("malformed", _JWT_NOW.replace(tzinfo=None))],
    ids=["malformed-compact", "naive-now"],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_invalid_verification_inputs(
    token: str, now: datetime, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=jwt_key_material["HS256"][1], require_key_id=False)

    assert await verifier.verify(token, now=now) == InvalidCredentials()


@pytest.mark.anyio
async def test_verified_claims_are_frozen_recursively_and_secret_safe(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    token = _encode_jwt(signing_key, "HS256", include_key_id=False)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)
    claims = outcome.claims
    with pytest.raises(FrozenInstanceError):
        claims.subject = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        verifier.config.issuer = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        claims.raw["sub"] = "changed"  # type: ignore[index]
    metadata = claims.raw["metadata"]
    assert isinstance(metadata, Mapping)
    with pytest.raises(TypeError):
        metadata["groups"] = []  # type: ignore[index]
    assert tuple(metadata["groups"]) == ("finance", "operations")  # type: ignore[arg-type]
    assert token not in repr(claims)
    assert token not in repr(verifier)
    assert verification_key.decode() not in repr(verifier)


@pytest.mark.parametrize(
    ("algorithm", "key_name", "key"),
    [
        ("HS256", None, b"short"),
        ("EdDSA", None, b"not-an-ed25519-key"),
        ("ES256", "ES384", None),
        ("RS256", "RS1024", None),
        ("RS256", "ES256", None),
    ],
    ids=["short-hmac", "invalid-ed25519", "wrong-ec-curve", "weak-rsa", "algorithm-key-mismatch"],
)
def test_pyjwt_verifier_validates_fixed_keys_at_startup_without_secret_repr(
    algorithm: str, key_name: str | None, key: bytes | None, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    verification_key = key if key is not None else jwt_key_material[cast("str", key_name)][1]

    with pytest.raises(ImproperlyConfiguredException, match=algorithm):
        PyJWTVerifier(config=_jwt_config(algorithm), key=verification_key, require_key_id=algorithm != "HS256")


@pytest.mark.parametrize(
    ("algorithm", "key"),
    [
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "sig", "d": "private"}),
        ("RS256", {"kty": "RSA", "alg": "ES256", "use": "sig"}),
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "enc"}),
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "sig", "key_ops": ["sign"]}),
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "sig", "key_ops": ["verify", "sign"]}),
        ("ES256", {"kty": "RSA", "alg": "ES256", "use": "sig"}),
        ("HS256", {"kty": "oct", "alg": "HS256", "use": "sig"}),
    ],
    ids=[
        "private-member",
        "alg-mismatch",
        "wrong-use",
        "wrong-key-op",
        "mixed-key-ops",
        "wrong-key-type",
        "remote-hmac",
    ],
)
def test_pyjwt_verifier_rejects_untrusted_or_incompatible_jwk_metadata(algorithm: str, key: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=algorithm):
        PyJWTVerifier(
            config=_jwt_config(algorithm),
            key=key,  # type: ignore[arg-type]
            require_key_id=algorithm != "HS256",
        )


@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_valid_public_jwk(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    signing_key, verification_key = jwt_key_material["RS256"]
    public_key = serialization.load_pem_public_key(verification_key)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    public_jwk.update({"alg": "RS256", "use": "sig"})
    verifier = PyJWTVerifier(config=_jwt_config("RS256"), key=public_jwk)

    outcome = await verifier.verify(_encode_jwt(signing_key, "RS256"), now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)


@pytest.mark.parametrize(
    ("algorithm", "prepared_key"),
    [
        ("ES256", ec.generate_private_key(ec.SECP384R1()).public_key()),
        ("EdDSA", ec.generate_private_key(ec.SECP256R1()).public_key()),
    ],
)
def test_pyjwt_verifier_rejects_incompatible_prepared_backend_keys(
    algorithm: str, prepared_key: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Algorithm:
        @staticmethod
        def prepare_key(_key: object) -> object:
            return prepared_key

    monkeypatch.setattr(jwt, "get_algorithm_by_name", lambda _algorithm: _Algorithm())

    with pytest.raises(ImproperlyConfiguredException, match=algorithm):
        PyJWTVerifier(config=_jwt_config(algorithm), key=b"configured-key")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer": " "},
        {"audiences": frozenset()},
        {"algorithms": frozenset()},
        {"algorithms": frozenset({"none"})},
        {"clock_skew": timedelta(seconds=-1)},
        {"maximum_lifetime": timedelta(0)},
        {"required_claims": frozenset({" "})},
        {"token_types": frozenset()},
    ],
)
def test_jwt_validation_config_rejects_unsafe_or_ambiguous_values(kwargs: dict[str, object]) -> None:
    values: dict[str, object] = {
        "issuer": _JWT_ISSUER,
        "audiences": frozenset({_JWT_AUDIENCE}),
        "algorithms": frozenset({"HS256"}),
    }
    values.update(kwargs)

    with pytest.raises(ImproperlyConfiguredException):
        JWTValidationConfig(**values)  # type: ignore[arg-type]


def test_pyjwt_verifier_rejects_non_positive_token_limit(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="maximum token bytes"):
        PyJWTVerifier(
            config=_jwt_config("HS256"), key=jwt_key_material["HS256"][1], require_key_id=False, maximum_token_bytes=0
        )


@pytest.mark.parametrize(
    ("error", "outcome_type"),
    [
        (jwt.InvalidTokenError("provider detail must not escape"), InvalidCredentials),
        (OSError("worker detail must not escape"), VerificationUnavailable),
    ],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_maps_and_sanitizes_verification_failures(
    error: Exception,
    outcome_type: type[InvalidCredentials] | type[VerificationUnavailable],
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    token = _encode_jwt(signing_key, "HS256", include_key_id=False)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    def fail_verification(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(jwt, "decode_complete", fail_verification)
    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert isinstance(outcome, outcome_type)
    assert "provider detail" not in repr(outcome)
    assert "worker detail" not in repr(outcome)


@pytest.mark.anyio
async def test_oidc_discovery_derives_one_exact_url_and_returns_pinned_metadata() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == _OIDC_DISCOVERY_URL
        return _oidc_response(content_type="application/json; charset=utf-8")

    client, transport, resolver = _oidc_client(handler)

    metadata = await _discover_and_close(client)

    assert metadata == OIDCMetadata(
        issuer=_OIDC_ISSUER,
        jwks_uri=f"{_OIDC_ISSUER}/jwks",
        authorization_endpoint=f"{_OIDC_ISSUER}/authorize",
        token_endpoint=f"{_OIDC_ISSUER}/token",
        end_session_endpoint=f"{_OIDC_ISSUER}/logout",
        algorithms=frozenset({"EdDSA"}),
    )
    assert transport.was_closed is True
    assert transport.requests[0].url == httpx.URL(_OIDC_DISCOVERY_URL)
    assert ("issuer.example", 443) in resolver.calls
    with pytest.raises(FrozenInstanceError):
        metadata.issuer = "changed"  # type: ignore[misc]


@pytest.mark.anyio
async def test_oidc_discovery_client_context_returns_itself_and_closes_transport() -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    async with client as entered:
        assert entered is client
        metadata = await entered.discover(_OIDC_ISSUER)

    assert metadata.issuer == _OIDC_ISSUER
    assert transport.was_closed is True


def test_discovery_policy_normalizes_configured_trust_boundaries_once() -> None:
    policy = DiscoveryPolicy(
        allowed_issuers=frozenset({"https://BÜCHER.example:443/", "https://EXAMPLE.com/tenant"}),
        allowed_jwks_origins=frozenset({"https://KEYS.example:443"}),
    )

    assert policy.allowed_issuers == frozenset({"https://xn--bcher-kva.example", "https://example.com/tenant"})
    assert policy.allowed_jwks_origins == frozenset({"https://keys.example"})
    with pytest.raises(FrozenInstanceError):
        policy.require_https = False  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"allowed_issuers": frozenset()},
        {"allowed_issuers": frozenset({""})},
        {"allowed_issuers": frozenset({7})},
        {"allowed_issuers": frozenset({"issuer.example"})},
        {"allowed_issuers": frozenset({"http://issuer.example"})},
        {"allowed_issuers": frozenset({"https://user@issuer.example"})},
        {"allowed_issuers": frozenset({"https://issuer.example?tenant=one"})},
        {"allowed_issuers": frozenset({"https://issuer.example#tenant"})},
        {"allowed_issuers": frozenset({"https://issuer.example:8443"})},
        {"allowed_issuers": frozenset({"https://issuer.example/tenant/"})},
        {"allowed_issuers": frozenset({"https://issuer.example/tenant/../other"})},
        {"allowed_issuers": frozenset({"https://issuer.example/tenant/%2e%2e/other"})},
        {
            "allowed_issuers": frozenset({_OIDC_ISSUER}),
            "allowed_jwks_origins": frozenset({"https://keys.example/path"}),
        },
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "allowed_ports": frozenset()},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "allowed_ports": frozenset({0})},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "connect_timeout": 0},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "read_timeout": -1},
        {"allowed_issuers": frozenset({_OIDC_ISSUER}), "maximum_document_bytes": 0},
    ],
    ids=[
        "empty-allowlist",
        "empty-url",
        "non-string-url",
        "relative",
        "http",
        "userinfo",
        "query",
        "fragment",
        "port",
        "non-root-trailing-slash",
        "dot-segment",
        "encoded-dot-segment",
        "jwks-origin-path",
        "empty-ports",
        "invalid-port",
        "connect-timeout",
        "read-timeout",
        "body-limit",
    ],
)
def test_discovery_policy_rejects_ambiguous_or_unsafe_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        DiscoveryPolicy(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "algorithms",
    [frozenset(), frozenset({"none"}), frozenset({""}), frozenset({" RS256"}), frozenset({7})],
    ids=["empty", "unsupported", "empty-member", "unnormalized", "non-string"],
)
def test_oidc_discovery_client_rejects_invalid_pinned_algorithms(algorithms: frozenset[object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        OIDCDiscoveryClient(
            policy=DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
            algorithms=algorithms,  # type: ignore[arg-type]
            transport=_RecordingMockTransport(lambda _request: _oidc_response()),
            resolver=_FakeOIDCResolver({"issuer.example": (_OIDC_PUBLIC_IP,)}),
        )


@pytest.mark.parametrize(
    "issuer",
    ["https://issuer.example/tenant/", "https://issuer.example/other", "https://unconfigured.example/tenant"],
    ids=["trailing-slash", "different-path", "different-host"],
)
@pytest.mark.anyio
async def test_oidc_discovery_rejects_non_exact_issuer_without_dns_or_network(issuer: str) -> None:
    def fail_request(_request: httpx.Request) -> httpx.Response:
        msg = "Discovery transport must not run"
        raise AssertionError(msg)

    client, transport, resolver = _oidc_client(fail_request, answers={})

    with pytest.raises(ImproperlyConfiguredException):
        await _discover_and_close(client, issuer)

    assert transport.requests == []
    assert resolver.calls == []


@pytest.mark.parametrize("issuer", ["https://ISSUER.example/tenant", "https://issuer.example:443/tenant"])
@pytest.mark.anyio
async def test_oidc_discovery_canonicalizes_equivalent_allowed_issuer_forms(issuer: str) -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    metadata = await _discover_and_close(client, issuer)

    assert metadata.issuer == _OIDC_ISSUER
    assert transport.requests[0].url == httpx.URL(_OIDC_DISCOVERY_URL)


@pytest.mark.parametrize(
    ("addresses", "accepted"),
    [
        (("93.184.216.34",), True),
        (("2001:4860:4860::8888",), True),
        (("93.184.216.34", "10.0.0.1"), False),
        (("127.0.0.1",), False),
        (("10.0.0.1",), False),
        (("172.16.0.1",), False),
        (("192.168.0.1",), False),
        (("169.254.1.1",), False),
        (("224.0.0.1",), False),
        (("0.0.0.0",), False),  # noqa: S104 - SSRF rejection fixture
        (("240.0.0.1",), False),
        (("::1",), False),
        (("fc00::1",), False),
        (("fe80::1",), False),
        (("ff00::1",), False),
        (("::",), False),
        (("::ffff:10.0.0.1",), False),
        (("not-an-ip",), False),
    ],
    ids=[
        "public-ipv4",
        "public-ipv6",
        "mixed-public-private",
        "loopback-v4",
        "private-10",
        "private-172",
        "private-192",
        "link-local-v4",
        "multicast-v4",
        "unspecified-v4",
        "reserved-v4",
        "loopback-v6",
        "private-v6",
        "link-local-v6",
        "multicast-v6",
        "unspecified-v6",
        "mapped-private-v4",
        "malformed-answer",
    ],
)
@pytest.mark.anyio
async def test_oidc_discovery_classifies_every_dns_answer(addresses: tuple[str, ...], *, accepted: bool) -> None:
    client, transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(), answers={"issuer.example": addresses}
    )

    if accepted:
        metadata = await _discover_and_close(client)
        assert metadata.issuer == _OIDC_ISSUER
        assert len(transport.requests) == 1
    else:
        with pytest.raises(OIDCDiscoveryError):
            await _discover_and_close(client)
        assert transport.requests == []


@pytest.mark.anyio
async def test_oidc_discovery_maps_resolver_runtime_failures_without_network() -> None:
    async def fail_resolution(_hostname: str, _port: int) -> tuple[str, ...]:
        message = "resolver detail must not escape"
        raise RuntimeError(message)

    transport = _RecordingMockTransport(lambda _request: _oidc_response())
    client = OIDCDiscoveryClient(
        policy=DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
        algorithms=frozenset({"EdDSA"}),
        transport=transport,
        resolver=fail_resolution,
    )

    with pytest.raises(OIDCDiscoveryError) as exc_info:
        await _discover_and_close(client)

    assert transport.requests == []
    assert "resolver detail" not in repr(exc_info.value)


@pytest.mark.anyio
async def test_oidc_discovery_rejects_an_empty_dns_result_without_network() -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response(), answers={"issuer.example": ()})

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)

    assert transport.requests == []


@pytest.mark.anyio
async def test_oidc_discovery_classifies_literal_public_ip_without_resolving() -> None:
    issuer = "https://93.184.216.34"
    resolver_calls: list[tuple[str, int]] = []

    async def fail_if_resolved(hostname: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((hostname, port))
        message = "Literal addresses must not reach DNS"
        raise AssertionError(message)

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == f"{issuer}/.well-known/openid-configuration"
        return _oidc_response(
            _oidc_document(
                issuer=issuer,
                jwks_uri=f"{issuer}/jwks",
                authorization_endpoint=None,
                token_endpoint=None,
                end_session_endpoint=None,
            )
        )

    transport = _RecordingMockTransport(handler)
    client = OIDCDiscoveryClient(
        policy=DiscoveryPolicy(allowed_issuers=frozenset({issuer})),
        algorithms=frozenset({"EdDSA"}),
        transport=transport,
        resolver=fail_if_resolved,
    )

    metadata = await _discover_and_close(client, issuer)

    assert metadata.issuer == issuer
    assert resolver_calls == []


@pytest.mark.anyio
async def test_oidc_discovery_default_resolver_deduplicates_getaddrinfo_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int, int]] = []

    async def fake_getaddrinfo(host: str, port: int, **kwargs: int) -> list[tuple[object, ...]]:
        calls.append((host, port, kwargs["type"]))
        address = (_OIDC_PUBLIC_IP, port)
        return [(object(), object(), object(), "", address), (object(), object(), object(), "", address)]

    monkeypatch.setattr(oidc_provider, "getaddrinfo", fake_getaddrinfo)
    transport = _RecordingMockTransport(lambda _request: _oidc_response())
    client = OIDCDiscoveryClient(
        policy=DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
        algorithms=frozenset({"EdDSA"}),
        transport=transport,
    )

    metadata = await _discover_and_close(client)

    assert metadata.issuer == _OIDC_ISSUER
    assert calls == [("issuer.example", 443, oidc_provider.socket.SOCK_STREAM)]


@pytest.mark.anyio
async def test_oidc_discovery_allows_explicit_controlled_private_keycloak_hosts() -> None:
    issuer = "http://keycloak.internal:8080/realms/application"
    policy = DiscoveryPolicy(
        allowed_issuers=frozenset({issuer}),
        require_https=False,
        allow_private_hosts=True,
        allowed_ports=frozenset({8080}),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == f"{issuer}/.well-known/openid-configuration"
        return _oidc_response(
            _oidc_document(
                issuer=issuer,
                jwks_uri=f"{issuer}/protocol/openid-connect/certs",
                authorization_endpoint=None,
                token_endpoint=None,
                end_session_endpoint=None,
            )
        )

    client, _transport, _resolver = _oidc_client(handler, policy=policy, answers={"keycloak.internal": ("10.0.0.10",)})

    metadata = await _discover_and_close(client, issuer)

    assert metadata.issuer == issuer
    assert metadata.jwks_uri == f"{issuer}/protocol/openid-connect/certs"


@pytest.mark.parametrize("allowed", [False, True])
@pytest.mark.anyio
async def test_oidc_discovery_requires_explicit_cross_origin_jwks(*, allowed: bool) -> None:
    policy = DiscoveryPolicy(
        allowed_issuers=frozenset({_OIDC_ISSUER}),
        allowed_jwks_origins=frozenset({"https://keys.example"}) if allowed else frozenset(),
    )
    client, _transport, resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(jwks_uri="https://keys.example/jwks")), policy=policy
    )

    if allowed:
        metadata = await _discover_and_close(client)
        assert metadata.jwks_uri == "https://keys.example/jwks"
        assert ("keys.example", 443) in resolver.calls
    else:
        with pytest.raises(OIDCDiscoveryError):
            await _discover_and_close(client)
        assert resolver.calls == [("issuer.example", 443)]


@pytest.mark.parametrize(
    ("jwks_uri", "answers"),
    [
        ("http://issuer.example/tenant/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example:8443/tenant/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://user@issuer.example/tenant/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example/tenant/jwks?version=1", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example/tenant/jwks#keys", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://issuer.example/tenant/../jwks", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("https://private.example/jwks", {"issuer.example": (_OIDC_PUBLIC_IP,), "private.example": ("192.168.1.10",)}),
    ],
    ids=["http", "port", "userinfo", "query", "fragment", "dot-segment", "private-dns"],
)
@pytest.mark.anyio
async def test_oidc_discovery_revalidates_untrusted_jwks_targets(
    jwks_uri: str, answers: Mapping[str, tuple[str, ...]]
) -> None:
    allowed_origins = frozenset({"https://private.example"}) if "private.example" in jwks_uri else frozenset()
    policy = DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER}), allowed_jwks_origins=allowed_origins)
    client, _transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(jwks_uri=jwks_uri)), policy=policy, answers=answers
    )

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.anyio
async def test_oidc_discovery_refuses_redirects_without_following_location() -> None:
    client, transport, resolver = _oidc_client(
        lambda _request: httpx.Response(302, headers={"location": "https://private.example/metadata"}),
        answers={"issuer.example": (_OIDC_PUBLIC_IP,)},
    )

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)

    assert len(transport.requests) == 1
    assert resolver.calls == [("issuer.example", 443)]


@pytest.mark.anyio
async def test_oidc_discovery_ignores_proxy_environment_with_injected_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    metadata = await _discover_and_close(client)

    assert metadata.issuer == _OIDC_ISSUER
    assert len(transport.requests) == 1


@pytest.mark.anyio
async def test_oidc_discovery_requests_identity_response_encoding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        return _oidc_response()

    client, _transport, _resolver = _oidc_client(handler)

    metadata = await _discover_and_close(client)

    assert metadata.issuer == _OIDC_ISSUER


@pytest.mark.anyio
async def test_oidc_discovery_rejects_compressed_response_before_decoding() -> None:
    encoded = json.dumps(_oidc_document(), separators=(",", ":")).encode()
    stream = _ChunkedOIDCStream(gzip.compress(encoded))
    response = httpx.Response(
        200, headers={"content-type": "application/json", "content-encoding": "gzip"}, stream=stream
    )
    client, _transport, _resolver = _oidc_client(lambda _request: response)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)

    assert stream.was_iterated is False


@pytest.mark.anyio
async def test_oidc_discovery_checks_streaming_capacity_before_extending(monkeypatch: pytest.MonkeyPatch) -> None:
    class _CapacityCheckedBytearray(bytearray):
        def extend(self, chunk: bytes) -> None:
            if len(self) + len(chunk) > 64:
                message = "Streaming chunk was appended before its size was checked"
                raise AssertionError(message)
            super().extend(chunk)

    monkeypatch.setattr(oidc_provider, "bytearray", _CapacityCheckedBytearray, raising=False)
    policy = DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER}), maximum_document_bytes=64)
    response = httpx.Response(
        200, headers={"content-type": "application/json"}, stream=_ChunkedOIDCStream(b"x" * 40, b"x" * 40)
    )
    client, _transport, _resolver = _oidc_client(lambda _request: response, policy=policy)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.anyio
async def test_oidc_discovery_enforces_streaming_body_limit_without_content_length() -> None:
    policy = DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER}), maximum_document_bytes=64)
    response = httpx.Response(
        200, headers={"content-type": "application/json"}, stream=_ChunkedOIDCStream(b"x" * 40, b"x" * 40)
    )
    assert "content-length" not in response.headers
    client, _transport, _resolver = _oidc_client(lambda _request: response, policy=policy)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.anyio
async def test_oidc_discovery_rejects_excessive_json_depth() -> None:
    nested: object = None
    for _ in range(65):
        nested = {"nested": nested}
    document = _oidc_document(extension=nested)
    client, _transport, _resolver = _oidc_client(lambda _request: _oidc_response(document))

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.parametrize(
    ("response", "case"),
    [
        (httpx.Response(404, json={"error": "missing"}), "status-4xx"),
        (httpx.Response(503, json={"error": "unavailable"}), "status-5xx"),
        (_oidc_response(content_type=None), "missing-content-type"),
        (_oidc_response(content_type="text/plain"), "wrong-content-type"),
        (_oidc_response(content=b"{"), "invalid-json"),
        (_oidc_response(content=b'{"issuer":"one","issuer":"two"}'), "duplicate-json-member"),
        (_oidc_response(content=b"[]"), "non-object-json"),
        (_oidc_response(content=b'{"unsupported":NaN}'), "non-finite-json"),
        (_oidc_response(content=b"x" * 65_537), "body-limit"),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
@pytest.mark.anyio
async def test_oidc_discovery_rejects_untrusted_http_or_document_shapes(response: httpx.Response, case: str) -> None:
    del case
    client, _transport, _resolver = _oidc_client(lambda _request: response)

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.parametrize(
    "document",
    [
        _oidc_document(issuer="https://issuer.examp\u043be/tenant"),
        {key: value for key, value in _oidc_document().items() if key != "issuer"},
        {key: value for key, value in _oidc_document().items() if key != "jwks_uri"},
        _oidc_document(issuer=7),
        _oidc_document(jwks_uri=["https://issuer.example/jwks"]),
        _oidc_document(authorization_endpoint=7),
        _oidc_document(token_endpoint=[]),
        _oidc_document(end_session_endpoint={}),
        _oidc_document(id_token_signing_alg_values_supported="EdDSA"),  # noqa: S106 - algorithm type fixture
        _oidc_document(id_token_signing_alg_values_supported=["EdDSA", 7]),
        _oidc_document(id_token_signing_alg_values_supported=[]),
        _oidc_document(id_token_signing_alg_values_supported=["RS256"]),
    ],
    ids=[
        "issuer-mismatch",
        "missing-issuer",
        "missing-jwks-uri",
        "issuer-type",
        "jwks-type",
        "authorization-endpoint-type",
        "token-endpoint-type",
        "end-session-endpoint-type",
        "algorithm-type",
        "algorithm-member-type",
        "empty-provider-algorithms",
        "empty-pinned-intersection",
    ],
)
@pytest.mark.anyio
async def test_oidc_discovery_rejects_mismatched_or_unsupported_metadata(document: dict[str, object]) -> None:
    client, _transport, _resolver = _oidc_client(lambda _request: _oidc_response(document))

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.anyio
async def test_oidc_discovery_preserves_absent_optional_endpoints() -> None:
    client, _transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(
            _oidc_document(authorization_endpoint=None, token_endpoint=None, end_session_endpoint=None)
        )
    )

    metadata = await _discover_and_close(client)

    assert metadata.authorization_endpoint is None
    assert metadata.token_endpoint is None
    assert metadata.end_session_endpoint is None


@pytest.mark.parametrize(
    ("field", "value", "answers"),
    [
        ("authorization_endpoint", "/authorize", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("token_endpoint", "http://issuer.example/token", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("end_session_endpoint", "https://user@issuer.example/logout", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        (
            "authorization_endpoint",
            "https://issuer.example/authorize?prompt=login",
            {"issuer.example": (_OIDC_PUBLIC_IP,)},
        ),
        ("token_endpoint", "https://issuer.example/token#fragment", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        ("end_session_endpoint", "https://issuer.example/tenant/../logout", {"issuer.example": (_OIDC_PUBLIC_IP,)}),
        (
            "token_endpoint",
            "https://private.example/token",
            {"issuer.example": (_OIDC_PUBLIC_IP,), "private.example": ("10.0.0.10",)},
        ),
    ],
    ids=["relative", "http", "userinfo", "query", "fragment", "dot-segment", "private-dns"],
)
@pytest.mark.anyio
async def test_oidc_discovery_rejects_unsafe_optional_endpoint_urls(
    field: str, value: str, answers: Mapping[str, tuple[str, ...]]
) -> None:
    client, _transport, _resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(**{field: value})), answers=answers
    )

    with pytest.raises(OIDCDiscoveryError):
        await _discover_and_close(client)


@pytest.mark.anyio
async def test_oidc_discovery_allows_public_cross_origin_optional_endpoints() -> None:
    endpoints = {
        "authorization_endpoint": "https://login.example/authorize",
        "token_endpoint": "https://login.example/token",
        "end_session_endpoint": "https://login.example/logout",
    }
    client, _transport, resolver = _oidc_client(
        lambda _request: _oidc_response(_oidc_document(**endpoints)),
        answers={"issuer.example": (_OIDC_PUBLIC_IP,), "login.example": (_OIDC_PUBLIC_IP,)},
    )

    metadata = await _discover_and_close(client)

    assert metadata.authorization_endpoint == endpoints["authorization_endpoint"]
    assert metadata.token_endpoint == endpoints["token_endpoint"]
    assert metadata.end_session_endpoint == endpoints["end_session_endpoint"]
    assert ("login.example", 443) in resolver.calls


@pytest.mark.anyio
async def test_oidc_discovery_sanitizes_transport_failures() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        message = "internal-host.example must not escape"
        raise httpx.ConnectError(message, request=request)

    client, _transport, _resolver = _oidc_client(fail)

    with pytest.raises(OIDCDiscoveryError) as exc_info:
        await _discover_and_close(client)

    assert "internal-host.example" not in repr(exc_info.value)


@pytest.mark.anyio
async def test_oidc_discovery_close_is_idempotent_and_closes_injected_transport() -> None:
    client, transport, _resolver = _oidc_client(lambda _request: _oidc_response())

    await client.aclose()
    await client.aclose()

    assert transport.was_closed is True
    with pytest.raises(OIDCDiscoveryError):
        await client.discover(_OIDC_ISSUER)


def test_jwks_public_cache_contracts_are_frozen_and_fetcher_is_runtime_checkable() -> None:
    policy = JWKSCachePolicy()
    request = JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, etag=None)
    response = JWKSFetchResponse(status_code=304, body=b"", headers={"cache-control": "max-age=60"})
    default_response = JWKSFetchResponse(status_code=304)
    entry = _jwks_entry()
    fetcher = _RecordingJWKSFetcher(response)

    assert isinstance(fetcher, AsyncJWKSFetcher)
    assert policy.default_ttl == timedelta(minutes=15)
    assert policy.minimum_ttl == timedelta(seconds=30)
    assert policy.maximum_ttl == timedelta(hours=24)
    assert policy.unknown_kid_cooldown == timedelta(seconds=30)
    assert policy.stale_if_error == timedelta(0)
    assert policy.warm_on_startup is False
    assert policy.maximum_unknown_keys == 1024
    assert default_response.body == b""
    assert default_response.headers == {}
    with pytest.raises(FrozenInstanceError):
        request.etag = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        entry.issuer = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        response.headers["cache-control"] = "changed"  # type: ignore[index]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"default_ttl": 30},
        {"default_ttl": timedelta(0)},
        {"minimum_ttl": timedelta(0)},
        {"maximum_ttl": timedelta(0)},
        {"minimum_ttl": timedelta(minutes=2), "maximum_ttl": timedelta(minutes=1)},
        {"default_ttl": timedelta(seconds=29)},
        {"default_ttl": timedelta(hours=25)},
        {"unknown_kid_cooldown": timedelta(0)},
        {"stale_if_error": timedelta(seconds=-1)},
        {"warm_on_startup": 1},
        {"maximum_document_bytes": 0},
        {"maximum_document_bytes": True},
        {"maximum_document_bytes": 1_048_577},
        {"maximum_keys": 0},
        {"maximum_keys": True},
        {"maximum_keys": 129},
        {"maximum_unknown_keys": 0},
        {"maximum_unknown_keys": True},
    ],
    ids=[
        "duration-type",
        "default-ttl",
        "minimum-ttl",
        "maximum-ttl",
        "ttl-order",
        "default-below-minimum",
        "default-above-maximum",
        "unknown-kid-cooldown",
        "negative-stale",
        "warmup-type",
        "document-bytes-zero",
        "document-bytes-bool",
        "document-bytes-maximum",
        "keys-zero",
        "keys-bool",
        "keys-maximum",
        "unknown-keys-zero",
        "unknown-keys-bool",
    ],
)
def test_jwks_cache_policy_rejects_unsafe_bounds(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        JWKSCachePolicy(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status_code": True},
        {"status_code": 99},
        {"status_code": 600},
        {"status_code": 200, "body": "body"},
        {"status_code": 200, "headers": {1: "value"}},
        {"status_code": 200, "headers": {"": "value"}},
        {"status_code": 200, "headers": {"name": 1}},
        {"status_code": 200, "headers": object()},
    ],
    ids=[
        "status-bool",
        "status-low",
        "status-high",
        "body-type",
        "header-name-type",
        "header-name-empty",
        "header-value-type",
        "header-mapping-type",
    ],
)
def test_jwks_fetch_response_rejects_invalid_transport_values(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        JWKSFetchResponse(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: JWKSCacheEntry(issuer=" ", jwks_uri=_JWKS_URI, algorithms=frozenset({"EdDSA"})),
        lambda: JWKSCacheEntry(issuer=_JWT_ISSUER, jwks_uri=" ", algorithms=frozenset({"EdDSA"})),
        lambda: JWKSCacheEntry(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, algorithms=frozenset()),
        lambda: JWKSCacheEntry(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, algorithms=frozenset({"none"})),
        lambda: CachedJWKSProvider(entries=(), fetcher=_RecordingJWKSFetcher()),
        lambda: CachedJWKSProvider(entries=(_jwks_entry(), _jwks_entry()), fetcher=_RecordingJWKSFetcher()),
        lambda: CachedJWKSProvider(
            entries=(object(),),  # type: ignore[arg-type]
            fetcher=_RecordingJWKSFetcher(),
        ),
        lambda: CachedJWKSProvider(
            entries=(_jwks_entry(),),
            fetcher=object(),  # type: ignore[arg-type]
        ),
    ],
    ids=[
        "issuer",
        "uri",
        "empty-algorithms",
        "unsupported-algorithm",
        "empty-entries",
        "duplicate-entry",
        "entry-type",
        "fetcher-type",
    ],
)
def test_jwks_provider_rejects_invalid_configured_entries(factory: Callable[[], object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        factory()


@pytest.mark.anyio
async def test_jwks_cold_load_uses_default_ttl_and_fresh_hit_does_no_fetch(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, etag='"generation-1"'), _jwks_response(jwk, etag='"generation-2"')
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    cold = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    fresh = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(minutes=14, seconds=59)
    )
    boundary = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(minutes=15))

    assert isinstance(cold, VerificationKey)
    assert fresh is cold
    assert isinstance(boundary, VerificationKey)
    assert fetcher.requests == [
        JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, etag=None),
        JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, etag='"generation-1"'),
    ]


@pytest.mark.parametrize("cache_state", ["cold", "expired"])
@pytest.mark.anyio
async def test_jwks_concurrent_callers_share_one_refresh(
    cache_state: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    expired = cache_state == "expired"
    jwk = _verification_jwk(jwt_key_material)
    response = _jwks_response(jwk, cache_control="max-age=30", etag='"generation-1"')
    fetcher = _BlockingJWKSFetcher(
        response, response, immediate_calls=1 if expired else 0, maximum_calls=2 if expired else 1
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    now = _JWT_NOW
    if expired:
        assert isinstance(await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=now), VerificationKey)
        now += timedelta(seconds=30)
    outcomes: list[object | None] = [None] * 100

    async def select(index: int) -> None:
        outcomes[index] = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=now)

    async with create_task_group() as task_group:
        for index in range(len(outcomes)):
            task_group.start_soon(select, index)
        await fetcher.started.wait()
        await checkpoint()
        fetcher.release.set()

    expected_fetches = 2 if expired else 1
    assert len(fetcher.requests) == expected_fetches
    assert isinstance(outcomes[0], VerificationKey)
    assert all(outcome is outcomes[0] for outcome in outcomes)


@pytest.mark.anyio
async def test_jwks_cancelling_one_waiter_preserves_shared_refresh(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _BlockingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material), cache_control="max-age=60"))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    cancelled_scope: list[CancelScope] = []
    cancelled_outcomes: list[object] = []
    survivor_outcomes: list[object] = []
    survivor_started = Event()
    cancelled_finished = Event()

    async def cancelled_waiter() -> None:
        try:
            with CancelScope() as scope:
                cancelled_scope.append(scope)
                cancelled_outcomes.append(
                    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
                )
        finally:
            cancelled_finished.set()

    async def survivor() -> None:
        survivor_started.set()
        survivor_outcomes.append(await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW))

    async with create_task_group() as task_group:
        task_group.start_soon(cancelled_waiter)
        await fetcher.started.wait()
        task_group.start_soon(survivor)
        await survivor_started.wait()
        await checkpoint()
        cancelled_scope[0].cancel()
        with fail_after(1):
            await cancelled_finished.wait()
        assert fetcher.active == 1
        fetcher.release.set()

    assert cancelled_outcomes == []
    assert len(fetcher.requests) == 1
    assert len(survivor_outcomes) == 1
    assert isinstance(survivor_outcomes[0], VerificationKey)


@pytest.mark.anyio
async def test_jwks_independent_issuer_refreshes_proceed_concurrently(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    second_issuer = "https://issuer-two.example"
    second_uri = f"{second_issuer}/jwks"
    first = _verification_jwk(jwt_key_material, "EdDSA", "first")
    second = _verification_jwk(jwt_key_material, "ES256", "second")

    def respond(request: JWKSFetchRequest) -> JWKSFetchResponse:
        return _jwks_response(first if request.issuer == _JWT_ISSUER else second, cache_control="max-age=60")

    fetcher = _BlockingJWKSFetcher(respond, respond, maximum_calls=2, issuers=(_JWT_ISSUER, second_issuer))
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri, frozenset({"ES256"}))), fetcher=fetcher
    )
    outcomes: list[object] = []

    async def select(issuer: str, uri: str, kid: str, algorithm: str) -> None:
        outcomes.append(await provider.select_key(issuer, uri, kid, algorithm, now=_JWT_NOW))

    async with create_task_group() as task_group:
        task_group.start_soon(select, _JWT_ISSUER, _JWKS_URI, "first", "EdDSA")
        await fetcher.started_by_issuer[_JWT_ISSUER].wait()
        task_group.start_soon(select, second_issuer, second_uri, "second", "ES256")
        with fail_after(1):
            await fetcher.started_by_issuer[second_issuer].wait()
        fetcher.release.set()

    assert len(fetcher.requests) == 2
    assert {outcome.algorithm for outcome in outcomes if isinstance(outcome, VerificationKey)} == {"EdDSA", "ES256"}


@pytest.mark.anyio
async def test_jwks_fresh_unknown_key_forces_one_refresh_and_retries(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    rotated = _verification_jwk(jwt_key_material, key_id="rotated")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'),
        _jwks_response(known, rotated, cache_control="max-age=60", etag='"generation-2"'),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "rotated", "EdDSA", now=_JWT_NOW + timedelta(seconds=1))

    assert isinstance(outcome, VerificationKey)
    assert outcome.key_id == "rotated"
    assert len(fetcher.requests) == 2


@pytest.mark.anyio
async def test_jwks_unknown_selection_negative_cache_is_per_generation_tuple(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="shared")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(algorithms=frozenset({"EdDSA", "ES256"})),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    first = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "ES256", now=_JWT_NOW + timedelta(seconds=1))
    second = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "ES256", now=_JWT_NOW + timedelta(seconds=2))
    valid_tuple = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "shared", "EdDSA", now=_JWT_NOW + timedelta(seconds=2)
    )

    assert isinstance(first, InvalidCredentials)
    assert isinstance(second, InvalidCredentials)
    assert isinstance(valid_tuple, VerificationKey)
    assert len(fetcher.requests) == 2


@pytest.mark.anyio
async def test_jwks_expired_unknown_selection_is_cached_after_refresh(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=30", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    outcome = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=30)
    )
    repeated = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=31)
    )

    assert isinstance(outcome, InvalidCredentials)
    assert isinstance(repeated, InvalidCredentials)
    assert len(fetcher.requests) == 2


@pytest.mark.anyio
async def test_jwks_failed_forced_refresh_is_generation_limited_and_prunes_expired_negative(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'), OSError("temporary")
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    failed = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=1))
    suppressed = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=2)
    )
    after_cooldown = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=32)
    )

    assert isinstance(failed, VerificationUnavailable)
    assert isinstance(suppressed, InvalidCredentials)
    assert isinstance(after_cooldown, InvalidCredentials)
    assert len(fetcher.requests) == 2


@pytest.mark.anyio
async def test_jwks_generation_replacement_invalidates_unknown_key_negatives(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    replacement = _verification_jwk(jwt_key_material, key_id="replacement")
    formerly_unknown = _verification_jwk(jwt_key_material, key_id="absent")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=30", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=30"}),
        _jwks_response(replacement, cache_control="max-age=30", etag='"generation-2"'),
        _jwks_response(replacement, formerly_unknown, cache_control="max-age=30", etag='"generation-3"'),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "absent", "EdDSA", now=_JWT_NOW + timedelta(seconds=1)),
        InvalidCredentials,
    )
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "replacement", "EdDSA", now=_JWT_NOW + timedelta(seconds=31)),
        VerificationKey,
    )
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "absent", "EdDSA", now=_JWT_NOW + timedelta(seconds=32))

    assert isinstance(outcome, VerificationKey)
    assert len(fetcher.requests) == 4


@pytest.mark.anyio
async def test_jwks_unknown_key_negative_cache_is_bounded_lru(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    not_modified = JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"})
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'), *(not_modified for _ in range(5))
    )
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),), fetcher=fetcher, policy=JWKSCachePolicy(maximum_unknown_keys=3)
    )

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    for kid in ("unknown-a", "unknown-b", "unknown-c", "unknown-d"):
        assert isinstance(
            await provider.select_key(_JWT_ISSUER, _JWKS_URI, kid, "EdDSA", now=_JWT_NOW + timedelta(seconds=1)),
            InvalidCredentials,
        )
    state = cast("Any", provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001
    assert tuple((generation, kid, algorithm) for generation, kid, algorithm in state.negative) == (
        (1, "unknown-b", "EdDSA"),
        (1, "unknown-c", "EdDSA"),
        (1, "unknown-d", "EdDSA"),
    )
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "unknown-a", "EdDSA", now=_JWT_NOW + timedelta(seconds=2)),
        InvalidCredentials,
    )

    assert len(state.negative) == 3
    assert tuple(key[1] for key in state.negative) == ("unknown-c", "unknown-d", "unknown-a")
    assert len(fetcher.requests) == 2


@pytest.mark.anyio
async def test_jwks_shared_refresh_failure_is_consistent_for_all_waiters(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    del jwt_key_material
    fetcher = _BlockingJWKSFetcher(OSError("shared fetch detail"))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    outcomes: list[object | None] = [None] * 100

    async def select(index: int) -> None:
        outcomes[index] = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    async with create_task_group() as task_group:
        for index in range(len(outcomes)):
            task_group.start_soon(select, index)
        await fetcher.started.wait()
        await checkpoint()
        fetcher.release.set()

    assert len(fetcher.requests) == 1
    assert isinstance(outcomes[0], VerificationUnavailable)
    assert all(outcome is outcomes[0] for outcome in outcomes)


@pytest.mark.anyio
async def test_jwks_pending_refresh_cancellation_is_sanitized() -> None:
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=_RecordingJWKSFetcher())
    cancelled_task = asyncio.create_task(checkpoint())
    cancelled_task.cancel()
    await checkpoint()
    state = cast("Any", provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001
    state.refresh = SimpleNamespace(task=cancelled_task)

    outcome = await cast("Any", provider)._refresh_singleflight(state, _JWT_NOW)  # noqa: SLF001

    assert isinstance(outcome, VerificationUnavailable)
    await provider.aclose()


@pytest.mark.anyio
async def test_jwks_close_cancels_and_awaits_live_refresh_tasks(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _BlockingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material)))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    async def select() -> None:
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    async with create_task_group() as task_group:
        task_group.start_soon(select)
        await fetcher.started.wait()
        task_group.start_soon(provider.aclose)
        with fail_after(1):
            await fetcher.finished.wait()

    assert fetcher.active == 0
    assert fetcher.cancelled == 1
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW), VerificationUnavailable
    )


@pytest.mark.parametrize(
    ("cache_control", "fresh_offset", "expired_offset"),
    [
        ("public, max-age=1", timedelta(seconds=29), timedelta(seconds=30)),
        ("max-age=999999", timedelta(minutes=59, seconds=59), timedelta(hours=1)),
        ("public, malformed=value", timedelta(minutes=14, seconds=59), timedelta(minutes=15)),
    ],
    ids=["minimum-clamp", "maximum-clamp", "default-fallback"],
)
@pytest.mark.anyio
async def test_jwks_cache_control_ttl_is_clamped_or_defaults(
    cache_control: str,
    fresh_offset: timedelta,
    expired_offset: timedelta,
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    policy = JWKSCachePolicy(maximum_ttl=timedelta(hours=1))
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control=cache_control), _jwks_response(jwk, cache_control=cache_control)
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, policy=policy)

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + fresh_offset)
    assert len(fetcher.requests) == 1

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + expired_offset)
    assert len(fetcher.requests) == 2


@pytest.mark.parametrize("directive", ["no-cache", "no-store"])
@pytest.mark.anyio
async def test_jwks_no_cache_and_no_store_revalidate_immediately(
    directive: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control=directive, etag='"generation-1"'),
        _jwks_response(jwk, cache_control="max-age=60", etag='"generation-2"'),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    first = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    second = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(first, VerificationKey)
    assert isinstance(second, VerificationKey)
    assert len(fetcher.requests) == 2
    assert fetcher.requests[1].etag == '"generation-1"'


@pytest.mark.anyio
async def test_jwks_conditional_304_retains_snapshot_and_recomputes_freshness(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, body=b"", headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    original = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    retained = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))
    fresh = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=89))

    assert retained is original
    assert fresh is original
    assert len(fetcher.requests) == 2
    assert fetcher.requests[1].etag == '"generation-1"'


@pytest.mark.anyio
async def test_jwks_304_without_a_live_snapshot_is_unavailable() -> None:
    fetcher = _RecordingJWKSFetcher(JWKSFetchResponse(status_code=304, body=b"", headers={}))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_fetcher_returning_wrong_response_type_is_unavailable() -> None:
    class _WrongResponseFetcher:
        async def fetch(self, _request: JWKSFetchRequest) -> object:
            return object()

    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),),
        fetcher=_WrongResponseFetcher(),  # type: ignore[arg-type]
    )

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_atomic_replacement_exposes_new_and_removes_old_keys(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    old = _verification_jwk(jwt_key_material, "EdDSA", "old")
    new = _verification_jwk(jwt_key_material, "ES256", "new")
    replacement = _jwks_response(new, cache_control="max-age=60", etag='"generation-2"')
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(old, cache_control="max-age=30", etag='"generation-1"'), replacement, replacement
    )
    entry = _jwks_entry(algorithms=frozenset({"EdDSA", "ES256"}))
    provider = CachedJWKSProvider(entries=(entry,), fetcher=fetcher)

    old_key = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "old", "EdDSA", now=_JWT_NOW)
    new_key = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "new", "ES256", now=_JWT_NOW + timedelta(seconds=30))
    removed = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "old", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))

    assert isinstance(old_key, VerificationKey)
    assert isinstance(new_key, VerificationKey)
    assert new_key.key_id == "new"
    assert isinstance(removed, InvalidCredentials)


@pytest.mark.parametrize(
    "failure",
    [
        OSError("fetch detail"),
        _jwks_response(status_code=500, body=b"upstream detail"),
        _jwks_response(status_code=404, body=b"upstream detail"),
        _jwks_response(body=b"{"),
        _jwks_response({"alg": "EdDSA", "crv": "Ed25519", "kid": "new", "kty": "OKP", "use": "sig", "x": "bad"}),
    ],
    ids=["fetch", "http-5xx", "http-4xx", "parse", "partial-key-parse"],
)
@pytest.mark.anyio
async def test_jwks_failed_refresh_does_not_mutate_live_snapshot(
    failure: JWKSFetchResponse | Exception, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30", etag='"generation-1"'),
        failure,
        JWKSFetchResponse(status_code=304, body=b"", headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    original = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    failed = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))
    retained = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=31))

    assert isinstance(failed, VerificationUnavailable)
    assert retained is original
    assert fetcher.requests[1].etag == '"generation-1"'
    assert fetcher.requests[2].etag == '"generation-1"'
    assert "detail" not in repr(failed)


@pytest.mark.anyio
async def test_jwks_stale_if_error_is_local_explicit_and_bounded(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30, stale-if-error=999", etag='"generation-1"'),
        OSError("temporary"),
        OSError("still unavailable"),
    )
    policy = JWKSCachePolicy(stale_if_error=timedelta(seconds=60))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, policy=policy)

    original = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    stale = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))
    expired = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=90))

    assert stale is original
    assert isinstance(expired, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_stale_if_error_never_accepts_an_unknown_key(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(_verification_jwk(jwt_key_material), cache_control="max-age=30"), OSError("temporary")
    )
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),), fetcher=fetcher, policy=JWKSCachePolicy(stale_if_error=timedelta(seconds=60))
    )

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    outcome = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=30)
    )

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_remote_stale_directive_cannot_enable_local_stale_use(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30, stale-if-error=999"), OSError("temporary")
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.parametrize(
    "case",
    [
        "body-limit",
        "key-limit",
        "duplicate-json",
        "invalid-json",
        "non-object-json",
        "non-finite-json",
        "excessive-json-depth",
        "keys-not-array",
        "key-not-object",
        "empty-keys",
        "private-member",
        "algorithm-not-configured",
        "wrong-use",
        "wrong-key-ops",
        "duplicate-selection-tuple",
        "missing-kid",
        "unsupported-key-type",
        "weak-rsa",
        "wrong-ec-curve",
    ],
)
@pytest.mark.anyio
async def test_jwks_rejects_unsafe_or_ambiguous_documents(  # noqa: C901, PLR0912, PLR0915
    case: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    valid = _verification_jwk(jwt_key_material)
    body: bytes
    entry_algorithms = frozenset({"EdDSA"})
    selected_algorithm = "EdDSA"
    if case == "body-limit":
        body = b"x" * 1_048_577
    elif case == "key-limit":
        keys = [{**valid, "kid": f"key-{index}"} for index in range(129)]
        body = _jwks_body(*keys)
    elif case == "duplicate-json":
        body = b'{"keys":[],"keys":[]}'
    elif case == "invalid-json":
        body = b"{"
    elif case == "non-object-json":
        body = b"[]"
    elif case == "non-finite-json":
        body = b'{"keys":[],"value":NaN}'
    elif case == "excessive-json-depth":
        nested: object = None
        for _ in range(65):
            nested = {"nested": nested}
        body = json.dumps({"keys": [valid], "extension": nested}, separators=(",", ":")).encode()
    elif case == "keys-not-array":
        body = b'{"keys":{}}'
    elif case == "key-not-object":
        body = b'{"keys":["key"]}'
    elif case == "empty-keys":
        body = _jwks_body()
    elif case == "private-member":
        body = _jwks_body({**valid, "d": "private"})
    elif case == "algorithm-not-configured":
        body = _jwks_body({**valid, "alg": "RS256"})
    elif case == "wrong-use":
        body = _jwks_body({**valid, "use": "enc"})
    elif case == "wrong-key-ops":
        body = _jwks_body({**valid, "key_ops": ["sign"]})
    elif case == "duplicate-selection-tuple":
        body = _jwks_body(valid, valid)
    elif case == "missing-kid":
        body = _jwks_body({key: value for key, value in valid.items() if key != "kid"})
    elif case == "unsupported-key-type":
        body = _jwks_body({**valid, "kty": "unsupported"})
    elif case == "weak-rsa":
        body = _jwks_body(_raw_public_jwk(jwt_key_material, "RS1024", "RS256", "key-1"))
        entry_algorithms = frozenset({"RS256"})
        selected_algorithm = "RS256"
    else:
        body = _jwks_body(_raw_public_jwk(jwt_key_material, "ES384", "ES256", "key-1"))
        entry_algorithms = frozenset({"ES256"})
        selected_algorithm = "ES256"
    fetcher = _RecordingJWKSFetcher(_jwks_response(body=body))
    provider = CachedJWKSProvider(entries=(_jwks_entry(algorithms=entry_algorithms),), fetcher=fetcher)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", selected_algorithm, now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_rejects_unsupported_prepared_key_type(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], monkeypatch: pytest.MonkeyPatch
) -> None:
    class _UnsupportedPyJWK:
        @staticmethod
        def from_dict(_value: dict[str, object], *, algorithm: str) -> SimpleNamespace:
            del algorithm
            return SimpleNamespace(key=object())

    monkeypatch.setattr(jwks_provider, "PyJWK", _UnsupportedPyJWK)
    fetcher = _RecordingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material)))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.anyio
async def test_jwks_entries_isolate_same_kid_by_issuer_uri_and_algorithm(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    second_issuer = "https://issuer-two.example"
    second_uri = f"{second_issuer}/jwks"
    first = _verification_jwk(jwt_key_material, "EdDSA", "shared")
    second = _verification_jwk(jwt_key_material, "ES256", "shared")

    def respond(request: JWKSFetchRequest) -> JWKSFetchResponse:
        return _jwks_response(first if request.issuer == _JWT_ISSUER else second, cache_control="max-age=60")

    fetcher = _RecordingJWKSFetcher(respond, respond)
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri, frozenset({"ES256"}))), fetcher=fetcher
    )

    first_key = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "EdDSA", now=_JWT_NOW)
    second_key = await provider.select_key(second_issuer, second_uri, "shared", "ES256", now=_JWT_NOW)

    assert isinstance(first_key, VerificationKey)
    assert isinstance(second_key, VerificationKey)
    assert first_key.algorithm == "EdDSA"
    assert second_key.algorithm == "ES256"
    assert tuple((request.issuer, request.jwks_uri) for request in fetcher.requests) == (
        (_JWT_ISSUER, _JWKS_URI),
        (second_issuer, second_uri),
    )


@pytest.mark.parametrize(
    ("issuer", "jwks_uri", "algorithm"),
    [
        ("https://unconfigured.example", _JWKS_URI, "EdDSA"),
        (_JWT_ISSUER, "https://unconfigured.example/jwks", "EdDSA"),
        (_JWT_ISSUER, _JWKS_URI, "RS256"),
    ],
    ids=["issuer", "uri", "algorithm"],
)
@pytest.mark.anyio
async def test_jwks_unconfigured_entry_coordinates_fail_without_fetch(
    issuer: str, jwks_uri: str, algorithm: str
) -> None:
    fetcher = _RecordingJWKSFetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    outcome = await provider.select_key(issuer, jwks_uri, "key-1", algorithm, now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert fetcher.requests == []


@pytest.mark.anyio
async def test_jwks_rejects_naive_time_without_fetch() -> None:
    fetcher = _RecordingJWKSFetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    with pytest.raises(ImproperlyConfiguredException):
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_NAIVE_JWT_NOW)

    assert fetcher.requests == []


@pytest.mark.parametrize(("warm_on_startup", "failure"), [(False, False), (True, False), (True, True)])
@pytest.mark.anyio
async def test_jwks_warmup_is_explicit_complete_and_failure_aware(
    *, warm_on_startup: bool, failure: bool, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    second_issuer = "https://issuer-two.example"
    second_uri = f"{second_issuer}/jwks"
    first_response: JWKSFetchResponse | Exception = (
        OSError("warmup unavailable")
        if failure
        else _jwks_response(_verification_jwk(jwt_key_material, "EdDSA", "first"))
    )
    second_response = _jwks_response(_verification_jwk(jwt_key_material, "ES256", "second"))
    fetcher = _RecordingJWKSFetcher(first_response, second_response)
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri, frozenset({"ES256"}))),
        fetcher=fetcher,
        policy=JWKSCachePolicy(warm_on_startup=warm_on_startup),
    )

    outcome = await provider.warmup(now=_JWT_NOW)
    repeated = outcome if failure else await provider.warmup(now=_JWT_NOW + timedelta(seconds=1))

    if not warm_on_startup:
        assert outcome is None
        assert repeated is None
        assert fetcher.requests == []
    else:
        assert isinstance(outcome, VerificationUnavailable) if failure else outcome is None
        assert isinstance(repeated, VerificationUnavailable) if failure else repeated is None
        assert tuple((request.issuer, request.jwks_uri) for request in fetcher.requests) == (
            (_JWT_ISSUER, _JWKS_URI),
            (second_issuer, second_uri),
        )


@pytest.mark.anyio
async def test_jwks_close_is_idempotent_and_prevents_selection_fetch(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _RecordingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material)))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    await provider.aclose()
    await provider.aclose()
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    warmup = await provider.warmup(now=_JWT_NOW)
    state = cast("Any", provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001
    refresh = await cast("Any", provider)._refresh_singleflight(state, _JWT_NOW)  # noqa: SLF001

    assert isinstance(outcome, VerificationUnavailable)
    assert isinstance(warmup, VerificationUnavailable)
    assert isinstance(refresh, VerificationUnavailable)
    assert fetcher.requests == []
