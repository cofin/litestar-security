"""JWKS fetching tests, including the fetcher's bounded worker normalization."""

import json
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from math import inf, nan
from threading import Event as ThreadEvent
from threading import Lock as ThreadLock
from typing import cast

import pytest
from anyio import CapacityLimiter, Event, create_task_group, fail_after
from anyio.lowlevel import checkpoint
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.providers.jwks import (
    AsyncJWKSFetcher,
    CachedJWKSProvider,
    JWKSFetchOutcome,
    JWKSFetchTarget,
    JWKSSource,
    NoOpSecurityMetrics,
    SecurityMetrics,
    SyncJWKSFetcher,
    WorkerLimits,
    normalize_fetcher,
)
from litestar_security.providers.jwt import (
    JWTValidationConfig,
    LocalKeyRing,
    PyJWTVerifier,
    SigningKey,
    SyncJWTVerifier,
    SyncTokenSigner,
    VerificationKey,
    VerificationKeySet,
    normalize_signer,
    normalize_verifier,
)
from litestar_security.providers.jwt import _keyring as jwt_keyring
from tests.fixtures.collaborators import RecordingJWKSFetcher

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)

_JWT_ISSUER = "https://issuer.example"

_JWT_AUDIENCE = "litestar-security"

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


async def test_jwks_fetcher_normalization_selects_async_or_bounded_sync_once() -> None:
    response = JWKSFetchOutcome(status_code=200, body=b'{"keys":[]}')
    metrics: list[str] = []

    class Metrics:
        def increment(self, name: str, *, attributes: Mapping[str, str] = {}) -> None:
            del attributes
            metrics.append(name)

        def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = {}) -> None:
            del name, value, attributes

    class AsyncFetcher:
        async def fetch(self, _request: JWKSFetchTarget) -> JWKSFetchOutcome:
            return response

    class SyncFetcher:
        def fetch(self, _request: JWKSFetchTarget) -> JWKSFetchOutcome:
            return response

    request = JWKSFetchTarget(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI)
    async_fetcher = AsyncFetcher()
    normalized_async = normalize_fetcher(async_fetcher, limiter=CapacityLimiter(1))
    normalized_sync = normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(2), metrics=Metrics())

    assert isinstance(normalized_sync, AsyncJWKSFetcher)
    assert isinstance(normalized_async, AsyncJWKSFetcher)
    assert isinstance(SyncFetcher(), SyncJWKSFetcher)
    assert await normalized_async.fetch(request) is response
    assert await normalized_sync.fetch(request) is response
    await normalized_async.aclose()
    await normalized_sync.aclose()
    assert "security.worker.saturation" not in metrics


@pytest.mark.parametrize("close_mode", ["absent", "sync", "async"])
async def test_jwks_async_fetcher_normalization_exposes_async_close(close_mode: str) -> None:
    closes: list[str] = []

    class Fetcher:
        async def fetch(self, _request: JWKSFetchTarget) -> JWKSFetchOutcome:
            return JWKSFetchOutcome(status_code=200)

    class SyncCloseFetcher(Fetcher):
        def aclose(self) -> None:
            closes.append("sync")

    class AsyncCloseFetcher(Fetcher):
        async def aclose(self) -> None:
            closes.append("async")

    fetchers = {"absent": Fetcher, "sync": SyncCloseFetcher, "async": AsyncCloseFetcher}
    normalized = normalize_fetcher(fetchers[close_mode](), limiter=CapacityLimiter(1))

    await normalized.aclose()

    assert closes == ([] if close_mode == "absent" else [close_mode])


@pytest.mark.parametrize(
    ("fetcher", "limiter_tokens", "timeout", "metrics", "match"),
    [
        (object(), 1, 1.0, None, "must define fetch"),
        (RecordingJWKSFetcher(), 1, 0.0, None, "timeout must be finite and positive"),
        (RecordingJWKSFetcher(), 1, 1.0, object(), "must implement SecurityMetrics"),
        (RecordingJWKSFetcher(), inf, 1.0, None, "limiter must have finite bounded capacity"),
    ],
    ids=["missing-fetch", "zero-timeout", "invalid-metrics", "unbounded-limiter"],
)
def test_jwks_fetcher_normalization_rejects_invalid_configuration(
    fetcher: object, limiter_tokens: float, timeout: float, metrics: object, match: str
) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        normalize_fetcher(  # type: ignore[arg-type]
            fetcher,
            limiter=CapacityLimiter(limiter_tokens),
            timeout=timeout,
            metrics=metrics,  # type: ignore[arg-type]
        )


async def test_jwks_sync_fetcher_is_bounded_without_blocking_the_event_loop() -> None:
    started = ThreadEvent()
    release = ThreadEvent()
    calls: list[JWKSFetchOutcome] = []

    class SyncFetcher:
        def fetch(self, _request: JWKSFetchTarget) -> JWKSFetchOutcome:
            started.set()
            release.wait(timeout=1)
            return JWKSFetchOutcome(status_code=200, body=b'{"keys":[]}')

    normalized = normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(1))
    request = JWKSFetchTarget(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI)

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
        with fail_after(5):
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


class _TestSyncSigner:
    def sign(self, _claims: Mapping[str, object], *, now: datetime) -> str:
        del now
        return "token"


class _TestSyncVerifier:
    def __init__(self) -> None:
        self.config = _jwt_config("EdDSA")

    def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
        del now
        return InvalidCredentials()


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda _sk, _vk: normalize_signer(object()), "must define sign"),
        (
            lambda _sk, _vk: normalize_signer(_TestSyncSigner(), worker_limits=object()),
            "worker limits must be WorkerLimits",
        ),
        (
            lambda _sk, _vk: normalize_signer(_TestSyncSigner(), metrics=object()),
            "metrics must implement SecurityMetrics",
        ),
        (lambda _sk, _vk: normalize_verifier(object()), "must define verify"),
        (
            lambda _sk, _vk: normalize_verifier(_TestSyncVerifier(), worker_limits=object()),
            "worker limits must be WorkerLimits",
        ),
        (
            lambda _sk, vk: VerificationKeySet(issuer=_JWT_ISSUER, keys=(vk,)).build_verifier(
                _jwt_config("EdDSA"),
                worker_limits=object(),  # type: ignore[arg-type]
            ),
            "worker limits must be WorkerLimits",
        ),
        (
            lambda sk, _vk: LocalKeyRing(
                issuer=_JWT_ISSUER,
                active_signing_key=sk,
                worker_limits=object(),  # type: ignore[arg-type]
            ),
            "worker limits must be WorkerLimits",
        ),
        (
            lambda _sk, vk: PyJWTVerifier(config=_jwt_config("EdDSA"), key=vk, limiter=CapacityLimiter(inf)),
            "limiter must have finite bounded capacity",
        ),
        (
            lambda _sk, vk: PyJWTVerifier(config=_jwt_config("EdDSA"), key=vk, worker_timeout=inf),
            "timeout must be finite and positive",
        ),
        (
            lambda sk, _vk: jwt_keyring._LocalJWTSigner(  # noqa: SLF001 - worker timeout validation boundary
                issuer=_JWT_ISSUER, signing_key=sk, worker_timeout=inf
            ),
            "timeout must be finite and positive",
        ),
    ],
    ids=[
        "signer-missing-sign",
        "signer-invalid-worker-limits",
        "signer-invalid-metrics",
        "verifier-missing-verify",
        "verifier-invalid-worker-limits",
        "keyset-invalid-worker-limits",
        "keyring-invalid-worker-limits",
        "pyjwt-unbounded-limiter",
        "pyjwt-infinite-timeout",
        "local-signer-infinite-timeout",
    ],
)
def test_crypto_worker_configuration_rejects_invalid_values(
    factory: Callable[[SigningKey, VerificationKey], object],
    match: str,
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key = SigningKey(key_id="active", algorithm="EdDSA", private_key=jwt_key_material["EdDSA"][0])
    verification_key = VerificationKey(key_id="active", algorithm="EdDSA", key=jwt_key_material["EdDSA"][1])
    with pytest.raises(ImproperlyConfiguredException, match=match):
        factory(signing_key, verification_key)


async def test_jwks_sync_fetcher_timeout_maps_to_unavailable(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    release = ThreadEvent()

    class SyncFetcher:
        def fetch(self, _request: JWKSFetchTarget) -> JWKSFetchOutcome:
            release.wait(timeout=1)
            return _jwks_response(_verification_jwk(jwt_key_material))

    normalized = normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(1), timeout=0.01)
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=normalized)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    release.set()

    assert isinstance(outcome, VerificationUnavailable)


def _jwt_config(
    algorithm: str,
    *,
    access_token_profile: bool = True,
    subject_required: bool = True,
    required_claims: frozenset[str] = frozenset({"iss", "sub", "aud", "exp", "iat"}),
    maximum_lifetime: timedelta | None = timedelta(hours=1),
) -> JWTValidationConfig:
    return JWTValidationConfig(
        issuer=_JWT_ISSUER,
        audiences=frozenset({_JWT_AUDIENCE}),
        algorithms=frozenset({algorithm}),
        required_claims=required_claims,
        access_token_profile=access_token_profile,
        subject_required=subject_required,
        maximum_lifetime=maximum_lifetime,
    )


def _verification_jwk(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], algorithm: str = "EdDSA", key_id: str = "key-1"
) -> dict[str, object]:
    key = VerificationKey(key_id=key_id, algorithm=algorithm, key=jwt_key_material[algorithm][1])  # type: ignore[arg-type]
    return dict(cast("Mapping[str, object]", key.public_jwk))


def _jwks_body(*keys: Mapping[str, object]) -> bytes:
    return json.dumps({"keys": [dict(key) for key in keys]}, separators=(",", ":")).encode()


def _jwks_response(
    *keys: Mapping[str, object],
    status_code: int = 200,
    body: bytes | None = None,
    cache_control: str | None = None,
    etag: str | None = None,
) -> JWKSFetchOutcome:
    headers: dict[str, str] = {"content-type": "application/json"}
    if cache_control is not None:
        headers["cache-control"] = cache_control
    if etag is not None:
        headers["etag"] = etag
    return JWKSFetchOutcome(status_code=status_code, body=_jwks_body(*keys) if body is None else body, headers=headers)


def _jwks_entry(
    issuer: str = _JWT_ISSUER, jwks_uri: str = _JWKS_URI, algorithms: frozenset[str] = frozenset({"EdDSA"})
) -> JWKSSource:
    return JWKSSource(issuer=issuer, jwks_uri=jwks_uri, algorithms=algorithms)
