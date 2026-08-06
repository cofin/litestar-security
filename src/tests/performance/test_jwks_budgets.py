"""Calibrated JWKS and synchronous-verifier performance benchmarks."""

import asyncio
import json
from collections.abc import Generator, Mapping
from datetime import datetime, timedelta, timezone
from time import sleep
from typing import Any, cast

import jwt
import pytest

from litestar_security.authentication import InvalidCredentials
from litestar_security.providers.jwks import (
    CachedJWKSProvider,
    JWKSCacheEntry,
    JWKSFetchRequest,
    JWKSFetchResponse,
    WorkerLimits,
)
from litestar_security.providers.jwt import JWTValidationConfig, VerificationKey, normalize_verifier

pytestmark = [pytest.mark.performance, pytest.mark.benchmark(disable_gc=True, warmup=True)]

_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
_ISSUER = "https://issuer.example"
_AUDIENCE = "litestar-security"
_JWKS_URI = f"{_ISSUER}/.well-known/jwks.json"
_CONCURRENCY = 100


class _Fetcher:
    def __init__(self, response: JWKSFetchResponse) -> None:
        self.response = response

    async def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
        return self.response


@pytest.fixture
def asyncio_runner() -> Generator[asyncio.Runner, None, None]:
    """Own one persistent event loop for all iterations of a benchmark case."""
    with asyncio.Runner() as runner:
        yield runner


def _claims() -> dict[str, object]:
    return {
        "iss": _ISSUER,
        "sub": "user-1",
        "aud": _AUDIENCE,
        "exp": int((_NOW + timedelta(minutes=10)).timestamp()),
        "iat": int(_NOW.timestamp()),
    }


def _verification_jwk(key_material: Mapping[str, tuple[bytes, bytes]]) -> dict[str, object]:
    key = VerificationKey(key_id="key-1", algorithm="EdDSA", key=key_material["EdDSA"][1])
    return dict(cast("Mapping[str, object]", key.public_jwk))


def _response(key_material: Mapping[str, tuple[bytes, bytes]]) -> JWKSFetchResponse:
    body = json.dumps({"keys": [_verification_jwk(key_material)]}, separators=(",", ":")).encode()
    return JWKSFetchResponse(
        status_code=200, body=body, headers={"content-type": "application/json", "cache-control": "max-age=300"}
    )


def _verify(token: str, key: bytes) -> object:
    return jwt.decode(
        token,
        key,
        algorithms=["EdDSA"],
        audience=_AUDIENCE,
        issuer=_ISSUER,
        options={"verify_exp": False, "verify_iat": False, "verify_nbf": False},
    )


@pytest.mark.benchmark(group="jwks-cached-select-and-verify")
def test_direct_jwt_verification_benchmark(
    benchmark: Any, asyncio_runner: asyncio.Runner, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    private_key, public_key = jwt_key_material["EdDSA"]
    token = jwt.encode(_claims(), private_key, algorithm="EdDSA", headers={"typ": "at+jwt", "kid": "key-1"})
    benchmark.extra_info.update({"algorithm": "EdDSA", "issuer_count": 1, "concurrency": 1, "workload_size": 1})

    async def verify() -> object:
        return _verify(token, public_key)

    def run() -> object:
        return asyncio_runner.run(verify())

    result = benchmark(run)

    assert result["sub"] == "user-1"


@pytest.mark.benchmark(group="jwks-cached-select-and-verify")
def test_cached_jwks_select_and_verification_benchmark(
    benchmark: Any, asyncio_runner: asyncio.Runner, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    private_key, _public_key = jwt_key_material["EdDSA"]
    token = jwt.encode(_claims(), private_key, algorithm="EdDSA", headers={"typ": "at+jwt", "kid": "key-1"})
    provider = CachedJWKSProvider(
        entries=(JWKSCacheEntry(_ISSUER, _JWKS_URI, frozenset({"EdDSA"})),),
        fetcher=_Fetcher(_response(jwt_key_material)),
    )
    selected = asyncio_runner.run(provider.select_key(_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_NOW))
    assert isinstance(selected, VerificationKey)
    benchmark.extra_info.update({"algorithm": "EdDSA", "issuer_count": 1, "concurrency": 1, "workload_size": 1})

    async def select_and_verify() -> object:
        key = await provider.select_key(_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_NOW)
        assert isinstance(key, VerificationKey)
        return _verify(token, key.key)

    def run() -> object:
        return asyncio_runner.run(select_and_verify())

    result = benchmark(run)

    assert result["sub"] == "user-1"


@pytest.mark.benchmark(group="saturated-sync-verification")
def test_saturated_sync_verification_benchmark(benchmark: Any, asyncio_runner: asyncio.Runner) -> None:
    class SyncVerifier:
        config = JWTValidationConfig(issuer=_ISSUER, audiences=frozenset({_AUDIENCE}), algorithms=frozenset({"EdDSA"}))

        def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            assert now is _NOW
            sleep(0.002)
            return InvalidCredentials()

    verifier = normalize_verifier(SyncVerifier(), worker_limits=WorkerLimits(crypto_tokens=2))
    benchmark.extra_info.update({
        "algorithm": "EdDSA",
        "issuer_count": 1,
        "concurrency": _CONCURRENCY,
        "workload_size": _CONCURRENCY,
    })

    async def workload() -> tuple[int, int]:
        completed = 0
        ticks = 0

        async def verify() -> None:
            nonlocal completed
            await verifier.verify("token", now=_NOW)
            completed += 1

        async def ticker() -> None:
            nonlocal ticks
            while completed < _CONCURRENCY:
                await asyncio.sleep(0)
                ticks += 1

        await asyncio.gather(ticker(), *(verify() for _ in range(_CONCURRENCY)))
        return completed, ticks

    def run() -> tuple[int, int]:
        return asyncio_runner.run(workload())

    completed, ticks = benchmark(run)

    assert completed == _CONCURRENCY
    assert ticks > 0
