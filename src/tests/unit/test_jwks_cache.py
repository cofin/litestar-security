"""Unit contracts for the swappable JWKS cache."""

import json
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt.algorithms
import pytest
from cryptography.hazmat.primitives import serialization
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.providers.jwks import (
    CachedJWKSProvider,
    InMemoryJWKSCache,
    JWKSCache,
    JWKSCacheEntry,
    JWKSCachePolicy,
    JWKSFetchRequest,
    JWKSFetchResponse,
    JWKSSnapshot,
)
from litestar_security.providers.jwt import VerificationKey

ISSUER = "https://issuer.example.com"
JWKS_URI = "https://issuer.example.com/jwks.json"
NOW = datetime(2026, 8, 4, tzinfo=timezone.utc)


class _CountingFetcher:
    """Serve one fixed key set and count how many times it is asked for it."""

    def __init__(self, document: bytes) -> None:
        self.document = document
        self.calls = 0

    async def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        del request
        self.calls += 1
        return JWKSFetchResponse(status_code=200, headers={"cache-control": "max-age=600"}, body=self.document)


@pytest.fixture
def jwks_document(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> bytes:
    _, verification_key = jwt_key_material["RS256"]
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(serialization.load_pem_public_key(verification_key)))
    public_jwk.update({"kid": "shared-key", "alg": "RS256", "use": "sig"})
    return json.dumps({"keys": [public_jwk]}).encode()


def _entry() -> JWKSCacheEntry:
    return JWKSCacheEntry(issuer=ISSUER, jwks_uri=JWKS_URI, algorithms=frozenset({"RS256"}))


def _snapshot(*, generation: int = 1, keys: Mapping[tuple[str, str], VerificationKey] | None = None) -> JWKSSnapshot:
    return JWKSSnapshot(
        keys={} if keys is None else keys,
        etag=None,
        fresh_until=NOW + timedelta(minutes=10),
        stale_until=NOW + timedelta(minutes=10),
        generation=generation,
        source_uri=JWKS_URI,
    )


def test_in_memory_cache_round_trips_a_snapshot() -> None:
    cache = InMemoryJWKSCache()
    snapshot = _snapshot()

    assert cache.get(ISSUER, JWKS_URI) is None
    cache.set(ISSUER, JWKS_URI, snapshot)

    assert cache.get(ISSUER, JWKS_URI) is snapshot


def test_in_memory_cache_is_keyed_by_issuer_and_uri() -> None:
    cache = InMemoryJWKSCache()
    cache.set(ISSUER, JWKS_URI, _snapshot())

    assert cache.get("https://other.example.com", JWKS_URI) is None
    assert cache.get(ISSUER, "https://issuer.example.com/other.json") is None


def test_in_memory_cache_set_is_last_write_wins() -> None:
    cache = InMemoryJWKSCache()
    cache.set(ISSUER, JWKS_URI, _snapshot(generation=1))
    latest = _snapshot(generation=2)
    cache.set(ISSUER, JWKS_URI, latest)

    assert cache.get(ISSUER, JWKS_URI) is latest


def test_in_memory_cache_invalidate_is_idempotent() -> None:
    cache = InMemoryJWKSCache()
    cache.set(ISSUER, JWKS_URI, _snapshot())

    cache.invalidate(ISSUER, JWKS_URI)
    cache.invalidate(ISSUER, JWKS_URI)

    assert cache.get(ISSUER, JWKS_URI) is None


def test_in_memory_cache_satisfies_the_protocol() -> None:
    assert isinstance(InMemoryJWKSCache(), JWKSCache)


def test_snapshot_is_immutable() -> None:
    snapshot = _snapshot()

    with pytest.raises(AttributeError):
        snapshot.generation = 2  # type: ignore[misc]


def test_provider_rejects_a_cache_that_does_not_implement_the_protocol(jwks_document: bytes) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="JWKS cache"):
        CachedJWKSProvider((_entry(),), _CountingFetcher(jwks_document), cache=object())  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_a_provider_defaults_to_its_own_cache(jwks_document: bytes) -> None:
    fetcher = _CountingFetcher(jwks_document)
    first = CachedJWKSProvider((_entry(),), fetcher)
    second = CachedJWKSProvider((_entry(),), fetcher)

    assert isinstance(await first.select_key(ISSUER, JWKS_URI, "shared-key", "RS256", now=NOW), VerificationKey)
    assert isinstance(await second.select_key(ISSUER, JWKS_URI, "shared-key", "RS256", now=NOW), VerificationKey)

    assert fetcher.calls == 2


@pytest.mark.anyio
async def test_a_second_component_sharing_the_cache_does_not_fetch_again(jwks_document: bytes) -> None:
    fetcher = _CountingFetcher(jwks_document)
    cache = InMemoryJWKSCache()
    first = CachedJWKSProvider((_entry(),), fetcher, cache=cache)
    second = CachedJWKSProvider((_entry(),), fetcher, cache=cache)

    assert isinstance(await first.select_key(ISSUER, JWKS_URI, "shared-key", "RS256", now=NOW), VerificationKey)
    assert fetcher.calls == 1

    assert isinstance(await second.select_key(ISSUER, JWKS_URI, "shared-key", "RS256", now=NOW), VerificationKey)
    assert fetcher.calls == 1


@pytest.mark.anyio
async def test_an_application_cache_receives_the_published_snapshot(jwks_document: bytes) -> None:
    class _RecordingCache:
        def __init__(self) -> None:
            self.entries: dict[tuple[str, str], JWKSSnapshot] = {}
            self.reads = 0

        def get(self, issuer: str, jwks_uri: str) -> "JWKSSnapshot | None":
            self.reads += 1
            return self.entries.get((issuer, jwks_uri))

        def set(self, issuer: str, jwks_uri: str, snapshot: JWKSSnapshot) -> None:
            self.entries[issuer, jwks_uri] = snapshot

        def invalidate(self, issuer: str, jwks_uri: str) -> None:
            self.entries.pop((issuer, jwks_uri), None)

    cache = _RecordingCache()
    provider = CachedJWKSProvider((_entry(),), _CountingFetcher(jwks_document), cache=cache)

    await provider.select_key(ISSUER, JWKS_URI, "shared-key", "RS256", now=NOW)

    stored = cache.entries[ISSUER, JWKS_URI]
    assert cache.reads > 0
    assert stored.generation == 1
    assert stored.source_uri == JWKS_URI
    assert ("shared-key", "RS256") in stored.keys


@pytest.mark.anyio
async def test_an_evicted_entry_is_refetched_like_a_cold_miss(jwks_document: bytes) -> None:
    fetcher = _CountingFetcher(jwks_document)
    cache = InMemoryJWKSCache()
    provider = CachedJWKSProvider((_entry(),), fetcher, cache=cache, policy=JWKSCachePolicy())

    await provider.select_key(ISSUER, JWKS_URI, "shared-key", "RS256", now=NOW)
    cache.invalidate(ISSUER, JWKS_URI)
    selection: Any = await provider.select_key(ISSUER, JWKS_URI, "shared-key", "RS256", now=NOW)

    assert isinstance(selection, VerificationKey)
    assert fetcher.calls == 2
