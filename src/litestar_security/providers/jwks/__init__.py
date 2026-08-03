"""Remote JWKS discovery with immutable per-issuer cache snapshots."""

from litestar_security.providers.jwks._cache import JWKSCacheEntry, JWKSCachePolicy
from litestar_security.providers.jwks._fetching import (
    AsyncJWKSFetcher,
    JWKSFetchRequest,
    JWKSFetchResponse,
    SyncJWKSFetcher,
    normalize_fetcher,
)
from litestar_security.providers.jwks._httpx import HttpxJWKSFetcher
from litestar_security.providers.jwks._provider import CachedJWKSProvider, JWKSProvider
from litestar_security.workers import NoOpSecurityMetrics, SecurityMetrics, WorkerLimits

__all__ = (
    "AsyncJWKSFetcher",
    "CachedJWKSProvider",
    "HttpxJWKSFetcher",
    "JWKSCacheEntry",
    "JWKSCachePolicy",
    "JWKSFetchRequest",
    "JWKSFetchResponse",
    "JWKSProvider",
    "NoOpSecurityMetrics",
    "SecurityMetrics",
    "SyncJWKSFetcher",
    "WorkerLimits",
    "normalize_fetcher",
)
