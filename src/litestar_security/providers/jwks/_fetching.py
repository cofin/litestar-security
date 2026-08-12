"""Fetcher protocols and normalization of sync or async transports.

Applications supply the HTTP client, so this module never imports one. Sync
fetchers are shared and run through an explicit finite worker limit.
"""

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from inspect import iscoroutinefunction
from math import isfinite
from time import perf_counter
from types import MappingProxyType
from typing import Protocol, cast, runtime_checkable

from anyio import CapacityLimiter, fail_after, to_thread

from litestar_security.providers._internal import raise_config, safe_increment, safe_observe
from litestar_security.providers.jwks._internal import empty_headers
from litestar_security.workers import NoOpSecurityMetrics, SecurityMetrics

__all__ = ("AsyncJWKSFetcher", "JWKSFetchOutcome", "JWKSFetchTarget", "SyncJWKSFetcher", "normalize_fetcher")


_DEFAULT_WORKER_TIMEOUT = 10.0


_MAXIMUM_WORKER_TOKENS = 1_024


_MINIMUM_HTTP_STATUS = 100


_MAXIMUM_HTTP_STATUS = 599


@dataclass(frozen=True, slots=True)
class JWKSFetchTarget:
    """One conditional request for an exact configured JWKS source."""

    issuer: str
    jwks_uri: str
    etag: str | None = None


@dataclass(frozen=True, slots=True)
class JWKSFetchOutcome:
    """Transport-neutral bounded response returned by a custom fetcher."""

    status_code: int
    body: bytes = field(default=b"", repr=False)
    headers: Mapping[str, str] = field(default_factory=empty_headers)

    def __post_init__(self) -> None:
        """Freeze a normalized case-insensitive header view."""
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            or not _MINIMUM_HTTP_STATUS <= self.status_code <= _MAXIMUM_HTTP_STATUS
            or not isinstance(self.body, bytes)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
        ):
            raise_config("Invalid JWKS fetch response")
        headers: dict[str, str] = {}
        try:
            raw_headers = cast("Mapping[object, object]", self.headers)
            for name, value in raw_headers.items():
                if not isinstance(name, str) or not isinstance(value, str) or not name:
                    raise_config("Invalid JWKS fetch response headers")
                headers[name.lower()] = value
        except (AttributeError, TypeError):
            raise_config("Invalid JWKS fetch response headers")
        object.__setattr__(self, "headers", MappingProxyType(headers))


@runtime_checkable
class AsyncJWKSFetcher(Protocol):
    """Async transport boundary for one exact configured JWKS source."""

    async def fetch(self, request: JWKSFetchTarget) -> JWKSFetchOutcome:
        """Return one finite-byte response without following redirects.

        Redirects are not followed, because a redirect could move key fetching to
        a host the operator never configured.

        Args:
            request: The issuer, configured JWKS URI, and optional ETag only;
                it carries no byte ceiling.

        Returns:
            A response with a finite ``bytes`` body.

        Raises:
            Exception: When the configured source cannot be fetched.

        Notes:
            The cache parser enforces
            ``JWKSCachePolicy.maximum_document_bytes`` after fetch. The
            optional HTTPX fetcher separately enforces its configured
            transport response ceiling.
        """
        ...  # pragma: no cover

    async def aclose(self) -> None:
        """Close resources owned by the fetcher."""
        ...  # pragma: no cover


@runtime_checkable
class SyncJWKSFetcher(Protocol):
    """Blocking transport boundary normalized once into a bounded worker."""

    def fetch(self, request: JWKSFetchTarget) -> JWKSFetchOutcome:
        """Return one finite-byte response without following redirects.

        Redirects are not followed, because a redirect could move key fetching to
        a host the operator never configured.

        Args:
            request: The issuer, configured JWKS URI, and optional ETag only;
                it carries no byte ceiling.

        Returns:
            A response with a finite ``bytes`` body.

        Raises:
            Exception: When the configured source cannot be fetched.

        Notes:
            The cache parser enforces
            ``JWKSCachePolicy.maximum_document_bytes`` after fetch. The
            optional HTTPX fetcher separately enforces its configured
            transport response ceiling.
        """
        ...  # pragma: no cover


def normalize_fetcher(
    fetcher: AsyncJWKSFetcher | SyncJWKSFetcher,
    *,
    limiter: CapacityLimiter,
    timeout: float = _DEFAULT_WORKER_TIMEOUT,
    metrics: SecurityMetrics | None = None,
) -> AsyncJWKSFetcher:
    """Normalize one custom transport once at configuration time.

    Args:
        fetcher: The application's transport, blocking or async.
        limiter: The capacity limiter a blocking transport runs inside.
        timeout: How long one blocking fetch may occupy a worker.
        metrics: The sink offered fetch measurements.

    Returns:
        An async fetcher. A blocking transport is wrapped so it never occupies
        the event loop.
    """
    fetch_method = getattr(fetcher, "fetch", None)
    if not callable(fetch_method):
        raise_config("JWKS fetcher must define fetch")
    total_tokens: object = limiter.total_tokens
    if (
        not isinstance(total_tokens, int)
        or isinstance(total_tokens, bool)
        or not 1 <= total_tokens <= _MAXIMUM_WORKER_TOKENS
    ):
        raise_config("JWKS worker limiter must have finite bounded capacity")
    if timeout.__class__ not in {int, float} or not isfinite(timeout) or timeout <= 0:
        raise_config("JWKS worker timeout must be finite and positive")
    metric_sink = NoOpSecurityMetrics() if metrics is None else metrics
    if not callable(getattr(metric_sink, "increment", None)) or not callable(getattr(metric_sink, "observe", None)):
        raise_config("JWKS metrics must implement SecurityMetrics")
    if iscoroutinefunction(fetch_method):
        close_method = getattr(fetcher, "aclose", None)
        if iscoroutinefunction(close_method):
            normalized_close = cast("Callable[[], Awaitable[None]]", close_method)
        elif callable(close_method):

            async def close_sync_method() -> None:
                close_method()

            normalized_close = close_sync_method

        else:

            async def close_noop() -> None:
                return None

            normalized_close = close_noop

        return _AsyncJWKSFetcher(
            fetch_async=cast("Callable[[JWKSFetchTarget], Awaitable[JWKSFetchOutcome]]", fetch_method),
            close_async=normalized_close,
        )
    return _WorkerJWKSFetcher(
        fetch_sync=cast("Callable[[JWKSFetchTarget], JWKSFetchOutcome]", fetch_method),
        limiter=limiter,
        timeout=float(timeout),
        metrics=metric_sink,
        source=fetcher,
    )


@dataclass(slots=True)
class _AsyncJWKSFetcher:
    fetch_async: Callable[[JWKSFetchTarget], Awaitable[JWKSFetchOutcome]] = field(repr=False)
    close_async: Callable[[], Awaitable[None]] = field(repr=False)

    async def fetch(self, request: JWKSFetchTarget) -> JWKSFetchOutcome:
        """Delegate to the configured async transport."""
        return await self.fetch_async(request)

    async def aclose(self) -> None:
        """Close the configured transport through one async contract."""
        await self.close_async()


@dataclass(slots=True)
class _WorkerJWKSFetcher:
    fetch_sync: Callable[[JWKSFetchTarget], JWKSFetchOutcome] = field(repr=False)
    limiter: CapacityLimiter = field(repr=False)
    timeout: float = field(repr=False)
    metrics: SecurityMetrics = field(repr=False)
    source: object = field(repr=False)

    async def fetch(self, request: JWKSFetchTarget) -> JWKSFetchOutcome:
        """Execute one blocking fetch without blocking the event loop."""
        if self.limiter.borrowed_tokens >= self.limiter.total_tokens:
            safe_increment(self.metrics, "security.worker.saturation")
        queued_at = perf_counter()

        def fetch_sync() -> JWKSFetchOutcome:
            started = perf_counter()
            safe_observe(self.metrics, "security.worker.wait", started - queued_at)
            try:
                return self.fetch_sync(request)
            finally:
                safe_observe(self.metrics, "security.worker.duration", perf_counter() - started)

        with fail_after(self.timeout):
            return await to_thread.run_sync(fetch_sync, abandon_on_cancel=True, limiter=self.limiter)

    async def aclose(self) -> None:
        """Close a blocking source when its provider explicitly owns it."""
        close = getattr(self.source, "close", None)
        if callable(close):
            with fail_after(self.timeout):
                await to_thread.run_sync(close, abandon_on_cancel=True, limiter=self.limiter)
