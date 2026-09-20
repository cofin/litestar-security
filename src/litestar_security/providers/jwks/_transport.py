"""Transport, HTTP client, fetching, and in-memory caching for JWKS sources."""

import ipaddress
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from inspect import iscoroutinefunction
from math import isfinite
from time import perf_counter
from types import MappingProxyType
from typing import Protocol, TypeAlias, cast, runtime_checkable
from urllib.parse import urlsplit

import httpx
from anyio import CapacityLimiter, Lock, fail_after, to_thread

from litestar_security.providers._internal import (
    AddressResolver,
    public_address,
    raise_config,
    resolve_addresses,
    safe_increment,
    safe_observe,
)
from litestar_security.providers.jwt import VerificationKey
from litestar_security.workers import NoOpSecurityMetrics, SecurityMetrics

__all__ = (
    "AsyncJWKSFetcher",
    "HttpxJWKSFetcher",
    "InMemoryJWKSCache",
    "JWKSCache",
    "JWKSCacheCoordinator",
    "JWKSCachePolicy",
    "JWKSFetchOutcome",
    "JWKSFetchTarget",
    "JWKSSnapshot",
    "JWKSSource",
    "SelectionKey",
    "SyncJWKSFetcher",
    "empty_headers",
    "freshness",
    "normalize_fetcher",
    "strict_value",
    "valid_selection_value",
)

SelectionKey: TypeAlias = tuple[str, str]

_DEFAULT_TTL = timedelta(minutes=15)
_MINIMUM_TTL = timedelta(seconds=30)
_MAXIMUM_TTL = timedelta(hours=24)
_UNKNOWN_KID_COOLDOWN = timedelta(seconds=30)
_MAXIMUM_DOCUMENT_BYTES = 1_048_576
_MAXIMUM_KEYS = 128
_MAXIMUM_UNKNOWN_KEYS = 1_024
_SUPPORTED_REMOTE_ALGORITHMS = frozenset({"EdDSA", "ES256", "RS256"})
_ASCII_CONTROL_LIMIT = 32
_ASCII_DELETE = 127
_EMPTY_HEADERS: Mapping[str, str] = MappingProxyType({})
_DEFAULT_WORKER_TIMEOUT = 10.0
_MAXIMUM_WORKER_TOKENS = 1_024
_MINIMUM_HTTP_STATUS = 100
_MAXIMUM_HTTP_STATUS = 599
_HOST_RESOLUTION_UNAVAILABLE = "JWKS host resolution unavailable"
_RESPONSE_TOO_LARGE = "JWKS response exceeds the configured byte limit"
_NO_RESOLVED_ADDRESSES = "JWKS host resolution returned no addresses"
_INVALID_RESOLVED_ADDRESS = "JWKS host resolution returned an invalid address"
_NON_PUBLIC_RESOLVED_ADDRESS = "JWKS host resolved outside the public network boundary"
_INVALID_URL = "JWKS URI must be an absolute HTTPS URL"
_UNSUPPORTED_CONTENT_ENCODING = "JWKS response encoding is not allowed"
_DEFAULT_HTTPS_PORT = 443


def empty_headers() -> Mapping[str, str]:
    """Return an immutable empty headers mapping."""
    return _EMPTY_HEADERS


def valid_selection_value(value: object) -> bool:
    """Validate that a selection value is a non-empty ASCII string without control characters."""
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and not any(ord(character) < _ASCII_CONTROL_LIMIT or ord(character) == _ASCII_DELETE for character in value)
    )


def strict_value(value: str, label: str) -> str:
    """Ensure a string satisfies valid selection value criteria."""
    if not valid_selection_value(value):
        raise_config(f"{label} must be a normalized non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class JWKSSource:
    """One exact configured issuer and JWKS source."""

    issuer: str
    jwks_uri: str
    algorithms: frozenset[str]

    def __post_init__(self) -> None:
        """Normalize immutable algorithms and reject ambiguous identifiers."""
        issuer = strict_value(self.issuer, "JWKS issuer")
        jwks_uri = strict_value(self.jwks_uri, "JWKS URI")
        algorithms = frozenset(self.algorithms)
        if not algorithms or not algorithms.issubset(_SUPPORTED_REMOTE_ALGORITHMS):
            raise_config("JWKS entry requires supported asymmetric signing algorithms")
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "jwks_uri", jwks_uri)
        object.__setattr__(self, "algorithms", algorithms)


def freshness(headers: Mapping[str, str], policy: "JWKSCachePolicy", now: datetime) -> tuple[datetime, datetime]:
    """Derive fresh_until and stale_until from Cache-Control headers."""
    directives = tuple(part.strip().lower() for part in headers.get("cache-control", "").split(",") if part.strip())
    no_store = "no-store" in directives
    no_cache = "no-cache" in directives
    max_ages = tuple(part.partition("=")[2].strip('"') for part in directives if part.partition("=")[0] == "max-age")
    ttl = policy.default_ttl
    if len(max_ages) == 1 and max_ages[0].isdecimal():
        ttl = timedelta(seconds=int(max_ages[0]))
        ttl = max(policy.minimum_ttl, min(ttl, policy.maximum_ttl))
    if no_store or no_cache:
        ttl = timedelta(0)
    fresh_until = now + ttl
    stale_until = fresh_until if no_store else fresh_until + policy.stale_if_error
    return fresh_until, stale_until


@dataclass(frozen=True, slots=True)
class JWKSCachePolicy:
    """Local freshness and bounded-document policy for remote JWKS entries."""

    default_ttl: timedelta = _DEFAULT_TTL
    minimum_ttl: timedelta = _MINIMUM_TTL
    maximum_ttl: timedelta = _MAXIMUM_TTL
    unknown_kid_cooldown: timedelta = _UNKNOWN_KID_COOLDOWN
    stale_if_error: timedelta = timedelta(0)
    warm_on_startup: bool = False
    maximum_document_bytes: int = _MAXIMUM_DOCUMENT_BYTES
    maximum_keys: int = _MAXIMUM_KEYS
    maximum_unknown_keys: int = _MAXIMUM_UNKNOWN_KEYS

    def __post_init__(self) -> None:
        """Reject unsafe or contradictory cache bounds."""
        raw_durations = (
            cast("object", self.default_ttl),
            cast("object", self.minimum_ttl),
            cast("object", self.maximum_ttl),
            cast("object", self.unknown_kid_cooldown),
            cast("object", self.stale_if_error),
        )
        if any(not isinstance(val, timedelta) for val in raw_durations):
            raise_config("JWKS cache durations must be timedeltas")
        warm_val = cast("object", self.warm_on_startup)
        if (
            not isinstance(warm_val, bool)
            or self.minimum_ttl <= timedelta(0)
            or self.maximum_ttl < self.minimum_ttl
            or not self.minimum_ttl <= self.default_ttl <= self.maximum_ttl
            or self.unknown_kid_cooldown <= timedelta(0)
            or self.stale_if_error < timedelta(0)
        ):
            raise_config("JWKS cache durations must be positive, ordered, and bounded")
        max_doc_bytes = cast("object", self.maximum_document_bytes)
        max_keys = cast("object", self.maximum_keys)
        max_unknown_keys = cast("object", self.maximum_unknown_keys)
        if (
            isinstance(max_doc_bytes, bool)
            or not isinstance(max_doc_bytes, int)
            or not 1 <= self.maximum_document_bytes <= _MAXIMUM_DOCUMENT_BYTES
            or isinstance(max_keys, bool)
            or not isinstance(max_keys, int)
            or not 1 <= self.maximum_keys <= _MAXIMUM_KEYS
            or isinstance(max_unknown_keys, bool)
            or not isinstance(max_unknown_keys, int)
            or not 1 <= self.maximum_unknown_keys <= _MAXIMUM_UNKNOWN_KEYS
        ):
            raise_config("JWKS cache limits must be positive and bounded")


@dataclass(frozen=True, slots=True)
class JWKSSnapshot:
    """One immutable parsed key set together with its freshness bounds.

    Args:
        keys: Verification keys indexed by the exact (kid, algorithm) pair a
            token header names.
        etag: The entity tag the source returned, used for conditional refresh.
        fresh_until: When the snapshot stops being served without a refresh.
        stale_until: How long the snapshot may still answer while the source is
            unreachable.
        generation: Increases on every parsed replacement, so a consumer can tell
            a rotation from a revalidation.
        source_uri: The key set this snapshot was parsed from.
    """

    keys: Mapping[SelectionKey, VerificationKey]
    etag: str | None
    fresh_until: datetime
    stale_until: datetime
    generation: int
    source_uri: str


@dataclass(slots=True)
class JWKSCacheCoordinator:
    """Share refresh and negative-key state for one exact cache entry.

    Cache implementations return the same coordinator for repeated requests for
    one exact (issuer, jwks_uri) pair. Applications normally only construct
    this value while implementing JWKSCache; providers manage its
    contents.

    Args:
        lock: Lock serializing refresh and negative-key changes.
        refresh: Opaque in-flight refresh state owned by a provider.
        forced_generation: The generation whose unknown-key refresh was used.
        negative: Bounded generation-scoped unknown-key expirations.
        users: Number of providers attached to this coordination state.
    """

    lock: Lock = field(default_factory=Lock)
    refresh: object | None = None
    forced_generation: int | None = None
    negative: OrderedDict[tuple[int, str, str], datetime] = field(
        default_factory=OrderedDict[tuple[int, str, str], datetime]
    )
    users: int = 0


@runtime_checkable
class JWKSCache(Protocol):
    """Store remote key snapshots so components can share one fetch schedule.

    An implementer must honor three invariants:
    - Snapshots are immutable.
    - set is last-write-wins.
    - A miss is indistinguishable from an expired entry.
    """

    def get(self, issuer: str, jwks_uri: str) -> JWKSSnapshot | None:
        """Return the stored snapshot for one configured source."""
        ...

    def set(self, issuer: str, jwks_uri: str, snapshot: JWKSSnapshot) -> None:
        """Store the newest snapshot for one configured source."""
        ...

    def invalidate(self, issuer: str, jwks_uri: str) -> None:
        """Drop any snapshot stored for one configured source."""
        ...

    def coordinator(self, issuer: str, jwks_uri: str) -> JWKSCacheCoordinator:
        """Return stable coordination state for one configured source."""
        ...


class InMemoryJWKSCache:
    """Hold key snapshots for the lifetime of one process."""

    __slots__ = ("_coordinators", "_entries")

    def __init__(self) -> None:
        """Start with no stored snapshots."""
        self._entries: dict[SelectionKey, JWKSSnapshot] = {}
        self._coordinators: dict[SelectionKey, JWKSCacheCoordinator] = {}

    def get(self, issuer: str, jwks_uri: str) -> JWKSSnapshot | None:
        """Return the stored snapshot for one configured source."""
        return self._entries.get((issuer, jwks_uri))

    def set(self, issuer: str, jwks_uri: str, snapshot: JWKSSnapshot) -> None:
        """Store the newest snapshot for one configured source."""
        self._entries[issuer, jwks_uri] = snapshot

    def invalidate(self, issuer: str, jwks_uri: str) -> None:
        """Drop any snapshot stored for one configured source."""
        self._entries.pop((issuer, jwks_uri), None)

    def coordinator(self, issuer: str, jwks_uri: str) -> JWKSCacheCoordinator:
        """Return stable coordination state for one configured source."""
        return self._coordinators.setdefault((issuer, jwks_uri), JWKSCacheCoordinator())


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
        status_val = cast("object", self.status_code)
        body_val = cast("object", self.body)
        if (
            isinstance(status_val, bool)
            or not isinstance(status_val, int)
            or not _MINIMUM_HTTP_STATUS <= self.status_code <= _MAXIMUM_HTTP_STATUS
            or not isinstance(body_val, bytes)
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
        """Return one finite-byte response without following redirects."""
        ...

    async def aclose(self) -> None:
        """Close resources owned by the fetcher."""
        ...


@runtime_checkable
class SyncJWKSFetcher(Protocol):
    """Blocking transport boundary normalized once into a bounded worker."""

    def fetch(self, request: JWKSFetchTarget) -> JWKSFetchOutcome:
        """Return one finite-byte response without following redirects."""
        ...


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


class _FetchGuardError(Exception):
    """Sanitized outbound JWKS boundary failure."""


@dataclass(slots=True)
class HttpxJWKSFetcher:
    """HTTPX-backed async fetcher for operator-configured JWKS endpoints."""

    timeout: float = 5.0
    maximum_response_bytes: int = 1_048_576
    allow_private_hosts: bool = False
    transport: httpx.AsyncBaseTransport | None = None
    resolver: AddressResolver | None = None
    _client: httpx.AsyncClient = field(init=False, repr=False)
    _closed: bool = field(init=False, default=False, repr=False)
    _resolve: AddressResolver = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate resource limits and construct the owned HTTP client."""
        timeout_val = cast("object", self.timeout)
        if (
            isinstance(timeout_val, bool)
            or not isinstance(timeout_val, (int, float))
            or not isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise_config("JWKS HTTPX timeout must be finite and positive")
        resp_bytes_val = cast("object", self.maximum_response_bytes)
        if (
            isinstance(resp_bytes_val, bool)
            or not isinstance(resp_bytes_val, int)
            or self.maximum_response_bytes <= 0
        ):
            raise_config("JWKS HTTPX maximum_response_bytes must be a positive integer")
        self._resolve = self.resolver or resolve_addresses
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(float(self.timeout)),
            transport=self.transport,
            trust_env=False,
        )

    async def fetch(self, request: JWKSFetchTarget) -> JWKSFetchOutcome:
        """Return one bounded response without following redirects.

        Args:
            request: The exact configured JWKS URI and optional ETag condition.

        Returns:
            The bounded transport response, including un-followed redirect status
            codes for the provider to reject.

        Raises:
            _FetchGuardError: If the configured URI or host fails its network
                boundary, the response is encoded, or it exceeds its byte ceiling.
            httpx.HTTPError: If the outbound request fails. Any exception raised
                here becomes VerificationUnavailable at the JWKS provider.
        """
        await self._guard_host(request.jwks_uri)
        headers = {"accept-encoding": "identity"}
        if request.etag is not None:
            headers["if-none-match"] = request.etag
        async with self._client.stream("GET", request.jwks_uri, headers=headers) as response:
            body = await self._read_bounded_body(response)
            return JWKSFetchOutcome(status_code=response.status_code, body=body, headers=dict(response.headers))

    async def aclose(self) -> None:
        """Close the owned HTTP client idempotently."""
        if not self._closed:
            self._closed = True
            await self._client.aclose()

    async def _guard_host(self, url: str) -> None:
        parsed = self._parse_url(url)
        if self.allow_private_hosts:
            return
        host = parsed.host
        port = parsed.port or _DEFAULT_HTTPS_PORT
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            try:
                addresses = tuple(await self._resolve(host, port))
            except (OSError, RuntimeError) as exc:
                raise _FetchGuardError(_HOST_RESOLUTION_UNAVAILABLE) from exc
        else:
            addresses = (str(literal),)
        self._validate_resolved_addresses(addresses)

    async def _read_bounded_body(self, response: httpx.Response) -> bytes:
        content_encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if content_encoding not in {"", "identity"}:
            raise _FetchGuardError(_UNSUPPORTED_CONTENT_ENCODING)
        body = bytearray()
        async for chunk in response.aiter_bytes():
            if len(chunk) > self.maximum_response_bytes - len(body):
                raise _FetchGuardError(_RESPONSE_TOO_LARGE)
            body.extend(chunk)
        return bytes(body)

    @staticmethod
    def _validate_resolved_addresses(addresses: Sequence[str]) -> None:
        if not addresses:
            raise _FetchGuardError(_NO_RESOLVED_ADDRESSES)
        try:
            parsed = tuple(ipaddress.ip_address(address) for address in addresses)
        except ValueError as exc:
            raise _FetchGuardError(_INVALID_RESOLVED_ADDRESS) from exc
        if any(not public_address(address) for address in parsed):
            raise _FetchGuardError(_NON_PUBLIC_RESOLVED_ADDRESS)

    @staticmethod
    def _parse_url(value: str) -> httpx.URL:
        value_obj = cast("object", value)
        if not isinstance(value_obj, str) or not value_obj or value_obj != value_obj.strip():
            raise _FetchGuardError(_INVALID_URL)
        try:
            split = urlsplit(value)
            url = httpx.URL(value)
        except (TypeError, ValueError, httpx.InvalidURL) as exc:
            raise _FetchGuardError(_INVALID_URL) from exc
        if (
            split.scheme.lower() != "https"
            or not split.netloc
            or split.username is not None
            or split.password is not None
            or split.fragment
            or not url.host
        ):
            raise _FetchGuardError(_INVALID_URL)
        return url
