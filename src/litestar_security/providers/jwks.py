"""Remote JWKS fetching, caching, and atomic rotation."""

import asyncio
import json
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from inspect import isawaitable, iscoroutinefunction
from math import isfinite
from time import perf_counter
from types import MappingProxyType
from typing import NoReturn, Protocol, TypeAlias, cast, runtime_checkable

from anyio import CapacityLimiter, Lock, fail_after, to_thread
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt import PyJWK
from litestar.exceptions import ImproperlyConfiguredException
from litestar.status_codes import HTTP_200_OK, HTTP_304_NOT_MODIFIED

from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.config import NoOpSecurityMetrics, SecurityMetrics, WorkerLimits
from litestar_security.providers.jwt import JSONValue, JWTAlgorithm, VerificationKey

__all__ = (
    "AsyncJWKSFetcher",
    "CachedJWKSProvider",
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

JWKSSelection: TypeAlias = VerificationKey | InvalidCredentials | VerificationUnavailable
_SelectionKey: TypeAlias = tuple[str, str]
_EntryKey: TypeAlias = tuple[str, str]
_NegativeKey: TypeAlias = tuple[int, str, str]

_DEFAULT_TTL = timedelta(minutes=15)
_MINIMUM_TTL = timedelta(seconds=30)
_MAXIMUM_TTL = timedelta(hours=24)
_UNKNOWN_KID_COOLDOWN = timedelta(seconds=30)
_MAXIMUM_DOCUMENT_BYTES = 1_048_576
_MAXIMUM_KEYS = 128
_MAXIMUM_UNKNOWN_KEYS = 1_024
_DEFAULT_WORKER_TIMEOUT = 10.0
_MAXIMUM_WORKER_TOKENS = 1_024
_MAXIMUM_JSON_DEPTH = 64
_MINIMUM_HTTP_STATUS = 100
_MAXIMUM_HTTP_STATUS = 599
_MAXIMUM_ETAG_LENGTH = 1_024
_ASCII_CONTROL_LIMIT = 32
_ASCII_DELETE = 127
_SUPPORTED_REMOTE_ALGORITHMS = frozenset({"EdDSA", "ES256", "RS256"})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "dp", "dq", "k", "oth", "p", "q", "qi"})
_INVALID = InvalidCredentials()
_UNAVAILABLE = VerificationUnavailable()
_EMPTY_HEADERS: Mapping[str, str] = MappingProxyType({})


def _empty_headers() -> Mapping[str, str]:
    return _EMPTY_HEADERS


def _negative_cache() -> OrderedDict[_NegativeKey, datetime]:
    return OrderedDict()


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
        durations: tuple[object, ...] = (
            self.default_ttl,
            self.minimum_ttl,
            self.maximum_ttl,
            self.unknown_kid_cooldown,
            self.stale_if_error,
        )
        if any(
            not isinstance(value, timedelta)  # pyright: ignore[reportUnnecessaryIsInstance]
            for value in durations
        ):
            _raise_config("JWKS cache durations must be timedeltas")
        if (
            not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                self.warm_on_startup, bool
            )
            or self.minimum_ttl <= timedelta(0)
            or self.maximum_ttl < self.minimum_ttl
            or not self.minimum_ttl <= self.default_ttl <= self.maximum_ttl
            or self.unknown_kid_cooldown <= timedelta(0)
            or self.stale_if_error < timedelta(0)
        ):
            _raise_config("JWKS cache durations must be positive, ordered, and bounded")
        if (
            isinstance(self.maximum_document_bytes, bool)
            or not isinstance(self.maximum_document_bytes, int)  # pyright: ignore[reportUnnecessaryIsInstance]
            or not 1 <= self.maximum_document_bytes <= _MAXIMUM_DOCUMENT_BYTES
            or isinstance(self.maximum_keys, bool)
            or not isinstance(self.maximum_keys, int)  # pyright: ignore[reportUnnecessaryIsInstance]
            or not 1 <= self.maximum_keys <= _MAXIMUM_KEYS
            or isinstance(self.maximum_unknown_keys, bool)
            or not isinstance(self.maximum_unknown_keys, int)  # pyright: ignore[reportUnnecessaryIsInstance]
            or not 1 <= self.maximum_unknown_keys <= _MAXIMUM_UNKNOWN_KEYS
        ):
            _raise_config("JWKS cache limits must be positive and bounded")


@dataclass(frozen=True, slots=True)
class JWKSCacheEntry:
    """One exact configured issuer and JWKS source."""

    issuer: str
    jwks_uri: str
    algorithms: frozenset[str]

    def __post_init__(self) -> None:
        """Normalize immutable algorithms and reject ambiguous identifiers."""
        issuer = _strict_value(self.issuer, "JWKS issuer")
        jwks_uri = _strict_value(self.jwks_uri, "JWKS URI")
        algorithms = frozenset(self.algorithms)
        if not algorithms or not algorithms.issubset(_SUPPORTED_REMOTE_ALGORITHMS):
            _raise_config("JWKS entry requires supported asymmetric signing algorithms")
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "jwks_uri", jwks_uri)
        object.__setattr__(self, "algorithms", algorithms)


@dataclass(frozen=True, slots=True)
class JWKSFetchRequest:
    """One conditional request for an exact configured JWKS source."""

    issuer: str
    jwks_uri: str
    etag: str | None = None


@dataclass(frozen=True, slots=True)
class JWKSFetchResponse:
    """Transport-neutral bounded response returned by a custom fetcher."""

    status_code: int
    body: bytes = field(default=b"", repr=False)
    headers: Mapping[str, str] = field(default_factory=_empty_headers)

    def __post_init__(self) -> None:
        """Freeze a normalized case-insensitive header view."""
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)  # pyright: ignore[reportUnnecessaryIsInstance]
            or not _MINIMUM_HTTP_STATUS <= self.status_code <= _MAXIMUM_HTTP_STATUS
            or not isinstance(self.body, bytes)  # pyright: ignore[reportUnnecessaryIsInstance]
        ):
            _raise_config("Invalid JWKS fetch response")
        headers: dict[str, str] = {}
        try:
            raw_headers = cast("Mapping[object, object]", self.headers)
            for name, value in raw_headers.items():
                if not isinstance(name, str) or not isinstance(value, str) or not name:
                    _raise_config("Invalid JWKS fetch response headers")
                headers[name.lower()] = value
        except (AttributeError, TypeError):
            _raise_config("Invalid JWKS fetch response headers")
        object.__setattr__(self, "headers", MappingProxyType(headers))


@runtime_checkable
class AsyncJWKSFetcher(Protocol):
    """Async transport boundary for one exact configured JWKS source."""

    async def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        """Return one bounded response without following redirects."""
        ...  # pragma: no cover


@runtime_checkable
class SyncJWKSFetcher(Protocol):
    """Blocking transport boundary normalized once into a bounded worker."""

    def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        """Return one bounded response without following redirects."""
        ...  # pragma: no cover


@dataclass(slots=True)
class _WorkerJWKSFetcher:
    fetch_sync: Callable[[JWKSFetchRequest], JWKSFetchResponse] = field(repr=False)
    limiter: CapacityLimiter = field(repr=False)
    timeout: float = field(repr=False)
    metrics: SecurityMetrics = field(repr=False)
    source: object = field(repr=False)

    async def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        """Execute one blocking fetch without blocking the event loop."""
        if self.limiter.borrowed_tokens >= self.limiter.total_tokens:
            _safe_increment(self.metrics, "security.worker.saturation")
        queued_at = perf_counter()

        def fetch_sync() -> JWKSFetchResponse:
            started = perf_counter()
            _safe_observe(self.metrics, "security.worker.wait", started - queued_at)
            try:
                return self.fetch_sync(request)
            finally:
                _safe_observe(self.metrics, "security.worker.duration", perf_counter() - started)

        with fail_after(self.timeout):
            return await to_thread.run_sync(fetch_sync, abandon_on_cancel=True, limiter=self.limiter)

    async def aclose(self) -> None:
        """Close a blocking source when its provider explicitly owns it."""
        close = getattr(self.source, "close", None)
        if callable(close):
            with fail_after(self.timeout):
                await to_thread.run_sync(close, abandon_on_cancel=True, limiter=self.limiter)


def normalize_fetcher(
    fetcher: AsyncJWKSFetcher | SyncJWKSFetcher,
    *,
    limiter: CapacityLimiter,
    timeout: float = _DEFAULT_WORKER_TIMEOUT,
    metrics: SecurityMetrics | None = None,
) -> AsyncJWKSFetcher:
    """Normalize one custom transport once at configuration time."""
    fetch_method = getattr(fetcher, "fetch", None)
    if not callable(fetch_method):
        _raise_config("JWKS fetcher must define fetch")
    total_tokens: object = limiter.total_tokens
    if (
        not isinstance(total_tokens, int)
        or isinstance(total_tokens, bool)
        or not 1 <= total_tokens <= _MAXIMUM_WORKER_TOKENS
    ):
        _raise_config("JWKS worker limiter must have finite bounded capacity")
    if timeout.__class__ not in {int, float} or not isfinite(timeout) or timeout <= 0:
        _raise_config("JWKS worker timeout must be finite and positive")
    metric_sink = NoOpSecurityMetrics() if metrics is None else metrics
    if not callable(getattr(metric_sink, "increment", None)) or not callable(getattr(metric_sink, "observe", None)):
        _raise_config("JWKS metrics must implement SecurityMetrics")
    if iscoroutinefunction(fetch_method):
        return cast("AsyncJWKSFetcher", fetcher)
    return _WorkerJWKSFetcher(
        fetch_sync=cast("Callable[[JWKSFetchRequest], JWKSFetchResponse]", fetch_method),
        limiter=limiter,
        timeout=float(timeout),
        metrics=metric_sink,
        source=fetcher,
    )


@runtime_checkable
class JWKSProvider(Protocol):
    """Select remote verification keys without exposing cache internals."""

    async def select_key(self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime) -> JWKSSelection:
        """Return a key or one stable authentication outcome."""
        ...  # pragma: no cover

    async def warmup(self, *, now: datetime) -> VerificationUnavailable | None:
        """Warm configured entries when enabled."""
        ...  # pragma: no cover

    async def aclose(self) -> None:
        """Close owned runtime resources."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class _Snapshot:
    keys: Mapping[_SelectionKey, VerificationKey]
    etag: str | None
    fresh_until: datetime
    stale_until: datetime
    generation: int
    source_uri: str


@dataclass(slots=True)
class _Refresh:
    forced_generation: int | None = None
    task: asyncio.Task[_Snapshot | VerificationUnavailable] | None = None


@dataclass(slots=True)
class _EntryState:
    config: JWKSCacheEntry
    snapshot: _Snapshot | None = None
    lock: Lock = field(default_factory=Lock)
    refresh: _Refresh | None = None
    forced_generation: int | None = None
    negative: OrderedDict[_NegativeKey, datetime] = field(default_factory=_negative_cache)


class CachedJWKSProvider:
    """Configured remote-key cache with a lock-free immutable fresh path."""

    __slots__ = ("_closed", "_entries", "_fetcher", "_fetcher_closed", "_fetcher_owned", "_metrics", "policy")

    def __init__(  # noqa: PLR0913 - provider assembly keeps ownership, workers, policy, and metrics explicit
        self,
        entries: Sequence[JWKSCacheEntry],
        fetcher: AsyncJWKSFetcher | SyncJWKSFetcher,
        *,
        policy: JWKSCachePolicy | None = None,
        metrics: SecurityMetrics | None = None,
        fetcher_owned: bool = False,
        worker_limits: WorkerLimits | None = None,
    ) -> None:
        """Allocate every exact cache entry at startup."""
        states: dict[_EntryKey, _EntryState] = {}
        for entry in entries:
            entry_value: object = entry
            if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                entry_value, JWKSCacheEntry
            ):
                _raise_config("JWKS provider entries must be JWKSCacheEntry values")
            key = (entry_value.issuer, entry_value.jwks_uri)
            if key in states:
                _raise_config("Duplicate JWKS provider entry")
            states[key] = _EntryState(config=entry_value)
        if not states:
            _raise_config("JWKS provider requires at least one configured entry")
        workers = WorkerLimits() if worker_limits is None else worker_limits
        if not isinstance(workers, WorkerLimits):  # pyright: ignore[reportUnnecessaryIsInstance]
            _raise_config("JWKS provider worker limits must be WorkerLimits")
        metric_sink = NoOpSecurityMetrics() if metrics is None else metrics
        if not callable(getattr(metric_sink, "increment", None)) or not callable(getattr(metric_sink, "observe", None)):
            _raise_config("JWKS metrics must implement SecurityMetrics")
        if not isinstance(fetcher_owned, bool):  # pyright: ignore[reportUnnecessaryIsInstance]
            _raise_config("JWKS fetcher ownership must be boolean")
        normalized_fetcher = normalize_fetcher(
            fetcher, limiter=workers.network_limiter, timeout=workers.timeout, metrics=metric_sink
        )
        self.policy = policy or JWKSCachePolicy()
        self._fetcher = normalized_fetcher
        self._fetcher_owned = fetcher_owned
        self._fetcher_closed = False
        self._metrics = metric_sink
        self._entries = MappingProxyType(states)
        self._closed = False

    async def select_key(self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime) -> JWKSSelection:
        """Read a fresh snapshot directly or refresh one exact entry."""
        if self._closed:
            return _UNAVAILABLE
        normalized_now = _aware_utc(now)
        state = self._entries.get((issuer, jwks_uri))
        if (
            state is None
            or not _valid_selection_value(kid)
            or not _valid_selection_value(algorithm)
            or algorithm not in state.config.algorithms
        ):
            return _INVALID
        selection = (kid, algorithm)
        snapshot = state.snapshot
        if snapshot is not None and normalized_now < snapshot.fresh_until:
            selected = snapshot.keys.get(selection)
            if selected is not None:
                self._increment("security.jwks.fresh_hit")
            return (
                selected
                if selected is not None
                else await self._select_unknown(state, snapshot, selection, normalized_now)
            )

        self._increment("security.jwks.cold_miss" if snapshot is None else "security.jwks.expired")
        refreshed = await self._refresh_singleflight(state, normalized_now)
        if isinstance(refreshed, VerificationUnavailable):
            if snapshot is not None and normalized_now < snapshot.stale_until:
                stale = snapshot.keys.get(selection, _UNAVAILABLE)
                if isinstance(stale, VerificationKey):
                    self._increment("security.jwks.stale_use")
                return stale
            selection_result: JWKSSelection = refreshed
        else:
            selected = refreshed.keys.get(selection)
            if selected is None:
                await self._remember_negative(state, refreshed.generation, selection, normalized_now)
            selection_result = selected or _INVALID
        return selection_result

    async def warmup(self, *, now: datetime) -> VerificationUnavailable | None:
        """Eagerly populate configured entries when startup warming is enabled."""
        if self._closed:
            return _UNAVAILABLE
        normalized_now = _aware_utc(now)
        if not self.policy.warm_on_startup:
            return None
        outcome: VerificationUnavailable | None = None
        for state in self._entries.values():
            if isinstance(await self._refresh_singleflight(state, normalized_now), VerificationUnavailable):
                outcome = _UNAVAILABLE
        return outcome

    async def aclose(self) -> None:
        """Close this provider idempotently without closing its caller-owned fetcher."""
        self._closed = True
        refreshes: list[tuple[_EntryState, _Refresh]] = []
        tasks: list[asyncio.Task[_Snapshot | VerificationUnavailable]] = []
        for state in self._entries.values():
            async with state.lock:
                if state.refresh is not None:
                    refresh = state.refresh
                    task = refresh.task
                    assert task is not None  # noqa: S101 - internal coordination invariant
                    task.cancel()
                    tasks.append(task)
                    refreshes.append((state, refresh))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for state, _refresh in refreshes:
            async with state.lock:
                state.refresh = None
        if self._fetcher_owned and not self._fetcher_closed:
            self._fetcher_closed = True
            close = getattr(self._fetcher, "aclose", None)
            if callable(close):
                close_result = close()
                if isawaitable(close_result):
                    await close_result

    async def _select_unknown(
        self, state: _EntryState, snapshot: _Snapshot, selection: _SelectionKey, now: datetime
    ) -> JWKSSelection:
        self._increment("security.jwks.unknown_key")
        if await self._negative_hit(state, snapshot.generation, selection, now):
            self._increment("security.jwks.negative_hit")
            return _INVALID
        refreshed = await self._refresh_singleflight(state, now, forced_generation=snapshot.generation)
        if isinstance(refreshed, VerificationUnavailable):
            await self._remember_negative(state, snapshot.generation, selection, now)
            return refreshed
        selected = refreshed.keys.get(selection)
        if selected is not None:
            return selected
        await self._remember_negative(state, refreshed.generation, selection, now)
        return _INVALID

    async def _refresh_singleflight(
        self, state: _EntryState, now: datetime, *, forced_generation: int | None = None
    ) -> _Snapshot | VerificationUnavailable:
        candidate = _Refresh(forced_generation=forced_generation)
        refresh, immediate = await self._coordinate_refresh(state, candidate, now, forced_generation)
        if refresh is None:
            return immediate
        task = refresh.task
        if task is None:  # pragma: no cover - assigned before coordination releases the entry lock
            return _UNAVAILABLE
        try:
            if refresh is not candidate:
                started = perf_counter()
                try:
                    return await asyncio.shield(task)
                finally:
                    self._observe("security.jwks.single_flight_wait", perf_counter() - started)
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.cancelled() or self._closed:
                return _UNAVAILABLE
            raise

    async def _coordinate_refresh(
        self, state: _EntryState, candidate: _Refresh, now: datetime, forced_generation: int | None
    ) -> tuple[_Refresh | None, _Snapshot | VerificationUnavailable]:
        refresh: _Refresh | None = None
        immediate: _Snapshot | VerificationUnavailable = _UNAVAILABLE
        async with state.lock:
            current = state.snapshot
            current_is_fresh = current is not None and now < current.fresh_until
            forced_generation_changed = forced_generation is not None and (
                current is None or current.generation != forced_generation
            )
            forced_generation_used = forced_generation is not None and state.forced_generation == forced_generation
            if self._closed:
                pass
            elif (forced_generation is None and current_is_fresh) or forced_generation_changed:
                immediate = current or _UNAVAILABLE
            elif state.refresh is not None:
                refresh = state.refresh
            elif forced_generation_used:
                immediate = current or _UNAVAILABLE
            else:
                if forced_generation is not None:
                    state.forced_generation = forced_generation
                state.refresh = candidate
                candidate.task = asyncio.create_task(
                    self._run_refresh(state, candidate, now), name="litestar-security-jwks-refresh"
                )
                refresh = candidate
        return refresh, immediate

    async def _run_refresh(
        self, state: _EntryState, refresh: _Refresh, now: datetime
    ) -> _Snapshot | VerificationUnavailable:
        try:
            result = await self._fetch_snapshot(state, now)
        except asyncio.CancelledError:
            result = _UNAVAILABLE
        self._increment(
            "security.jwks.refresh_failure"
            if isinstance(result, VerificationUnavailable)
            else "security.jwks.refresh_success"
        )
        await self._publish_refresh(state, refresh, result)
        return _UNAVAILABLE if self._closed else result

    async def _publish_refresh(
        self, state: _EntryState, refresh: _Refresh, result: _Snapshot | VerificationUnavailable
    ) -> None:
        async with state.lock:
            current = state.snapshot
            if isinstance(result, _Snapshot) and not self._closed:
                state.snapshot = result
                if refresh.forced_generation is not None:
                    state.forced_generation = result.generation
                if current is None or result.generation != current.generation:
                    state.negative.clear()
                    if current is not None:
                        self._increment("security.jwks.rotation")
            state.refresh = None

    async def _fetch_snapshot(self, state: _EntryState, now: datetime) -> _Snapshot | VerificationUnavailable:
        current = state.snapshot
        request = JWKSFetchRequest(
            issuer=state.config.issuer, jwks_uri=state.config.jwks_uri, etag=None if current is None else current.etag
        )
        try:
            fetch_started = perf_counter()
            try:
                response_value = cast("object", await self._fetcher.fetch(request))
            finally:
                self._observe("security.jwks.fetch_duration", perf_counter() - fetch_started)
            if not isinstance(response_value, JWKSFetchResponse):
                return _UNAVAILABLE
            response = response_value
            if response.status_code == HTTP_304_NOT_MODIFIED:
                if current is None:
                    return _UNAVAILABLE
                self._increment("security.jwks.not_modified")
                fresh_until, stale_until = _freshness(response.headers, self.policy, now)
                snapshot = _Snapshot(
                    keys=current.keys,
                    etag=_etag(response.headers.get("etag")) or current.etag,
                    fresh_until=fresh_until,
                    stale_until=stale_until,
                    generation=current.generation,
                    source_uri=current.source_uri,
                )
            elif response.status_code == HTTP_200_OK:
                parse_started = perf_counter()
                try:
                    keys = _parse_document(response.body, state.config, self.policy)
                except Exception:
                    self._increment("security.jwks.invalid_document")
                    raise
                finally:
                    self._observe("security.jwks.parse_duration", perf_counter() - parse_started)
                fresh_until, stale_until = _freshness(response.headers, self.policy, now)
                snapshot = _Snapshot(
                    keys=keys,
                    etag=_etag(response.headers.get("etag")),
                    fresh_until=fresh_until,
                    stale_until=stale_until,
                    generation=1 if current is None else current.generation + 1,
                    source_uri=state.config.jwks_uri,
                )
            else:
                return _UNAVAILABLE
        except Exception:  # noqa: BLE001 - custom fetcher and parser failures are one sanitized operational outcome
            return _UNAVAILABLE
        return snapshot

    def _increment(self, name: str) -> None:
        _safe_increment(self._metrics, name)

    def _observe(self, name: str, value: float) -> None:
        _safe_observe(self._metrics, name, value)

    async def _negative_hit(self, state: _EntryState, generation: int, selection: _SelectionKey, now: datetime) -> bool:
        key = (generation, *selection)
        async with state.lock:
            self._prune_negative(state, generation, now)
            expires_at = state.negative.get(key)
            if expires_at is None:
                return False
            state.negative.move_to_end(key)
            return True

    async def _remember_negative(
        self, state: _EntryState, generation: int, selection: _SelectionKey, now: datetime
    ) -> None:
        key = (generation, *selection)
        async with state.lock:
            self._prune_negative(state, generation, now)
            state.negative[key] = now + self.policy.unknown_kid_cooldown
            state.negative.move_to_end(key)
            while len(state.negative) > self.policy.maximum_unknown_keys:
                state.negative.popitem(last=False)

    @staticmethod
    def _prune_negative(state: _EntryState, generation: int, now: datetime) -> None:
        stale = tuple(key for key, expires_at in state.negative.items() if key[0] != generation or expires_at <= now)
        for key in stale:
            del state.negative[key]


def _freshness(headers: Mapping[str, str], policy: JWKSCachePolicy, now: datetime) -> tuple[datetime, datetime]:
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


def _parse_document(
    body: bytes, entry: JWKSCacheEntry, policy: JWKSCachePolicy
) -> Mapping[_SelectionKey, VerificationKey]:
    if len(body) > policy.maximum_document_bytes:
        raise ValueError
    decoded = cast("object", json.loads(body, object_pairs_hook=_unique_object, parse_constant=_reject_non_finite))
    if not isinstance(decoded, dict):
        raise TypeError
    document = cast("dict[str, object]", decoded)
    _validate_depth(cast("JSONValue", document))
    raw_keys: object = document.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        raise ValueError
    raw_key_values = cast("list[object]", raw_keys)
    if len(raw_key_values) > policy.maximum_keys:
        raise ValueError
    keys: dict[_SelectionKey, VerificationKey] = {}
    for raw_key in raw_key_values:
        if not isinstance(raw_key, Mapping):
            raise TypeError
        key = _parse_key(cast("Mapping[str, JSONValue]", raw_key), entry)
        selection = (key.key_id, key.algorithm)
        if selection in keys:
            raise ValueError
        keys[selection] = key
    return MappingProxyType(keys)


def _parse_key(value: Mapping[str, JSONValue], entry: JWKSCacheEntry) -> VerificationKey:
    if _PRIVATE_JWK_MEMBERS.intersection(value):
        raise ValueError
    algorithm = value.get("alg")
    key_id = value.get("kid")
    if (
        not isinstance(algorithm, str)
        or algorithm not in entry.algorithms
        or algorithm not in _SUPPORTED_REMOTE_ALGORITHMS
        or not isinstance(key_id, str)
        or not _valid_selection_value(key_id)
        or value.get("use") not in {None, "sig"}
    ):
        raise ValueError
    key_ops = value.get("key_ops")
    if key_ops is not None and (
        not isinstance(key_ops, list)
        or "verify" not in key_ops
        or any(not isinstance(operation, str) for operation in cast("list[object]", key_ops))
    ):
        raise ValueError
    canonical = dict(value)
    canonical["alg"] = algorithm
    canonical["kid"] = key_id
    canonical["use"] = "sig"
    canonical["key_ops"] = ["verify"]
    pyjwk = PyJWK.from_dict(cast("dict[str, object]", canonical), algorithm=algorithm)
    prepared = pyjwk.key
    if not isinstance(prepared, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)):
        raise TypeError
    pem = prepared.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return VerificationKey(key_id=key_id, algorithm=cast("JWTAlgorithm", algorithm), key=pem, public_jwk=canonical)


def _unique_object(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    value: dict[str, JSONValue] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _validate_depth(value: JSONValue) -> None:
    stack: list[tuple[JSONValue, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAXIMUM_JSON_DEPTH:
            raise ValueError
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _reject_non_finite(_value: str) -> float:
    raise ValueError


def _etag(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return (
        normalized
        if normalized
        and len(normalized) <= _MAXIMUM_ETAG_LENGTH
        and not any(ord(char) < _ASCII_CONTROL_LIMIT for char in normalized)
        else None
    )


def _aware_utc(value: datetime) -> datetime:
    time_value: object = value
    if (
        not isinstance(time_value, datetime)  # pyright: ignore[reportUnnecessaryIsInstance]
        or time_value.tzinfo is None
        or time_value.utcoffset() is None
    ):
        _raise_config("JWKS selection time must be timezone-aware")
    return time_value.astimezone(timezone.utc)


def _strict_value(value: str, label: str) -> str:
    if not _valid_selection_value(value):
        _raise_config(f"{label} must be a normalized non-empty string")
    return value


def _valid_selection_value(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and not any(ord(character) < _ASCII_CONTROL_LIMIT or ord(character) == _ASCII_DELETE for character in value)
    )


def _safe_increment(metrics: SecurityMetrics, name: str) -> None:
    with suppress(Exception):  # observability must never alter authentication behavior
        metrics.increment(name)


def _safe_observe(metrics: SecurityMetrics, name: str, value: float) -> None:
    with suppress(Exception):  # observability must never alter authentication behavior
        metrics.observe(name, value)


def _raise_config(detail: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=detail)
