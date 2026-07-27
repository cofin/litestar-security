"""The cached JWKS provider: lock-free reads and single-flight refresh.

Fresh reads never take a lock; refreshes are owned by the provider and coalesced so
concurrent misses issue one request. Unknown-key state is generation-scoped and
bounded so a hostile issuer cannot grow it without limit.
"""

import asyncio
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from inspect import isawaitable
from time import perf_counter
from types import MappingProxyType
from typing import Protocol, TypeAlias, cast, runtime_checkable

from anyio import Lock
from litestar.status_codes import HTTP_200_OK, HTTP_304_NOT_MODIFIED

from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.config import NoOpSecurityMetrics, SecurityMetrics, WorkerLimits
from litestar_security.providers._internal import raise_config, safe_increment, safe_observe
from litestar_security.providers.jwks._cache import JWKSCacheEntry, JWKSCachePolicy, freshness
from litestar_security.providers.jwks._documents import parse_document
from litestar_security.providers.jwks._fetching import (
    AsyncJWKSFetcher,
    JWKSFetchRequest,
    JWKSFetchResponse,
    SyncJWKSFetcher,
    normalize_fetcher,
)
from litestar_security.providers.jwks._internal import aware_utc, etag, negative_cache, valid_selection_value
from litestar_security.providers.jwt import VerificationKey

__all__ = ("CachedJWKSProvider", "JWKSProvider")


JWKSSelection: TypeAlias = VerificationKey | InvalidCredentials | VerificationUnavailable


_SelectionKey: TypeAlias = tuple[str, str]


_EntryKey: TypeAlias = tuple[str, str]


_NegativeKey: TypeAlias = tuple[int, str, str]


_INVALID = InvalidCredentials()


_UNAVAILABLE = VerificationUnavailable()


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
            if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
                entry_value, JWKSCacheEntry
            ):
                raise_config("JWKS provider entries must be JWKSCacheEntry values")
            key = (entry_value.issuer, entry_value.jwks_uri)
            if key in states:
                raise_config("Duplicate JWKS provider entry")
            states[key] = _EntryState(config=entry_value)
        if not states:
            raise_config("JWKS provider requires at least one configured entry")
        workers = WorkerLimits() if worker_limits is None else worker_limits
        if not isinstance(workers, WorkerLimits):  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            raise_config("JWKS provider worker limits must be WorkerLimits")
        metric_sink = NoOpSecurityMetrics() if metrics is None else metrics
        if not callable(getattr(metric_sink, "increment", None)) or not callable(getattr(metric_sink, "observe", None)):
            raise_config("JWKS metrics must implement SecurityMetrics")
        if not isinstance(fetcher_owned, bool):  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            raise_config("JWKS fetcher ownership must be boolean")
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
        normalized_now = aware_utc(now)
        state = self._entries.get((issuer, jwks_uri))
        if (
            state is None
            or not valid_selection_value(kid)
            or not valid_selection_value(algorithm)
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
        normalized_now = aware_utc(now)
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
        self, state: "_EntryState", snapshot: "_Snapshot", selection: _SelectionKey, now: datetime
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
        self, state: "_EntryState", now: datetime, *, forced_generation: int | None = None
    ) -> "_Snapshot | VerificationUnavailable":
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
        self, state: "_EntryState", candidate: "_Refresh", now: datetime, forced_generation: int | None
    ) -> "tuple[_Refresh | None, _Snapshot | VerificationUnavailable]":
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
        self, state: "_EntryState", refresh: "_Refresh", now: datetime
    ) -> "_Snapshot | VerificationUnavailable":
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
        self, state: "_EntryState", refresh: "_Refresh", result: "_Snapshot | VerificationUnavailable"
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

    async def _fetch_snapshot(self, state: "_EntryState", now: datetime) -> "_Snapshot | VerificationUnavailable":
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
                fresh_until, stale_until = freshness(response.headers, self.policy, now)
                snapshot = _Snapshot(
                    keys=current.keys,
                    etag=etag(response.headers.get("etag")) or current.etag,
                    fresh_until=fresh_until,
                    stale_until=stale_until,
                    generation=current.generation,
                    source_uri=current.source_uri,
                )
            elif response.status_code == HTTP_200_OK:
                parse_started = perf_counter()
                try:
                    keys = parse_document(response.body, state.config, self.policy)
                except Exception:
                    self._increment("security.jwks.invalid_document")
                    raise
                finally:
                    self._observe("security.jwks.parse_duration", perf_counter() - parse_started)
                fresh_until, stale_until = freshness(response.headers, self.policy, now)
                snapshot = _Snapshot(
                    keys=keys,
                    etag=etag(response.headers.get("etag")),
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
        safe_increment(self._metrics, name)

    def _observe(self, name: str, value: float) -> None:
        safe_observe(self._metrics, name, value)

    async def _negative_hit(
        self, state: "_EntryState", generation: int, selection: _SelectionKey, now: datetime
    ) -> bool:
        key = (generation, *selection)
        async with state.lock:
            self._prune_negative(state, generation, now)
            expires_at = state.negative.get(key)
            if expires_at is None:
                return False
            state.negative.move_to_end(key)
            return True

    async def _remember_negative(
        self, state: "_EntryState", generation: int, selection: _SelectionKey, now: datetime
    ) -> None:
        key = (generation, *selection)
        async with state.lock:
            self._prune_negative(state, generation, now)
            state.negative[key] = now + self.policy.unknown_kid_cooldown
            state.negative.move_to_end(key)
            while len(state.negative) > self.policy.maximum_unknown_keys:
                state.negative.popitem(last=False)

    @staticmethod
    def _prune_negative(state: "_EntryState", generation: int, now: datetime) -> None:
        stale = tuple(key for key, expires_at in state.negative.items() if key[0] != generation or expires_at <= now)
        for key in stale:
            del state.negative[key]


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
    negative: OrderedDict[_NegativeKey, datetime] = field(default_factory=negative_cache)
