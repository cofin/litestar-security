"""The cached JWKS provider: lock-free reads, single-flight refresh, and document parsing."""

import asyncio
import json
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import perf_counter
from types import MappingProxyType
from typing import Any, Protocol, TypeAlias, cast, runtime_checkable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt import PyJWK
from litestar.status_codes import HTTP_200_OK, HTTP_304_NOT_MODIFIED

from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.providers._internal import (
    JSONValue,
    raise_config,
    reject_non_finite,
    safe_increment,
    safe_observe,
    unique_object,
    validate_depth,
)
from litestar_security.providers.jwks._transport import (
    AsyncJWKSFetcher,
    InMemoryJWKSCache,
    JWKSCache,
    JWKSCacheCoordinator,
    JWKSCachePolicy,
    JWKSFetchOutcome,
    JWKSFetchTarget,
    JWKSSnapshot,
    JWKSSource,
    SyncJWKSFetcher,
    freshness,
    normalize_fetcher,
    valid_selection_value,
)
from litestar_security.providers.jwt import JWTAlgorithm, VerificationKey
from litestar_security.workers import NoOpSecurityMetrics, SecurityMetrics, WorkerLimits

__all__ = (
    "CachedJWKSProvider",
    "JWKSProvider",
    "JWKSSelection",
    "aware_utc",
    "etag",
    "negative_cache",
    "parse_document",
)

JWKSSelection: TypeAlias = VerificationKey | InvalidCredentials | VerificationUnavailable

_SelectionKey: TypeAlias = tuple[str, str]
_EntryKey: TypeAlias = tuple[str, str]
_NegativeKey: TypeAlias = tuple[int, str, str]

_INVALID = InvalidCredentials()
_UNAVAILABLE = VerificationUnavailable()

_MAXIMUM_ETAG_LENGTH = 1_024
_MAXIMUM_JSON_DEPTH = 64
_ASCII_CONTROL_LIMIT = 32
_SUPPORTED_REMOTE_ALGORITHMS = frozenset({"EdDSA", "ES256", "RS256"})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "dp", "dq", "k", "oth", "p", "q", "qi"})


def negative_cache() -> OrderedDict[_NegativeKey, datetime]:
    """Allocate an ordered dictionary for negative cache entries."""
    return OrderedDict()


def aware_utc(value: datetime) -> datetime:
    """Ensure a datetime is timezone-aware and converted to UTC."""
    time_value = cast("object", value)
    if not isinstance(time_value, datetime) or time_value.tzinfo is None or time_value.utcoffset() is None:
        raise_config("JWKS selection time must be timezone-aware")
    return value.astimezone(timezone.utc)


def etag(value: str | None) -> str | None:
    """Normalize and validate an ETag header value."""
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


def parse_document(body: bytes, entry: JWKSSource, policy: JWKSCachePolicy) -> Mapping[_SelectionKey, VerificationKey]:
    """Parse and validate a raw JWKS document into immutable verification keys."""
    if len(body) > policy.maximum_document_bytes:
        raise ValueError
    decoded = cast("object", json.loads(body, object_pairs_hook=unique_object, parse_constant=reject_non_finite))
    if not isinstance(decoded, dict):
        raise TypeError
    document = cast("dict[str, object]", decoded)
    validate_depth(cast("JSONValue", document), maximum=_MAXIMUM_JSON_DEPTH)
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


def _parse_key(value: Mapping[str, JSONValue], entry: JWKSSource) -> VerificationKey:
    if _PRIVATE_JWK_MEMBERS.intersection(value):
        raise ValueError
    algorithm = value.get("alg")
    key_id = value.get("kid")
    if (
        not isinstance(algorithm, str)
        or algorithm not in entry.algorithms
        or algorithm not in _SUPPORTED_REMOTE_ALGORITHMS
        or not isinstance(key_id, str)
        or not valid_selection_value(key_id)
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


@runtime_checkable
class JWKSProvider(Protocol):
    """Select remote verification keys without exposing cache internals."""

    async def select_key(self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime) -> JWKSSelection:
        """Return a key or one stable authentication outcome."""
        ...

    async def warmup(self, *, now: datetime) -> VerificationUnavailable | None:
        """Warm configured entries when enabled."""
        ...

    async def aclose(self) -> None:
        """Close owned runtime resources."""
        ...


class CachedJWKSProvider:
    """Configured remote-key cache with a lock-free immutable fresh path."""

    __slots__ = ("_cache", "_closed", "_entries", "_fetcher", "_fetcher_closed", "_fetcher_owned", "_metrics", "policy")

    def __init__(
        self,
        entries: Sequence[JWKSSource],
        fetcher: AsyncJWKSFetcher | SyncJWKSFetcher,
        *,
        policy: JWKSCachePolicy | None = None,
        cache: JWKSCache | None = None,
        metrics: SecurityMetrics | None = None,
        fetcher_owned: bool = False,
        worker_limits: WorkerLimits | None = None,
    ) -> None:
        """Allocate every exact cache entry at startup."""
        states: dict[_EntryKey, _EntryState] = {}
        for entry in entries:
            entry_value = cast("object", entry)
            if not isinstance(entry_value, JWKSSource):
                raise_config("JWKS provider entries must be JWKSSource values")
            key = (entry_value.issuer, entry_value.jwks_uri)
            if key in states:
                raise_config("Duplicate JWKS provider entry")
            states[key] = _EntryState(config=entry_value)
        if not states:
            raise_config("JWKS provider requires at least one configured entry")
        workers = WorkerLimits() if worker_limits is None else worker_limits
        workers_obj = cast("object", workers)
        if not isinstance(workers_obj, WorkerLimits):
            raise_config("JWKS provider worker limits must be WorkerLimits")
        metric_sink = NoOpSecurityMetrics() if metrics is None else metrics
        if not callable(getattr(metric_sink, "increment", None)) or not callable(getattr(metric_sink, "observe", None)):
            raise_config("JWKS metrics must implement SecurityMetrics")
        owned_obj = cast("object", fetcher_owned)
        if not isinstance(owned_obj, bool):
            raise_config("JWKS fetcher ownership must be boolean")
        snapshots = InMemoryJWKSCache() if cache is None else cache
        cache_obj = cast("object", snapshots)
        if not isinstance(cache_obj, JWKSCache):
            raise_config("JWKS cache must implement JWKSCache")
        normalized_fetcher = normalize_fetcher(
            fetcher, limiter=workers.network_limiter, timeout=workers.timeout, metrics=metric_sink
        )
        self.policy = policy or JWKSCachePolicy()
        self._cache = snapshots
        for state in states.values():
            state.coordination = snapshots.coordinator(state.config.issuer, state.config.jwks_uri)
            state.coordination.users += 1
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
        snapshot = self._snapshot(state)
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
        if self._closed:
            return
        self._closed = True
        refreshes: list[tuple[_EntryState, _Refresh]] = []
        tasks: list[asyncio.Task[JWKSSnapshot | VerificationUnavailable]] = []
        for state in self._entries.values():
            coordination = state.coordination
            async with coordination.lock:
                coordination.users -= 1
                if coordination.refresh is not None:
                    refresh = cast("_Refresh", coordination.refresh)
                    task = refresh.task
                    if task is not None:
                        if coordination.users == 0:
                            task.cancel()
                        tasks.append(task)
                        refreshes.append((state, refresh))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for state, _refresh in refreshes:
            async with state.coordination.lock:
                if state.coordination.refresh is _refresh and _refresh.task is not None and _refresh.task.done():
                    state.coordination.refresh = None
        if self._fetcher_owned and not self._fetcher_closed:
            self._fetcher_closed = True
            await self._fetcher.aclose()

    async def _select_unknown(
        self, state: "_EntryState", snapshot: "JWKSSnapshot", selection: _SelectionKey, now: datetime
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
    ) -> "JWKSSnapshot | VerificationUnavailable":
        candidate = _Refresh(forced_generation=forced_generation)
        refresh, immediate = await self._coordinate_refresh(state, candidate, now, forced_generation)
        if refresh is None:
            return immediate
        task = refresh.task
        if task is None:
            return _UNAVAILABLE
        try:
            if refresh is not candidate:
                started = perf_counter()
                try:
                    result = await asyncio.shield(task)
                finally:
                    self._observe("security.jwks.single_flight_wait", perf_counter() - started)
            else:
                result = await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.cancelled() or self._closed:
                return _UNAVAILABLE
            raise
        return _UNAVAILABLE if self._closed else result

    async def _coordinate_refresh(
        self, state: "_EntryState", candidate: "_Refresh", now: datetime, forced_generation: int | None
    ) -> "tuple[_Refresh | None, JWKSSnapshot | VerificationUnavailable]":
        refresh: _Refresh | None = None
        immediate: JWKSSnapshot | VerificationUnavailable = _UNAVAILABLE
        coordination = state.coordination
        async with coordination.lock:
            current = self._snapshot(state)
            current_is_fresh = current is not None and now < current.fresh_until
            forced_generation_changed = forced_generation is not None and (
                current is None or current.generation != forced_generation
            )
            forced_generation_used = (
                forced_generation is not None and coordination.forced_generation == forced_generation
            )
            if self._closed:
                pass
            elif (forced_generation is None and current_is_fresh) or forced_generation_changed:
                immediate = current or _UNAVAILABLE
            elif coordination.refresh is not None:
                refresh = cast("_Refresh", coordination.refresh)
            elif forced_generation_used:
                immediate = current or _UNAVAILABLE
            else:
                if forced_generation is not None:
                    coordination.forced_generation = forced_generation
                coordination.refresh = candidate
                candidate.task = asyncio.create_task(
                    self._run_refresh(state, candidate, now), name="litestar-security-jwks-refresh"
                )
                refresh = candidate
        return refresh, immediate

    async def _run_refresh(
        self, state: "_EntryState", refresh: "_Refresh", now: datetime
    ) -> "JWKSSnapshot | VerificationUnavailable":
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
        return result

    async def _publish_refresh(
        self, state: "_EntryState", refresh: "_Refresh", result: "JWKSSnapshot | VerificationUnavailable"
    ) -> None:
        coordination = state.coordination
        async with coordination.lock:
            current = self._snapshot(state)
            if isinstance(result, JWKSSnapshot):
                self._cache.set(state.config.issuer, state.config.jwks_uri, result)
                if refresh.forced_generation is not None:
                    coordination.forced_generation = result.generation
                if current is None or result.generation != current.generation:
                    coordination.negative.clear()
                    if current is not None:
                        self._increment("security.jwks.rotation")
            if coordination.refresh is refresh:
                coordination.refresh = None

    async def _fetch_snapshot(self, state: "_EntryState", now: datetime) -> "JWKSSnapshot | VerificationUnavailable":
        current = self._snapshot(state)
        request = JWKSFetchTarget(
            issuer=state.config.issuer, jwks_uri=state.config.jwks_uri, etag=None if current is None else current.etag
        )
        try:
            fetch_started = perf_counter()
            try:
                response_value = cast("object", await self._fetcher.fetch(request))
            finally:
                self._observe("security.jwks.fetch_duration", perf_counter() - fetch_started)
            if not isinstance(response_value, JWKSFetchOutcome):
                return _UNAVAILABLE
            response = response_value
            if response.status_code == HTTP_304_NOT_MODIFIED:
                if current is None:
                    return _UNAVAILABLE
                self._increment("security.jwks.not_modified")
                fresh_until, stale_until = freshness(response.headers, self.policy, now)
                snapshot = JWKSSnapshot(
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
                snapshot = JWKSSnapshot(
                    keys=keys,
                    etag=etag(response.headers.get("etag")),
                    fresh_until=fresh_until,
                    stale_until=stale_until,
                    generation=1 if current is None else current.generation + 1,
                    source_uri=state.config.jwks_uri,
                )
            else:
                return _UNAVAILABLE
        except Exception:
            return _UNAVAILABLE
        return snapshot

    def _snapshot(self, state: "_EntryState") -> "JWKSSnapshot | None":
        return self._cache.get(state.config.issuer, state.config.jwks_uri)

    def _increment(self, name: str) -> None:
        safe_increment(self._metrics, name)

    def _observe(self, name: str, value: float) -> None:
        safe_observe(self._metrics, name, value)

    async def _negative_hit(
        self, state: "_EntryState", generation: int, selection: _SelectionKey, now: datetime
    ) -> bool:
        key = (generation, *selection)
        coordination = state.coordination
        async with coordination.lock:
            self._prune_negative(state, generation, now)
            expires_at = coordination.negative.get(key)
            if expires_at is None:
                return False
            coordination.negative.move_to_end(key)
            return True

    async def _remember_negative(
        self, state: "_EntryState", generation: int, selection: _SelectionKey, now: datetime
    ) -> None:
        key = (generation, *selection)
        coordination = state.coordination
        async with coordination.lock:
            self._prune_negative(state, generation, now)
            coordination.negative[key] = now + self.policy.unknown_kid_cooldown
            coordination.negative.move_to_end(key)
            while len(coordination.negative) > self.policy.maximum_unknown_keys:
                coordination.negative.popitem(last=False)

    @staticmethod
    def _prune_negative(state: "_EntryState", generation: int, now: datetime) -> None:
        stale = tuple(
            key for key, expires_at in state.coordination.negative.items() if key[0] != generation or expires_at <= now
        )
        for key in stale:
            del state.coordination.negative[key]


@dataclass(slots=True)
class _Refresh:
    forced_generation: int | None = None
    task: asyncio.Task[JWKSSnapshot | VerificationUnavailable] | None = None


@dataclass(slots=True)
class _EntryState:
    config: JWKSSource
    coordination: JWKSCacheCoordinator = field(init=False)

    @property
    def lock(self) -> object:
        return self.coordination.lock

    @lock.setter
    def lock(self, value: object) -> None:
        self.coordination.lock = cast("Any", value)

    @property
    def refresh(self) -> "_Refresh | None":
        return cast("_Refresh | None", self.coordination.refresh)

    @refresh.setter
    def refresh(self, value: "_Refresh | None") -> None:
        self.coordination.refresh = value

    @property
    def forced_generation(self) -> int | None:
        return self.coordination.forced_generation

    @forced_generation.setter
    def forced_generation(self, value: int | None) -> None:
        self.coordination.forced_generation = value

    @property
    def negative(self) -> "OrderedDict[tuple[int, str, str], datetime]":
        return self.coordination.negative
