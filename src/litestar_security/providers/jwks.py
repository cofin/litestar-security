"""Remote JWKS fetching, caching, and atomic rotation."""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import NoReturn, Protocol, TypeAlias, cast, runtime_checkable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt import PyJWK
from litestar.exceptions import ImproperlyConfiguredException
from litestar.status_codes import HTTP_200_OK, HTTP_304_NOT_MODIFIED

from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.providers.jwt import JSONValue, JWTAlgorithm, VerificationKey

__all__ = (
    "AsyncJWKSFetcher",
    "CachedJWKSProvider",
    "JWKSCacheEntry",
    "JWKSCachePolicy",
    "JWKSFetchRequest",
    "JWKSFetchResponse",
    "JWKSProvider",
)

JWKSSelection: TypeAlias = VerificationKey | InvalidCredentials | VerificationUnavailable
_SelectionKey: TypeAlias = tuple[str, str]
_EntryKey: TypeAlias = tuple[str, str]

_DEFAULT_TTL = timedelta(minutes=15)
_MINIMUM_TTL = timedelta(seconds=30)
_MAXIMUM_TTL = timedelta(hours=24)
_UNKNOWN_KID_COOLDOWN = timedelta(seconds=30)
_MAXIMUM_DOCUMENT_BYTES = 1_048_576
_MAXIMUM_KEYS = 128
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
        ):
            _raise_config("JWKS document limits must be positive and bounded")


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
class JWKSProvider(Protocol):
    """Select remote verification keys without exposing cache internals."""

    async def select_key(self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime) -> JWKSSelection:
        """Return a key or one stable authentication outcome."""
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
class _EntryState:
    config: JWKSCacheEntry
    snapshot: _Snapshot | None = None


class CachedJWKSProvider:
    """Configured remote-key cache with a lock-free immutable fresh path."""

    __slots__ = ("_closed", "_entries", "_fetcher", "policy")

    def __init__(
        self, entries: Sequence[JWKSCacheEntry], fetcher: AsyncJWKSFetcher, *, policy: JWKSCachePolicy | None = None
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
        fetcher_value: object = fetcher
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            fetcher_value, AsyncJWKSFetcher
        ):
            _raise_config("JWKS provider requires an async fetcher")
        self.policy = policy or JWKSCachePolicy()
        self._fetcher = fetcher
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
            return snapshot.keys.get(selection, _INVALID)

        refreshed = await self._refresh(state, normalized_now)
        if isinstance(refreshed, VerificationUnavailable):
            if snapshot is not None and normalized_now < snapshot.stale_until:
                return snapshot.keys.get(selection, _UNAVAILABLE)
            selection_result: JWKSSelection = refreshed
        else:
            selection_result = refreshed.keys.get(selection, _INVALID)
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
            if isinstance(await self._refresh(state, normalized_now), VerificationUnavailable):
                outcome = _UNAVAILABLE
        return outcome

    async def aclose(self) -> None:
        """Close this provider idempotently without closing its caller-owned fetcher."""
        self._closed = True

    async def _refresh(self, state: _EntryState, now: datetime) -> _Snapshot | VerificationUnavailable:
        current = state.snapshot
        request = JWKSFetchRequest(
            issuer=state.config.issuer, jwks_uri=state.config.jwks_uri, etag=None if current is None else current.etag
        )
        try:
            response_value = cast("object", await self._fetcher.fetch(request))
            if not isinstance(response_value, JWKSFetchResponse):
                return _UNAVAILABLE
            response = response_value
            if response.status_code == HTTP_304_NOT_MODIFIED:
                if current is None:
                    return _UNAVAILABLE
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
                keys = _parse_document(response.body, state.config, self.policy)
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
        state.snapshot = snapshot
        return snapshot


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


def _raise_config(detail: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=detail)
