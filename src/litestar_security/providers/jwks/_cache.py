"""Cache policy, the configured source entry, and the shareable key snapshot.

Snapshots are immutable: a refresh builds a new one and replaces the old one
atomically, so a reader never observes a half-updated key set. The store holding
them is swappable, which is how two components in one application share a single
key set and a single fetch schedule.
"""

from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol, TypeAlias, runtime_checkable

from anyio import Lock

from litestar_security.providers._internal import raise_config
from litestar_security.providers.jwks._internal import strict_value
from litestar_security.providers.jwt import VerificationKey

__all__ = (
    "InMemoryJWKSCache",
    "JWKSCache",
    "JWKSCacheCoordinator",
    "JWKSCacheEntry",
    "JWKSCachePolicy",
    "JWKSSnapshot",
)


SelectionKey: TypeAlias = tuple[str, str]
"""The exact ``(kid, algorithm)`` pair a token header names."""


_DEFAULT_TTL = timedelta(minutes=15)


_MINIMUM_TTL = timedelta(seconds=30)


_MAXIMUM_TTL = timedelta(hours=24)


_UNKNOWN_KID_COOLDOWN = timedelta(seconds=30)


_MAXIMUM_DOCUMENT_BYTES = 1_048_576


_MAXIMUM_KEYS = 128


_MAXIMUM_UNKNOWN_KEYS = 1_024


_SUPPORTED_REMOTE_ALGORITHMS = frozenset({"EdDSA", "ES256", "RS256"})


@dataclass(frozen=True, slots=True)
class JWKSCacheEntry:
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
        durations: tuple[object, ...] = (
            self.default_ttl,
            self.minimum_ttl,
            self.maximum_ttl,
            self.unknown_kid_cooldown,
            self.stale_if_error,
        )
        if any(
            not isinstance(value, timedelta)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            for value in durations
        ):
            raise_config("JWKS cache durations must be timedeltas")
        if (
            not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
                self.warm_on_startup, bool
            )
            or self.minimum_ttl <= timedelta(0)
            or self.maximum_ttl < self.minimum_ttl
            or not self.minimum_ttl <= self.default_ttl <= self.maximum_ttl
            or self.unknown_kid_cooldown <= timedelta(0)
            or self.stale_if_error < timedelta(0)
        ):
            raise_config("JWKS cache durations must be positive, ordered, and bounded")
        if (
            isinstance(self.maximum_document_bytes, bool)
            or not isinstance(self.maximum_document_bytes, int)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            or not 1 <= self.maximum_document_bytes <= _MAXIMUM_DOCUMENT_BYTES
            or isinstance(self.maximum_keys, bool)
            or not isinstance(self.maximum_keys, int)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            or not 1 <= self.maximum_keys <= _MAXIMUM_KEYS
            or isinstance(self.maximum_unknown_keys, bool)
            or not isinstance(self.maximum_unknown_keys, int)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            or not 1 <= self.maximum_unknown_keys <= _MAXIMUM_UNKNOWN_KEYS
        ):
            raise_config("JWKS cache limits must be positive and bounded")


@dataclass(frozen=True, slots=True)
class JWKSSnapshot:
    """One immutable parsed key set together with its freshness bounds.

    Args:
        keys: Verification keys indexed by the exact ``(kid, algorithm)`` pair a
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
    one exact ``(issuer, jwks_uri)`` pair. Applications normally only construct
    this value while implementing :class:`JWKSCache`; providers manage its
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

    - **Snapshots are immutable.** Store and return the value as given; never
      mutate one in place, and never hand back a partially populated key set.
    - **``set`` is last-write-wins.** The most recent write for a key is the one
      a later ``get`` returns. No merging, no ordering by generation.
    - **A miss is indistinguishable from an expired entry.** Returning ``None``
      is always safe: the caller refetches. An implementation may therefore
      evict, expire, or bound itself however it likes, and must never fabricate
      or extend a snapshot to avoid a miss.

    Methods are synchronous because they sit on the token-verification hot path,
    where the fresh read must not await.
    """

    def get(self, issuer: str, jwks_uri: str) -> "JWKSSnapshot | None":
        """Return the stored snapshot for one configured source.

        Args:
            issuer: The configured issuer the snapshot belongs to.
            jwks_uri: The key set the snapshot was parsed from.

        Returns:
            The stored snapshot, or ``None`` when nothing is stored.
        """
        ...  # pragma: no cover

    def set(self, issuer: str, jwks_uri: str, snapshot: "JWKSSnapshot") -> None:
        """Store the newest snapshot for one configured source.

        Args:
            issuer: The configured issuer the snapshot belongs to.
            jwks_uri: The key set the snapshot was parsed from.
            snapshot: The immutable snapshot to store.
        """
        ...  # pragma: no cover

    def invalidate(self, issuer: str, jwks_uri: str) -> None:
        """Drop any snapshot stored for one configured source.

        Dropping an absent entry is not an error.

        Args:
            issuer: The configured issuer the snapshot belongs to.
            jwks_uri: The key set the snapshot was parsed from.
        """
        ...  # pragma: no cover

    def coordinator(self, issuer: str, jwks_uri: str) -> JWKSCacheCoordinator:
        """Return stable coordination state for one configured source.

        Calls for the same exact pair must return the same object so providers
        sharing this cache also share refresh and unknown-key coordination.

        Args:
            issuer: The configured issuer the coordination belongs to.
            jwks_uri: The configured key-set URI.

        Returns:
            Stable coordination state for the exact source pair.
        """
        ...  # pragma: no cover


class InMemoryJWKSCache:
    """Hold key snapshots for the lifetime of one process.

    This is the default. Construct one explicitly and hand it to several
    providers to give them a shared key set and a shared fetch schedule.
    """

    __slots__ = ("_coordinators", "_entries")

    def __init__(self) -> None:
        """Start with no stored snapshots."""
        self._entries: dict[SelectionKey, JWKSSnapshot] = {}
        self._coordinators: dict[SelectionKey, JWKSCacheCoordinator] = {}

    def get(self, issuer: str, jwks_uri: str) -> "JWKSSnapshot | None":
        """Return the stored snapshot for one configured source.

        Args:
            issuer: The configured issuer the snapshot belongs to.
            jwks_uri: The key set the snapshot was parsed from.

        Returns:
            The stored snapshot, or ``None`` when nothing is stored.
        """
        return self._entries.get((issuer, jwks_uri))

    def set(self, issuer: str, jwks_uri: str, snapshot: "JWKSSnapshot") -> None:
        """Store the newest snapshot for one configured source.

        Args:
            issuer: The configured issuer the snapshot belongs to.
            jwks_uri: The key set the snapshot was parsed from.
            snapshot: The immutable snapshot to store.
        """
        self._entries[issuer, jwks_uri] = snapshot

    def invalidate(self, issuer: str, jwks_uri: str) -> None:
        """Drop any snapshot stored for one configured source.

        Args:
            issuer: The configured issuer the snapshot belongs to.
            jwks_uri: The key set the snapshot was parsed from.
        """
        self._entries.pop((issuer, jwks_uri), None)

    def coordinator(self, issuer: str, jwks_uri: str) -> JWKSCacheCoordinator:
        """Return stable coordination state for one configured source.

        Args:
            issuer: The configured issuer the coordination belongs to.
            jwks_uri: The configured key-set URI.

        Returns:
            Stable coordination state for the exact source pair.
        """
        return self._coordinators.setdefault((issuer, jwks_uri), JWKSCacheCoordinator())
