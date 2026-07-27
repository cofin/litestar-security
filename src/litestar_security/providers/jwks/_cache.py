"""Cache policy and the immutable per-issuer cache entry.

Entries are immutable snapshots: a refresh builds a new entry and replaces the old
one atomically, so a reader never observes a half-updated key set.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

from litestar_security.providers._internal import raise_config
from litestar_security.providers.jwks._internal import strict_value

__all__ = ("JWKSCacheEntry", "JWKSCachePolicy")


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
