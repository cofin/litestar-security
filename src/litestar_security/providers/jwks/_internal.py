"""Header, timestamp, and selection primitives local to JWKS handling.

These sit below the cache so that parsing and freshness decisions can be tested
without constructing a provider.
"""

from collections import OrderedDict
from collections.abc import Mapping
from datetime import datetime, timezone
from types import MappingProxyType
from typing import TypeAlias

from litestar_security.providers._internal import raise_config

__all__ = ("aware_utc", "empty_headers", "etag", "negative_cache", "strict_value", "valid_selection_value")


_NegativeKey: TypeAlias = tuple[int, str, str]
_MAXIMUM_ETAG_LENGTH = 1_024
_ASCII_CONTROL_LIMIT = 32
_ASCII_DELETE = 127
_EMPTY_HEADERS: Mapping[str, str] = MappingProxyType({})


def empty_headers() -> Mapping[str, str]:
    return _EMPTY_HEADERS


def negative_cache() -> OrderedDict[_NegativeKey, datetime]:
    return OrderedDict()


def strict_value(value: str, label: str) -> str:
    if not valid_selection_value(value):
        raise_config(f"{label} must be a normalized non-empty string")
    return value


def valid_selection_value(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and not any(ord(character) < _ASCII_CONTROL_LIMIT or ord(character) == _ASCII_DELETE for character in value)
    )


def aware_utc(value: datetime) -> datetime:
    time_value: object = value
    if (
        not isinstance(time_value, datetime)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
        or time_value.tzinfo is None
        or time_value.utcoffset() is None
    ):
        raise_config("JWKS selection time must be timezone-aware")
    return time_value.astimezone(timezone.utc)


def etag(value: str | None) -> str | None:
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
