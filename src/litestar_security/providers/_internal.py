"""Primitives shared by every provider package.

These helpers are message-free and transport-free: they reject malformed JSON by
shape and keep observability failures from reaching the caller. Provider-specific
wording belongs in the provider that raises it, so nothing here formats an error
beyond the message it is handed.
"""

from collections.abc import Mapping
from contextlib import suppress
from typing import NoReturn, TypeAlias

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.config import SecurityMetrics

__all__ = ("JSONValue",)

JSONValue: TypeAlias = bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"] | None


def raise_config(message: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=message)


def unique_object(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    value: dict[str, JSONValue] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def reject_non_finite(value: str) -> float:
    del value
    raise ValueError


def validate_depth(value: JSONValue, *, maximum: int) -> None:
    stack: list[tuple[JSONValue, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > maximum:
            raise ValueError
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend((item, depth + 1) for item in current)


def safe_increment(metrics: SecurityMetrics, name: str) -> None:
    with suppress(Exception):  # observability must never alter authentication behavior
        metrics.increment(name)


def safe_observe(metrics: SecurityMetrics, name: str, value: float) -> None:
    with suppress(Exception):  # observability must never alter authentication behavior
        metrics.observe(name, value)
