"""Primitives shared by every provider package.

These helpers are message-free and transport-free except for the shared DNS
resolver. They reject malformed JSON by shape, keep observability failures from
reaching the caller, and resolve addresses for provider network boundaries.
Provider-specific wording belongs in the provider that raises it, so nothing
here formats an error beyond the message it is handed.
"""

import ipaddress
import socket
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import suppress
from typing import NoReturn, TypeAlias

from anyio import getaddrinfo
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.workers import SecurityMetrics

__all__ = ("AddressResolver", "JSONValue", "public_address", "resolve_addresses")

JSONValue: TypeAlias = bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"] | None
AddressResolver: TypeAlias = Callable[[str, int], Awaitable[Sequence[str]]]


def public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Report whether an IP address is safe for an outbound provider request.

    Args:
        address: Parsed IPv4 or IPv6 address.

    Returns:
        Whether the address is globally routable and not multicast.
    """
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


async def resolve_addresses(host: str, port: int) -> tuple[str, ...]:
    """Resolve and deduplicate stream addresses for a provider endpoint.

    Args:
        host: Endpoint hostname.
        port: Endpoint port.

    Returns:
        Resolved address strings in resolver order without duplicates.
    """
    results = await getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return tuple(dict.fromkeys(result[4][0] for result in results))


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
