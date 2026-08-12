"""Primitives shared by every provider package.

These helpers are message-free and transport-free except for the shared DNS
resolver. They reject malformed JSON by shape, keep observability failures from
reaching the caller, and resolve addresses for provider network boundaries.
Provider-specific wording belongs in the provider that raises it, so nothing
here formats an error beyond the message it is handed.
"""

import ipaddress
import socket
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import suppress
from typing import Generic, NoReturn, TypeAlias, TypeVar

from anyio import getaddrinfo
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.workers import SecurityMetrics

__all__ = ("AddressResolver", "JSONValue", "public_address", "resolve_addresses")

JSONValue: TypeAlias = bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"] | None
AddressResolver: TypeAlias = Callable[[str, int], Awaitable[Sequence[str]]]
VerifierT = TypeVar("VerifierT")


class DynamicVerifierCache(Generic[VerifierT]):
    """Bounded LRU of prepared verifiers keyed by route and exact key material."""

    __slots__ = ("_entries", "_maximum")

    def __init__(self, maximum: int = 128) -> None:
        self._entries: OrderedDict[tuple[str, str], tuple[bytes, VerifierT]] = OrderedDict()
        self._maximum = maximum

    def get_or_create(self, route: tuple[str, str], material: bytes, factory: Callable[[], VerifierT]) -> VerifierT:
        """Return a verifier for the exact selected key and refresh LRU position."""
        cached = self._entries.get(route)
        if cached is not None and cached[0] == material:
            self._entries.move_to_end(route)
            return cached[1]
        verifier = factory()
        self._entries[route] = (material, verifier)
        self._entries.move_to_end(route)
        while len(self._entries) > self._maximum:
            self._entries.popitem(last=False)
        return verifier

    def __len__(self) -> int:
        return len(self._entries)

    def __getitem__(self, route: tuple[str, str]) -> VerifierT:
        return self._entries[route][1]


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
