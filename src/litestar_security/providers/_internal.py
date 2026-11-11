"""Primitives shared across provider packages.

These helpers centralize message-free SSRF address validation, bounded HTTP
response reading, conditional ETag handling, JSON depth/uniqueness checks,
finite numeric validation, and bounded worker execution with isolated metrics.
Provider-specific error types and wording remain in each calling provider.
"""

import hashlib
import ipaddress
import json
import socket
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import suppress
from math import isfinite
from time import perf_counter
from typing import Any, Generic, Literal, NoReturn, TypeAlias, TypeVar

import httpx
from anyio import CapacityLimiter, fail_after, getaddrinfo, to_thread
from litestar import Request, Response
from litestar.enums import MediaType
from litestar.exceptions import ImproperlyConfiguredException
from litestar.status_codes import HTTP_200_OK, HTTP_304_NOT_MODIFIED

from litestar_security.workers import NoOpSecurityMetrics, SecurityMetrics

__all__ = ("AddressResolver", "JSONValue", "public_address", "resolve_addresses")

JSONValue: TypeAlias = bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"] | None
AddressResolver: TypeAlias = Callable[[str, int], Awaitable[Sequence[str]]]
AddressResolutionReason: TypeAlias = Literal["unavailable", "empty", "invalid", "non_public"]
BoundedBodyReason: TypeAlias = Literal["unsupported_encoding", "too_large"]
VerifierT = TypeVar("VerifierT")
ResultT = TypeVar("ResultT")
MAXIMUM_WORKER_TOKENS = 1_024


class AddressResolutionError(Exception):
    """Message-free SSRF address-resolution failure carrying a structural reason."""

    def __init__(self, reason: AddressResolutionReason) -> None:
        self.reason: AddressResolutionReason = reason
        super().__init__(reason)


class BoundedBodyError(Exception):
    """Message-free bounded HTTP body failure carrying a structural reason."""

    def __init__(self, reason: BoundedBodyReason) -> None:
        self.reason: BoundedBodyReason = reason
        super().__init__(reason)


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


async def resolve_public_addresses(
    host: str, port: int, *, resolver: AddressResolver = resolve_addresses
) -> tuple[str, ...]:
    """Resolve stream addresses for ``host`` and verify all addresses are globally routable."""
    reason: AddressResolutionReason
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            addresses = tuple(await resolver(host, port))
        except (OSError, RuntimeError) as exc:
            reason = "unavailable"
            raise AddressResolutionError(reason) from exc
    else:
        addresses = (str(literal),)
    if not addresses:
        reason = "empty"
        raise AddressResolutionError(reason)
    try:
        parsed = tuple(ipaddress.ip_address(address) for address in addresses)
    except ValueError as exc:
        reason = "invalid"
        raise AddressResolutionError(reason) from exc
    if any(not public_address(address) for address in parsed):
        reason = "non_public"
        raise AddressResolutionError(reason)
    return tuple(str(address) for address in parsed)


async def read_bounded_body(response: httpx.Response, maximum_bytes: int) -> bytes:
    """Read an unencoded HTTP response stream without exceeding ``maximum_bytes``."""
    reason: BoundedBodyReason
    content_encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if content_encoding not in {"", "identity"}:
        reason = "unsupported_encoding"
        raise BoundedBodyError(reason)
    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(chunk) > maximum_bytes - len(body):
            reason = "too_large"
            raise BoundedBodyError(reason)
        body.extend(chunk)
    return bytes(body)


def positive_finite(value: object) -> bool:
    """Return whether ``value`` is a finite positive int or float, excluding booleans."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and isfinite(value) and value > 0


def validate_metrics(metrics: SecurityMetrics | None, *, message: str) -> SecurityMetrics:
    """Normalize optional security metrics or reject non-conforming sinks."""
    sink = NoOpSecurityMetrics() if metrics is None else metrics
    if not callable(getattr(sink, "increment", None)) or not callable(getattr(sink, "observe", None)):
        raise_config(message)
    return sink


def validate_worker_limiter(limiter: object, *, message: str) -> CapacityLimiter:
    """Validate that ``limiter`` is a bounded ``CapacityLimiter``."""
    total_tokens: object = getattr(limiter, "total_tokens", None)
    if (
        not isinstance(limiter, CapacityLimiter)
        or not isinstance(total_tokens, int)
        or isinstance(total_tokens, bool)
        or not 1 <= total_tokens <= MAXIMUM_WORKER_TOKENS
    ):
        raise_config(message)
    return limiter


async def run_worker_operation(
    operation: Callable[[], ResultT],
    *,
    limiter: CapacityLimiter,
    worker_timeout: float,
    metrics: SecurityMetrics,
    operation_metric: str | None = None,
) -> ResultT:
    """Run one blocking operation inside a bounded worker thread with metrics and timeout."""
    if limiter.borrowed_tokens >= limiter.total_tokens:
        safe_increment(metrics, "security.worker.saturation")
    queued_at = perf_counter()

    def run() -> ResultT:
        started = perf_counter()
        safe_observe(metrics, "security.worker.wait", started - queued_at)
        try:
            return operation()
        finally:
            elapsed = perf_counter() - started
            safe_observe(metrics, "security.worker.duration", elapsed)
            if operation_metric is not None:
                safe_observe(metrics, operation_metric, elapsed)

    with fail_after(worker_timeout):
        return await to_thread.run_sync(run, abandon_on_cancel=True, limiter=limiter)


def if_none_match(value: str | None, etag: str) -> bool:
    """Return whether an HTTP ``If-None-Match`` header matches ``etag``."""
    if value is None:
        return False
    return any(
        candidate == "*" or candidate.removeprefix("W/") == etag for candidate in map(str.strip, value.split(","))
    )


def canonical_json_etag(document: object) -> tuple[bytes, str]:
    """Serialize ``document`` as canonical ASCII JSON and return its strong SHA-256 ETag."""
    canonical_bytes = json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    return canonical_bytes, f'"{hashlib.sha256(canonical_bytes).hexdigest()}"'


def conditional_etag_response(
    request: Request[Any, Any, Any],
    *,
    canonical_bytes: bytes,
    etag: str,
    headers: Mapping[str, str],
    media_type: MediaType | str,
) -> Response[bytes]:
    """Return ``304 Not Modified`` when ``If-None-Match`` matches ``etag``, else ``200 OK``."""
    if if_none_match(request.headers.get("if-none-match"), etag):
        return Response(b"", headers=headers, status_code=HTTP_304_NOT_MODIFIED)
    return Response(canonical_bytes, headers=headers, media_type=media_type, status_code=HTTP_200_OK)


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
    """Increment ``name`` while suppressing metric sink failures."""
    with suppress(Exception):
        metrics.increment(name)


def safe_observe(metrics: SecurityMetrics, name: str, value: float) -> None:
    """Observe ``value`` for ``name`` while suppressing metric sink failures."""
    with suppress(Exception):
        metrics.observe(name, value)
