"""Centralized SSRF protection, URL validation, and safe HTTP transport."""

import ipaddress
from collections.abc import Sequence
from typing import cast
from urllib.parse import unquote, urlsplit

import httpx

from litestar_security.providers._internal import AddressResolver, public_address, resolve_addresses

__all__ = (
    "create_ssrf_safe_transport",
    "pin_url_to_ip",
    "resolve_and_validate_host",
    "validate_public_addresses",
    "validate_ssrf_safe_url",
)


def validate_public_addresses(addresses: Sequence[str]) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """Ensure all resolved addresses are valid and globally routable public IPs.

    Args:
        addresses: Sequence of resolved IP address strings.

    Returns:
        Tuple of parsed public IP address objects.

    Raises:
        ValueError: If any address is invalid or not public.
    """
    if not addresses:
        raise ValueError("No addresses resolved")
    parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not public_address(ip):
            raise ValueError(f"Resolved address {address} is not public")
        parsed.append(ip)
    return tuple(parsed)


async def resolve_and_validate_host(
    host: str, port: int, *, resolver: AddressResolver = resolve_addresses, allow_private_hosts: bool = False
) -> tuple[str, ...]:
    """Resolve a host and validate all resolved addresses against SSRF constraints.

    Args:
        host: Hostname or IP string.
        port: TCP port number.
        resolver: Address resolution callable.
        allow_private_hosts: Whether private/internal IPs are permitted.

    Returns:
        Tuple of verified IP address strings.

    Raises:
        ValueError: If resolution fails or any IP is not safe.
    """
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        addresses = tuple(await resolver(host, port))
    else:
        addresses = (str(literal),)
    if not addresses:
        raise ValueError(f"Host {host} resolved to no addresses")
    if not allow_private_hosts:
        validate_public_addresses(addresses)
    return addresses


def validate_ssrf_safe_url(
    url: str,
    *,
    allowed_schemes: frozenset[str] = frozenset({"https"}),
    allowed_ports: frozenset[int] | None = None,
    allowed_hosts: Sequence[str] | None = None,
) -> httpx.URL:
    """Validate that a URL string is structurally safe against SSRF manipulation.

    Args:
        url: Raw URL string.
        allowed_schemes: Set of permitted URL schemes (default: https).
        allowed_ports: Optional set of allowed TCP ports.
        allowed_hosts: Optional allowlist of hostnames.

    Returns:
        Validated httpx.URL instance.

    Raises:
        ValueError: If the URL fails structural or safety checks.
    """
    url_obj = cast("object", url)
    if not isinstance(url_obj, str) or not url or url != url.strip():
        raise ValueError("Invalid URL string")
    split = urlsplit(url)
    decoded_path = unquote(split.path)
    if (
        not split.scheme
        or not split.netloc
        or split.username is not None
        or split.password is not None
        or split.query
        or split.fragment
        or any(segment in {".", ".."} for segment in decoded_path.split("/"))
        or "%2f" in split.path.lower()
        or "%5c" in split.path.lower()
    ):
        raise ValueError("URL contains forbidden characters or credentials")
    parsed = httpx.URL(url)
    scheme = parsed.scheme.lower()
    if scheme not in allowed_schemes:
        raise ValueError(f"Scheme {scheme} not allowed")
    port = parsed.port or (443 if scheme == "https" else 80)
    if allowed_ports is not None and port not in allowed_ports:
        raise ValueError(f"Port {port} not allowed")
    host = parsed.raw_host.decode("ascii")
    if allowed_hosts is not None and host not in allowed_hosts:
        raise ValueError(f"Host {host} not in allowed list")
    return parsed


def pin_url_to_ip(url: httpx.URL, ip_address: str) -> tuple[httpx.URL, str, str]:
    """Produce a pinned target URL and matching Host header for safe outbound HTTP.

    Args:
        url: Original target URL.
        ip_address: Verified target IP address.

    Returns:
        A tuple of (pinned_url, host_header_value, original_hostname).
    """
    hostname = url.raw_host.decode("ascii")
    port = url.port or (443 if url.scheme == "https" else 80)
    default_port = 443 if url.scheme == "https" else 80
    authority_host = f"[{hostname}]" if ":" in hostname else hostname
    host = authority_host if port == default_port else f"{authority_host}:{port}"
    return url.copy_with(host=ip_address), host, hostname


def create_ssrf_safe_transport(
    *, max_connections: int = 10, max_keepalive_connections: int = 10, verify: bool = True
) -> httpx.AsyncBaseTransport:
    """Create an HTTPX async transport configured for SSRF-safe outbound requests.

    Args:
        max_connections: Pool connection limit.
        max_keepalive_connections: Pool keepalive connection limit.
        verify: SSL certificate verification flag.

    Returns:
        An httpx.AsyncHTTPTransport instance.
    """
    limits = httpx.Limits(max_connections=max_connections, max_keepalive_connections=max_keepalive_connections)
    return httpx.AsyncHTTPTransport(limits=limits, verify=verify)
