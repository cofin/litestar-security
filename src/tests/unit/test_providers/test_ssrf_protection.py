"""Unit tests for centralized SSRF protection and worker offload routines."""

import ipaddress
from collections.abc import Sequence

import httpx
import pytest
from anyio import CapacityLimiter

from litestar_security.providers._transport import (
    create_ssrf_safe_transport,
    pin_url_to_ip,
    resolve_and_validate_host,
    validate_public_addresses,
    validate_ssrf_safe_url,
)
from litestar_security.workers import NoOpSecurityMetrics, run_in_cpu_worker, run_in_io_worker


def test_validate_public_addresses_success() -> None:
    """Valid global public addresses must be accepted and parsed."""
    addresses = ("8.8.8.8", "1.1.1.1", "2607:f8b0:4005:805::200e")
    result = validate_public_addresses(addresses)
    assert len(result) == 3
    assert isinstance(result[0], ipaddress.IPv4Address)
    assert isinstance(result[2], ipaddress.IPv6Address)


@pytest.mark.parametrize(
    "invalid_address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "224.0.0.1",
        "invalid-ip",
    ],
)
def test_validate_public_addresses_rejects_non_public(invalid_address: str) -> None:
    """Non-public or invalid IP addresses must be rejected with ValueError."""
    with pytest.raises(ValueError, match=r"is not public|does not appear to be an IPv4 or IPv6 address"):
        validate_public_addresses([invalid_address])


def test_validate_public_addresses_rejects_empty() -> None:
    """Empty address sequence must raise ValueError."""
    with pytest.raises(ValueError, match=r"No addresses resolved"):
        validate_public_addresses([])


async def test_resolve_and_validate_host_success() -> None:
    """Publicly resolvable hosts must succeed."""

    async def fake_resolver(host: str, port: int) -> Sequence[str]:
        del host, port
        return ("93.184.216.34",)

    result = await resolve_and_validate_host("example.com", 443, resolver=fake_resolver)
    assert result == ("93.184.216.34",)


async def test_resolve_and_validate_host_rejects_private() -> None:
    """Hosts resolving to private addresses must be rejected when allow_private_hosts is False."""

    async def fake_resolver(host: str, port: int) -> Sequence[str]:
        del host, port
        return ("10.0.0.1",)

    with pytest.raises(ValueError, match=r"is not public"):
        await resolve_and_validate_host("internal.local", 443, resolver=fake_resolver)


async def test_resolve_and_validate_host_allows_private_when_configured() -> None:
    """Hosts resolving to private addresses must succeed when allow_private_hosts is True."""

    async def fake_resolver(host: str, port: int) -> Sequence[str]:
        del host, port
        return ("10.0.0.1",)

    result = await resolve_and_validate_host("internal.local", 443, resolver=fake_resolver, allow_private_hosts=True)
    assert result == ("10.0.0.1",)


def test_validate_ssrf_safe_url_valid() -> None:
    """Safe HTTPS URLs must pass validation and return an httpx.URL object."""
    url = "https://example.com/oauth/token"
    parsed = validate_ssrf_safe_url(url)
    assert parsed.scheme == "https"
    assert parsed.host == "example.com"


@pytest.mark.parametrize(
    "unsafe_url",
    [
        "http://example.com/oauth/token",
        "https://user:pass@example.com/token",
        "https://example.com/path/../secret",
        "https://example.com/path%2f..%2fsecret",
        "https://example.com/path%5csecret",
        "ftp://example.com/file",
        "",
        "   https://example.com/token  ",
    ],
)
def test_validate_ssrf_safe_url_rejects_unsafe(unsafe_url: str) -> None:
    """Unsafe or non-HTTPS URLs must be rejected with ValueError."""
    with pytest.raises(ValueError, match=r"Invalid URL string|forbidden characters|Scheme .* not allowed"):
        validate_ssrf_safe_url(unsafe_url)


def test_validate_ssrf_safe_url_port_and_host_constraints() -> None:
    """Port and host constraints must be enforced when configured."""
    url = "https://auth.example.com:8443/jwks.json"
    with pytest.raises(ValueError, match=r"Port 8443 not allowed"):
        validate_ssrf_safe_url(url, allowed_ports=frozenset({443}))

    with pytest.raises(ValueError, match=r"Host auth\.example\.com not in allowed list"):
        validate_ssrf_safe_url(url, allowed_hosts=["other.example.com"])

    parsed = validate_ssrf_safe_url(url, allowed_ports=frozenset({8443}), allowed_hosts=["auth.example.com"])
    assert parsed.port == 8443


def test_pin_url_to_ip_standard_port() -> None:
    """URL pinning to an IP on standard HTTPS port 443 must set Host header without port."""
    url = httpx.URL("https://example.com/jwks.json")
    pinned, host_header, original_host = pin_url_to_ip(url, "93.184.216.34")
    assert str(pinned) == "https://93.184.216.34/jwks.json"
    assert host_header == "example.com"
    assert original_host == "example.com"


def test_pin_url_to_ip_custom_port() -> None:
    """URL pinning on custom port must retain port in the Host header."""
    url = httpx.URL("https://example.com:8443/jwks.json")
    pinned, host_header, original_host = pin_url_to_ip(url, "93.184.216.34")
    assert str(pinned) == "https://93.184.216.34:8443/jwks.json"
    assert host_header == "example.com:8443"
    assert original_host == "example.com"


def test_create_ssrf_safe_transport() -> None:
    """Safe transport factory must return configured AsyncHTTPTransport."""
    transport = create_ssrf_safe_transport(max_connections=5, max_keepalive_connections=2)
    assert isinstance(transport, httpx.AsyncHTTPTransport)


async def test_run_in_cpu_worker() -> None:
    """CPU worker runner must execute synchronous callable in thread pool."""
    limiter = CapacityLimiter(2)
    result = await run_in_cpu_worker(lambda: 21 * 2, limiter=limiter, metrics=NoOpSecurityMetrics())
    assert result == 42


async def test_run_in_io_worker() -> None:
    """IO worker runner must execute synchronous callable in thread pool."""
    limiter = CapacityLimiter(2)
    result = await run_in_io_worker(lambda: "worker-output", limiter=limiter, metrics=NoOpSecurityMetrics())
    assert result == "worker-output"
