"""Issuer URL normalization and public-address enforcement.

URL handling is isolated because it decides whether a discovery request may leave
the host at all: resolved addresses are checked before any request is issued.
"""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

import httpx
from anyio import getaddrinfo

_DEFAULT_HTTPS_PORT = 443
_DEFAULT_HTTP_PORT = 80


@dataclass(frozen=True, slots=True)
class NormalizedURL:
    value: str
    origin: str
    host: str
    port: int


def normalize_url(
    value: str, *, require_https: bool, allowed_ports: frozenset[int], allow_origin_only: bool
) -> NormalizedURL:
    if (
        not isinstance(value, str)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
        or not value
        or value != value.strip()
    ):
        raise ValueError
    split = urlsplit(value)
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
        or (split.path not in {"", "/"} and split.path.endswith("/"))
    ):
        raise ValueError
    url = httpx.URL(value)
    scheme = url.scheme.lower()
    if scheme not in {"http", "https"} or (require_https and scheme != "https"):
        raise ValueError
    default_port = _DEFAULT_HTTPS_PORT if scheme == "https" else _DEFAULT_HTTP_PORT
    port = url.port or default_port
    if port not in allowed_ports:
        raise ValueError
    host = url.raw_host.decode("ascii")
    authority_host = f"[{host}]" if ":" in host else host
    authority = authority_host if port == default_port else f"{authority_host}:{port}"
    origin = f"{scheme}://{authority}"
    raw_path = url.raw_path.decode("ascii")
    path = "" if raw_path == "/" else raw_path
    if allow_origin_only and path:
        raise ValueError
    return NormalizedURL(value=f"{origin}{path}", origin=origin, host=host, port=port)


def public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


async def resolve_addresses(host: str, port: int) -> tuple[str, ...]:
    results = await getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return tuple(dict.fromkeys(result[4][0] for result in results))


def optional_url_value(value: NormalizedURL | None) -> str | None:
    return value.value if value is not None else None
