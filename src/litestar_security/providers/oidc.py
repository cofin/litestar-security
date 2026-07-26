"""OIDC discovery metadata and SSRF policy."""

import ipaddress
import json
import math
import socket
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import NoReturn, TypeAlias, cast
from urllib.parse import unquote, urlsplit

import httpx
from anyio import getaddrinfo
from litestar.exceptions import ImproperlyConfiguredException
from litestar.status_codes import HTTP_200_OK, HTTP_300_MULTIPLE_CHOICES, HTTP_400_BAD_REQUEST

__all__ = ("DiscoveryPolicy", "OIDCDiscoveryClient", "OIDCDiscoveryError", "OIDCMetadata")

AddressResolver: TypeAlias = Callable[[str, int], Awaitable[Sequence[str]]]
JSONObject: TypeAlias = dict[str, object]

_DEFAULT_HTTPS_PORT = 443
_DEFAULT_HTTP_PORT = 80
_MAXIMUM_CONFIGURED_DOCUMENT_BYTES = 1_048_576
_MAXIMUM_JSON_DEPTH = 64
_MAXIMUM_TCP_PORT = 65_535
_POOL_CONNECTIONS = 10
_SUPPORTED_SIGNING_ALGORITHMS = frozenset({"EdDSA", "ES256", "HS256", "RS256"})


class OIDCDiscoveryError(RuntimeError):
    """Sanitized operational or remote-metadata discovery failure."""


@dataclass(frozen=True, slots=True)
class _NormalizedURL:
    value: str
    origin: str
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class DiscoveryPolicy:
    """Exact operator-controlled OIDC discovery network boundary."""

    allowed_issuers: frozenset[str]
    allowed_jwks_origins: frozenset[str] = frozenset()
    require_https: bool = True
    allow_private_hosts: bool = False
    allowed_ports: frozenset[int] = frozenset({_DEFAULT_HTTPS_PORT})
    connect_timeout: float = 2.0
    read_timeout: float = 3.0
    maximum_document_bytes: int = 65_536

    def __post_init__(self) -> None:
        """Normalize configured trust anchors and reject unsafe bounds."""
        allowed_ports = frozenset(self.allowed_ports)
        if not allowed_ports or any(
            isinstance(port, bool)
            or not isinstance(port, int)  # pyright: ignore[reportUnnecessaryIsInstance]
            or not 1 <= port <= _MAXIMUM_TCP_PORT
            for port in allowed_ports
        ):
            _raise_config("OIDC discovery allowed_ports must contain valid TCP ports")
        if (
            not _positive_finite(self.connect_timeout)
            or not _positive_finite(self.read_timeout)
            or isinstance(self.maximum_document_bytes, bool)
            or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                self.maximum_document_bytes, int
            )
            or not 1 <= self.maximum_document_bytes <= _MAXIMUM_CONFIGURED_DOCUMENT_BYTES
        ):
            _raise_config("OIDC discovery timeout and document limits must be positive and bounded")
        try:
            allowed_issuers = frozenset(
                _normalize_url(
                    issuer, require_https=self.require_https, allowed_ports=allowed_ports, allow_origin_only=False
                ).value
                for issuer in self.allowed_issuers
            )
            allowed_jwks_origins = frozenset(
                _normalize_url(
                    origin, require_https=self.require_https, allowed_ports=allowed_ports, allow_origin_only=True
                ).origin
                for origin in self.allowed_jwks_origins
            )
        except (TypeError, ValueError):
            _raise_config("Invalid OIDC discovery URL policy")
        if not allowed_issuers:
            _raise_config("OIDC discovery requires at least one allowed issuer")
        object.__setattr__(self, "allowed_issuers", allowed_issuers)
        object.__setattr__(self, "allowed_jwks_origins", allowed_jwks_origins)
        object.__setattr__(self, "allowed_ports", allowed_ports)


@dataclass(frozen=True, slots=True)
class OIDCMetadata:
    """Validated provider metadata needed by authentication integrations."""

    issuer: str
    jwks_uri: str
    authorization_endpoint: str | None
    token_endpoint: str | None
    end_session_endpoint: str | None
    algorithms: frozenset[str]


class OIDCDiscoveryClient:
    """Async-native bounded discovery client for an exact issuer allowlist."""

    __slots__ = ("_client", "_closed", "_resolver", "algorithms", "policy")

    def __init__(
        self,
        policy: DiscoveryPolicy,
        algorithms: frozenset[str],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: AddressResolver | None = None,
    ) -> None:
        """Create one owned client with redirects and proxy environment disabled."""
        algorithms = frozenset(algorithms)
        if (
            not algorithms
            or any(
                not isinstance(algorithm, str)  # pyright: ignore[reportUnnecessaryIsInstance]
                or not algorithm
                or algorithm != algorithm.strip()
                for algorithm in algorithms
            )
            or not algorithms.issubset(_SUPPORTED_SIGNING_ALGORITHMS)
        ):
            _raise_config("OIDC discovery requires supported pinned signing algorithms")
        self.policy = policy
        self.algorithms = algorithms
        self._resolver = resolver or _resolve_addresses
        self._closed = False
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            limits=httpx.Limits(max_connections=_POOL_CONNECTIONS, max_keepalive_connections=_POOL_CONNECTIONS),
            timeout=httpx.Timeout(
                connect=policy.connect_timeout,
                read=policy.read_timeout,
                write=policy.read_timeout,
                pool=policy.connect_timeout,
            ),
            transport=transport,
            trust_env=False,
        )

    async def discover(self, issuer: str) -> OIDCMetadata:
        """Fetch and validate metadata for one configured issuer."""
        if self._closed:
            _raise_discovery("OIDC discovery client is closed")
        try:
            normalized_issuer = _normalize_url(
                issuer,
                require_https=self.policy.require_https,
                allowed_ports=self.policy.allowed_ports,
                allow_origin_only=False,
            )
        except (TypeError, ValueError):
            _raise_config("Invalid OIDC discovery issuer")
        if normalized_issuer.value not in self.policy.allowed_issuers:
            _raise_config("OIDC discovery issuer is not in the configured allowlist")

        resolved: dict[tuple[str, int], tuple[str, ...]] = {}
        await self._validate_addresses(normalized_issuer, resolved)
        discovery_url = f"{normalized_issuer.value}/.well-known/openid-configuration"
        document = await self._fetch_document(discovery_url)
        return await self._parse_metadata(document, normalized_issuer, resolved)

    async def aclose(self) -> None:
        """Close the owned HTTP client idempotently."""
        if not self._closed:
            self._closed = True
            await self._client.aclose()

    async def __aenter__(self) -> "OIDCDiscoveryClient":  # noqa: PYI034
        """Enter the owned-client context."""
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Close the owned client on context exit."""
        await self.aclose()

    async def _fetch_document(self, url: str) -> JSONObject:
        try:
            async with self._client.stream(
                "GET", url, headers={"Accept": "application/json", "Accept-Encoding": "identity"}
            ) as response:
                _validate_document_response(response, self.policy.maximum_document_bytes)
                body = await _read_bounded_body(response, self.policy.maximum_document_bytes)
        except OIDCDiscoveryError:
            raise
        except httpx.HTTPError:
            _raise_discovery("OIDC discovery request unavailable")
        try:
            return _load_document(body)
        except (RecursionError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            _raise_discovery("OIDC discovery response is invalid")

    async def _parse_metadata(
        self, document: JSONObject, issuer: _NormalizedURL, resolved: dict[tuple[str, int], tuple[str, ...]]
    ) -> OIDCMetadata:
        if document.get("issuer") != issuer.value:
            _raise_discovery("OIDC discovery issuer mismatch")
        jwks_uri = await self._metadata_url(
            document,
            "jwks_uri",
            resolved,
            required=True,
            allowed_origins=self.policy.allowed_jwks_origins.union({issuer.origin}),
        )
        normalized_jwks = cast("_NormalizedURL", jwks_uri)

        advertised_value = document.get("id_token_signing_alg_values_supported")
        if (
            not isinstance(advertised_value, list)
            or not advertised_value
            or any(not isinstance(item, str) for item in cast("list[object]", advertised_value))
        ):
            _raise_discovery("OIDC discovery signing algorithms are invalid")
        advertised = cast("list[str]", advertised_value)
        algorithms = self.algorithms.intersection(advertised)
        if not algorithms:
            _raise_discovery("OIDC discovery has no compatible signing algorithm")

        return OIDCMetadata(
            issuer=issuer.value,
            jwks_uri=normalized_jwks.value,
            authorization_endpoint=_optional_url_value(
                await self._metadata_url(document, "authorization_endpoint", resolved, required=False)
            ),
            token_endpoint=_optional_url_value(
                await self._metadata_url(document, "token_endpoint", resolved, required=False)
            ),
            end_session_endpoint=_optional_url_value(
                await self._metadata_url(document, "end_session_endpoint", resolved, required=False)
            ),
            algorithms=frozenset(algorithms),
        )

    async def _metadata_url(
        self,
        document: JSONObject,
        name: str,
        resolved: dict[tuple[str, int], tuple[str, ...]],
        *,
        required: bool,
        allowed_origins: frozenset[str] | None = None,
    ) -> _NormalizedURL | None:
        value = document.get(name)
        if value is None and not required:
            return None
        if not isinstance(value, str):
            _raise_discovery("OIDC discovery endpoint metadata is invalid")
        try:
            normalized = _normalize_url(
                value,
                require_https=self.policy.require_https,
                allowed_ports=self.policy.allowed_ports,
                allow_origin_only=False,
            )
        except (TypeError, ValueError):
            _raise_discovery("OIDC discovery endpoint metadata is invalid")
        if allowed_origins is not None and normalized.origin not in allowed_origins:
            _raise_discovery("OIDC discovery JWKS origin is not allowed")
        await self._validate_addresses(normalized, resolved)
        return normalized

    async def _validate_addresses(self, url: _NormalizedURL, resolved: dict[tuple[str, int], tuple[str, ...]]) -> None:
        if self.policy.allow_private_hosts:
            return
        key = (url.host, url.port)
        addresses = resolved.get(key)
        if addresses is None:
            try:
                literal = ipaddress.ip_address(url.host)
            except ValueError:
                try:
                    addresses = tuple(await self._resolver(url.host, url.port))
                except (OSError, RuntimeError):
                    _raise_discovery("OIDC discovery host resolution unavailable")
            else:
                addresses = (str(literal),)
            resolved[key] = addresses
        if not addresses:
            _raise_discovery("OIDC discovery host resolution returned no addresses")
        try:
            parsed = tuple(ipaddress.ip_address(address) for address in addresses)
        except ValueError:
            _raise_discovery("OIDC discovery host resolution returned an invalid address")
        if any(not _public_address(address) for address in parsed):
            _raise_discovery("OIDC discovery host resolved outside the public network boundary")


async def _resolve_addresses(host: str, port: int) -> tuple[str, ...]:
    results = await getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return tuple(dict.fromkeys(result[4][0] for result in results))


def _validate_document_response(response: httpx.Response, maximum_document_bytes: int) -> None:
    if HTTP_300_MULTIPLE_CHOICES <= response.status_code < HTTP_400_BAD_REQUEST:
        _raise_discovery("OIDC discovery redirects are not allowed")
    if response.status_code != HTTP_200_OK:
        _raise_discovery("OIDC discovery request failed")
    content_type = response.headers.get("content-type", "").split(";", maxsplit=1)[0].strip().lower()
    if content_type != "application/json":
        _raise_discovery("OIDC discovery response must be JSON")
    content_encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if content_encoding != "identity":
        _raise_discovery("OIDC discovery response encoding is not allowed")
    content_length = response.headers.get("content-length")
    if content_length is not None and (not content_length.isdecimal() or int(content_length) > maximum_document_bytes):
        _raise_discovery("OIDC discovery response exceeds the configured limit")


async def _read_bounded_body(response: httpx.Response, maximum_document_bytes: int) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(chunk) > maximum_document_bytes - len(body):
            _raise_discovery("OIDC discovery response exceeds the configured limit")
        body.extend(chunk)
    return bytes(body)


def _normalize_url(
    value: str, *, require_https: bool, allowed_ports: frozenset[int], allow_origin_only: bool
) -> _NormalizedURL:
    if (
        not isinstance(value, str)  # pyright: ignore[reportUnnecessaryIsInstance]
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
    return _NormalizedURL(value=f"{origin}{path}", origin=origin, host=host, port=port)


def _load_document(value: bytes) -> JSONObject:
    decoded = json.loads(value, object_pairs_hook=_unique_object, parse_constant=_reject_non_finite)
    if not isinstance(decoded, dict):
        raise TypeError
    _validate_depth(cast("object", decoded))
    return cast("JSONObject", decoded)


def _unique_object(pairs: list[tuple[str, object]]) -> JSONObject:
    value: JSONObject = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _validate_depth(value: object) -> None:
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAXIMUM_JSON_DEPTH:
            raise ValueError
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in cast("Mapping[object, object]", current).values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in cast("list[object]", current))


def _reject_non_finite(_value: str) -> NoReturn:
    raise ValueError


def _public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


def _optional_url_value(value: _NormalizedURL | None) -> str | None:
    return value.value if value is not None else None


def _positive_finite(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0


def _raise_config(detail: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=detail)


def _raise_discovery(detail: str) -> NoReturn:
    raise OIDCDiscoveryError(detail) from None
