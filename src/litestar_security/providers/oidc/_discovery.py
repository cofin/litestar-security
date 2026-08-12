"""Discovery policy, validated metadata, and the discovery client.

Metadata is validated against the requested issuer before it is returned, so a
response can never redirect trust to an issuer the caller did not ask for.
"""

import ipaddress
import json
from dataclasses import dataclass
from typing import TypeAlias, cast

import httpx
from litestar.status_codes import HTTP_200_OK, HTTP_300_MULTIPLE_CHOICES, HTTP_400_BAD_REQUEST

from litestar_security.providers._internal import AddressResolver, public_address, raise_config, resolve_addresses
from litestar_security.providers.oidc._internal import (
    OIDCDiscoveryError,
    load_document,
    positive_finite,
    raise_discovery,
)
from litestar_security.providers.oidc._urls import NormalizedURL, normalize_url, optional_url_value

__all__ = ("DiscoveryPolicy", "OIDCDiscoveryClient", "OIDCMetadata")


JSONObject: TypeAlias = dict[str, object]


_DEFAULT_HTTPS_PORT = 443


_MAXIMUM_CONFIGURED_DOCUMENT_BYTES = 1_048_576


_MAXIMUM_TCP_PORT = 65_535


_POOL_CONNECTIONS = 10


_SUPPORTED_SIGNING_ALGORITHMS = frozenset({"EdDSA", "ES256", "HS256", "RS256"})


@dataclass(frozen=True, slots=True)
class DiscoveryPolicy:
    """Exact operator-controlled OIDC discovery network boundary."""

    allowed_issuers: frozenset[str]
    allowed_jwks_origins: frozenset[str] = frozenset()
    allowed_oauth_origins: frozenset[str] = frozenset()
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
            or not isinstance(port, int)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
            or not 1 <= port <= _MAXIMUM_TCP_PORT
            for port in allowed_ports
        ):
            raise_config("OIDC discovery allowed_ports must contain valid TCP ports")
        if (
            not positive_finite(self.connect_timeout)
            or not positive_finite(self.read_timeout)
            or isinstance(self.maximum_document_bytes, bool)
            or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
                self.maximum_document_bytes, int
            )
            or not 1 <= self.maximum_document_bytes <= _MAXIMUM_CONFIGURED_DOCUMENT_BYTES
        ):
            raise_config("OIDC discovery timeout and document limits must be positive and bounded")
        try:
            allowed_issuers = frozenset(
                normalize_url(
                    issuer, require_https=self.require_https, allowed_ports=allowed_ports, allow_origin_only=False
                ).value
                for issuer in self.allowed_issuers
            )
            allowed_jwks_origins = frozenset(
                normalize_url(
                    origin, require_https=self.require_https, allowed_ports=allowed_ports, allow_origin_only=True
                ).origin
                for origin in self.allowed_jwks_origins
            )
            allowed_oauth_origins = frozenset(
                normalize_url(
                    origin, require_https=self.require_https, allowed_ports=allowed_ports, allow_origin_only=True
                ).origin
                for origin in self.allowed_oauth_origins
            )
        except (TypeError, ValueError):
            raise_config("Invalid OIDC discovery URL policy")
        if not allowed_issuers:
            raise_config("OIDC discovery requires at least one allowed issuer")
        object.__setattr__(self, "allowed_issuers", allowed_issuers)
        object.__setattr__(self, "allowed_jwks_origins", allowed_jwks_origins)
        object.__setattr__(self, "allowed_oauth_origins", allowed_oauth_origins)
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
    revocation_endpoint: str | None = None


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
                not isinstance(algorithm, str)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
                or not algorithm
                or algorithm != algorithm.strip()
                for algorithm in algorithms
            )
            or not algorithms.issubset(_SUPPORTED_SIGNING_ALGORITHMS)
        ):
            raise_config("OIDC discovery requires supported pinned signing algorithms")
        self.policy = policy
        self.algorithms = algorithms
        self._resolver = resolver or resolve_addresses
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

    async def discover(self, issuer: str, *, discovery_url: str | None = None) -> OIDCMetadata:
        """Fetch and validate metadata for one configured issuer.

        Args:
            issuer: The issuer to discover, matched against configured trust anchors.
            discovery_url: Where the metadata document lives, for a provider that
                does not publish it at ``{issuer}/.well-known/openid-configuration``.
                It must share the issuer's exact origin, so an override changes the
                path this client requests and never the host it reaches.

        Returns:
            The validated metadata.

        Raises:
            OIDCDiscoveryError: If the client is closed, the issuer is not a
                configured anchor, or the document fails validation.
        """
        if self._closed:
            raise_discovery("OIDC discovery client is closed")
        try:
            normalized_issuer = normalize_url(
                issuer,
                require_https=self.policy.require_https,
                allowed_ports=self.policy.allowed_ports,
                allow_origin_only=False,
            )
        except (TypeError, ValueError):
            raise_config("Invalid OIDC discovery issuer")
        if normalized_issuer.value not in self.policy.allowed_issuers:
            raise_config("OIDC discovery issuer is not in the configured allowlist")

        requested_url = self._discovery_url(normalized_issuer, discovery_url)
        resolved: dict[tuple[str, int], tuple[str, ...]] = {}
        await self._validate_addresses(normalized_issuer, resolved)
        document = await self._fetch_document(requested_url)
        return await self._parse_metadata(document, normalized_issuer, resolved)

    async def aclose(self) -> None:
        """Close the owned HTTP client idempotently."""
        if not self._closed:
            self._closed = True
            await self._client.aclose()

    async def __aenter__(self) -> "OIDCDiscoveryClient":  # noqa: PYI034 - the fluent builder returns its own concrete type
        """Enter the owned-client context."""
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Close the owned client on context exit."""
        await self.aclose()

    def _discovery_url(self, issuer: NormalizedURL, override: str | None) -> str:
        if override is None:
            return f"{issuer.value}/.well-known/openid-configuration"
        try:
            normalized = normalize_url(
                override,
                require_https=self.policy.require_https,
                allowed_ports=self.policy.allowed_ports,
                allow_origin_only=False,
            )
        except (TypeError, ValueError):
            raise_config("Invalid OIDC discovery URL override")
        if normalized.origin != issuer.origin:
            raise_config("OIDC discovery URL override must share the issuer origin")
        return normalized.value

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
            raise_discovery("OIDC discovery request unavailable")
        try:
            return load_document(body)
        except (RecursionError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise_discovery("OIDC discovery response is invalid")

    async def _parse_metadata(
        self, document: JSONObject, issuer: NormalizedURL, resolved: dict[tuple[str, int], tuple[str, ...]]
    ) -> OIDCMetadata:
        if document.get("issuer") != issuer.value:
            raise_discovery("OIDC discovery issuer mismatch")
        jwks_uri = await self._metadata_url(
            document,
            "jwks_uri",
            resolved,
            required=True,
            allowed_origins=self.policy.allowed_jwks_origins.union({issuer.origin}),
        )
        normalized_jwks = cast("NormalizedURL", jwks_uri)

        advertised_value = document.get("id_token_signing_alg_values_supported")
        if (
            not isinstance(advertised_value, list)
            or not advertised_value
            or any(not isinstance(item, str) for item in cast("list[object]", advertised_value))
        ):
            raise_discovery("OIDC discovery signing algorithms are invalid")
        advertised = cast("list[str]", advertised_value)
        algorithms = self.algorithms.intersection(advertised)
        if not algorithms:
            raise_discovery("OIDC discovery has no compatible signing algorithm")

        oauth_origins = frozenset({issuer.origin, *self.policy.allowed_oauth_origins})
        return OIDCMetadata(
            issuer=issuer.value,
            jwks_uri=normalized_jwks.value,
            authorization_endpoint=optional_url_value(
                await self._metadata_url(
                    document, "authorization_endpoint", resolved, required=False, allowed_origins=oauth_origins
                )
            ),
            token_endpoint=optional_url_value(
                await self._metadata_url(
                    document, "token_endpoint", resolved, required=False, allowed_origins=oauth_origins
                )
            ),
            end_session_endpoint=optional_url_value(
                await self._metadata_url(
                    document, "end_session_endpoint", resolved, required=False, allowed_origins=oauth_origins
                )
            ),
            algorithms=frozenset(algorithms),
            revocation_endpoint=optional_url_value(
                await self._metadata_url(
                    document, "revocation_endpoint", resolved, required=False, allowed_origins=oauth_origins
                )
            ),
        )

    async def _metadata_url(
        self,
        document: JSONObject,
        name: str,
        resolved: dict[tuple[str, int], tuple[str, ...]],
        *,
        required: bool,
        allowed_origins: frozenset[str] | None = None,
    ) -> NormalizedURL | None:
        value = document.get(name)
        if value is None and not required:
            return None
        if not isinstance(value, str):
            raise_discovery("OIDC discovery endpoint metadata is invalid")
        try:
            normalized = normalize_url(
                value,
                require_https=self.policy.require_https,
                allowed_ports=self.policy.allowed_ports,
                allow_origin_only=False,
            )
        except (TypeError, ValueError):
            raise_discovery("OIDC discovery endpoint metadata is invalid")
        if allowed_origins is not None and normalized.origin not in allowed_origins:
            raise_discovery(f"OIDC discovery {name} origin is not allowed")
        await self._validate_addresses(normalized, resolved)
        return normalized

    async def _validate_addresses(self, url: NormalizedURL, resolved: dict[tuple[str, int], tuple[str, ...]]) -> None:
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
                    raise_discovery("OIDC discovery host resolution unavailable")
            else:
                addresses = (str(literal),)
            resolved[key] = addresses
        if not addresses:
            raise_discovery("OIDC discovery host resolution returned no addresses")
        try:
            parsed = tuple(ipaddress.ip_address(address) for address in addresses)
        except ValueError:
            raise_discovery("OIDC discovery host resolution returned an invalid address")
        if any(not public_address(address) for address in parsed):
            raise_discovery("OIDC discovery host resolved outside the public network boundary")


def _validate_document_response(response: httpx.Response, maximum_document_bytes: int) -> None:
    if HTTP_300_MULTIPLE_CHOICES <= response.status_code < HTTP_400_BAD_REQUEST:
        raise_discovery("OIDC discovery redirects are not allowed")
    if response.status_code != HTTP_200_OK:
        raise_discovery("OIDC discovery request failed")
    content_type = response.headers.get("content-type", "").split(";", maxsplit=1)[0].strip().lower()
    if content_type != "application/json":
        raise_discovery("OIDC discovery response must be JSON")
    content_encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if content_encoding != "identity":
        raise_discovery("OIDC discovery response encoding is not allowed")
    content_length = response.headers.get("content-length")
    if content_length is not None and (not content_length.isdecimal() or int(content_length) > maximum_document_bytes):
        raise_discovery("OIDC discovery response exceeds the configured limit")


async def _read_bounded_body(response: httpx.Response, maximum_document_bytes: int) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(chunk) > maximum_document_bytes - len(body):
            raise_discovery("OIDC discovery response exceeds the configured limit")
        body.extend(chunk)
    return bytes(body)
