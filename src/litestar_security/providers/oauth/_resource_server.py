"""RFC 9728 protected-resource metadata: configuration and its published document.

The advertised member names are fixed by the specification. They are the wire
contract an authorization server and a client read, so they are spelled here
exactly as RFC 9728 spells them and are never derived from a casing policy.
"""

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, NoReturn, TypedDict, cast
from urllib.parse import urlsplit, urlunsplit

from litestar import Request, Response
from litestar.datastructures import ResponseHeader
from litestar.enums import MediaType
from litestar.exceptions import ImproperlyConfiguredException
from litestar.handlers.http_handlers import HTTPRouteHandler, get
from litestar.openapi.datastructures import ResponseSpec
from litestar.status_codes import HTTP_200_OK, HTTP_304_NOT_MODIFIED

from litestar_security.authentication import public
from litestar_security.providers._internal import JSONValue

__all__ = ("ProtectedResourceConfig", "ProtectedResourceMetadata", "build_protected_resource_handler")


WELL_KNOWN_SEGMENT = "/.well-known/oauth-protected-resource"
"""The RFC 9728 well-known URI segment, inserted between host and resource path."""


_BEARER_METHODS = frozenset({"body", "header", "query"})


_ASCII_CONTROL_LIMIT = 32


_SCOPE_EXCLUDED = frozenset({'"', "\\"})


_UNMOUNTABLE = frozenset({"{", "}", "\\"})


_MAXIMUM_CACHE_AGE = 86_400


class _RequiredProtectedResourceMetadata(TypedDict):
    resource: str


class ProtectedResourceMetadata(_RequiredProtectedResourceMetadata, total=False):
    """The RFC 9728 protected-resource metadata document.

    Member names are defined by the specification, not by this application's
    wire conventions, and an absent optional member is omitted rather than
    emitted empty.
    """

    authorization_servers: list[str]
    scopes_supported: list[str]
    bearer_methods_supported: list[str]
    resource_documentation: str


@dataclass(frozen=True, slots=True)
class ProtectedResourceConfig:
    """Describe this application as an OAuth 2.1 protected resource.

    The values become the RFC 9728 metadata document served from
    ``/.well-known/oauth-protected-resource``. Every member is validated at
    construction so an invalid advertisement fails at startup rather than
    reaching a client that trusts it.

    Args:
        resource: The resource identifier, an absolute URI carrying no query
            and no fragment.
        authorization_servers: Issuer identifiers of the authorization servers
            able to issue tokens for this resource.
        scopes_supported: Scope tokens this resource understands.
        bearer_methods_supported: How a bearer token may be presented; one or
            more of ``header``, ``body``, and ``query``.
        resource_documentation: An absolute URI where developer documentation
            for this resource is published.
        route_prefix: Where the metadata route is mounted. The default empty
            value mounts it at the application root, which is where RFC 9728
            requires it to be reachable; a non-empty value must be an absolute
            non-root path.
        advertise_resource_metadata: Whether bearer authentication failures
            advertise this document through the RFC 9728
            ``resource_metadata`` challenge parameter.
        cache_max_age: Seconds a client may cache the document, at most a day.
    """

    resource: str
    authorization_servers: Sequence[str] = ()
    scopes_supported: Sequence[str] = ()
    bearer_methods_supported: Sequence[str] = ("header",)
    resource_documentation: str | None = None
    route_prefix: str = ""
    advertise_resource_metadata: bool = True
    cache_max_age: int = 300
    document: Mapping[str, JSONValue] = field(init=False)
    canonical_bytes: bytes = field(init=False, repr=False)
    etag: str = field(init=False)
    path: str = field(init=False)
    metadata_url: str = field(init=False)
    cache_control: str = field(init=False)

    def __post_init__(self) -> None:
        """Validate every advertised value and build the canonical response once."""
        resource = _absolute_uri(self.resource, "resource identifier")
        if urlsplit(resource).query:
            _reject("Protected resource identifier must not carry a query")
        authorization_servers = _unique(
            tuple(
                _absolute_uri(value, "authorization server issuer") for value in _sequence(self.authorization_servers)
            ),
            "authorization servers",
        )
        scopes_supported = _unique(
            tuple(_scope_token(value) for value in _sequence(self.scopes_supported)), "supported scopes"
        )
        bearer_methods_supported = _unique(
            tuple(_bearer_method(value) for value in _sequence(self.bearer_methods_supported)),
            "supported bearer methods",
        )
        documentation = (
            None
            if self.resource_documentation is None
            else _absolute_uri(self.resource_documentation, "resource documentation URI")
        )
        object.__setattr__(self, "resource", resource)
        object.__setattr__(self, "authorization_servers", authorization_servers)
        object.__setattr__(self, "scopes_supported", scopes_supported)
        object.__setattr__(self, "bearer_methods_supported", bearer_methods_supported)
        object.__setattr__(self, "resource_documentation", documentation)
        route_prefix = _mount_prefix(self.route_prefix)
        object.__setattr__(self, "route_prefix", route_prefix)
        if self.advertise_resource_metadata.__class__ is not bool:
            _reject("Protected resource challenge advertisement must be boolean")
        if (
            isinstance(self.cache_max_age, bool)
            or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
                self.cache_max_age, int
            )
            or not 0 <= self.cache_max_age <= _MAXIMUM_CACHE_AGE
        ):
            _reject(f"Protected resource cache_max_age must be between 0 and {_MAXIMUM_CACHE_AGE}")

        document: dict[str, JSONValue] = {"resource": resource}
        if authorization_servers:
            document["authorization_servers"] = list(authorization_servers)
        if scopes_supported:
            document["scopes_supported"] = list(scopes_supported)
        if bearer_methods_supported:
            document["bearer_methods_supported"] = list(bearer_methods_supported)
        if documentation is not None:
            document["resource_documentation"] = documentation
        canonical_bytes = json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()

        object.__setattr__(self, "document", MappingProxyType(document))
        object.__setattr__(self, "canonical_bytes", canonical_bytes)
        object.__setattr__(self, "etag", f'"{hashlib.sha256(canonical_bytes).hexdigest()}"')
        path = f"{route_prefix}{WELL_KNOWN_SEGMENT}{_resource_path(resource)}"
        resource_parts = urlsplit(resource)
        object.__setattr__(self, "path", path)
        metadata_url = urlunsplit((resource_parts.scheme, resource_parts.netloc, path, "", ""))
        object.__setattr__(self, "metadata_url", metadata_url)
        object.__setattr__(self, "cache_control", f"public, max-age={self.cache_max_age}")


def build_protected_resource_handler(config: ProtectedResourceConfig) -> HTTPRouteHandler:
    """Build one native public Litestar handler for the RFC 9728 metadata document.

    Args:
        config: The advertised values and their precomputed canonical response.

    Returns:
        A public handler serving the metadata with a stable ETag and cache headers.
    """
    headers = {"Cache-Control": config.cache_control, "ETag": config.etag}

    @get(
        config.path,
        name="litestar_security_protected_resource",
        operation_id="LitestarSecurityProtectedResourceMetadata",
        media_type=MediaType.JSON,
        auth=public(),
        response_headers=(
            ResponseHeader(
                name="Cache-Control",
                documentation_only=True,
                description="Public cache policy for this resource advertisement.",
                required=True,
            ),
            ResponseHeader(
                name="ETag",
                documentation_only=True,
                description="Strong entity tag for conditional metadata requests.",
                required=True,
            ),
        ),
        responses={
            HTTP_304_NOT_MODIFIED: ResponseSpec(
                data_container=None, description="The client's entity tag already identifies the current advertisement."
            )
        },
        summary="OAuth 2.0 protected resource metadata",
    )
    async def protected_resource_metadata(request: Request[Any, Any, Any]) -> Response[ProtectedResourceMetadata]:
        if _if_none_match(request.headers.get("if-none-match"), config.etag):
            return Response(cast("ProtectedResourceMetadata", b""), headers=headers, status_code=HTTP_304_NOT_MODIFIED)
        return Response(
            cast("ProtectedResourceMetadata", config.canonical_bytes),
            headers=headers,
            media_type=MediaType.JSON,
            status_code=HTTP_200_OK,
        )

    return protected_resource_metadata


def _sequence(value: object) -> tuple[object, ...]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        _reject("Protected resource metadata sequences must be ordered collections of text")
    return tuple(cast("Sequence[object]", value))


def _absolute_uri(value: object, subject: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        _reject(f"Protected {subject} must be an absolute URI")
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc or parts.fragment:
        _reject(f"Protected {subject} must be an absolute URI")
    return value


def _scope_token(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(
            character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT or character in _SCOPE_EXCLUDED
            for character in value
        )
    ):
        _reject("Protected resource scopes must be single scope tokens")
    return value


def _bearer_method(value: object) -> str:
    if value not in _BEARER_METHODS:
        _reject("Protected resource bearer methods must be 'header', 'body', or 'query'")
    return str(value)


def _unique(values: tuple[str, ...], subject: str) -> tuple[str, ...]:
    if len(set(values)) != len(values):
        _reject(f"Protected resource {subject} must not repeat a value")
    return values


def _mount_prefix(value: object) -> str:
    if not isinstance(value, str):
        _reject("Protected resource route_prefix must be the application root or an absolute path")
    if not value:
        return ""
    normalized = value.rstrip("/")
    if (
        not normalized.startswith("/")
        or not normalized
        or "//" in normalized
        or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in normalized)
    ):
        _reject("Protected resource route_prefix must be the application root or an absolute path")
    return normalized


def _resource_path(resource: str) -> str:
    path = urlsplit(resource).path.rstrip("/")
    if (
        "//" in path
        or any(character in _UNMOUNTABLE for character in path)
        or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in path)
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        _reject("Protected resource identifier path cannot be mounted as a route")
    return path


def _if_none_match(value: str | None, etag: str) -> bool:
    if value is None:
        return False
    return any(
        candidate == "*" or candidate.removeprefix("W/") == etag for candidate in map(str.strip, value.split(","))
    )


def _reject(message: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=message)
