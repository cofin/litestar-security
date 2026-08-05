"""RFC 9728 protected-resource metadata: configuration and its published document.

The advertised member names are fixed by the specification. They are the wire
contract an authorization server and a client read, so they are spelled here
exactly as RFC 9728 spells them and are never derived from a casing policy.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import NoReturn, cast
from urllib.parse import urlsplit

from litestar.exceptions import ImproperlyConfiguredException

__all__ = ("ProtectedResourceConfig",)


_BEARER_METHODS = frozenset({"body", "header", "query"})


_ASCII_CONTROL_LIMIT = 32


_SCOPE_EXCLUDED = frozenset({'"', "\\"})


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
    """

    resource: str
    authorization_servers: Sequence[str] = ()
    scopes_supported: Sequence[str] = ()
    bearer_methods_supported: Sequence[str] = ("header",)
    resource_documentation: str | None = None
    route_prefix: str = ""

    def __post_init__(self) -> None:
        """Validate every advertised value and freeze the ordered sequences."""
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
        object.__setattr__(self, "route_prefix", _mount_prefix(self.route_prefix))


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


def _reject(message: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=message)
