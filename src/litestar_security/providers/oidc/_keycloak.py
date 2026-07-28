"""Pure mapping of already-verified Keycloak roles, scopes, and RPT permissions."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import cast

from litestar_security.authentication import InvalidCredentials
from litestar_security.context import ResourcePermission
from litestar_security.providers.jwt import JSONValue, JWTClaims

__all__ = ("KeycloakClaims", "map_keycloak_claims")


@dataclass(frozen=True, slots=True)
class KeycloakClaims:
    """Deterministic authorization fields mapped from a verified Keycloak JWT."""

    realm_roles: frozenset[str] = frozenset()
    client_roles: Mapping[str, frozenset[str]] = field(
        default_factory=lambda: cast("Mapping[str, frozenset[str]]", MappingProxyType({}))
    )
    scopes: frozenset[str] = frozenset()
    permissions: frozenset[ResourcePermission] = frozenset()

    def __post_init__(self) -> None:
        """Freeze client namespaces and all mapped authorization values."""
        object.__setattr__(self, "realm_roles", frozenset(self.realm_roles))
        object.__setattr__(
            self,
            "client_roles",
            MappingProxyType({client_id: frozenset(roles) for client_id, roles in self.client_roles.items()}),
        )
        object.__setattr__(self, "scopes", frozenset(self.scopes))
        object.__setattr__(self, "permissions", frozenset(self.permissions))


def map_keycloak_claims(claims: JWTClaims) -> KeycloakClaims | InvalidCredentials:
    """Map verified Keycloak claims without discovery, HTTP, or token exchange.

    Args:
        claims: Claims returned by an already-successful JWT verifier.

    Returns:
        Validated Keycloak authorization fields or ``InvalidCredentials``.
    """
    raw = claims.raw
    realm_roles = _realm_roles(raw.get("realm_access"))
    client_roles = _client_roles(raw.get("resource_access"))
    scopes = _scopes(raw)
    permissions = _permissions(raw.get("authorization"))
    if any(value is None for value in (realm_roles, client_roles, scopes, permissions)):
        return InvalidCredentials()
    return KeycloakClaims(
        realm_roles=cast("frozenset[str]", realm_roles),
        client_roles=cast("Mapping[str, frozenset[str]]", client_roles),
        scopes=cast("frozenset[str]", scopes),
        permissions=cast("frozenset[ResourcePermission]", permissions),
    )


def _realm_roles(value: JSONValue | None) -> frozenset[str] | None:
    if value is None:
        return frozenset()
    if not isinstance(value, Mapping):
        return None
    return _string_set(value.get("roles"))


def _client_roles(value: JSONValue | None) -> Mapping[str, frozenset[str]] | None:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        return None
    result: dict[str, frozenset[str]] = {}
    for client_id, access in value.items():
        if not client_id or not isinstance(access, Mapping):
            return None
        roles = _string_set(access.get("roles"))
        if roles is None:
            return None
        result[client_id] = roles
    return MappingProxyType(result)


def _scopes(raw: Mapping[str, JSONValue]) -> frozenset[str] | None:
    scope = raw.get("scope")
    if scope is not None:
        if not isinstance(scope, str):
            return None
        values = scope.split()
        return frozenset(values) if all(values) else frozenset()
    scp = raw.get("scp")
    return frozenset() if scp is None else _string_set(scp)


def _permissions(value: JSONValue | None) -> frozenset[ResourcePermission] | None:
    if value is None:
        return frozenset()
    if not isinstance(value, Mapping):
        return None
    items = value.get("permissions")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        return None
    result: set[ResourcePermission] = set()
    for item in items:
        if not isinstance(item, Mapping):
            return None
        resource = item.get("rsid")
        if resource is None:
            resource = item.get("rsname")
        scopes = item.get("scopes", ())
        normalized_scopes = _string_set(scopes)
        if not isinstance(resource, str) or not resource or normalized_scopes is None:
            return None
        result.add(ResourcePermission(resource_id=resource, scopes=normalized_scopes))
    return frozenset(result)


def _string_set(value: object) -> frozenset[str] | None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return None
    items = cast("Sequence[object]", value)
    if any(not isinstance(item, str) or not item for item in items):
        return None
    return frozenset(cast("Sequence[str]", items))
