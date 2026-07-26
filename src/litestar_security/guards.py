"""Pure authorization predicates exposed as native Litestar guards."""

from collections.abc import Collection
from dataclasses import dataclass
from typing import Any, Literal, cast

from litestar.connection import ASGIConnection
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException, PermissionDeniedException
from litestar.handlers import BaseRouteHandler

from litestar_security.context import AuthorizationSnapshot, Principal, SecurityContext

__all__ = (
    "AuthorizationPredicate",
    "all_of",
    "any_of",
    "at_least",
    "one_of",
    "requires_authenticated",
    "requires_capability",
    "requires_role",
    "requires_scope",
    "requires_team_role",
    "requires_tenant",
)

_AUTHENTICATION_REQUIRED = "Authentication required"
_PERMISSION_DENIED = "Permission denied"


@dataclass(frozen=True, slots=True)
class _AuthorizationDecision:
    granted: bool
    code: str = "allowed"
    path: tuple[str, ...] = ()
    authentication_required: bool = False

    def prefixed(self, *parts: str) -> "_AuthorizationDecision":
        return _AuthorizationDecision(
            granted=self.granted,
            code=self.code,
            path=(*parts, *self.path),
            authentication_required=self.authentication_required,
        )


_ALLOWED = _AuthorizationDecision(granted=True)


class AuthorizationPredicate:
    """Immutable authorization decision exposed as a native Litestar guard."""

    __slots__ = ()

    def __call__(self, connection: ASGIConnection[Any, Any, Any, Any], route_handler: BaseRouteHandler) -> None:
        """Evaluate the predicate and translate denial to a generic HTTP exception."""
        del route_handler
        decision = self._decide(connection)
        if decision.granted:
            return
        if decision.authentication_required:
            raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
        raise PermissionDeniedException(detail=_PERMISSION_DENIED)

    def _decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> _AuthorizationDecision:
        raise NotImplementedError  # pragma: no cover


def _principal(connection: ASGIConnection[Any, Any, Any, Any]) -> Principal[Any]:
    return cast("Principal[Any]", connection.user)


def _authorization(connection: ASGIConnection[Any, Any, Any, Any]) -> AuthorizationSnapshot:
    return cast("SecurityContext", connection.auth).authorization


def _grant_decision(
    connection: ASGIConnection[Any, Any, Any, Any], *, granted: bool, code: str, path: str
) -> _AuthorizationDecision:
    if not _principal(connection).is_authenticated:
        return _AuthorizationDecision(
            granted=False, code="authentication_required", path=("authenticated",), authentication_required=True
        )
    if granted:
        return _ALLOWED
    return _AuthorizationDecision(granted=False, code=code, path=(path,))


def _normalize_name(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        message = f"{label} must not be blank"
        raise ImproperlyConfiguredException(detail=message)
    return normalized


@dataclass(frozen=True, slots=True)
class _AuthenticatedPredicate(AuthorizationPredicate):
    def _decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> _AuthorizationDecision:
        return _grant_decision(
            connection,
            granted=_principal(connection).is_authenticated,
            code="authentication_required",
            path="authenticated",
        )


@dataclass(frozen=True, slots=True)
class _GrantPredicate(AuthorizationPredicate):
    kind: Literal["scope", "role", "capability"]
    value: str

    def _decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> _AuthorizationDecision:
        authorization = _authorization(connection)
        grants = {"scope": authorization.scopes, "role": authorization.roles, "capability": authorization.capabilities}[
            self.kind
        ]
        return _grant_decision(connection, granted=self.value in grants, code=f"missing_{self.kind}", path=self.kind)


@dataclass(frozen=True, slots=True)
class _TeamRolePredicate(AuthorizationPredicate):
    team_parameter: str
    roles: frozenset[str]

    def _decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> _AuthorizationDecision:
        team_id = connection.path_params.get(self.team_parameter)
        team_roles = _authorization(connection).team_roles.get(str(team_id), frozenset()) if team_id is not None else ()
        return _grant_decision(
            connection, granted=bool(self.roles.intersection(team_roles)), code="missing_team_role", path="team_role"
        )


@dataclass(frozen=True, slots=True)
class _TenantPredicate(AuthorizationPredicate):
    tenant_parameter: str

    def _decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> _AuthorizationDecision:
        tenant_id = connection.path_params.get(self.tenant_parameter)
        return _grant_decision(
            connection,
            granted=tenant_id is not None and str(tenant_id) in _authorization(connection).tenant_ids,
            code="missing_tenant",
            path="tenant",
        )


_CompositeOperator = Literal["all_of", "any_of", "one_of", "at_least"]


@dataclass(frozen=True, slots=True)
class _CompositePredicate(AuthorizationPredicate):
    operator: _CompositeOperator
    children: tuple[AuthorizationPredicate, ...]
    count: int

    def _decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> _AuthorizationDecision:
        decisions = tuple(child._decide(connection) for child in self.children)  # noqa: SLF001
        granted_count = sum(decision.granted for decision in decisions)
        if self.operator == "all_of":
            granted = granted_count == len(decisions)
        elif self.operator == "one_of":
            granted = granted_count == 1
        else:
            granted = granted_count >= self.count
        if granted:
            return _ALLOWED
        if not _principal(connection).is_authenticated:
            return _AuthorizationDecision(
                granted=False, code="authentication_required", path=(self.operator,), authentication_required=True
            )
        if self.operator == "one_of" and granted_count > 1:
            return _AuthorizationDecision(granted=False, code="one_of_mismatch", path=(self.operator,))
        failed_index, failure = next(
            (index, decision) for index, decision in enumerate(decisions) if not decision.granted
        )
        return failure.prefixed(self.operator, str(failed_index))


def requires_authenticated() -> AuthorizationPredicate:
    """Require any authenticated principal."""
    return _AuthenticatedPredicate()


def requires_scope(scope: str) -> AuthorizationPredicate:
    """Require one scope from the immutable authorization snapshot."""
    return _GrantPredicate(kind="scope", value=_normalize_name(scope, "Scope"))


def requires_role(role: str) -> AuthorizationPredicate:
    """Require one role from the immutable authorization snapshot."""
    return _GrantPredicate(kind="role", value=_normalize_name(role, "Role"))


def requires_capability(capability: str) -> AuthorizationPredicate:
    """Require one capability from the immutable authorization snapshot."""
    return _GrantPredicate(kind="capability", value=_normalize_name(capability, "Capability"))


def requires_team_role(*, team_parameter: str = "team_id", roles: Collection[str]) -> AuthorizationPredicate:
    """Require one allowed role for the team selected by a parsed path parameter."""
    normalized_roles = frozenset(_normalize_name(role, "Team role") for role in roles)
    if not normalized_roles:
        message = "Team-role guard requires at least one role"
        raise ImproperlyConfiguredException(detail=message)
    return _TeamRolePredicate(
        team_parameter=_normalize_name(team_parameter, "Team path parameter"), roles=normalized_roles
    )


def requires_tenant(*, tenant_parameter: str = "tenant_id") -> AuthorizationPredicate:
    """Require membership in the tenant selected by a parsed path parameter."""
    return _TenantPredicate(tenant_parameter=_normalize_name(tenant_parameter, "Tenant path parameter"))


def _composite(
    operator: _CompositeOperator, children: tuple[AuthorizationPredicate, ...], *, count: int
) -> AuthorizationPredicate:
    if not children:
        message = f"{operator} authorization guard requires at least one child"
        raise ImproperlyConfiguredException(detail=message)
    if len({id(child) for child in children}) != len(children):
        message = f"{operator} authorization guard contains a duplicate child object"
        raise ImproperlyConfiguredException(detail=message)
    return _CompositePredicate(operator=operator, children=children, count=count)


def all_of(*children: AuthorizationPredicate) -> AuthorizationPredicate:
    """Require every child predicate."""
    return _composite("all_of", children, count=len(children))


def any_of(*children: AuthorizationPredicate) -> AuthorizationPredicate:
    """Require at least one child predicate."""
    return _composite("any_of", children, count=1)


def one_of(*children: AuthorizationPredicate) -> AuthorizationPredicate:
    """Require exactly one child predicate."""
    return _composite("one_of", children, count=1)


def at_least(count: int, *children: AuthorizationPredicate) -> AuthorizationPredicate:
    """Require at least ``count`` child predicates."""
    if not 1 <= count <= len(children):
        message = f"at_least count must be between 1 and {len(children)}"
        raise ImproperlyConfiguredException(detail=message)
    return _composite("at_least", children, count=count)
