"""Pure authorization predicates exposed as native Litestar guards."""

from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Literal, cast

from litestar.connection import ASGIConnection
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException, PermissionDeniedException
from litestar.handlers import BaseRouteHandler

from litestar_security.context import AuthorizationSnapshot, Principal, SecurityContext

__all__ = (
    "AssuranceRequirement",
    "AssuranceTrait",
    "AuthorizationDecision",
    "AuthorizationPredicate",
    "requires_all_of",
    "requires_any_of",
    "requires_assurance",
    "requires_at_least",
    "requires_authenticated",
    "requires_capability",
    "requires_one_of",
    "requires_role",
    "requires_scope",
    "requires_team_role",
    "requires_tenant",
)


_AUTHENTICATION_REQUIRED = "Authentication required"


_PERMISSION_DENIED = "Permission denied"


class AssuranceTrait(str, Enum):
    """Normalized assurance properties established by verified evidence."""

    PHISHING_RESISTANT = "phishing-resistant"
    USER_VERIFIED = "user-verified"
    HARDWARE_BACKED = "hardware-backed"


@dataclass(frozen=True, slots=True)
class AssuranceRequirement:
    """Method, trait, freshness, and purpose observations required by a route."""

    methods: frozenset[str] = frozenset()
    traits: frozenset[AssuranceTrait] = frozenset()
    max_age: timedelta | None = None
    purpose: str | None = None

    def __post_init__(self) -> None:
        """Normalize and validate the immutable assurance requirement."""
        try:
            methods = frozenset(_normalize_name(method, "Assurance method") for method in self.methods)
            traits = frozenset(AssuranceTrait(trait) for trait in self.traits)
        except (TypeError, ValueError) as exc:
            message = "Assurance methods and traits must be supported non-blank values"
            raise ImproperlyConfiguredException(detail=message) from exc
        if self.max_age is not None and self.max_age <= timedelta():
            message = "Assurance max_age must be positive"
            raise ImproperlyConfiguredException(detail=message)
        purpose = _normalize_name(self.purpose, "Assurance purpose") if self.purpose is not None else None
        object.__setattr__(self, "methods", methods)
        object.__setattr__(self, "traits", traits)
        object.__setattr__(self, "purpose", purpose)


class AuthorizationPredicate:
    """Immutable authorization decision exposed as a native Litestar guard."""

    __slots__ = ()

    def __call__(self, connection: ASGIConnection[Any, Any, Any, Any], route_handler: BaseRouteHandler) -> None:
        """Evaluate the predicate and translate denial to a generic HTTP exception."""
        del route_handler
        decision = self.decide(connection)
        if decision.granted:
            return
        if decision.authentication_required:
            raise NotAuthorizedException(detail=_AUTHENTICATION_REQUIRED)
        raise PermissionDeniedException(detail=_PERMISSION_DENIED)

    def decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> "AuthorizationDecision":
        """Decide whether this predicate allows the connection.

        Override this to add a predicate of your own; the built-in composites accept any
        subclass. Return a decision rather than raising, so a composite can report which
        branch denied access.

        Args:
            connection: The connection being authorized.

        Returns:
            This predicate's verdict.

        Raises:
            NotImplementedError: If a subclass does not override this method.
        """
        raise NotImplementedError  # pragma: no cover


def requires_authenticated() -> AuthorizationPredicate:
    """Require any authenticated principal.

    Returns:
        A predicate satisfied by any non-anonymous principal.
    """
    return _AuthenticatedPredicate()


def requires_assurance(
    *,
    methods: Collection[str] = (),
    traits: Collection[AssuranceTrait] = (),
    max_age: timedelta | None = None,
    purpose: str | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> AuthorizationPredicate:
    """Require normalized authentication observations from immutable evidence.

    Raw provider ``acr`` and ``amr`` values remain inert. Applications that
    understand them must map them to project-owned methods or traits before
    constructing evidence.

    Args:
        methods: Verified authentication methods that must all be represented.
        traits: Verified assurance traits that must all be represented.
        max_age: Maximum age of every item of evidence used by the requirement.
        purpose: Optional action to which a step-up observation must be bound.
        clock: Injected UTC clock used for deterministic freshness decisions.

    Returns:
        A synchronous native Litestar authorization predicate.
    """
    return _AssurancePredicate(
        requirement=AssuranceRequirement(
            methods=frozenset(methods), traits=frozenset(traits), max_age=max_age, purpose=purpose
        ),
        clock=clock,
    )


def requires_scope(scope: str) -> AuthorizationPredicate:
    """Require one scope from the immutable authorization snapshot.

    Args:
        scope: The scope name, normalized before comparison.

    Returns:
        A predicate satisfied when the principal holds the scope.
    """
    return _GrantPredicate(kind="scope", value=_normalize_name(scope, "Scope"))


def requires_role(role: str) -> AuthorizationPredicate:
    """Require one role from the immutable authorization snapshot.

    Args:
        role: The role name, normalized before comparison.

    Returns:
        A predicate satisfied when the principal holds the role.
    """
    return _GrantPredicate(kind="role", value=_normalize_name(role, "Role"))


def requires_capability(capability: str) -> AuthorizationPredicate:
    """Require one capability from the immutable authorization snapshot.

    Args:
        capability: The capability name, normalized before comparison.

    Returns:
        A predicate satisfied when the principal holds the capability.
    """
    return _GrantPredicate(kind="capability", value=_normalize_name(capability, "Capability"))


def requires_team_role(*, team_parameter: str = "team_id", roles: Collection[str]) -> AuthorizationPredicate:
    """Require one allowed role for the team selected by a parsed path parameter.

    The team is read from the parsed path parameter rather than the request body,
    so the value the guard checks is the one the route will act on.

    Args:
        team_parameter: The path parameter naming the team.
        roles: The roles that satisfy the guard, normalized before comparison.

    Returns:
        A predicate satisfied when the principal holds one of the roles in that team.

    Raises:
        ImproperlyConfiguredException: If no roles are supplied.
    """
    normalized_roles = frozenset(_normalize_name(role, "Team role") for role in roles)
    if not normalized_roles:
        message = "Team-role guard requires at least one role"
        raise ImproperlyConfiguredException(detail=message)
    return _TeamRolePredicate(
        team_parameter=_normalize_name(team_parameter, "Team path parameter"), roles=normalized_roles
    )


def requires_tenant(*, tenant_parameter: str = "tenant_id") -> AuthorizationPredicate:
    """Require membership in the tenant selected by a parsed path parameter.

    Args:
        tenant_parameter: The path parameter naming the tenant.

    Returns:
        A predicate satisfied when the principal belongs to that tenant.
    """
    return _TenantPredicate(tenant_parameter=_normalize_name(tenant_parameter, "Tenant path parameter"))


def requires_all_of(*children: AuthorizationPredicate) -> AuthorizationPredicate:
    """Require every child predicate.

    Args:
        *children: The predicates that must all be satisfied.

    Returns:
        The composed predicate.
    """
    return _composite("all_of", children, count=len(children))


def requires_any_of(*children: AuthorizationPredicate) -> AuthorizationPredicate:
    """Require at least one child predicate.

    Args:
        *children: The predicates to draw from.

    Returns:
        The composed predicate.
    """
    return _composite("any_of", children, count=1)


def requires_one_of(*children: AuthorizationPredicate) -> AuthorizationPredicate:
    """Require exactly one child predicate.

    Args:
        *children: The predicates to draw from.

    Returns:
        The composed predicate, denying when more than one child is satisfied.
    """
    return _composite("one_of", children, count=1)


def requires_at_least(count: int, *children: AuthorizationPredicate) -> AuthorizationPredicate:
    """Require at least ``count`` child predicates.

    Args:
        count: How many children must be satisfied.
        *children: The predicates to draw from.

    Returns:
        The composed predicate.

    Raises:
        ImproperlyConfiguredException: If the count is not between one and the
            number of children.
    """
    if not 1 <= count <= len(children):
        message = f"at_least count must be between 1 and {len(children)}"
        raise ImproperlyConfiguredException(detail=message)
    return _composite("at_least", children, count=count)


_CompositeOperator = Literal["all_of", "any_of", "one_of", "at_least"]


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """One predicate's verdict, carrying why it was reached.

    Args:
        granted: Whether the predicate allows the connection.
        code: Stable machine-readable reason, reported when access is denied.
        path: Predicate names from the outermost composite inward, for diagnostics.
        authentication_required: Deny because no principal is authenticated, which
            translates to ``401`` instead of ``403``.
    """

    granted: bool
    code: str = "allowed"
    path: tuple[str, ...] = ()
    authentication_required: bool = False

    def prefixed(self, *parts: str) -> "AuthorizationDecision":
        """Return this decision with ``parts`` prepended to its diagnostic path.

        Args:
            *parts: Names to record ahead of the existing path.

        Returns:
            An equivalent decision reached through the named enclosing predicates.
        """
        return AuthorizationDecision(
            granted=self.granted,
            code=self.code,
            path=(*parts, *self.path),
            authentication_required=self.authentication_required,
        )


_ALLOWED = AuthorizationDecision(granted=True)


def _principal(connection: ASGIConnection[Any, Any, Any, Any]) -> Principal[Any]:
    return cast("Principal[Any]", connection.user)


def _authorization(connection: ASGIConnection[Any, Any, Any, Any]) -> AuthorizationSnapshot:
    return cast("SecurityContext", connection.auth).authorization


def _grant_decision(
    connection: ASGIConnection[Any, Any, Any, Any], *, granted: bool, code: str, path: str
) -> AuthorizationDecision:
    if not _principal(connection).is_authenticated:
        return AuthorizationDecision(
            granted=False, code="authentication_required", path=("authenticated",), authentication_required=True
        )
    if granted:
        return _ALLOWED
    return AuthorizationDecision(granted=False, code=code, path=(path,))


def _normalize_name(value: str, label: str) -> str:
    value_object = cast("object", value)
    if not isinstance(value_object, str):
        raise TypeError
    normalized = value_object.strip()
    if not normalized:
        message = f"{label} must not be blank"
        raise ImproperlyConfiguredException(detail=message)
    return normalized


@dataclass(frozen=True, slots=True)
class _AuthenticatedPredicate(AuthorizationPredicate):
    def decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> AuthorizationDecision:
        return _grant_decision(
            connection,
            granted=_principal(connection).is_authenticated,
            code="authentication_required",
            path="authenticated",
        )


@dataclass(frozen=True, slots=True)
class _AssurancePredicate(AuthorizationPredicate):
    requirement: AssuranceRequirement
    clock: Callable[[], datetime] = field(repr=False, compare=False)

    def decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> AuthorizationDecision:
        if not _principal(connection).is_authenticated:
            return AuthorizationDecision(
                granted=False, code="authentication_required", path=("assurance",), authentication_required=True
            )
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            message = "Assurance clock must return a timezone-aware datetime"
            raise ImproperlyConfiguredException(detail=message)
        now = now.astimezone(timezone.utc)
        evidence = cast("SecurityContext", connection.auth).evidence
        purpose_trait = f"purpose:{self.requirement.purpose}" if self.requirement.purpose is not None else None
        live_evidence = tuple(item for item in evidence if item.expires_at is None or item.expires_at > now)
        available_methods = frozenset(method for item in live_evidence for method in item.methods)
        available_traits = frozenset(trait for item in live_evidence for trait in item.traits)
        required_traits = frozenset(trait.value for trait in self.requirement.traits)
        if purpose_trait is not None and purpose_trait not in available_traits:
            code = (
                "assurance_purpose_mismatch"
                if any(trait.startswith("purpose:") for trait in available_traits)
                else "missing_assurance"
            )
            return AuthorizationDecision(granted=False, code=code, path=("assurance",))
        if not self.requirement.methods.issubset(available_methods) or not required_traits.issubset(available_traits):
            return AuthorizationDecision(granted=False, code="missing_assurance", path=("assurance",))
        if self.requirement.max_age is not None:
            relevant = tuple(
                item
                for item in live_evidence
                if item.methods.intersection(self.requirement.methods)
                or item.traits.intersection(required_traits)
                or (purpose_trait is not None and purpose_trait in item.traits)
            )
            if not relevant:
                relevant = live_evidence
            current = tuple(
                item
                for item in relevant
                if item.authenticated_at <= now
                and now - item.authenticated_at <= self.requirement.max_age
                and (item.expires_at is None or item.expires_at > now)
            )
            current_methods = frozenset(method for item in current for method in item.methods)
            current_traits = frozenset(trait for item in current for trait in item.traits)
            if (
                not current
                or not self.requirement.methods.issubset(current_methods)
                or not required_traits.issubset(current_traits)
                or (purpose_trait is not None and purpose_trait not in current_traits)
            ):
                return AuthorizationDecision(granted=False, code="assurance_too_old", path=("assurance",))
        return _ALLOWED


@dataclass(frozen=True, slots=True)
class _GrantPredicate(AuthorizationPredicate):
    kind: Literal["scope", "role", "capability"]
    value: str

    def decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> AuthorizationDecision:
        authorization = _authorization(connection)
        grants = {"scope": authorization.scopes, "role": authorization.roles, "capability": authorization.capabilities}[
            self.kind
        ]
        return _grant_decision(connection, granted=self.value in grants, code=f"missing_{self.kind}", path=self.kind)


@dataclass(frozen=True, slots=True)
class _TeamRolePredicate(AuthorizationPredicate):
    team_parameter: str
    roles: frozenset[str]

    def decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> AuthorizationDecision:
        team_id = connection.path_params.get(self.team_parameter)
        team_roles = _authorization(connection).team_roles.get(str(team_id), frozenset()) if team_id is not None else ()
        return _grant_decision(
            connection, granted=bool(self.roles.intersection(team_roles)), code="missing_team_role", path="team_role"
        )


@dataclass(frozen=True, slots=True)
class _TenantPredicate(AuthorizationPredicate):
    tenant_parameter: str

    def decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> AuthorizationDecision:
        tenant_id = connection.path_params.get(self.tenant_parameter)
        return _grant_decision(
            connection,
            granted=tenant_id is not None and str(tenant_id) in _authorization(connection).tenant_ids,
            code="missing_tenant",
            path="tenant",
        )


@dataclass(frozen=True, slots=True)
class _CompositePredicate(AuthorizationPredicate):
    operator: _CompositeOperator
    children: tuple[AuthorizationPredicate, ...]
    count: int

    def decide(self, connection: ASGIConnection[Any, Any, Any, Any]) -> AuthorizationDecision:
        decisions = tuple(child.decide(connection) for child in self.children)
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
            return AuthorizationDecision(
                granted=False, code="authentication_required", path=(self.operator,), authentication_required=True
            )
        if self.operator == "one_of" and granted_count > 1:
            return AuthorizationDecision(granted=False, code="one_of_mismatch", path=(self.operator,))
        failed_index, failure = next(
            (index, decision) for index, decision in enumerate(decisions) if not decision.granted
        )
        return failure.prefixed(self.operator, str(failed_index))


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
