"""Compile route security policy for runtime and native OpenAPI projection."""

# The compiler is the sole package-internal consumer of the closed policy AST.

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from inspect import iscoroutine
from itertools import combinations
from math import comb
from types import MappingProxyType
from typing import Generic, NoReturn, TypeVar, cast
from warnings import catch_warnings, simplefilter

from litestar.exceptions import ImproperlyConfiguredException, LitestarDeprecationWarning
from litestar.handlers.base import BaseRouteHandler
from litestar.handlers.http_handlers import HTTPRouteHandler
from litestar.openapi.config import OpenAPIConfig
from litestar.openapi.spec import Components, Reference, SecurityRequirement, SecurityScheme
from litestar.router import Router
from litestar.routes import ASGIRoute, BaseRoute, HTTPRoute, WebSocketRoute

from litestar_security.authentication import (
    RUNTIME_PLAN_OPT_KEY,
    SECURITY_POLICY_OPT_KEY,
    AuthenticationPolicy,
    AuthenticationRegistry,
    MechanismPolicy,
    MechanismRequirement,
    OptionalPolicy,
    PublicPolicy,
    RouteSecurityDeclaration,
    SecurityRuntimePlan,
    mechanism,
    public,
)
from litestar_security.config import ExternalCSRF

__all__ = ()

UserT = TypeVar("UserT")
_OPENAPI_SECURITY_OPT_KEY = "litestar_security_openapi_security"
_CSRF_COVERAGE_OPT_KEY = "litestar_security_csrf"
_RESERVED_OPT_KEYS = frozenset({
    _CSRF_COVERAGE_OPT_KEY,
    _OPENAPI_SECURITY_OPT_KEY,
    RUNTIME_PLAN_OPT_KEY,
    SECURITY_POLICY_OPT_KEY,
})
_MISSING = object()


@dataclass(slots=True)
class PolicyCompiler(Generic[UserT]):
    """Compile and cache policy plans for one immutable mechanism registry."""

    registry: AuthenticationRegistry[UserT]
    max_openapi_combinations: int = 32
    _cache: dict[tuple[AuthenticationPolicy, bool | None], SecurityRuntimePlan] = field(
        init=False, default_factory=dict[tuple[AuthenticationPolicy, bool | None], SecurityRuntimePlan], repr=False
    )
    _canonical_plans: dict[SecurityRuntimePlan, SecurityRuntimePlan] = field(
        init=False, default_factory=dict[SecurityRuntimePlan, SecurityRuntimePlan], repr=False
    )

    def compile(self, policy: AuthenticationPolicy, *, csrf_required: bool | None = None) -> SecurityRuntimePlan:
        """Return the identity-stable plan for a normalized policy."""
        key = (policy, csrf_required)
        if cached := self._cache.get(key):
            return cached
        plan = self._compile(policy, csrf_required=csrf_required)
        plan = self._canonical_plans.setdefault(plan, plan)
        self._cache[key] = plan
        return plan

    def _compile(self, policy: AuthenticationPolicy, *, csrf_required: bool | None) -> SecurityRuntimePlan:
        if isinstance(policy, PublicPolicy):
            return SecurityRuntimePlan(authenticate=False, csrf_required=csrf_required)
        if isinstance(policy, OptionalPolicy):
            allow_anonymous = True
            expression = policy.policy
        else:
            allow_anonymous = False
            expression = policy
        if not isinstance(expression, MechanismPolicy):
            message = "Authentication policy must be created by a Litestar Security policy helper"
            raise ImproperlyConfiguredException(detail=message)
        requirements = self._requirements(expression)
        alternatives: tuple[tuple[MechanismRequirement, ...], ...]
        if expression.operator == "any_of":
            alternatives = tuple((requirement,) for requirement in requirements)
        elif expression.operator == "all_of":
            alternatives = (requirements,)
        else:
            count = cast("int", expression.count)
            combination_count = comb(len(requirements), count)
            if combination_count > self.max_openapi_combinations:
                message = (
                    f"at_least({count}) over {len(requirements)} participants expands to {combination_count} "
                    f"OpenAPI combinations, exceeding cap {self.max_openapi_combinations}"
                )
                raise ImproperlyConfiguredException(detail=message)
            alternatives = tuple(combinations(requirements, count))
        return SecurityRuntimePlan(
            authenticate=True,
            required=not allow_anonymous,
            alternatives=alternatives,
            allow_anonymous=allow_anonymous,
            csrf_required=csrf_required,
        )

    def _requirements(self, policy: MechanismPolicy) -> tuple[MechanismRequirement, ...]:
        if policy.implicit:
            if not self.registry.default_mechanism_names:
                message = "Implicit required authentication needs at least one default-participating mechanism"
                raise ImproperlyConfiguredException(detail=message)
            return tuple(mechanism(name) for name in self.registry.default_mechanism_names)

        by_name = {requirement.name: requirement for requirement in policy.requirements}
        undefined = tuple(name for name in by_name if name not in self.registry.mechanism_names)
        if undefined:
            message = f"Policy references undefined authentication mechanism: {undefined[0]}"
            raise ImproperlyConfiguredException(detail=message)
        return tuple(by_name[name] for name in self.registry.mechanism_names if name in by_name)


@dataclass(frozen=True, slots=True)
class OpenAPISchemeSet:
    """Validated native OpenAPI schemes indexed by authentication mechanism."""

    by_mechanism: Mapping[str, tuple[str, SecurityScheme]]
    unique_schemes: Mapping[str, SecurityScheme]

    @classmethod
    def from_registry(cls, registry: AuthenticationRegistry[object]) -> "OpenAPISchemeSet":
        """Compile documentable schemes from one authentication registry."""
        by_mechanism: dict[str, tuple[str, SecurityScheme]] = {}
        unique_schemes: dict[str, SecurityScheme] = {}
        for mechanism_name in registry.mechanism_names:
            mechanism_value = registry.get_mechanism(mechanism_name)
            scheme_name = mechanism_value.scheme_name
            scheme = mechanism_value.security_scheme
            if scheme_name is None or scheme is None:
                message = f"Authentication mechanism {mechanism_name} has no native OpenAPI security scheme"
                raise ImproperlyConfiguredException(detail=message)
            if existing := unique_schemes.get(scheme_name):
                if existing != scheme:
                    message = f"Conflicting native OpenAPI security scheme: {scheme_name}"
                    raise ImproperlyConfiguredException(detail=message)
            else:
                unique_schemes[scheme_name] = scheme
            by_mechanism[mechanism_name] = (scheme_name, scheme)
        return cls(by_mechanism=MappingProxyType(by_mechanism), unique_schemes=MappingProxyType(unique_schemes))

    def project(self, plan: SecurityRuntimePlan) -> list[SecurityRequirement]:
        """Project one runtime plan into native OpenAPI requirements."""
        if not plan.authenticate:
            return [{}]
        projection: list[SecurityRequirement] = []
        if plan.allow_anonymous:
            projection.append({})
        for alternative in plan.alternatives:
            requirement: SecurityRequirement = {}
            for participant in alternative:
                scheme_name, scheme = self.by_mechanism[participant.name]
                if participant.scopes and scheme.type not in {"oauth2", "openIdConnect"}:
                    message = f"OpenAPI security scheme {scheme_name} does not support OAuth or OIDC scopes"
                    raise ImproperlyConfiguredException(detail=message)
                scopes = list(participant.scopes)
                if scheme_name in requirement and requirement[scheme_name] != scopes:
                    message = f"OpenAPI security scheme {scheme_name} has conflicting scopes in one requirement"
                    raise ImproperlyConfiguredException(detail=message)
                requirement[scheme_name] = scopes
            projection.append(requirement)
        return projection


def prepare_openapi_config(config: OpenAPIConfig, schemes: OpenAPISchemeSet) -> OpenAPIConfig:
    """Copy an OpenAPI config with a separate native scheme contribution."""
    components = config.components if isinstance(config.components, list) else [config.components]
    contribution: dict[str, SecurityScheme | Reference] = dict(schemes.unique_schemes)
    for existing_components in components:
        for name, existing in (existing_components.security_schemes or {}).items():
            if name not in contribution:
                continue
            if contribution[name] != existing:
                message = f"Conflicting native OpenAPI security scheme: {name}"
                raise ImproperlyConfiguredException(detail=message)
            contribution.pop(name)
    if not contribution:
        return config
    with catch_warnings():
        simplefilter("ignore", LitestarDeprecationWarning)
        return replace(config, components=[*components, Components(security_schemes=contribution)])


@dataclass(slots=True)
class RouteCompiler(Generic[UserT]):
    """Compile one effective runtime plan for every registered Litestar handler."""

    registry: AuthenticationRegistry[UserT]
    default_policy: AuthenticationPolicy
    openapi_policy: AuthenticationPolicy | None = None
    openapi_config: OpenAPIConfig | None = None
    max_openapi_combinations: int = 32
    csrf_exclude_key: str | None = None
    external_csrf: ExternalCSRF | None = None
    _policy_compiler: PolicyCompiler[UserT] = field(init=False, repr=False)
    _schemes: OpenAPISchemeSet | None = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Create one per-registry policy compiler."""
        if self.csrf_exclude_key in _RESERVED_OPT_KEYS:
            message = "Native CSRF exclusion opt key collides with reserved Litestar Security metadata"
            raise ImproperlyConfiguredException(detail=message)
        self._policy_compiler = PolicyCompiler(self.registry, max_openapi_combinations=self.max_openapi_combinations)
        self._schemes = (
            OpenAPISchemeSet.from_registry(cast("AuthenticationRegistry[object]", self.registry))
            if self.openapi_config is not None
            else None
        )

    def receive_route(self, route: BaseRoute) -> None:
        """Compile and attach runtime plans for one registered native route."""
        if isinstance(route, HTTPRoute):
            for route_handler in route.route_handlers:
                self._compile_http_handler(route, route_handler)
            return
        if isinstance(route, WebSocketRoute):
            self._attach_plan(route, route.route_handler, self._effective_plan(route, route.route_handler))
            return
        asgi_route = cast("ASGIRoute", route)
        declaration = self._resolved_declaration(asgi_route, asgi_route.route_handler)
        if declaration is not None:
            self._raise_route_error(
                asgi_route, asgi_route.route_handler, "Raw ASGI routes do not support security policy"
            )
        self._attach_plan(
            asgi_route, asgi_route.route_handler, self._default_plan(asgi_route, asgi_route.route_handler)
        )

    def _compile_http_handler(self, route: HTTPRoute, route_handler: HTTPRouteHandler) -> None:
        csrf_override: bool | None
        if self._is_generated_options(route_handler):
            policy = public()
            csrf_override = False
        elif self._is_openapi_handler(route_handler):
            declaration = self._nearest_non_application_declaration(route, route_handler)
            policy = declaration.policy if declaration is not None else self.openapi_policy or public()
            csrf_override = declaration.csrf_required if declaration is not None else None
        else:
            declaration = self._resolved_declaration(route, route_handler)
            if declaration is not None:
                policy = declaration.policy
                csrf_override = declaration.csrf_required
            elif not self.registry.mechanism_names:
                policy = public()
                csrf_override = None
            else:
                policy = self.default_policy
                csrf_override = None
        plan = self._compile_http_policy(route, route_handler, policy, csrf_override=csrf_override)
        plan = self._apply_csrf_enforcement(route, route_handler, policy, plan)
        self._attach_plan(route, route_handler, plan)
        if self._schemes is not None:
            self._attach_openapi_security(route, route_handler, plan)

    def _compile_http_policy(
        self,
        route: HTTPRoute,
        route_handler: HTTPRouteHandler,
        policy: AuthenticationPolicy,
        *,
        csrf_override: bool | None,
    ) -> SecurityRuntimePlan:
        base_plan = self._compile_policy(route, route_handler, policy)
        session_names = tuple(
            name
            for name in self.registry.mechanism_names
            if self.registry.get_mechanism(name).session_capable
            and any(requirement.name == name for alternative in base_plan.alternatives for requirement in alternative)
        )
        derived = bool(session_names)
        if csrf_override is False and derived:
            self._raise_route_error(
                route, route_handler, f"csrf_required=False cannot exclude session-capable mechanism {session_names[0]}"
            )
        effective = derived if csrf_override is None else csrf_override
        return self._compile_policy(route, route_handler, policy, csrf_required=effective)

    def _apply_csrf_enforcement(
        self, route: HTTPRoute, route_handler: HTTPRouteHandler, policy: AuthenticationPolicy, plan: SecurityRuntimePlan
    ) -> SecurityRuntimePlan:
        native = self.csrf_exclude_key is not None
        desired_exclusion = not bool(plan.csrf_required)
        self._validate_csrf_metadata(route, route_handler, desired_exclusion=desired_exclusion)
        enforcement = self._resolve_csrf_enforcement(route, route_handler, plan, native=native)
        compiled = replace(plan, csrf_enforcement=enforcement)
        existing_plan = route_handler.opt.get(RUNTIME_PLAN_OPT_KEY)
        if existing_plan == compiled:
            return cast("SecurityRuntimePlan", existing_plan)
        if enforcement not in {None, "native"}:
            self._validate_external_csrf(route, route_handler, policy)
        if native:
            if desired_exclusion:
                route_handler.opt[cast("str", self.csrf_exclude_key)] = True
            route_handler.opt[_CSRF_COVERAGE_OPT_KEY] = desired_exclusion
        return compiled

    def _validate_csrf_metadata(
        self, route: HTTPRoute, route_handler: HTTPRouteHandler, *, desired_exclusion: bool
    ) -> None:
        marker = route_handler.opt.get(_CSRF_COVERAGE_OPT_KEY)
        existing = (
            route_handler.opt.get(self.csrf_exclude_key, _MISSING) if self.csrf_exclude_key is not None else _MISSING
        )
        if marker is None and existing is not _MISSING:
            self._raise_route_error(route, route_handler, "Conflicting manual native CSRF exclusion metadata")
        if marker is not None and marker != desired_exclusion:
            self._raise_route_error(route, route_handler, "Conflicting compiled native CSRF coverage")
        if marker is not None and (
            (desired_exclusion and existing is not True) or (not desired_exclusion and existing is not _MISSING)
        ):
            self._raise_route_error(route, route_handler, "Conflicting compiled native CSRF coverage")

    def _resolve_csrf_enforcement(
        self, route: HTTPRoute, route_handler: HTTPRouteHandler, plan: SecurityRuntimePlan, *, native: bool
    ) -> str | None:
        if plan.csrf_required:
            if native:
                return "native"
            if self.external_csrf is not None:
                return self.external_csrf.name
            self._raise_route_error(route, route_handler, "Route requires native CSRF or a named ExternalCSRF")
        return None

    def _validate_external_csrf(
        self, route: HTTPRoute, route_handler: HTTPRouteHandler, policy: AuthenticationPolicy
    ) -> None:
        external = cast("ExternalCSRF", self.external_csrf)
        for method in sorted(route_handler.http_methods):
            result = cast("object", external.validate(route.path, method, policy))
            if iscoroutine(result):
                result.close()
            if result is not True:
                self._raise_route_error(
                    route, route_handler, f"External CSRF integration {external.name} rejected coverage for {method}"
                )

    def _effective_plan(self, route: BaseRoute, route_handler: BaseRouteHandler) -> SecurityRuntimePlan:
        if declaration := self._resolved_declaration(route, route_handler):
            return self._compile_policy(
                route, route_handler, declaration.policy, csrf_required=declaration.csrf_required
            )
        return self._default_plan(route, route_handler)

    def _default_plan(self, route: BaseRoute, route_handler: BaseRouteHandler) -> SecurityRuntimePlan:
        if not self.registry.mechanism_names:
            return self._compile_policy(route, route_handler, public())
        return self._compile_policy(route, route_handler, self.default_policy)

    def _compile_policy(
        self,
        route: BaseRoute,
        route_handler: BaseRouteHandler,
        policy: AuthenticationPolicy,
        *,
        csrf_required: bool | None = None,
    ) -> SecurityRuntimePlan:
        try:
            return self._policy_compiler.compile(policy, csrf_required=csrf_required)
        except ImproperlyConfiguredException as exc:
            self._raise_route_error(route, route_handler, exc.detail)

    def _resolved_declaration(
        self, route: BaseRoute, route_handler: BaseRouteHandler
    ) -> RouteSecurityDeclaration | None:
        value = route_handler.opt.get(SECURITY_POLICY_OPT_KEY)
        if value is None:
            return None
        if not isinstance(value, RouteSecurityDeclaration):
            self._raise_route_error(route, route_handler, "Invalid Litestar Security route policy metadata")
        return value

    def _nearest_non_application_declaration(
        self, route: BaseRoute, route_handler: BaseRouteHandler
    ) -> RouteSecurityDeclaration | None:
        for layer in reversed(route_handler.ownership_layers[1:-1]):
            layer_opt = getattr(layer, "opt", None)
            if not isinstance(layer_opt, Mapping) or SECURITY_POLICY_OPT_KEY not in layer_opt:
                continue
            value = cast("Mapping[str, object]", layer_opt)[SECURITY_POLICY_OPT_KEY]
            if not isinstance(value, RouteSecurityDeclaration):
                self._raise_route_error(route, route_handler, "Invalid Litestar Security route policy metadata")
            return value
        return None

    def _is_openapi_handler(self, route_handler: BaseRouteHandler) -> bool:
        if self.openapi_config is None:
            return False
        configured_router = self.openapi_config.openapi_router
        configured_controller = self.openapi_config.openapi_controller
        base_path = (
            configured_router.path
            if configured_router is not None
            else configured_controller.path
            if configured_controller is not None
            else self.openapi_config.path or "/schema"
        )
        for layer in route_handler.ownership_layers[1:]:
            if isinstance(layer, Router) and layer.path == base_path:
                return True
        return False

    def _attach_openapi_security(
        self, route: HTTPRoute, route_handler: HTTPRouteHandler, plan: SecurityRuntimePlan
    ) -> None:
        schemes = cast("OpenAPISchemeSet", self._schemes)
        try:
            projection = schemes.project(plan)
        except ImproperlyConfiguredException as exc:
            self._raise_route_error(route, route_handler, exc.detail)
        canonical = tuple(tuple((name, tuple(scopes)) for name, scopes in item.items()) for item in projection)
        existing_canonical = route_handler.opt.get(_OPENAPI_SECURITY_OPT_KEY)
        for layer in route_handler.ownership_layers:
            native_security = getattr(layer, "security", None)
            if not isinstance(native_security, Sequence) or isinstance(native_security, str) or not native_security:
                continue
            if (
                layer is route_handler
                and existing_canonical == canonical
                and list(cast("Sequence[SecurityRequirement]", native_security)) == projection
            ):
                continue
            self._raise_route_error(route, route_handler, "Competing native Litestar security declaration")
        route_handler.security = projection
        route_handler.resolve_security()[:] = projection
        route_handler.opt[_OPENAPI_SECURITY_OPT_KEY] = canonical

    @staticmethod
    def _is_generated_options(route_handler: BaseRouteHandler) -> bool:
        handler = route_handler.fn
        return (
            getattr(handler, "__module__", None) == HTTPRoute.create_options_handler.__module__
            and getattr(handler, "__qualname__", None)
            == f"{HTTPRoute.create_options_handler.__qualname__}.<locals>.options_handler"
        )

    @staticmethod
    def _attach_plan(route: BaseRoute, route_handler: BaseRouteHandler, plan: SecurityRuntimePlan) -> None:
        existing = route_handler.opt.get(RUNTIME_PLAN_OPT_KEY)
        if existing is not None:
            if existing != plan:
                RouteCompiler._raise_route_error(route, route_handler, "Conflicting compiled security runtime plan")
            return
        route_handler.opt[RUNTIME_PLAN_OPT_KEY] = plan

    @staticmethod
    def _raise_route_error(route: BaseRoute, route_handler: BaseRouteHandler, detail: str) -> NoReturn:
        methods = getattr(route_handler, "http_methods", None)
        method = ",".join(sorted(methods)) if methods else route.scope_type.value
        message = f"{detail} for {method} {route.path}"
        raise ImproperlyConfiguredException(detail=message)
