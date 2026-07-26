"""Compile route security policy for runtime and native OpenAPI projection."""

# The compiler is the sole package-internal consumer of the closed policy AST.

from collections.abc import Mapping
from dataclasses import dataclass, field
from itertools import combinations
from typing import Generic, NoReturn, TypeVar, cast

from litestar.exceptions import ImproperlyConfiguredException
from litestar.handlers.base import BaseRouteHandler
from litestar.openapi.config import OpenAPIConfig
from litestar.router import Router
from litestar.routes import ASGIRoute, BaseRoute, HTTPRoute, WebSocketRoute

from litestar_security.authentication import (
    _RUNTIME_PLAN_OPT_KEY,  # pyright: ignore[reportPrivateUsage]
    _SECURITY_POLICY_OPT_KEY,  # pyright: ignore[reportPrivateUsage]
    AuthenticationPolicy,
    AuthenticationRegistry,
    MechanismRequirement,
    SecurityRuntimePlan,
    _MechanismPolicy,  # pyright: ignore[reportPrivateUsage]
    _OptionalPolicy,  # pyright: ignore[reportPrivateUsage]
    _PublicPolicy,  # pyright: ignore[reportPrivateUsage]
    _RouteSecurityDeclaration,  # pyright: ignore[reportPrivateUsage]
    mechanism,
    public,
)

__all__ = ("PolicyCompiler", "RouteCompiler")

UserT = TypeVar("UserT")


@dataclass(slots=True)
class PolicyCompiler(Generic[UserT]):
    """Compile and cache policy plans for one immutable mechanism registry."""

    registry: AuthenticationRegistry[UserT]
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
        if isinstance(policy, _PublicPolicy):
            return SecurityRuntimePlan(authenticate=False, csrf_required=csrf_required)
        if isinstance(policy, _OptionalPolicy):
            allow_anonymous = True
            expression = policy.policy
        else:
            allow_anonymous = False
            expression = policy
        if not isinstance(expression, _MechanismPolicy):
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
            alternatives = tuple(combinations(requirements, count))
        return SecurityRuntimePlan(
            authenticate=True,
            required=not allow_anonymous,
            alternatives=alternatives,
            allow_anonymous=allow_anonymous,
            csrf_required=csrf_required,
        )

    def _requirements(self, policy: _MechanismPolicy) -> tuple[MechanismRequirement, ...]:
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


@dataclass(slots=True)
class RouteCompiler(Generic[UserT]):
    """Compile one effective runtime plan for every registered Litestar handler."""

    registry: AuthenticationRegistry[UserT]
    default_policy: AuthenticationPolicy
    openapi_policy: AuthenticationPolicy | None = None
    openapi_config: OpenAPIConfig | None = None
    _policy_compiler: PolicyCompiler[UserT] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Create one per-registry policy compiler."""
        self._policy_compiler = PolicyCompiler(self.registry)

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

    def _compile_http_handler(self, route: HTTPRoute, route_handler: BaseRouteHandler) -> None:
        if self._is_generated_options(route_handler):
            plan = self._compile_policy(route, route_handler, public())
        elif self._is_openapi_handler(route_handler):
            declaration = self._nearest_non_application_declaration(route, route_handler)
            policy = declaration.policy if declaration is not None else self.openapi_policy or public()
            csrf_required = declaration.csrf_required if declaration is not None else None
            plan = self._compile_policy(route, route_handler, policy, csrf_required=csrf_required)
        else:
            plan = self._effective_plan(route, route_handler)
        self._attach_plan(route, route_handler, plan)

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
    ) -> _RouteSecurityDeclaration | None:
        value = route_handler.opt.get(_SECURITY_POLICY_OPT_KEY)
        if value is None:
            return None
        if not isinstance(value, _RouteSecurityDeclaration):
            self._raise_route_error(route, route_handler, "Invalid Litestar Security route policy metadata")
        return value

    def _nearest_non_application_declaration(
        self, route: BaseRoute, route_handler: BaseRouteHandler
    ) -> _RouteSecurityDeclaration | None:
        for layer in reversed(route_handler.ownership_layers[1:-1]):
            layer_opt = getattr(layer, "opt", None)
            if not isinstance(layer_opt, Mapping) or _SECURITY_POLICY_OPT_KEY not in layer_opt:
                continue
            value = cast("Mapping[str, object]", layer_opt)[_SECURITY_POLICY_OPT_KEY]
            if not isinstance(value, _RouteSecurityDeclaration):
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
        existing = route_handler.opt.get(_RUNTIME_PLAN_OPT_KEY)
        if existing is not None and existing != plan:
            RouteCompiler._raise_route_error(route, route_handler, "Conflicting compiled security runtime plan")
        route_handler.opt[_RUNTIME_PLAN_OPT_KEY] = plan

    @staticmethod
    def _raise_route_error(route: BaseRoute, route_handler: BaseRouteHandler, detail: str) -> NoReturn:
        methods = getattr(route_handler, "http_methods", None)
        method = ",".join(sorted(methods)) if methods else route.scope_type.value
        message = f"{detail} for {method} {route.path}"
        raise ImproperlyConfiguredException(detail=message)
