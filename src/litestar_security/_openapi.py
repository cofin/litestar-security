"""Compile route security policy for runtime and native OpenAPI projection."""

# The compiler is the sole package-internal consumer of the closed policy AST.

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from inspect import iscoroutine
from itertools import combinations
from math import comb
from re import Pattern
from re import compile as recompile
from types import MappingProxyType
from typing import Generic, NoReturn, TypeVar, cast
from warnings import catch_warnings, simplefilter, warn

from litestar import Response
from litestar._openapi.plugin import OpenAPIPlugin
from litestar.exceptions import ImproperlyConfiguredException, LitestarDeprecationWarning, LitestarWarning
from litestar.handlers.base import BaseRouteHandler
from litestar.handlers.http_handlers import HTTPRouteHandler
from litestar.middleware._utils import (
    build_exclude_path_pattern,  # pyright: ignore[reportUnknownVariableType] - Litestar returns an unparameterized re.Pattern
)
from litestar.openapi.config import OpenAPIConfig
from litestar.openapi.controller import OpenAPIController
from litestar.openapi.plugins import OpenAPIRenderPlugin
from litestar.openapi.spec import Components, Reference, SecurityRequirement, SecurityScheme, Tag
from litestar.routes import ASGIRoute, BaseRoute, HTTPRoute, WebSocketRoute
from litestar.types import Empty

from litestar_security._docs import converted_denial, describes_raised_denial
from litestar_security._internal import GENERATED_ROUTE_OPT_KEY, RUNTIME_PLAN_OPT_KEY
from litestar_security.authentication import (
    AUTH_POLICY_OPT_KEY,
    CSRF_REQUIRED_OPT_KEY,
    AuthenticationPolicy,
    AuthenticationRegistry,
    ExcludePolicy,
    MechanismPolicy,
    MechanismRequirement,
    OptionalPolicy,
    PublicPolicy,
    SecurityRuntimePlan,
    exclude,
    is_generated_options_handler,
    mechanism,
    public,
    required,
)
from litestar_security.config import ExternalCSRF
from litestar_security.websocket import WebSocketSecurityConfig

__all__ = ()

UserT = TypeVar("UserT")
_OPENAPI_SECURITY_OPT_KEY = "litestar_security_openapi_security"
_CSRF_COVERAGE_OPT_KEY = "litestar_security_csrf"
_OPENAPI_HANDLER_MODULES = frozenset({
    OpenAPIPlugin.__module__,
    OpenAPIController.__module__,
    OpenAPIRenderPlugin.__module__,
})
"""Modules that define Litestar's own OpenAPI schema and documentation handlers.

`OpenAPIPlugin.__module__` covers the render-plugin router Litestar builds
internally, `OpenAPIController.__module__` the deprecated controller, and
`OpenAPIRenderPlugin.__module__` the handlers render plugins contribute
directly. The modules are read from the classes rather than spelled as string
literals so that a Litestar reorganization fails at import instead of silently
reclassifying schema routes.
"""
_RESERVED_OPT_KEYS = frozenset({
    AUTH_POLICY_OPT_KEY,
    CSRF_REQUIRED_OPT_KEY,
    _CSRF_COVERAGE_OPT_KEY,
    _OPENAPI_SECURITY_OPT_KEY,
    GENERATED_ROUTE_OPT_KEY,
    RUNTIME_PLAN_OPT_KEY,
})
_EXCLUDE_FROM_AUTH_OPT_KEY = "exclude_from_auth"
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
        """Return the identity-stable plan for a normalized policy.

        Args:
            policy: The policy to compile.
            csrf_required: Override CSRF coverage, or ``None`` to derive it.

        Returns:
            The compiled plan. Equal policies share one object, so route lookup
            can compare plans by identity.
        """
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
        if isinstance(policy, ExcludePolicy):
            return SecurityRuntimePlan(authenticate=False, bypass_authentication=True, csrf_required=csrf_required)
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
        """Compile documentable schemes from one authentication registry.

        Args:
            registry: The compiled authentication registry.

        Returns:
            The schemes indexed by mechanism and deduplicated by scheme name.

        Raises:
            ImproperlyConfiguredException: If a mechanism declares no scheme, or
                two mechanisms declare conflicting definitions under one name.
        """
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
        """Project one runtime plan into native OpenAPI requirements.

        Args:
            plan: The compiled runtime plan.

        Returns:
            The security requirements for the operation. An empty requirement
            represents anonymous access.

        Raises:
            ImproperlyConfiguredException: If a scheme is given scopes it cannot
                express, or one requirement assigns conflicting scopes to a scheme.
        """
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
    """Copy an OpenAPI config with a separate native scheme contribution.

    Args:
        config: The application's OpenAPI configuration.
        schemes: The schemes compiled from the authentication registry.

    Returns:
        The same object when nothing needs adding, otherwise a copy carrying the
        contributed schemes in their own components entry.

    Raises:
        ImproperlyConfiguredException: If the application already declares a
            scheme of the same name with a different definition.
    """
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


def merge_openapi_tags(config: OpenAPIConfig, tags: Sequence[Tag]) -> OpenAPIConfig:
    """Copy an OpenAPI config with descriptions for undeclared generated-route tag groups.

    A tag description is documentation rather than policy, so a name the application
    already declared keeps the application's version instead of raising: the generated
    routes still land in that group, described the way its owner chose.
    """
    declared = {tag.name for tag in config.tags or ()}
    contribution = [tag for tag in tags if tag.name not in declared]
    if not contribution:
        return config
    with catch_warnings():
        simplefilter("ignore", LitestarDeprecationWarning)
        return replace(config, tags=[*(config.tags or ()), *contribution])


@dataclass(slots=True)
class RouteCompiler(Generic[UserT]):
    """Compile one effective runtime plan for every registered Litestar handler."""

    registry: AuthenticationRegistry[UserT]
    openapi_config: OpenAPIConfig | None = None
    max_openapi_combinations: int = 32
    csrf_exclude_key: str | None = None
    external_csrf: ExternalCSRF | None = None
    websocket_config: WebSocketSecurityConfig = field(default_factory=WebSocketSecurityConfig)
    exclude: Sequence[str] | str | None = None
    converts_to_problem_details: bool = False
    _policy_compiler: PolicyCompiler[UserT] = field(init=False, repr=False)
    _schemes: OpenAPISchemeSet | None = field(init=False, repr=False)
    _exclude_pattern: Pattern[str] | None = field(init=False, repr=False)
    _reported_exclusions: tuple[tuple[str, Pattern[str]], ...] = field(init=False, repr=False)
    _matched_exclusions: set[str] = field(init=False, repr=False, default_factory=set[str])
    _reported_response_classes: set[type] = field(init=False, repr=False, default_factory=set[type])

    def __post_init__(self) -> None:
        """Create one per-registry policy compiler."""
        if self.csrf_exclude_key in _RESERVED_OPT_KEYS:
            message = "Native CSRF exclusion opt key collides with reserved Litestar Security metadata"
            raise ImproperlyConfiguredException(detail=message)
        self._exclude_pattern = build_exclude_path_pattern(exclude=self.exclude, middleware_cls=type(self))
        # build_exclude_path_pattern joins the sequence into one expression, so
        # attributing a match back to the pattern that produced it needs the
        # originals compiled separately. These are used for reporting only.
        sources = (self.exclude,) if isinstance(self.exclude, str) else tuple(self.exclude or ())
        self._reported_exclusions = tuple((source, recompile(source)) for source in sources)
        self._policy_compiler = PolicyCompiler(self.registry, max_openapi_combinations=self.max_openapi_combinations)
        self._schemes = (
            OpenAPISchemeSet.from_registry(cast("AuthenticationRegistry[object]", self.registry))
            if self.openapi_config is not None
            else None
        )

    def receive_route(self, route: BaseRoute) -> None:
        """Compile and attach runtime plans for one registered native route.

        Args:
            route: The route to compile.

        Raises:
            ImproperlyConfiguredException: If the route declares invalid policy
                metadata, competes with a native security declaration, or requires
                CSRF coverage the application has not configured.
        """
        if isinstance(route, HTTPRoute):
            for route_handler in route.route_handlers:
                self._compile_http_handler(route, route_handler)
            return
        if isinstance(route, WebSocketRoute):
            self._reject_csrf_metadata(route, route.route_handler)
            plan = self._effective_plan(route, route.route_handler)
            if not self.websocket_config.allowed_origins and any(
                self.registry.get_mechanism(name).session_capable for name in plan.participant_names or ()
            ):
                self._raise_route_error(
                    route, route.route_handler, "Session-capable security requires a trusted WebSocket Origin"
                )
            self._attach_plan(route, route.route_handler, plan)
            return
        asgi_route = cast("ASGIRoute", route)
        self._reject_csrf_metadata(asgi_route, asgi_route.route_handler)
        self._attach_plan(
            asgi_route, asgi_route.route_handler, self._effective_plan(asgi_route, asgi_route.route_handler)
        )

    def unmatched_exclusions(self) -> tuple[str, ...]:
        """Report configured exclusion patterns that no compiled route has matched.

        Returns:
            The configured patterns, in declaration order, whose own expression
            matched no route path seen so far.
        """
        return tuple(source for source, _ in self._reported_exclusions if source not in self._matched_exclusions)

    def _report_customized_response_class(self, route: HTTPRoute, route_handler: HTTPRouteHandler) -> None:
        """Report once that a generated route no longer renders through Litestar's own response.

        The documented response specifications describe what the generated
        handlers return. A response class that reshapes the body - a
        presentation plugin's, or an application's own - makes them describe
        something the route no longer sends. Every generated handler resolves
        the same application-level class, so the report is one per distinct
        class rather than one per route.

        This warns rather than raises: a customized response class is
        legitimate, and refusing to run beside one would make this plugin
        incompatible with presentation plugins for no security reason.

        Args:
            route: The route being compiled, named as the representative one.
            route_handler: The handler whose resolved response class is read.
        """
        if not route_handler.opt.get(GENERATED_ROUTE_OPT_KEY) or self._is_generated_options(route_handler):
            return
        resolved = cast(
            "type[object]",
            route_handler.resolve_response_class(),  # pyright: ignore[reportUnknownMemberType] - Litestar returns an unparameterized Response type
        )
        if resolved is Response or resolved in self._reported_response_classes:
            return
        self._reported_response_classes.add(resolved)
        message = (
            f"Generated Litestar Security routes resolve the response class {resolved.__qualname__!r} "
            f"rather than Litestar's own, first at {route.path}. The documented response schemas describe "
            "what the handlers return, so a response class that reshapes the body makes them inaccurate."
        )
        warn(message, category=LitestarWarning, stacklevel=1)

    def _restate_denials_as_problem_details(self, route_handler: HTTPRouteHandler) -> None:
        """Restate a generated route's raised denials as the bodies the application converts them to.

        The denial specifications are module-level, shared by every application
        that installs this plugin, so whether problem details are in effect
        cannot be decided where they are declared. It is decided here, per
        application, against the copy of the handler this registration owns -
        by assigning a new mapping rather than mutating the shared one.

        Only a specification for a status the route *raises* is restated. A
        status the handler returns is untouched: the second-factor challenge
        and the conflict are return values, and no exception handling sees
        them.

        Args:
            route_handler: The handler whose response specifications are restated.
        """
        if not self.converts_to_problem_details or not route_handler.opt.get(GENERATED_ROUTE_OPT_KEY):
            return
        responses = route_handler.responses
        if not responses or not any(describes_raised_denial(spec) for spec in responses.values()):
            return
        route_handler.responses = {
            status: converted_denial(spec.description) if describes_raised_denial(spec) else spec
            for status, spec in responses.items()
        }

    def _compile_http_handler(self, route: HTTPRoute, route_handler: HTTPRouteHandler) -> None:
        self._report_customized_response_class(route, route_handler)
        self._restate_denials_as_problem_details(route_handler)
        policy: AuthenticationPolicy
        csrf_override: bool | None
        native_exclude = self._handler_excludes_auth(route, route_handler)
        if self._is_excluded(route):
            self._reject_excluded_policy(route, route_handler, self._resolved_policy(route, route_handler))
            policy = exclude()
            csrf_override = self._http_csrf_override(route, route_handler)
        elif self._is_generated_options(route_handler):
            policy = public()
            csrf_override = False
        elif self._is_openapi_handler(route_handler):
            policy = self._nearest_non_application_policy(route, route_handler) or public()
            csrf_override = self._http_csrf_override(route, route_handler)
        else:
            resolved_policy = self._resolved_policy(route, route_handler)
            if native_exclude and resolved_policy is not None:
                self._raise_route_error(route, route_handler, "Route declares both auth and exclude_from_auth")
            if native_exclude:
                resolved_policy = exclude()
            if resolved_policy is None:
                policy = required() if self.registry.mechanism_names else public()
            else:
                policy = resolved_policy
            csrf_override = self._http_csrf_override(route, route_handler)
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
        if isinstance(policy, ExcludePolicy):
            derived = any(
                self.registry.get_mechanism(name).session_capable for name in self.registry.default_mechanism_names
            )
        else:
            derived = any(
                self.registry.get_mechanism(name).session_capable
                for name in self.registry.mechanism_names
                if any(
                    requirement.name == name for alternative in base_plan.alternatives for requirement in alternative
                )
            )
        effective = derived if csrf_override is None else csrf_override
        return self._compile_policy(route, route_handler, policy, csrf_required=effective)

    def _apply_csrf_enforcement(
        self, route: HTTPRoute, route_handler: HTTPRouteHandler, policy: AuthenticationPolicy, plan: SecurityRuntimePlan
    ) -> SecurityRuntimePlan:
        native = self.csrf_exclude_key is not None
        # A public() plan is excluded from native CSRF. A public route that
        # establishes cookie state must instead declare csrf_required=True;
        # see patterns.md, "Local generated routes".
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
            if existing is not True:
                self._raise_route_error(route, route_handler, "Native CSRF exclusions must be exactly True")
            if not desired_exclusion:
                self._raise_route_error(route, route_handler, "Session-capable routes cannot exclude native CSRF")
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
        native_exclude = self._handler_excludes_auth(route, route_handler)
        policy = self._resolved_policy(route, route_handler)
        if native_exclude and policy is not None:
            self._raise_route_error(route, route_handler, "Route declares both auth and exclude_from_auth")
        if self._is_excluded(route):
            self._reject_excluded_policy(route, route_handler, policy)
            return self._compile_policy(route, route_handler, exclude())
        if native_exclude:
            return self._compile_policy(route, route_handler, exclude())
        if policy is not None:
            return self._compile_policy(route, route_handler, policy)
        return self._default_plan(route, route_handler)

    def _default_plan(self, route: BaseRoute, route_handler: BaseRouteHandler) -> SecurityRuntimePlan:
        if not self.registry.mechanism_names:
            return self._compile_policy(route, route_handler, public())
        return self._compile_policy(route, route_handler, required())

    def _is_excluded(self, route: BaseRoute) -> bool:
        if self._exclude_pattern is None or not self._exclude_pattern.match(route.path):
            return False
        self._matched_exclusions.update(
            source for source, pattern in self._reported_exclusions if pattern.match(route.path)
        )
        return True

    def _reject_excluded_policy(
        self, route: BaseRoute, route_handler: BaseRouteHandler, policy: AuthenticationPolicy | None
    ) -> None:
        # A route that declares a policy and also matches an exclusion pattern
        # states two incompatible intentions, so neither is silently preferred.
        if policy is not None:
            message = "Route declares auth but matches a security exclusion pattern"
            self._raise_route_error(route, route_handler, message)

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

    def _resolved_policy(self, route: BaseRoute, route_handler: BaseRouteHandler) -> AuthenticationPolicy | None:
        for layer in reversed(route_handler.ownership_layers):
            layer_opt = getattr(layer, "opt", None)
            if not isinstance(layer_opt, Mapping):
                continue  # pragma: no cover - Litestar ownership layers expose opt as mappings
            policy = self._policy_from_opt(route, route_handler, cast("Mapping[str, object]", layer_opt))
            if policy is not None:
                return policy
        return None

    def _nearest_non_application_policy(
        self, route: BaseRoute, route_handler: BaseRouteHandler
    ) -> AuthenticationPolicy | None:
        """Resolve the policy an owning layer declares for a generated handler.

        The walk covers ``ownership_layers[1:-1]``, which excludes the
        application layer and the handler itself: a Litestar-generated schema
        handler carries no ``auth=`` of its own, and an application-wide default
        must not silently protect the documentation. Wrapping the schema router
        or controller in an owner that carries ``opt={"auth": ...}`` is the
        supported way to require authentication for the schema routes.

        Only handlers `_is_openapi_handler` identified as Litestar's own reach
        this walk, so excluding the handler layer cannot discard an application
        route's declared policy.

        Args:
            route: The route being compiled.
            route_handler: The handler being compiled.

        Returns:
            The policy declared by the nearest owning layer, or None when no
            layer between the application and the handler declares one.
        """
        for layer in reversed(route_handler.ownership_layers[1:-1]):
            layer_opt = getattr(layer, "opt", None)
            if not isinstance(layer_opt, Mapping):
                continue  # pragma: no cover - Litestar ownership layers expose opt as mappings
            policy = self._policy_from_opt(route, route_handler, cast("Mapping[str, object]", layer_opt))
            if policy is not None:
                return policy
        return None

    def _policy_from_opt(
        self, route: BaseRoute, route_handler: BaseRouteHandler, opt: Mapping[str, object]
    ) -> AuthenticationPolicy | None:
        if AUTH_POLICY_OPT_KEY not in opt:
            return None
        value = opt[AUTH_POLICY_OPT_KEY]
        if not isinstance(value, AuthenticationPolicy):
            self._raise_route_error(route, route_handler, "Invalid Litestar Security auth policy")
        return value

    def _http_csrf_override(self, route: HTTPRoute, route_handler: HTTPRouteHandler) -> bool | None:
        owner_layers = cast("Sequence[object]", route_handler.ownership_layers[:-1])
        for layer in owner_layers:
            layer_opt = getattr(layer, "opt", None)
            if isinstance(layer_opt, Mapping) and CSRF_REQUIRED_OPT_KEY in layer_opt:
                self._raise_route_error(
                    route, route_handler, "csrf_required is supported only on individual HTTP route handlers"
                )
        if CSRF_REQUIRED_OPT_KEY not in route_handler.opt:
            return None
        if route_handler.opt[CSRF_REQUIRED_OPT_KEY] is not True:
            self._raise_route_error(route, route_handler, "csrf_required must be exactly True when present")
        return True

    def _handler_excludes_auth(self, route: BaseRoute, route_handler: BaseRouteHandler) -> bool:
        """Validate and resolve Litestar's handler-local authentication bypass opt.

        Args:
            route: The route containing the handler.
            route_handler: The handler whose metadata is being compiled.

        Returns:
            Whether the handler requests native authentication bypass.
        """
        for layer in route_handler.ownership_layers[:-1]:
            layer_opt = getattr(layer, "opt", None)
            if isinstance(layer_opt, Mapping) and _EXCLUDE_FROM_AUTH_OPT_KEY in layer_opt:
                self._raise_route_error(
                    route, route_handler, "exclude_from_auth is supported only on individual route handlers"
                )
        if _EXCLUDE_FROM_AUTH_OPT_KEY not in route_handler.opt:
            return False
        if route_handler.opt[_EXCLUDE_FROM_AUTH_OPT_KEY] is not True:
            self._raise_route_error(route, route_handler, "exclude_from_auth must be exactly True when present")
        return True

    def _reject_csrf_metadata(self, route: BaseRoute, route_handler: BaseRouteHandler) -> None:
        for layer in route_handler.ownership_layers:
            layer_opt = getattr(layer, "opt", None)
            if isinstance(layer_opt, Mapping) and CSRF_REQUIRED_OPT_KEY in layer_opt:
                self._raise_route_error(route, route_handler, "csrf_required is supported only on HTTP routes")

    def _is_openapi_handler(self, route_handler: HTTPRouteHandler) -> bool:
        """Report whether a handler is one Litestar generated to serve the schema.

        The handler is matched by the module that defines it, never by its URL.
        An application route is free to share the configured OpenAPI base path;
        it is still an application route and its own ``auth=`` is honored.

        A handler this cannot positively identify is reported as an application
        handler, so an unrecognized route is authenticated rather than served
        anonymously. An application that serves documentation from its own
        handlers therefore declares ``opt={"auth": public()}`` on the owning
        router or controller to keep them open.

        Args:
            route_handler: The handler compiled for the current route.

        Returns:
            True when Litestar defined the handler as part of its OpenAPI
            support, False for every application handler.
        """
        if self.openapi_config is None:
            return False
        return getattr(route_handler.fn, "__module__", None) in _OPENAPI_HANDLER_MODULES

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
        # A plugin registered ahead of this one may already have memoized the
        # stale resolution, so drop it and let the next resolve_security() flow
        # through Litestar's own layer merge; the competing-declaration check
        # above guarantees no other ownership layer contributes to that merge.
        route_handler._resolved_security = Empty  # noqa: SLF001 # pyright: ignore[reportPrivateUsage] - Litestar exposes no resolution-invalidation API
        route_handler.opt[_OPENAPI_SECURITY_OPT_KEY] = canonical

    @staticmethod
    def _is_generated_options(route_handler: BaseRouteHandler) -> bool:
        return is_generated_options_handler(route_handler.fn)

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
