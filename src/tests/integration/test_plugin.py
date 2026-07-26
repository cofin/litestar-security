"""Integration tests for plugin ownership, session wiring, and CLI behavior."""

from __future__ import annotations

import sys
from copy import deepcopy
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Any, ClassVar, Literal, cast

import click
import pytest
from click.testing import CliRunner
from litestar import Controller, Litestar, Router, WebSocket, asgi, get, post, route, websocket
from litestar.config.app import AppConfig
from litestar.di import Provide
from litestar.enums import HttpMethod
from litestar.exceptions import ImproperlyConfiguredException
from litestar.middleware import DefineMiddleware
from litestar.middleware.session.base import SessionMiddleware
from litestar.openapi import OpenAPIConfig
from litestar.openapi.controller import OpenAPIController
from litestar.openapi.plugins import JsonRenderPlugin
from litestar.openapi.spec import Components, OpenAPIResponse, SecurityScheme
from litestar.plugins import CLIPlugin, CLIPluginProtocol, InitPlugin, ReceiveRoutePlugin
from litestar.routes import ASGIRoute, BaseRoute, HTTPRoute, WebSocketRoute

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security._cli import register, security_group
from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationPolicy,
    SecurityMiddlewareWrapper,
    SecurityRuntimePlan,
    all_of,
    any_of,
    at_least,
    mechanism,
    optional,
    public,
    required,
    security,
)
from litestar_security.context import Principal, SecurityContext
from litestar_security.plugin import CurrentUser, PrincipalDependency, SecurityContextDependency

if TYPE_CHECKING:
    from litestar.middleware.session.base import BaseSessionBackend
    from litestar.types import Receive, Scope, Send


class _CompilerSlot:
    def __init__(self, name: str) -> None:
        self.name = name

    def extract(self, _connection: object) -> object:
        raise AssertionError


class _CompilerAuthenticator:
    participates_by_default = True

    def __init__(self, name: str, slot: str) -> None:
        self.name = name
        self.slot = slot

    async def authenticate(self, _credential: object, _connection: object) -> Authenticated[str]:
        raise AssertionError


class _CompilerResolver:
    async def resolve(self, _claims: str) -> Principal[object]:
        raise AssertionError


def _compiler_config(
    *,
    openapi_policy: AuthenticationPolicy | None = None,
    names: tuple[str, ...] = ("a", "b"),
    scheme_names: dict[str, str] | None = None,
    scheme_types: dict[str, Literal["apiKey", "http", "mutualTLS", "oauth2", "openIdConnect"]] | None = None,
    max_openapi_combinations: int = 32,
) -> SecurityConfig[object]:
    slots = tuple(_CompilerSlot(name=f"slot-{name}") for name in names)
    mechanisms = tuple(
        AuthenticationMechanism(
            authenticator=_CompilerAuthenticator(name=name, slot=f"slot-{name}"),  # type: ignore[arg-type]
            resolver=_CompilerResolver(),
            scheme_name=(scheme_names or {}).get(name, name),
            security_scheme=SecurityScheme(
                type=(scheme_types or {}).get(name, "http"),
                scheme="bearer" if (scheme_types or {}).get(name, "http") == "http" else None,
                open_id_connect_url=(
                    "https://issuer.example/.well-known/openid-configuration"
                    if (scheme_types or {}).get(name) == "openIdConnect"
                    else None
                ),
            ),
        )
        for name in names
    )
    return SecurityConfig(
        slots=slots,  # type: ignore[arg-type]
        mechanisms=mechanisms,
        openapi_policy=openapi_policy,
        max_openapi_combinations=max_openapi_combinations,
    )


def _http_plan(app: Litestar, path: str, method: str = "GET") -> SecurityRuntimePlan:
    route_value = next(
        route_value for route_value in app.routes if isinstance(route_value, HTTPRoute) and route_value.path == path
    )
    return cast("SecurityRuntimePlan", route_value.route_handler_map[method][0].opt["litestar_security_plan"])


def _operation_security(app: Litestar, path: str) -> list[dict[str, list[str]]] | None:
    operation = app.openapi_schema.paths[path].get
    assert operation is not None
    return cast("list[dict[str, list[str]]] | None", operation.security)


def test_plugin_constructs_default_config() -> None:
    plugin = SecurityPlugin()

    assert isinstance(plugin.config, SecurityConfig)


def test_plugin_preserves_supplied_config_by_identity() -> None:
    config = SecurityConfig()

    assert SecurityPlugin(config).config is config


def test_config_freezes_authentication_collections() -> None:
    slots: list[Any] = []
    mechanisms: list[Any] = []

    config = SecurityConfig(slots=slots, mechanisms=mechanisms)

    assert config.slots == ()
    assert config.mechanisms == ()
    slots.append(object())
    mechanisms.append(object())
    assert config.slots == ()
    assert config.mechanisms == ()


def test_plugin_is_an_init_and_cli_plugin() -> None:
    plugin = SecurityPlugin()
    app = Litestar(plugins=[plugin])

    assert isinstance(plugin, InitPlugin)
    assert isinstance(plugin, CLIPlugin)
    assert isinstance(plugin, CLIPluginProtocol)
    assert any(registered is plugin for registered in app.plugins.cli)


def test_plugin_receives_routes_and_attaches_public_runtime_plan() -> None:
    @get("/", opt=security(public()))
    async def handler() -> None:
        return None

    plugin = SecurityPlugin()
    app = Litestar(route_handlers=[handler], openapi_config=None, plugins=[plugin])
    route = next(route for route in app.routes if isinstance(route, HTTPRoute))
    route_handler = route.route_handler_map["GET"][0]

    assert isinstance(plugin, ReceiveRoutePlugin)
    assert route_handler.opt["litestar_security_plan"] == SecurityRuntimePlan(authenticate=False)


def test_route_policy_uses_native_nearest_owner_inheritance() -> None:
    @get("/application")
    async def application_handler() -> None:
        return None

    @get("/owned")
    async def router_handler() -> None:
        return None

    class PolicyController(Controller):
        path = "/controller"
        opt: ClassVar = security(required("b"))

        @get("/owned")
        async def owned(self) -> None:
            return None

        @get("/handler", opt=security(required("a")))
        async def handler_override(self) -> None:
            return None

    app = Litestar(
        route_handlers=[
            application_handler,
            Router(path="/router", route_handlers=[router_handler], opt=security(required("b"))),
            PolicyController,
        ],
        opt=security(required("a")),
        openapi_config=None,
        plugins=[SecurityPlugin(_compiler_config())],
    )

    assert _http_plan(app, "/application").participant_names == frozenset({"a"})
    assert _http_plan(app, "/router/owned").participant_names == frozenset({"b"})
    assert _http_plan(app, "/controller/owned").participant_names == frozenset({"b"})
    assert _http_plan(app, "/controller/handler").participant_names == frozenset({"a"})


def test_http_methods_and_options_receive_distinct_compiled_plans() -> None:
    @get("/resource", opt=security(public()))
    async def read_resource() -> None:
        return None

    @post("/resource", opt=security(required("b"), csrf_required=True))
    async def write_resource() -> None:
        return None

    app = Litestar(
        route_handlers=[read_resource, write_resource],
        openapi_config=None,
        plugins=[SecurityPlugin(_compiler_config())],
    )

    assert not _http_plan(app, "/resource", "GET").authenticate
    assert _http_plan(app, "/resource", "POST").participant_names == frozenset({"b"})
    assert _http_plan(app, "/resource", "POST").csrf_required is True
    assert not _http_plan(app, "/resource", "OPTIONS").authenticate
    assert _http_plan(app, "/resource", "OPTIONS").csrf_required is None


def test_websocket_compiles_runtime_only_and_explicit_asgi_policy_fails() -> None:
    @websocket("/socket", opt=security(required("b")))
    async def socket_handler(socket: WebSocket) -> None:
        del socket

    app = Litestar(route_handlers=[socket_handler], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])
    socket_route = next(route_value for route_value in app.routes if isinstance(route_value, WebSocketRoute))

    assert socket_route.route_handler.opt["litestar_security_plan"].participant_names == frozenset({"b"})
    assert not hasattr(socket_route.route_handler, "security")

    @asgi("/mount", opt=security(public()), copy_scope=True)
    async def mounted_app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive, send

    with pytest.raises(ImproperlyConfiguredException, match=r"Raw ASGI.*asgi /mount"):
        Litestar(route_handlers=[mounted_app], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])


def test_asgi_default_dynamic_registration_and_receive_route_are_idempotent() -> None:
    @asgi("/mount", copy_scope=True)
    async def mounted_app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive, send

    plugin = SecurityPlugin(_compiler_config())
    app = Litestar(route_handlers=[mounted_app], openapi_config=None, plugins=[plugin])
    mount_route = next(route_value for route_value in app.routes if isinstance(route_value, ASGIRoute))
    mount_plan = mount_route.route_handler.opt["litestar_security_plan"]

    @get("/dynamic", opt=security(required("b")))
    async def dynamic_handler() -> None:
        return None

    app.register(dynamic_handler)
    dynamic_plan = _http_plan(app, "/dynamic")
    dynamic_route = next(
        route_value
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path == "/dynamic"
    )
    plugin.receive_route(dynamic_route)

    assert mount_plan.participant_names == frozenset({"a", "b"})
    assert dynamic_plan.participant_names == frozenset({"b"})
    assert _http_plan(app, "/dynamic") is dynamic_plan


def test_generated_and_explicit_options_are_distinguished() -> None:
    @post("/generated", opt=security(public(), csrf_required=True))
    async def generated() -> None:
        return None

    @route("/explicit", http_method=HttpMethod.OPTIONS, opt=security(required("b")))
    async def explicit() -> None:
        return None

    app = Litestar(
        route_handlers=[generated, explicit], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())]
    )

    assert not _http_plan(app, "/generated", "OPTIONS").authenticate
    assert _http_plan(app, "/generated", "OPTIONS").csrf_required is None
    assert _http_plan(app, "/explicit", "OPTIONS").participant_names == frozenset({"b"})


@pytest.mark.parametrize(
    ("openapi_config", "plugin_policy", "expected_path", "expected_participants"),
    [
        (OpenAPIConfig(title="Test", version="1.0"), None, "/schema/openapi.json", None),
        (
            OpenAPIConfig(title="Test", version="1.0", path="/docs"),
            required("b"),
            "/docs/openapi.json",
            frozenset({"b"}),
        ),
        (
            OpenAPIConfig(
                title="Test",
                version="1.0",
                openapi_router=Router(path="/reference", route_handlers=[], opt=security(required("a"))),
                render_plugins=[JsonRenderPlugin()],
            ),
            required("b"),
            "/reference/openapi.json",
            frozenset({"a"}),
        ),
    ],
)
def test_openapi_routes_use_default_configured_and_custom_router_policy(
    openapi_config: OpenAPIConfig,
    plugin_policy: AuthenticationPolicy | None,
    expected_path: str,
    expected_participants: frozenset[str] | None,
) -> None:
    @get("/application")
    async def application_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[application_handler],
        opt=security(required("a")),
        openapi_config=openapi_config,
        plugins=[SecurityPlugin(_compiler_config(openapi_policy=plugin_policy))],
    )
    plan = _http_plan(app, expected_path)

    assert plan.participant_names == expected_participants
    assert plan.authenticate is (expected_participants is not None)


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        (public(), [{}]),
        (required("a"), [{"a": []}]),
        (any_of("a", "b"), [{"a": []}, {"b": []}]),
        (all_of("a", "b"), [{"a": [], "b": []}]),
        (optional(required("a")), [{}, {"a": []}]),
        (at_least(2, "a", "b", "c"), [{"a": [], "b": []}, {"a": [], "c": []}, {"b": [], "c": []}]),
        (required(mechanism("oidc", "reports:read")), [{"oidc": ["reports:read"]}]),
    ],
)
def test_native_openapi_projection_matches_runtime_policy(
    policy: AuthenticationPolicy, expected: list[dict[str, list[str]]]
) -> None:
    @get("/resource", opt=security(policy))
    async def handler() -> None:
        return None

    config = _compiler_config(names=("a", "b", "c", "oidc"), scheme_types={"oidc": "openIdConnect"})
    app = Litestar(
        route_handlers=[handler],
        openapi_config=OpenAPIConfig(title="Test", version="1.0", render_plugins=[JsonRenderPlugin()]),
        plugins=[SecurityPlugin(config)],
    )
    route_handler = next(
        route_value.route_handler_map["GET"][0]
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path == "/resource"
    )

    assert route_handler.resolve_security() == expected
    assert _operation_security(app, "/resource") == expected
    assert [
        tuple((requirement.name, requirement.scopes) for requirement in alternative)
        for alternative in _http_plan(app, "/resource").alternatives
    ] == [
        tuple((name, tuple(scopes)) for name, scopes in alternative.items()) for alternative in expected if alternative
    ]


def test_openapi_scope_and_combination_limits_fail_with_route_context() -> None:
    @get("/scoped", opt=security(required(mechanism("a", "read"))))
    async def scoped_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"a.*scopes.*GET /scoped"):
        Litestar(
            route_handlers=[scoped_handler],
            openapi_config=OpenAPIConfig(title="Test", version="1.0"),
            plugins=[SecurityPlugin(_compiler_config(names=("a",)))],
        )

    names = tuple(f"m{index}" for index in range(9))

    @get("/threshold", opt=security(at_least(2, *names)))
    async def threshold_handler() -> None:
        return None

    with pytest.raises(
        ImproperlyConfiguredException, match=r"at_least\(2\).*9 participants.*36.*cap 32.*GET /threshold"
    ):
        Litestar(
            route_handlers=[threshold_handler],
            openapi_config=OpenAPIConfig(title="Test", version="1.0"),
            plugins=[SecurityPlugin(_compiler_config(names=names))],
        )

    @get("/threshold", opt=security(at_least(2, *names)))
    async def threshold_success() -> None:
        return None

    app = Litestar(
        route_handlers=[threshold_success],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(_compiler_config(names=names, max_openapi_combinations=36))],
    )

    assert len(cast("list[object]", _operation_security(app, "/threshold"))) == 36


def test_openapi_component_contribution_preserves_callers_and_validates_duplicates() -> None:
    scheme = SecurityScheme(type="http", scheme="bearer")
    caller_components = Components(
        responses={"Existing": OpenAPIResponse(description="Existing response")},
        security_schemes={"foreign": SecurityScheme(type="mutualTLS"), "shared": scheme},
    )
    original_value = deepcopy(caller_components)
    openapi_config = OpenAPIConfig(
        title="Test", version="1.0", components=caller_components, render_plugins=[JsonRenderPlugin()]
    )
    app = Litestar(
        route_handlers=[],
        openapi_config=openapi_config,
        plugins=[SecurityPlugin(_compiler_config(scheme_names={"a": "shared", "b": "shared"}))],
    )

    assert openapi_config.components is caller_components
    assert caller_components == original_value
    assert app.openapi_schema.components is not None
    assert app.openapi_schema.components.responses == {"Existing": OpenAPIResponse(description="Existing response")}
    assert app.openapi_schema.components.security_schemes == {
        "foreign": SecurityScheme(type="mutualTLS"),
        "shared": scheme,
    }

    with pytest.raises(ImproperlyConfiguredException, match=r"Conflicting.*shared"):
        Litestar(
            route_handlers=[],
            openapi_config=OpenAPIConfig(
                title="Test",
                version="1.0",
                components=Components(
                    security_schemes={
                        "shared": SecurityScheme(type="apiKey", name="X-Key", security_scheme_in="header")
                    }
                ),
            ),
            plugins=[SecurityPlugin(_compiler_config(names=("a",), scheme_names={"a": "shared"}))],
        )

    with pytest.raises(ImproperlyConfiguredException, match=r"Conflicting.*shared"):
        Litestar(
            route_handlers=[],
            openapi_config=OpenAPIConfig(title="Test", version="1.0"),
            plugins=[
                SecurityPlugin(
                    _compiler_config(scheme_names={"a": "shared", "b": "shared"}, scheme_types={"b": "openIdConnect"})
                )
            ],
        )


def test_openapi_rejects_conflicting_shared_scheme_scopes_and_dynamic_native_security() -> None:
    @get("/scopes", opt=security(all_of(mechanism("a", "one"), mechanism("b", "two"))))
    async def scoped_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"conflicting scopes.*GET /scopes"):
        Litestar(
            route_handlers=[scoped_handler],
            openapi_config=OpenAPIConfig(title="Test", version="1.0"),
            plugins=[
                SecurityPlugin(
                    _compiler_config(
                        scheme_names={"a": "shared", "b": "shared"},
                        scheme_types={"a": "openIdConnect", "b": "openIdConnect"},
                    )
                )
            ],
        )

    plugin = SecurityPlugin()
    app = Litestar(route_handlers=[], openapi_config=OpenAPIConfig(title="Test", version="1.0"), plugins=[plugin])

    @get("/dynamic-native", security=[{"native": []}])
    async def dynamic_native() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"Competing.*GET /dynamic-native"):
        app.register(dynamic_native)


@pytest.mark.parametrize("owner", ["application", "openapi", "router", "controller", "handler"])
def test_competing_native_security_declarations_fail(owner: str) -> None:
    native_security = [{"native": []}]

    @get("/", security=native_security if owner == "handler" else None)
    async def handler() -> None:
        return None

    route_handlers: list[Any]
    if owner == "router":
        route_handlers = [Router(path="/router", route_handlers=[handler], security=native_security)]
    elif owner == "controller":

        class NativeController(Controller):
            path = "/controller"
            security: ClassVar = native_security

            @get("/")
            async def owned(self) -> None:
                return None

        route_handlers = [NativeController]
    else:
        route_handlers = [handler]

    openapi_config = OpenAPIConfig(
        title="Test", version="1.0", security=native_security if owner == "openapi" else None
    )
    kwargs = {"security": native_security} if owner == "application" else {}

    with pytest.raises(ImproperlyConfiguredException, match="competing"):
        Litestar(route_handlers=route_handlers, openapi_config=openapi_config, plugins=[SecurityPlugin()], **kwargs)


def test_memoized_native_security_is_replaced_and_openapi_disabled_needs_no_scheme() -> None:
    class MemoizeSecurity(ReceiveRoutePlugin):
        def receive_route(self, route_value: BaseRoute) -> None:
            if isinstance(route_value, HTTPRoute):
                for route_handler in route_value.route_handlers:
                    route_handler.resolve_security()

    @get("/memoized", opt=security(required("a")))
    async def memoized_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[memoized_handler],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[MemoizeSecurity(), SecurityPlugin(_compiler_config(names=("a",)))],
    )

    assert _operation_security(app, "/memoized") == [{"a": []}]

    slot = _CompilerSlot("slot-a")
    mechanism_without_schema = AuthenticationMechanism(
        authenticator=_CompilerAuthenticator("a", "slot-a"),  # type: ignore[arg-type]
        resolver=_CompilerResolver(),
    )
    runtime_config = SecurityConfig(
        slots=(slot,),  # type: ignore[arg-type]
        mechanisms=(mechanism_without_schema,),
    )

    with pytest.raises(ImproperlyConfiguredException, match="a has no native OpenAPI security scheme"):
        Litestar(route_handlers=[], plugins=[SecurityPlugin(runtime_config)])

    @get("/memoized", opt=security(required("a")))
    async def runtime_handler() -> None:
        return None

    runtime_only = Litestar(
        route_handlers=[runtime_handler], openapi_config=None, plugins=[SecurityPlugin(runtime_config)]
    )

    assert _http_plan(runtime_only, "/memoized").participant_names == frozenset({"a"})


def test_route_compiler_errors_include_method_and_path() -> None:
    @get("/missing", opt=security(required("missing")))
    async def handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"GET /missing"):
        Litestar(route_handlers=[handler], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])


def test_route_compiler_rejects_invalid_metadata_and_conflicting_private_plan() -> None:
    @get("/invalid", opt={"litestar_security_policy": object()})
    async def invalid_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"Invalid.*GET /invalid"):
        Litestar(route_handlers=[invalid_handler], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])

    @get("/conflict", opt=security(public()))
    async def conflict_handler() -> None:
        return None

    plugin = SecurityPlugin(_compiler_config())
    app = Litestar(route_handlers=[conflict_handler], openapi_config=None, plugins=[plugin])
    conflict_route = next(route_value for route_value in app.routes if isinstance(route_value, HTTPRoute))
    conflict_route.route_handler_map["GET"][0].opt["litestar_security_plan"] = SecurityRuntimePlan(
        authenticate=True, required=True
    )

    with pytest.raises(ImproperlyConfiguredException, match=r"Conflicting.*GET /conflict"):
        plugin.receive_route(conflict_route)


def test_openapi_controller_and_invalid_custom_router_metadata_use_native_ownership() -> None:
    class TestOpenAPIController(OpenAPIController):
        path = "/legacy-docs"

    with pytest.warns(DeprecationWarning, match="openapi_controller"):
        openapi_config = OpenAPIConfig(
            title="Test", version="1.0", openapi_controller=TestOpenAPIController, render_plugins=[]
        )
    app = Litestar(route_handlers=[], openapi_config=openapi_config, plugins=[SecurityPlugin(_compiler_config())])

    assert not _http_plan(app, "/legacy-docs/openapi.json").authenticate

    invalid_router = Router(path="/reference", route_handlers=[], opt={"litestar_security_policy": object()})
    invalid_config = OpenAPIConfig(
        title="Test", version="1.0", openapi_router=invalid_router, render_plugins=[JsonRenderPlugin()]
    )

    with pytest.raises(ImproperlyConfiguredException, match=r"Invalid.*GET /reference"):
        Litestar(route_handlers=[], openapi_config=invalid_config, plugins=[SecurityPlugin(_compiler_config())])


def test_receive_route_before_application_initialization_fails() -> None:
    @get("/")
    async def handler() -> None:
        return None

    route_value = HTTPRoute(path="/", route_handlers=[handler])

    with pytest.raises(ImproperlyConfiguredException, match="before application initialization"):
        SecurityPlugin().receive_route(route_value)


def test_plugin_traverses_constructed_controller_ownership_without_collisions() -> None:
    class TestController(Controller):
        path = "/"

        @get("/")
        async def route(self) -> None:
            return None

    router = Router(path="/api", route_handlers=[TestController])

    app_config = SecurityPlugin().on_app_init(AppConfig(route_handlers=[router]))

    assert set(app_config.dependencies) == {"current_user", "principal", "security_context"}


def test_plugin_traverses_direct_controller_and_leaves_unknown_handlers_to_litestar() -> None:
    class TestController(Controller):
        path = "/"

        @get("/")
        async def route(self) -> None:
            return None

    app_config = SecurityPlugin().on_app_init(AppConfig(route_handlers=[TestController, cast("Any", object())]))

    assert set(app_config.dependencies) == {"current_user", "principal", "security_context"}


def test_plugin_registers_runtime_contract_idempotently() -> None:
    plugin = SecurityPlugin()
    app_config = AppConfig()

    assert plugin.on_app_init(app_config) is app_config
    providers = dict(app_config.dependencies)
    middleware = list(app_config.middleware)
    namespace = dict(app_config.signature_namespace)

    assert set(providers) == {"current_user", "principal", "security_context"}
    assert len(middleware) == 1
    assert isinstance(middleware[0], DefineMiddleware)
    assert middleware[0].middleware is SecurityMiddlewareWrapper
    assert namespace == {
        "CurrentUser": CurrentUser,
        "Principal": Principal,
        "PrincipalDependency": PrincipalDependency,
        "SecurityContext": SecurityContext,
        "SecurityContextDependency": SecurityContextDependency,
    }

    assert plugin.on_app_init(app_config) is app_config
    assert app_config.dependencies == providers
    assert app_config.middleware == middleware
    assert app_config.signature_namespace == namespace


@pytest.mark.parametrize("reserved_name", ["principal", "security_context", "current_user"])
@pytest.mark.parametrize("owner", ["application", "router", "controller", "handler"])
def test_plugin_rejects_reserved_dependency_collisions(reserved_name: str, owner: str) -> None:
    provider = Provide(object, sync_to_thread=False, use_cache=False)

    @get("/")
    async def handler() -> None:
        return None

    if owner == "application":
        app_config = AppConfig(dependencies={reserved_name: provider}, route_handlers=[handler])
    elif owner == "router":
        app_config = AppConfig(
            route_handlers=[Router(path="/", route_handlers=[handler], dependencies={reserved_name: provider})]
        )
    elif owner == "controller":

        class TestController(Controller):
            path = "/"
            dependencies: ClassVar = {reserved_name: provider}

            @get("/")
            async def route(self) -> None:
                return None

        app_config = AppConfig(route_handlers=[TestController])
    else:

        @get("/", dependencies={reserved_name: provider})
        async def owned_handler() -> None:
            return None

        app_config = AppConfig(route_handlers=[owned_handler])

    with pytest.raises(ImproperlyConfiguredException, match=rf"{reserved_name}.*{owner}"):
        SecurityPlugin().on_app_init(app_config)

    if owner == "application":
        assert app_config.dependencies[reserved_name] is provider


def test_exact_plugin_owned_provider_is_accepted_at_lower_layer() -> None:
    plugin = SecurityPlugin()
    first_config = plugin.on_app_init(AppConfig())

    @get("/", dependencies={"principal": first_config.dependencies["principal"]})
    async def handler() -> None:
        return None

    app_config = AppConfig(
        dependencies=dict(first_config.dependencies),
        middleware=list(first_config.middleware),
        route_handlers=[handler],
        signature_namespace=dict(first_config.signature_namespace),
    )

    assert plugin.on_app_init(app_config) is app_config


def test_controller_handler_collision_is_reported_as_handler_owned() -> None:
    provider = Provide(object, sync_to_thread=False, use_cache=False)

    class TestController(Controller):
        path = "/"

        @get("/", dependencies={"principal": provider})
        async def route(self) -> None:
            return None

    with pytest.raises(ImproperlyConfiguredException, match=r"principal.*handler"):
        SecurityPlugin().on_app_init(AppConfig(route_handlers=[TestController]))


def test_existing_native_session_remains_outer_to_security() -> None:
    session = DefineMiddleware(SessionMiddleware, backend=object())
    app_config = AppConfig(middleware=[session])

    SecurityPlugin().on_app_init(app_config)

    assert app_config.middleware[0] is session
    assert isinstance(app_config.middleware[1], DefineMiddleware)
    assert app_config.middleware[1].middleware is SecurityMiddlewareWrapper


def test_config_owned_session_is_compiled_inside_security_wrapper() -> None:
    backend = cast("BaseSessionBackend[Any]", object())
    app_config = AppConfig()

    SecurityPlugin(SecurityConfig(session_backend=backend)).on_app_init(app_config)

    middleware = cast("DefineMiddleware", app_config.middleware[0])
    runtime_config = middleware.kwargs["config"]
    assert runtime_config.owned_session_backend is not None
    assert runtime_config.owned_session_backend.backend is backend


def test_duplicate_native_sessions_fail_startup() -> None:
    sessions = [
        DefineMiddleware(SessionMiddleware, backend=object()),
        DefineMiddleware(SessionMiddleware, backend=object()),
    ]

    with pytest.raises(ImproperlyConfiguredException, match="multiple native Litestar session"):
        SecurityPlugin().on_app_init(AppConfig(middleware=sessions))


def test_plugin_owned_and_application_session_conflict_fails_startup() -> None:
    session = DefineMiddleware(SessionMiddleware, backend=object())
    config = SecurityConfig(session_backend=cast("BaseSessionBackend[Any]", object()))

    with pytest.raises(ImproperlyConfiguredException, match="both configure native Litestar session"):
        SecurityPlugin(config).on_app_init(AppConfig(middleware=[session]))


def test_foreign_security_wrapper_fails_startup() -> None:
    middleware = DefineMiddleware(SecurityMiddlewareWrapper, config=object())

    with pytest.raises(ImproperlyConfiguredException, match="not owned by this plugin"):
        SecurityPlugin().on_app_init(AppConfig(middleware=[middleware]))


def test_required_default_without_participants_fails_startup() -> None:
    with pytest.raises(
        ImproperlyConfiguredException, match=r"required default authentication plan.*participating mechanism"
    ):
        SecurityPlugin(SecurityConfig(require_default=True)).on_app_init(AppConfig())


def test_importing_plugin_does_not_import_private_cli() -> None:
    existing_module = sys.modules.pop("litestar_security._cli", None)
    try:
        SecurityPlugin()

        assert "litestar_security._cli" not in sys.modules
    finally:
        if existing_module is not None:
            sys.modules["litestar_security._cli"] = existing_module


def _root_group() -> click.Group:
    return click.Group(name="litestar")


def test_cli_entry_point_and_lazy_plugin_registration() -> None:
    entry_point = next(
        candidate for candidate in entry_points(group="litestar.commands") if candidate.name == "security"
    )
    cli = _root_group()

    SecurityPlugin().on_cli_init(cli)

    assert entry_point.load() is security_group
    assert cli.commands["security"] is security_group


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (["security", "--help"], "Litestar Security operations."),
        (["security", "--version"], "litestar-security, version 0.1.0"),
    ],
)
def test_cli_output(arguments: list[str], expected: str) -> None:
    cli = _root_group()
    register(cli)

    result = CliRunner().invoke(cli, arguments)

    assert result.exit_code == 0
    assert expected in result.output


def test_cli_registration_is_idempotent() -> None:
    cli = _root_group()

    register(cli)
    register(cli)
    SecurityPlugin().on_cli_init(cli)

    assert list(cli.commands) == ["security"]
