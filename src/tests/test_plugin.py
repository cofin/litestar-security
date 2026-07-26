import sys
from typing import TYPE_CHECKING, Any, ClassVar, cast

import pytest
from litestar import Controller, Litestar, Router, get
from litestar.config.app import AppConfig
from litestar.di import Provide
from litestar.exceptions import ImproperlyConfiguredException
from litestar.middleware import DefineMiddleware
from litestar.middleware.session.base import SessionMiddleware
from litestar.plugins import CLIPlugin, CLIPluginProtocol, InitPlugin

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security.authentication import SecurityMiddlewareWrapper
from litestar_security.context import Principal, SecurityContext
from litestar_security.plugin import CurrentUser, PrincipalDependency, SecurityContextDependency

if TYPE_CHECKING:
    from litestar.middleware.session.base import BaseSessionBackend


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
