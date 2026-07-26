"""Litestar Security plugin integration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Generic, TypeAlias, TypeVar, cast

from litestar.controller import Controller
from litestar.di import NamedDependency, Provide
from litestar.exceptions import ImproperlyConfiguredException
from litestar.handlers.base import BaseRouteHandler
from litestar.middleware import DefineMiddleware
from litestar.middleware.session.base import SessionMiddleware
from litestar.plugins import CLIPlugin, InitPlugin
from litestar.router import Router
from litestar.types import Scope  # noqa: TC002 - Litestar resolves provider annotations at startup.

from litestar_security.authentication import (
    AuthenticationRegistry,
    OwnedSessionBackend,
    SecurityMiddlewareWrapper,
    SecurityRuntimeConfig,
)
from litestar_security.config import SecurityConfig
from litestar_security.context import Principal, SecurityContext

if TYPE_CHECKING:
    from collections.abc import Iterator

    from click import Group as ClickGroup
    from litestar.config.app import AppConfig

__all__ = ("CurrentUser", "PrincipalDependency", "SecurityContextDependency", "SecurityPlugin")

UserT = TypeVar("UserT")

PrincipalDependency: TypeAlias = NamedDependency[Principal[UserT]]
SecurityContextDependency: TypeAlias = NamedDependency[SecurityContext]
CurrentUser: TypeAlias = NamedDependency[UserT]

_RESERVED_DEPENDENCIES = ("principal", "security_context", "current_user")
_SIGNATURE_NAMESPACE: Mapping[str, object] = {
    "CurrentUser": CurrentUser,
    "Principal": Principal,
    "PrincipalDependency": PrincipalDependency,
    "SecurityContext": SecurityContext,
    "SecurityContextDependency": SecurityContextDependency,
}


def _provide_principal(scope: Scope) -> Principal[Any]:
    return cast("Principal[Any]", scope["user"])


def _provide_security_context(scope: Scope) -> SecurityContext:
    return cast("SecurityContext", scope["auth"])


def _provide_current_user(scope: Scope) -> object:
    return cast("Principal[object]", scope["user"]).require_user()


def _owner_name(layer: object) -> str:
    if isinstance(layer, Router):
        return "router"
    if isinstance(layer, Controller) or (isinstance(layer, type) and issubclass(layer, Controller)):
        return "controller"
    return "handler"


def _iter_route_handler_layers(route_handler: object) -> Iterator[object]:
    if isinstance(route_handler, Router):
        for route in route_handler.routes:
            candidates = (
                *cast("tuple[BaseRouteHandler, ...]", getattr(route, "route_handlers", ())),
                getattr(route, "route_handler", None),
            )
            for handler in candidates:
                if isinstance(handler, BaseRouteHandler):
                    yield from handler.ownership_layers
    elif isinstance(route_handler, type) and issubclass(route_handler, Controller):
        yield route_handler
        for name in dir(route_handler):
            value = getattr(route_handler, name)
            if isinstance(value, BaseRouteHandler):
                yield value
    elif isinstance(route_handler, BaseRouteHandler):
        yield route_handler


def _layer_dependencies(layer: object) -> Mapping[str, object] | None:
    dependencies = getattr(layer, "dependencies", None)
    return cast("Mapping[str, object]", dependencies) if isinstance(dependencies, Mapping) else None


class SecurityPlugin(InitPlugin, CLIPlugin, Generic[UserT]):
    """Expose the Litestar Security configuration and CLI integration points."""

    __slots__ = ("_middleware", "_providers", "_runtime_config", "config")

    def __init__(self, config: SecurityConfig[UserT] | None = None) -> None:
        """Initialize the plugin."""
        self.config = config if config is not None else SecurityConfig[UserT]()
        self._providers = {
            "principal": Provide(_provide_principal, sync_to_thread=False, use_cache=False),
            "security_context": Provide(_provide_security_context, sync_to_thread=False, use_cache=False),
            "current_user": Provide(_provide_current_user, sync_to_thread=False, use_cache=False),
        }
        self._runtime_config: SecurityRuntimeConfig[UserT] | None = None
        self._middleware: DefineMiddleware | None = None

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """Validate ownership and install one typed security runtime."""
        self._validate_dependency_map(app_config.dependencies, "application")
        for dependencies, owner in self._iter_owned_dependency_maps(app_config):
            self._validate_dependency_map(dependencies, owner)

        native_sessions = [
            (index, middleware)
            for index, middleware in enumerate(app_config.middleware)
            if self._is_native_session_middleware(middleware)
        ]
        if len(native_sessions) > 1:
            message = "Application config contains multiple native Litestar session middleware definitions"
            raise ImproperlyConfiguredException(detail=message)
        if native_sessions and self.config.session_backend is not None:
            message = "Security config and application middleware both configure native Litestar session handling"
            raise ImproperlyConfiguredException(detail=message)

        _, middleware = self._get_runtime(existing_session=bool(native_sessions))
        app_config.dependencies.update(self._providers)
        for name, value in _SIGNATURE_NAMESPACE.items():
            app_config.signature_namespace.setdefault(name, value)

        plugin_middleware = [
            item
            for item in app_config.middleware
            if isinstance(item, DefineMiddleware) and item.middleware is SecurityMiddlewareWrapper
        ]
        if any(item is not middleware for item in plugin_middleware):
            message = "Application config already contains a security middleware not owned by this plugin"
            raise ImproperlyConfiguredException(detail=message)
        if middleware in app_config.middleware:
            app_config.middleware.remove(middleware)
        insertion_index = native_sessions[0][0] + 1 if native_sessions else len(app_config.middleware)
        app_config.middleware.insert(insertion_index, middleware)
        return app_config

    def on_cli_init(self, cli: ClickGroup) -> None:
        """Attach the security command group to the Litestar CLI."""
        from litestar_security._cli import register  # noqa: PLC0415

        register(cli)

    def _get_runtime(self, *, existing_session: bool) -> tuple[SecurityRuntimeConfig[UserT], DefineMiddleware]:
        if self._runtime_config is None:
            registry = AuthenticationRegistry(
                slots=self.config.slots, mechanisms=self.config.mechanisms, require_default=self.config.require_default
            )
            owned_session = None
            if self.config.session_backend is not None and not existing_session:
                backend = self.config.session_backend
                owned_session = OwnedSessionBackend(
                    middleware=DefineMiddleware(SessionMiddleware, backend=backend), backend=backend
                )
            self._runtime_config = SecurityRuntimeConfig(
                registry=registry, owned_session_backend=owned_session, plan_lookup=self.config.plan_lookup
            )
            self._middleware = DefineMiddleware(SecurityMiddlewareWrapper, config=self._runtime_config)
        return self._runtime_config, cast("DefineMiddleware", self._middleware)

    def _validate_dependency_map(self, dependencies: Mapping[str, object] | None, owner: str) -> None:
        for name in _RESERVED_DEPENDENCIES:
            if dependencies and name in dependencies and dependencies[name] is not self._providers[name]:
                message = f"Reserved security dependency {name!r} collides at the {owner} ownership level"
                raise ImproperlyConfiguredException(detail=message)

    @staticmethod
    def _is_native_session_middleware(middleware: object) -> bool:
        candidate = middleware.middleware if isinstance(middleware, DefineMiddleware) else middleware
        return isinstance(candidate, type) and issubclass(candidate, SessionMiddleware)

    @staticmethod
    def _iter_owned_dependency_maps(app_config: AppConfig) -> Iterator[tuple[Mapping[str, object] | None, str]]:
        seen: set[int] = set()
        for route_handler in app_config.route_handlers:
            for layer in _iter_route_handler_layers(route_handler):
                if id(layer) in seen:
                    continue
                seen.add(id(layer))
                yield (_layer_dependencies(layer), _owner_name(layer))
