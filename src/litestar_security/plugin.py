"""Litestar Security plugin integration."""

import asyncio
import sys
from collections.abc import AsyncGenerator, Callable, Iterator, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Generic, TypeAlias, TypeVar, cast

from click import Group as ClickGroup
from litestar import Litestar
from litestar.config.app import AppConfig
from litestar.controller import Controller
from litestar.di import NamedDependency, Provide
from litestar.enums import ScopeType
from litestar.exceptions import ImproperlyConfiguredException
from litestar.handlers.base import BaseRouteHandler
from litestar.middleware import DefineMiddleware
from litestar.middleware.session.base import SessionMiddleware
from litestar.openapi.spec import SecurityScheme
from litestar.plugins import CLIPlugin, InitPlugin, ReceiveRoutePlugin
from litestar.router import Router
from litestar.routes import BaseRoute
from litestar.types import Scope

from litestar_security._openapi import OpenAPISchemeSet, RouteCompiler, merge_openapi_tags, prepare_openapi_config
from litestar_security.authentication import (
    AuthenticationMechanism,
    AuthenticationRegistry,
    CredentialSlot,
    SecurityMiddlewareWrapper,
    SecurityRuntimeConfig,
    VerificationUnavailable,
)
from litestar_security.config import SecurityConfig
from litestar_security.context import Principal, SecurityContext
from litestar_security.headers import CSPHook, configure_security_headers
from litestar_security.websocket import WebSocketConnectTokenIssuer

__all__ = ("CurrentUser", "SecurityPlugin")


UserT = TypeVar("UserT")


CurrentUser: TypeAlias = NamedDependency[UserT]


_RESERVED_DEPENDENCIES = ("principal", "security_context", "current_user", "websocket_connect_tokens")


_SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


_SIGNATURE_NAMESPACE: Mapping[str, object] = {
    "CurrentUser": CurrentUser,
    "Principal": Principal,
    "SecurityContext": SecurityContext,
}


class SecurityPlugin(InitPlugin, ReceiveRoutePlugin, CLIPlugin, Generic[UserT]):
    """Expose the Litestar Security configuration and CLI integration points."""

    __slots__ = (
        "_api_key_lifespan",
        "_api_key_service",
        "_headers_hooks",
        "_jwks_lifespan",
        "_local_auth_route_handlers",
        "_mfa_route_handlers",
        "_middleware",
        "_oauth_lifespan",
        "_oauth_route_handlers",
        "_providers",
        "_rate_limit_lifespan",
        "_route_compiler",
        "_runtime_config",
        "config",
    )

    def __init__(self, config: SecurityConfig[UserT] | None = None) -> None:
        """Initialize the plugin."""
        self.config = config if config is not None else SecurityConfig[UserT]()
        self._providers = {
            "principal": Provide(_provide_principal, sync_to_thread=False, use_cache=False),
            "security_context": Provide(_provide_security_context, sync_to_thread=False, use_cache=False),
            "current_user": Provide(_provide_current_user, sync_to_thread=False, use_cache=False),
            "websocket_connect_tokens": Provide(
                self._provide_websocket_connect_tokens, sync_to_thread=False, use_cache=False
            ),
        }
        self._route_compiler: RouteCompiler[UserT] | None = None
        self._runtime_config: SecurityRuntimeConfig[UserT] | None = None
        self._middleware: DefineMiddleware | None = None
        self._jwks_lifespan: Callable[[Litestar], AbstractAsyncContextManager[None]] | None = None
        self._headers_hooks: tuple[CSPHook, ...] = ()
        self._api_key_lifespan: Callable[[Litestar], AbstractAsyncContextManager[None]] | None = None
        self._api_key_service: object | None = None
        self._local_auth_route_handlers: tuple[Router, ...] | None = None
        self._mfa_route_handlers: tuple[Router, ...] | None = None
        self._oauth_route_handlers: tuple[Router, ...] | None = None
        self._oauth_lifespan: Callable[[Litestar], AbstractAsyncContextManager[None]] | None = None
        self._rate_limit_lifespan: Callable[[Litestar], AbstractAsyncContextManager[None]] | None = None

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """Validate ownership and install one typed security runtime.

        Args:
            app_config: The application configuration to extend.

        Returns:
            The same configuration, with the security middleware, dependencies,
            generated routes, and OpenAPI contributions installed.

        Raises:
            ImproperlyConfiguredException: If the application already owns
                something this plugin must own, such as a competing session
                middleware, CSRF config, or reserved dependency name.
        """
        self._configure_headers(app_config)
        self._configure_local_auth_rate_limits(app_config)
        self._configure_mfa_login()
        self._configure_local_auth_routes(app_config)
        self._configure_mfa_routes(app_config)
        self._configure_oauth_routes(app_config)
        self._configure_oauth_lifespan(app_config)
        self._configure_local_jwks(app_config)
        self._configure_jwks_lifespan(app_config)
        self._validate_dependency_map(app_config.dependencies, "application")
        self._validate_native_security(app_config)
        for dependencies, owner in self._iter_owned_dependency_maps(app_config):
            self._validate_dependency_map(dependencies, owner)

        native_sessions = cast(
            "list[tuple[int, DefineMiddleware]]",
            [
                (index, middleware)
                for index, middleware in enumerate(app_config.middleware)
                if self._is_native_session_middleware(middleware)
            ],
        )
        if len(native_sessions) > 1:
            message = "Application config contains multiple native Litestar session middleware definitions"
            raise ImproperlyConfiguredException(detail=message)
        self._configure_csrf(app_config)
        self._validate_local_session_backend(app_config, native_sessions)

        runtime, middleware = self._get_runtime()
        self._configure_api_key_lifespan(app_config)
        openapi_config = app_config.openapi_config
        if openapi_config is not None:
            schemes = OpenAPISchemeSet.from_registry(cast("AuthenticationRegistry[object]", runtime.registry))
            openapi_config = prepare_openapi_config(openapi_config, schemes)
            local_auth = self.config.local_auth
            if local_auth is not None:
                openapi_config = merge_openapi_tags(openapi_config, local_auth.openapi_tags())
            app_config.openapi_config = openapi_config
        if self._route_compiler is None:
            self._route_compiler = RouteCompiler(
                registry=runtime.registry,
                openapi_config=openapi_config,
                max_openapi_combinations=self.config.max_openapi_combinations,
                csrf_exclude_key=(
                    app_config.csrf_config.exclude_from_csrf_key if app_config.csrf_config is not None else None
                ),
                external_csrf=self.config.external_csrf,
                websocket_config=self.config.websocket,
            )
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

    def receive_route(self, route: BaseRoute) -> None:
        """Compile every initial or dynamically registered route.

        Args:
            route: The route Litestar just registered.

        Raises:
            ImproperlyConfiguredException: If called before application
                initialization, or if the route's declared policy cannot compile.
        """
        if self._route_compiler is None:
            message = "Security route compiler is unavailable before application initialization"
            raise ImproperlyConfiguredException(detail=message)
        self._route_compiler.receive_route(route)

    def on_cli_init(self, cli: ClickGroup) -> None:
        """Attach the security command group to the Litestar CLI.

        Args:
            cli: The root Litestar CLI group.
        """
        from litestar_security._cli import register  # noqa: PLC0415 - the CLI registrar loads only when the CLI runs

        register(cli)

    def _configure_headers(self, app_config: AppConfig) -> None:
        headers = self.config.headers
        if headers is not None:
            self._headers_hooks = configure_security_headers(app_config, headers, self._headers_hooks)

    def _get_runtime(self) -> tuple[SecurityRuntimeConfig[UserT], DefineMiddleware]:
        if self._runtime_config is None:
            slots = list(self.config.slots)
            mechanisms = list(self.config.mechanisms)
            provider_slots, provider_mechanisms = self._build_configured_providers()
            slots.extend(provider_slots)
            mechanisms.extend(provider_mechanisms)
            local_auth = self.config.local_auth
            if local_auth is not None and local_auth.bearer_slot is not None:
                from litestar_security.providers.jwt import (  # noqa: PLC0415 - deferred to break an import cycle
                    CompositeBearerConfig,
                    extend_composite_bearer,
                )

                bearer_resolver = local_auth.bearer_resolver
                if bearer_resolver is None:  # pragma: no cover - LocalAuthConfig invariant
                    message = "Local token authentication resolver is unavailable"
                    raise ImproperlyConfiguredException(detail=message)
                physical_slots = tuple(slot for slot in slots if slot.name == "authorization.bearer")
                bearer_mechanisms = tuple(
                    mechanism for mechanism in mechanisms if mechanism.authenticator.slot == "authorization.bearer"
                )
                if not physical_slots and not bearer_mechanisms:
                    bearer_slot, bearer_mechanism = CompositeBearerConfig(
                        mechanism_name="bearer", slots=(local_auth.bearer_slot,)
                    ).build(bearer_resolver, scheme_name="bearer")
                    slots.append(bearer_slot)
                    mechanisms.append(bearer_mechanism)
                elif len(physical_slots) == len(bearer_mechanisms) == 1:
                    existing = bearer_mechanisms[0]
                    if local_auth.register_routes and existing.authenticator.name != "bearer":
                        message = (
                            "Generated local token routes require the composite bearer mechanism to be named 'bearer'"
                        )
                        raise ImproperlyConfiguredException(detail=message)
                    try:
                        extended = extend_composite_bearer(existing, local_auth.bearer_slot, bearer_resolver)
                    except ImproperlyConfiguredException as exc:
                        message = "Local token authentication requires the application's sole composite bearer owner"
                        raise ImproperlyConfiguredException(detail=message) from exc
                    mechanisms[mechanisms.index(existing)] = extended
                else:
                    message = "Local token authentication requires exactly one composite bearer owner"
                    raise ImproperlyConfiguredException(detail=message)
            if local_auth is not None and local_auth.session_auth is not None:
                session_auth = local_auth.session_auth
                slots.append(session_auth)
                mechanisms.append(
                    AuthenticationMechanism(
                        authenticator=session_auth,
                        resolver=session_auth,
                        scheme_name="LocalSession",
                        security_scheme=SecurityScheme(
                            type="apiKey",
                            name=session_auth.binding.cookie_name,
                            security_scheme_in="cookie",
                            description="Litestar native session plus independent binding cookie.",
                        ),
                        session_capable=True,
                    )
                )
            registry = AuthenticationRegistry(
                slots=slots,
                mechanisms=mechanisms,
                authorization_resolver=self.config.authorization_resolver,
                require_default=self.config.require_default,
            )
            self._runtime_config = SecurityRuntimeConfig(registry=registry, websocket=self.config.websocket)
            self._middleware = DefineMiddleware(SecurityMiddlewareWrapper, config=self._runtime_config)
        return self._runtime_config, cast("DefineMiddleware", self._middleware)

    def _build_configured_providers(
        self,
    ) -> tuple[list[CredentialSlot[Any]], list[AuthenticationMechanism[Any, Any, UserT]]]:
        slots: list[CredentialSlot[Any]] = []
        mechanisms: list[AuthenticationMechanism[Any, Any, UserT]] = []
        if self.config.api_key is not None:
            api_key_slot, api_key_mechanism, api_key_service = cast(
                "tuple[CredentialSlot[Any], AuthenticationMechanism[Any, Any, UserT], object]",
                self.config.api_key.build(),
            )
            slots.append(api_key_slot)
            mechanisms.append(api_key_mechanism)
            self._api_key_service = api_key_service
        if self.config.iap is not None:
            iap_slot, iap_mechanism = self.config.iap.build()
            slots.append(iap_slot)
            mechanisms.append(iap_mechanism)
        if self.config.service_token is not None:
            service_slot, service_mechanism = self.config.service_token.build()
            slots.append(service_slot)
            mechanisms.append(cast("AuthenticationMechanism[Any, Any, UserT]", service_mechanism))
        return slots, mechanisms

    def _provide_websocket_connect_tokens(self, scope: Scope) -> WebSocketConnectTokenIssuer:
        """Provide the configured issuer for one-time WebSocket connect tokens."""
        websocket_config = self.config.websocket
        connect_token_store = websocket_config.connect_token_store
        if connect_token_store is None:
            message = (
                "WebSocket connect token minting requires SecurityConfig.websocket.connect_token_store to be configured"
            )
            raise ImproperlyConfiguredException(detail=message)
        return WebSocketConnectTokenIssuer(
            app=scope["litestar_app"],
            store=connect_token_store,
            clock=websocket_config.clock,
            ttl=websocket_config.connect_token_ttl,
        )

    def _configure_api_key_lifespan(self, app_config: AppConfig) -> None:
        api_key_service = self._api_key_service
        if api_key_service is None:
            return
        if self._api_key_lifespan is None:

            @asynccontextmanager
            async def api_key_lifespan(_app: Litestar) -> AsyncGenerator[None, None]:
                try:
                    yield
                finally:
                    await cast("Any", api_key_service).close()

            self._api_key_lifespan = api_key_lifespan
        lifespan_handlers = cast(
            "list[Callable[[Litestar], AbstractAsyncContextManager[None]]]",
            app_config.lifespan,  # pyright: ignore[reportUnknownMemberType] - third-party callable is untyped
        )
        if self._api_key_lifespan not in lifespan_handlers:
            lifespan_handlers.append(self._api_key_lifespan)

    def _validate_dependency_map(self, dependencies: Mapping[str, object] | None, owner: str) -> None:
        for name in _RESERVED_DEPENDENCIES:
            if dependencies and name in dependencies and dependencies[name] is not self._providers[name]:
                message = f"Reserved security dependency {name!r} collides at the {owner} ownership level"
                raise ImproperlyConfiguredException(detail=message)

    @staticmethod
    def _validate_native_security(app_config: AppConfig) -> None:
        if app_config.security:
            message = "Application config contains competing native Litestar security declarations"
            raise ImproperlyConfiguredException(detail=message)
        if app_config.openapi_config is not None and app_config.openapi_config.security:
            message = "OpenAPI config contains competing root native security declarations"
            raise ImproperlyConfiguredException(detail=message)
        for route_handler in app_config.route_handlers:
            for layer in _iter_route_handler_layers(route_handler):
                native_security = getattr(layer, "security", None)
                if isinstance(native_security, Sequence) and not isinstance(native_security, str) and native_security:
                    message = f"{_owner_name(layer).title()} contains competing native Litestar security declarations"
                    raise ImproperlyConfiguredException(detail=message)

    def _configure_csrf(self, app_config: AppConfig) -> None:
        existing = app_config.csrf_config
        if existing is not None:
            self._validate_csrf_config(existing)
        if existing is not None and self.config.external_csrf is not None:
            message = "Security configuration cannot combine native and external CSRF enforcement"
            raise ImproperlyConfiguredException(detail=message)

    @staticmethod
    def _validate_csrf_config(config: object) -> None:
        from litestar.config.csrf import CSRFConfig  # noqa: PLC0415 - read only when a policy asks

        if not isinstance(config, CSRFConfig):
            message = "Native CSRF configuration must be a Litestar CSRFConfig"
            raise ImproperlyConfiguredException(detail=message)
        if config.exclude is not None:
            message = (
                "Native CSRF path exclusions are forbidden; use compiled route policy (`auth=`) or csrf_required=True"
            )
            raise ImproperlyConfiguredException(detail=message)
        try:
            safe_methods = frozenset(config.safe_methods)
        except TypeError as exc:
            message = "Native CSRF safe methods must contain only safe HTTP methods"
            raise ImproperlyConfiguredException(detail=message) from exc
        unsafe_methods = safe_methods.difference(_SAFE_HTTP_METHODS)
        if unsafe_methods:
            message = "Native CSRF safe methods cannot include unsafe HTTP methods"
            raise ImproperlyConfiguredException(detail=message)
        if safe_methods != _SAFE_HTTP_METHODS:
            message = "Native CSRF safe methods must include GET, HEAD, and OPTIONS"
            raise ImproperlyConfiguredException(detail=message)
        if config.exclude_from_csrf_key.__class__ is not str or not config.exclude_from_csrf_key.strip():
            message = "Native CSRF route exclusion opt key must be non-empty text"
            raise ImproperlyConfiguredException(detail=message)

    def _configure_local_auth_rate_limits(self, app_config: AppConfig) -> None:
        local_auth = self.config.local_auth
        if local_auth is None:
            return
        _validate_local_auth(local_auth)
        if self._rate_limit_lifespan is None:
            # The bundled limiter names a store rather than holding one, so the
            # application can point that name at a shared backend. The registry only
            # exists once the app is built, which is why this binds at startup.
            @asynccontextmanager
            async def rate_limit_lifespan(app: Litestar) -> AsyncGenerator[None, None]:
                local_auth.bind_rate_limit_store(app.stores)
                yield

            self._rate_limit_lifespan = rate_limit_lifespan
        lifespan_handlers = cast(
            "list[object]",
            app_config.lifespan,  # pyright: ignore[reportUnknownMemberType] - third-party callable is untyped at this boundary
        )
        if self._rate_limit_lifespan not in lifespan_handlers:
            lifespan_handlers.append(self._rate_limit_lifespan)

    def _configure_local_auth_routes(self, app_config: AppConfig) -> None:
        local_auth = self.config.local_auth
        if local_auth is None or not local_auth.register_routes:
            return
        route_handlers = self._local_auth_route_handlers
        if route_handlers is None:
            route_handlers = local_auth.build_route_handlers()
            self._local_auth_route_handlers = route_handlers
        for route_handler in route_handlers:
            if not any(existing is route_handler for existing in app_config.route_handlers):
                app_config.route_handlers.append(route_handler)

    def _configure_mfa_login(self) -> None:
        """Bind MFA-login challenges independently of generated MFA management routes."""
        mfa = self.config.mfa
        if mfa is None or not mfa.require_at_login:
            return
        local_auth = self.config.local_auth
        if local_auth is None:
            message = "MFA login requires local authentication"
            raise ImproperlyConfiguredException(detail=message)
        _validate_local_auth(local_auth)
        local_auth.bind_mfa_login(mfa)

    def _configure_mfa_routes(self, app_config: AppConfig) -> None:
        mfa_config = self.config.mfa
        passkey_config = self.config.passkeys
        enabled_mfa = mfa_config if mfa_config is not None and mfa_config.register_routes else None
        enabled_passkeys = passkey_config if passkey_config is not None and passkey_config.register_routes else None
        if enabled_mfa is None and enabled_passkeys is None:
            return
        local_auth = self.config.local_auth
        if local_auth is None:
            message = "Generated MFA and passkey routes require local authentication for epoch validation"
            raise ImproperlyConfiguredException(detail=message)
        prefixes = {config.route_prefix for config in (enabled_mfa, enabled_passkeys) if config is not None}
        if len(prefixes) != 1:
            message = "Generated MFA and passkey routes must share one route prefix"
            raise ImproperlyConfiguredException(detail=message)
        step_up = (
            enabled_mfa.step_up_service
            if enabled_mfa is not None and enabled_mfa.step_up_service is not None
            else enabled_passkeys.step_up_service
            if enabled_passkeys is not None
            else None
        )
        if step_up is None:
            message = "Generated MFA and passkey routes require an atomic StepUpStore"
            raise ImproperlyConfiguredException(detail=message)
        route_handlers = self._mfa_route_handlers
        if route_handlers is None:
            from litestar_security.accounts import (  # noqa: PLC0415 - route imports remain feature-local
                MFAService,
                PasskeyService,
                StepUpService,
                build_mfa_routes,
            )

            if not isinstance(step_up, StepUpService):
                message = "Generated MFA and passkey routes require a StepUpService"
                raise ImproperlyConfiguredException(detail=message)
            router = build_mfa_routes(
                step_up=step_up,
                epochs=local_auth.accounts,
                mfa=(
                    enabled_mfa.mfa_service
                    if enabled_mfa is not None and isinstance(enabled_mfa.mfa_service, MFAService)
                    else None
                ),
                passkeys=(
                    enabled_passkeys.passkey_service
                    if enabled_passkeys is not None and isinstance(enabled_passkeys.passkey_service, PasskeyService)
                    else None
                ),
                rate_limits=local_auth.rate_limits,
                client_key=local_auth.local_auth_service.client_key_for,
                local_auth=local_auth.local_auth_service,
                session_capable=local_auth.session_auth is not None,
                token_capable=local_auth.local_auth_service.refresh_tokens is not None,
                route_prefix=prefixes.pop(),
            )
            route_handlers = (router,)
            self._mfa_route_handlers = route_handlers
        for route_handler in route_handlers:
            if not any(existing is route_handler for existing in app_config.route_handlers):
                app_config.route_handlers.append(route_handler)

    def _configure_oauth_routes(self, app_config: AppConfig) -> None:
        oauth = self.config.oauth
        if oauth is None or not oauth.register_routes:
            return
        route_handlers = self._oauth_route_handlers
        if route_handlers is None:
            route_handlers = oauth.build_route_handlers()
            self._oauth_route_handlers = route_handlers
        for route_handler in route_handlers:
            if not any(existing is route_handler for existing in app_config.route_handlers):
                app_config.route_handlers.append(route_handler)

    def _configure_oauth_lifespan(self, app_config: AppConfig) -> None:
        oauth = self.config.oauth
        if oauth is None:
            return
        closable = tuple(provider for provider in oauth.providers if callable(getattr(provider, "aclose", None)))
        if not closable:
            return
        if self._oauth_lifespan is None:

            @asynccontextmanager
            async def oauth_lifespan(_app: Litestar) -> AsyncGenerator[None, None]:
                try:
                    yield
                finally:
                    primary_error = sys.exc_info()[1]
                    results = await asyncio.gather(
                        *(cast("Any", provider).aclose() for provider in closable), return_exceptions=True
                    )
                    if primary_error is None and any(isinstance(result, BaseException) for result in results):
                        message = "OAuth provider shutdown failed"
                        raise ImproperlyConfiguredException(detail=message)

            self._oauth_lifespan = oauth_lifespan
        lifespan_handlers = cast(
            "list[object]",
            app_config.lifespan,  # pyright: ignore[reportUnknownMemberType] - third-party callable is untyped
        )
        if self._oauth_lifespan not in lifespan_handlers:
            lifespan_handlers.append(self._oauth_lifespan)

    def _validate_local_session_backend(
        self, app_config: AppConfig, native_sessions: Sequence[tuple[int, DefineMiddleware]]
    ) -> None:
        local_auth = self.config.local_auth
        if local_auth is None or local_auth.session_auth is None:
            return
        backend = native_sessions[0][1].kwargs.get("backend") if native_sessions else None
        if backend is None:
            message = "Session local authentication requires one native Litestar session middleware"
            raise ImproperlyConfiguredException(detail=message)
        if app_config.csrf_config is None and self.config.external_csrf is None:
            message = "Session local authentication requires exactly one native or external CSRF implementation"
            raise ImproperlyConfiguredException(detail=message)
        backend_config = getattr(backend, "config", None)
        scopes = getattr(backend_config, "scopes", ())
        if not {ScopeType.HTTP, ScopeType.WEBSOCKET}.issubset(scopes):
            message = "Session local authentication requires native HTTP and WebSocket session scopes"
            raise ImproperlyConfiguredException(detail=message)
        native_cookie = getattr(backend_config, "key", None)
        csrf_cookie = app_config.csrf_config.cookie_name if app_config.csrf_config is not None else None
        binding = local_auth.session_auth.binding
        cookie_names = tuple(name for name in (native_cookie, csrf_cookie, binding.cookie_name) if name is not None)
        if len(cookie_names) != len(frozenset(cookie_names)):
            message = "Native session, CSRF, and binding cookie names must be distinct"
            raise ImproperlyConfiguredException(detail=message)
        backend_max_age = getattr(backend_config, "max_age", None)
        if backend_max_age.__class__ is not int or binding.max_age > cast(  # type: ignore[redundant-cast]  # mypy narrows this; pyright does not
            "int", backend_max_age
        ):
            message = "Session binding lifetime cannot exceed the native session lifetime"
            raise ImproperlyConfiguredException(detail=message)
        native_secure = getattr(backend_config, "secure", None)
        if native_secure is not True and not binding.allow_insecure:
            message = "Production native session cookies must be Secure"
            raise ImproperlyConfiguredException(detail=message)
        if getattr(backend_config, "httponly", None) is not True:
            message = "Native session cookies used for authentication must be HttpOnly"
            raise ImproperlyConfiguredException(detail=message)
        if getattr(backend_config, "samesite", None) == "none" and native_secure is not True:
            message = "Native session SameSite=None requires Secure"
            raise ImproperlyConfiguredException(detail=message)

    def _configure_local_jwks(self, app_config: AppConfig) -> None:
        if self.config.local_jwks is None:
            return
        from litestar_security.providers.jwt import build_local_jwks_handler  # noqa: PLC0415 - breaks an import cycle

        app_config.route_handlers.append(build_local_jwks_handler(self.config.local_jwks))

    def _configure_jwks_lifespan(self, app_config: AppConfig) -> None:
        if not self.config.jwks_providers:
            return
        from litestar_security.providers.jwks import JWKSProvider  # noqa: PLC0415 - deferred to break an import cycle

        provider_values = cast("tuple[object, ...]", self.config.jwks_providers)
        if not all(isinstance(provider, JWKSProvider) for provider in provider_values):
            message = "JWKS lifespan providers must implement JWKSProvider"
            raise ImproperlyConfiguredException(detail=message)
        if self._jwks_lifespan is None:
            providers = tuple(self.config.jwks_providers)
            failure_mode = self.config.jwks_warmup_failure

            @asynccontextmanager
            async def jwks_lifespan(_app: Litestar) -> AsyncGenerator[None, None]:
                try:
                    for provider in providers:
                        outcome = await provider.warmup(now=datetime.now(timezone.utc))
                        if isinstance(outcome, VerificationUnavailable) and failure_mode == "fail_startup":
                            message = "JWKS warmup failed during application startup"
                            raise ImproperlyConfiguredException(detail=message)
                    yield
                finally:
                    primary_error = sys.exc_info()[1]
                    close_results = await asyncio.gather(
                        *(provider.aclose() for provider in providers), return_exceptions=True
                    )
                    if primary_error is None and any(isinstance(result, BaseException) for result in close_results):
                        message = "JWKS provider shutdown failed"
                        raise ImproperlyConfiguredException(detail=message)

            self._jwks_lifespan = jwks_lifespan
        lifespan_handlers = cast(
            "list[object]",
            app_config.lifespan,  # pyright: ignore[reportUnknownMemberType] - third-party callable is untyped at this boundary
        )
        if self._jwks_lifespan not in lifespan_handlers:
            lifespan_handlers.append(self._jwks_lifespan)

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


def _validate_local_auth(value: object) -> None:
    from litestar_security.accounts import LocalAuthConfig  # noqa: PLC0415 - account services load only when configured

    if not isinstance(value, LocalAuthConfig):
        message = "Security local authentication must be a LocalAuthConfig"
        raise ImproperlyConfiguredException(detail=message)


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
