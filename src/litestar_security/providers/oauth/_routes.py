"""Native Litestar route bundle for interactive OAuth provider lifecycles."""

from typing import Annotated, Any, Protocol, cast, runtime_checkable

import msgspec
from litestar import Controller, Request, Response, Router, delete, get, post
from litestar.datastructures import CacheControlHeader, Cookie
from litestar.di import NamedDependency, Provide
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException
from litestar.params import FromPath, FromQuery, JSONBody, QueryParameter, SkipValidation
from litestar.status_codes import HTTP_200_OK, HTTP_302_FOUND

from litestar_security.authentication import public, required, security
from litestar_security.context import Principal
from litestar_security.providers.oauth._transactions import OAuthOperation

__all__ = (
    "OAuthAuthorization",
    "OAuthConfig",
    "OAuthLinkRequest",
    "OAuthLogoutResult",
    "OAuthRouteResponse",
    "OAuthRouteService",
    "OAuthScopeRequest",
    "OAuthStepUpRequest",
    "build_oauth_routes",
)


class OAuthRouteResponse(msgspec.Struct, frozen=True, rename="camel", forbid_unknown_fields=True, kw_only=True):
    """Secret-free provider lifecycle response."""

    detail: str
    provider_account_id: str | None = None


class OAuthLinkRequest(msgspec.Struct, frozen=True, rename="camel", forbid_unknown_fields=True, kw_only=True):
    """Purpose-bound link request."""

    step_up_grant: str
    return_to: str = "/"

    def __repr__(self) -> str:
        """Redact the one-time step-up credential."""
        return f"{type(self).__name__}(step_up_grant=<redacted>, return_to={self.return_to!r})"


class OAuthScopeRequest(msgspec.Struct, frozen=True, rename="camel", forbid_unknown_fields=True, kw_only=True):
    """Incremental provider-scope request."""

    provider_account_id: str
    scopes: frozenset[str]
    step_up_grant: str
    return_to: str = "/"

    def __repr__(self) -> str:
        """Redact the one-time step-up credential."""
        return (
            f"{type(self).__name__}(provider_account_id={self.provider_account_id!r}, "
            f"scopes={self.scopes!r}, step_up_grant=<redacted>, return_to={self.return_to!r})"
        )


class OAuthStepUpRequest(msgspec.Struct, frozen=True, rename="camel", forbid_unknown_fields=True, kw_only=True):
    """Provider-account action requiring fresh step-up."""

    step_up_grant: str

    def __repr__(self) -> str:
        """Redact the one-time step-up credential."""
        return f"{type(self).__name__}(step_up_grant=<redacted>)"


class OAuthAuthorization(msgspec.Struct, frozen=True, kw_only=True):
    """Authorization redirect and dedicated browser-binding cookie."""

    url: str
    binding_cookie: Cookie


class OAuthLogoutResult(msgspec.Struct, frozen=True, kw_only=True):
    """Local logout result plus optional validated provider redirect."""

    detail: str = "Logged out."
    redirect_url: str | None = None


@runtime_checkable
class OAuthRouteService(Protocol):
    """Application boundary used identically by generated or custom controllers."""

    @property
    def provider_names(self) -> frozenset[str]:
        """Return the exact configured interactive provider names."""
        ...  # pragma: no cover

    async def begin(  # noqa: PLR0913 - every transaction and request binding remains explicit
        self,
        *,
        provider: str,
        operation: OAuthOperation,
        account_id: str | None,
        return_to: str,
        scopes: frozenset[str] | None,
        step_up_grant: str | None,
        request: Request[Any, Any, Any],
    ) -> OAuthAuthorization:
        """Create one transaction and return its safe redirect."""
        ...  # pragma: no cover

    async def callback(
        self, *, provider: str, code: str, state: str, request: Request[Any, Any, Any]
    ) -> OAuthRouteResponse:
        """Consume a callback and issue the configured local transport."""
        ...  # pragma: no cover

    async def unlink(
        self,
        *,
        provider: str,
        provider_account_id: str,
        account_id: str,
        step_up_grant: str,
        request: Request[Any, Any, Any],
    ) -> OAuthRouteResponse:
        """Atomically unlink a provider account."""
        ...  # pragma: no cover

    async def revoke(
        self, *, provider: str, account_id: str, step_up_grant: str, request: Request[Any, Any, Any]
    ) -> OAuthRouteResponse:
        """Locally delete and attempt upstream revocation."""
        ...  # pragma: no cover

    async def logout(self, *, provider: str, account_id: str, request: Request[Any, Any, Any]) -> OAuthLogoutResult:
        """Complete local logout independently of provider availability."""
        ...  # pragma: no cover


class OAuthConfig:
    """Interactive provider route configuration and service graph."""

    __slots__ = ("_route_handlers", "providers", "register_routes", "route_prefix", "service")

    def __init__(
        self,
        *,
        service: OAuthRouteService,
        providers: tuple[object, ...],
        route_prefix: str = "/auth",
        register_routes: bool = True,
    ) -> None:
        """Validate provider uniqueness and generated-route ownership.

        Args:
            service: Shared route and custom-controller service.
            providers: Configured interactive providers.
            route_prefix: Absolute non-root mount path.
            register_routes: Whether the plugin installs generated routes.
        """
        service_value = cast("object", service)
        if not isinstance(service_value, OAuthRouteService):
            message = "OAuth route service is invalid"
            raise ImproperlyConfiguredException(detail=message)
        names = tuple(getattr(provider, "name", None) for provider in providers)
        if (
            not providers
            or any(not isinstance(name, str) or not name.strip() for name in names)
            or len(names) != len(set(names))
            or frozenset(cast("tuple[str, ...]", names)) != service.provider_names
        ):
            message = "OAuth providers are invalid"
            raise ImproperlyConfiguredException(detail=message)
        normalized_prefix = route_prefix.rstrip("/")
        if (
            not normalized_prefix.startswith("/")
            or normalized_prefix == ""
            or "//" in normalized_prefix
            or any(value in normalized_prefix for value in ("\\", "{", "}", "?", "#"))
        ):
            message = "OAuth route prefix is invalid"
            raise ImproperlyConfiguredException(detail=message)
        register_routes_value = cast("object", register_routes)
        if register_routes_value.__class__ is not bool:
            message = "OAuth route registration flag is invalid"
            raise ImproperlyConfiguredException(detail=message)
        self.service = service
        self.providers = providers
        self.route_prefix = normalized_prefix
        self.register_routes = register_routes
        self._route_handlers: tuple[Router, ...] | None = None

    def build_route_handlers(self) -> tuple[Router, ...]:
        """Build and cache generated OAuth routes."""
        if not self.register_routes:
            return ()
        if self._route_handlers is None:
            self._route_handlers = (build_oauth_routes(self),)
        return self._route_handlers


_OAuthServiceDependency = NamedDependency[SkipValidation[OAuthRouteService]]


def build_oauth_routes(config: OAuthConfig) -> Router:
    """Build native generated OAuth lifecycle routes.

    Args:
        config: Validated provider route configuration.

    Returns:
        One no-store router.
    """

    def provide_oauth_route_service() -> OAuthRouteService:
        return config.service

    return Router(
        path=config.route_prefix,
        route_handlers=[_OAuthController],
        cache_control=CacheControlHeader(no_store=True),
        response_headers={"Pragma": "no-cache"},
        dependencies={
            "oauth_route_service": Provide(provide_oauth_route_service, sync_to_thread=False, use_cache=False)
        },
    )


def _account_id(principal: Principal[Any]) -> str:
    if not principal.is_authenticated:
        raise NotAuthorizedException(detail="Authentication required")
    return cast("str", principal.id)


def _authorization_response(result: OAuthAuthorization) -> Response[None]:
    return Response(
        content=None, status_code=HTTP_302_FOUND, headers={"Location": result.url}, cookies=[result.binding_cookie]
    )


class _OAuthController(Controller):
    path = "/oauth/{provider:str}"
    tags = ("OAuth providers",)

    @get("/login", operation_id="OAuthLogin", status_code=HTTP_302_FOUND, **security(public(), csrf_required=False))
    async def login(
        self,
        provider: FromPath[str],
        request: Request[Any, Any, Any],
        oauth_route_service: _OAuthServiceDependency,
        return_to: FromQuery[str] = "/",
    ) -> Response[None]:
        """Create a public login transaction."""
        result = await oauth_route_service.begin(
            provider=provider,
            operation=OAuthOperation.LOGIN,
            account_id=None,
            return_to=return_to,
            scopes=None,
            step_up_grant=None,
            request=request,
        )
        return _authorization_response(result)

    @get("/callback", operation_id="OAuthCallback", **security(public(), csrf_required=False))
    async def callback(
        self,
        provider: FromPath[str],
        code: FromQuery[str],
        oauth_state: Annotated[str, QueryParameter(name="state", include_in_schema=False)],
        request: Request[Any, Any, Any],
        oauth_route_service: _OAuthServiceDependency,
    ) -> OAuthRouteResponse:
        """Consume a transaction-bound callback and issue local authentication."""
        return await oauth_route_service.callback(provider=provider, code=code, state=oauth_state, request=request)

    @post("/link", operation_id="OAuthLink", status_code=HTTP_302_FOUND, **security(required()))
    async def link(
        self,
        provider: FromPath[str],
        data: JSONBody[OAuthLinkRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_route_service: _OAuthServiceDependency,
    ) -> Response[None]:
        """Begin an authenticated provider link."""
        result = await oauth_route_service.begin(
            provider=provider,
            operation=OAuthOperation.LINK,
            account_id=_account_id(principal),
            return_to=data.return_to,
            scopes=None,
            step_up_grant=data.step_up_grant,
            request=request,
        )
        return _authorization_response(result)

    @delete(
        "/links/{provider_account_id:str}", operation_id="OAuthUnlink", status_code=HTTP_200_OK, **security(required())
    )
    async def unlink(  # noqa: PLR0913 - Litestar injects each route binding explicitly
        self,
        provider: FromPath[str],
        provider_account_id: FromPath[str],
        data: JSONBody[OAuthStepUpRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_route_service: _OAuthServiceDependency,
    ) -> OAuthRouteResponse:
        """Unlink one provider identity without removing the final login method."""
        return await oauth_route_service.unlink(
            provider=provider,
            provider_account_id=provider_account_id,
            account_id=_account_id(principal),
            step_up_grant=data.step_up_grant,
            request=request,
        )

    @post("/scopes", operation_id="OAuthScopeUpgrade", status_code=HTTP_302_FOUND, **security(required()))
    async def scopes(
        self,
        provider: FromPath[str],
        data: JSONBody[OAuthScopeRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_route_service: _OAuthServiceDependency,
    ) -> Response[None]:
        """Begin allowlisted incremental provider consent."""
        result = await oauth_route_service.begin(
            provider=provider,
            operation=OAuthOperation.SCOPE_UPGRADE,
            account_id=_account_id(principal),
            return_to=data.return_to,
            scopes=data.scopes,
            step_up_grant=data.step_up_grant,
            request=request,
        )
        return _authorization_response(result)

    @post("/revoke", operation_id="OAuthRevoke", **security(required()))
    async def revoke(
        self,
        provider: FromPath[str],
        data: JSONBody[OAuthStepUpRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_route_service: _OAuthServiceDependency,
    ) -> OAuthRouteResponse:
        """Delete local provider tokens regardless of upstream retry state."""
        return await oauth_route_service.revoke(
            provider=provider, account_id=_account_id(principal), step_up_grant=data.step_up_grant, request=request
        )

    @post("/logout", operation_id="OAuthLogout", **security(required()))
    async def logout(
        self,
        provider: FromPath[str],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_route_service: _OAuthServiceDependency,
    ) -> Response[OAuthRouteResponse] | OAuthRouteResponse:
        """Complete local logout, then optionally redirect to a validated RP endpoint."""
        result = await oauth_route_service.logout(provider=provider, account_id=_account_id(principal), request=request)
        if result.redirect_url is not None:
            return Response(
                content=OAuthRouteResponse(detail=result.detail),
                status_code=HTTP_302_FOUND,
                headers={"Location": result.redirect_url},
            )
        return OAuthRouteResponse(detail=result.detail)
