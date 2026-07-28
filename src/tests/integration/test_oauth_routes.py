from typing import Any

import pytest
from litestar import Litestar, Request
from litestar.config.app import AppConfig
from litestar.datastructures import Cookie
from litestar.di import Provide
from litestar.testing import AsyncTestClient

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security.context import Principal
from litestar_security.providers.oauth import (
    OAuthAuthorization,
    OAuthConfig,
    OAuthLinkRequest,
    OAuthLogoutResult,
    OAuthOperation,
    OAuthRouteResponse,
    OAuthScopeRequest,
    OAuthStepUpRequest,
    build_oauth_routes,
)


class Provider:
    name = "example"


class RouteService:
    provider_names = frozenset({"example"})

    def __init__(self) -> None:
        self.operations: list[OAuthOperation] = []

    async def begin(  # noqa: PLR0913 - fake mirrors the explicit public service contract
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
        del account_id, return_to, scopes, step_up_grant, request
        self.operations.append(operation)
        return OAuthAuthorization(
            url=f"https://issuer.example/authorize?provider={provider}",
            binding_cookie=Cookie(
                key="__Host-litestar-security-oauth",
                value="binding",
                path="/",
                secure=True,
                httponly=True,
                samesite="lax",
            ),
        )

    async def callback(
        self, *, provider: str, code: str, state: str, request: Request[Any, Any, Any]
    ) -> OAuthRouteResponse:
        del code, state, request
        return OAuthRouteResponse(detail="Authenticated.", provider_account_id=f"{provider}-account")

    async def unlink(self, **kwargs: object) -> OAuthRouteResponse:
        del kwargs
        return OAuthRouteResponse(detail="Unlinked.")

    async def revoke(self, **kwargs: object) -> OAuthRouteResponse:
        del kwargs
        return OAuthRouteResponse(detail="Revoked.")

    async def logout(self, **kwargs: object) -> OAuthLogoutResult:
        del kwargs
        return OAuthLogoutResult()


def oauth_config(*, register_routes: bool = True) -> OAuthConfig:
    return OAuthConfig(service=RouteService(), providers=(Provider(),), register_routes=register_routes)


def oauth_app(*, openapi: bool) -> Litestar:
    kwargs = {
        "route_handlers": [build_oauth_routes(oauth_config())],
        "dependencies": {"principal": Provide(Principal.anonymous, sync_to_thread=False)},
    }
    return Litestar(**kwargs) if openapi else Litestar(**kwargs, openapi_config=None)  # type: ignore[arg-type]


def test_oauth_config_caches_routes_and_plugin_registers_once() -> None:
    config = oauth_config()
    assert config.build_route_handlers() is config.build_route_handlers()

    plugin: SecurityPlugin[object] = SecurityPlugin(SecurityConfig(oauth=config))
    app_config = plugin.on_app_init(AppConfig())
    second = plugin.on_app_init(app_config)

    assert second.route_handlers.count(config.build_route_handlers()[0]) == 1


def test_oauth_config_can_disable_generated_routes() -> None:
    config = oauth_config(register_routes=False)

    assert config.build_route_handlers() == ()
    assert SecurityPlugin(SecurityConfig[object](oauth=config)).on_app_init(AppConfig()).route_handlers == []


@pytest.mark.anyio
async def test_public_login_and_callback_have_binding_and_no_store_headers() -> None:
    app = oauth_app(openapi=False)

    async with AsyncTestClient(app=app) as client:
        login = await client.get("/auth/oauth/example/login", follow_redirects=False)
        callback = await client.get("/auth/oauth/example/callback?code=code&state=state")

    assert login.status_code == 302
    assert login.headers["location"] == "https://issuer.example/authorize?provider=example"
    assert "__Host-litestar-security-oauth=binding" in login.headers["set-cookie"]
    assert "HttpOnly" in login.headers["set-cookie"]
    assert "Secure" in login.headers["set-cookie"]
    assert login.headers["cache-control"] == "no-store"
    assert callback.status_code == 200
    assert callback.json() == {"detail": "Authenticated.", "providerAccountId": "example-account"}
    assert callback.headers["cache-control"] == "no-store"


def test_oauth_dtos_are_frozen_camel_case_and_redact_step_up() -> None:
    link = OAuthLinkRequest(step_up_grant="secret", return_to="/")
    scope = OAuthScopeRequest(
        provider_account_id="provider-account", scopes=frozenset({"email"}), step_up_grant="secret"
    )
    action = OAuthStepUpRequest(step_up_grant="secret")

    with pytest.raises(AttributeError):
        link.return_to = "/other"  # type: ignore[misc]
    assert "secret" not in repr(link)
    assert "secret" not in repr(scope)
    assert "secret" not in repr(action)


def test_openapi_never_contains_provider_secrets_or_protocol_credentials() -> None:
    app = oauth_app(openapi=True)

    document = str(app.openapi_schema.to_schema())

    for forbidden in ("client_secret", "access_token", "refresh_token", "raw_claims", "nonce", "state"):
        assert forbidden not in document.lower()
