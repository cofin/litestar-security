"""Integration tests for path-pattern route exclusion."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast

import pytest
from litestar import Litestar, WebSocket, asgi, get, websocket
from litestar.exceptions import ImproperlyConfiguredException, LitestarWarning
from litestar.openapi import OpenAPIConfig
from litestar.openapi.spec import SecurityScheme
from litestar.routes import ASGIRoute, BaseRoute, WebSocketRoute
from litestar.static_files import create_static_files_router
from litestar.testing import TestClient

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security.authentication import (
    Authenticated,
    AuthenticationEvidence,
    AuthenticationMechanism,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    required,
)
from litestar_security.context import Principal

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from litestar.handlers.base import BaseRouteHandler
    from litestar.types import Receive, Scope, Send

    from litestar_security.authentication import SecurityRuntimePlan


class _HeaderSlot:
    def __init__(self, name: str) -> None:
        self.name = name

    def extract(self, connection: Any) -> object:
        value = cast("str | None", connection.headers.get(f"x-auth-{self.name.removeprefix('slot-')}"))
        if value is None:
            return NoCredentials()
        if value != "valid":
            return InvalidCredentials()
        return PresentedCredential("user")


class _HeaderAuthenticator:
    participates_by_default = True

    def __init__(self, name: str, slot: str) -> None:
        self.name = name
        self.slot = slot

    async def authenticate(self, credential: object, _connection: object) -> Authenticated[str]:
        return Authenticated(
            claims=cast("str", credential),
            evidence=AuthenticationEvidence(
                mechanism=self.name, slot=self.slot, authenticated_at=datetime(2026, 8, 4, tzinfo=timezone.utc)
            ),
        )


class _HeaderResolver:
    async def resolve(self, claims: str) -> Principal[object]:
        return Principal(id=claims)


def _api_team_config(*, exclude: Sequence[str] | str | None = None) -> SecurityConfig[object]:
    """Build a minimal two-mechanism configuration with optional path exclusion."""
    names = ("api-key", "service-jwt")
    return SecurityConfig(
        slots=tuple(_HeaderSlot(name=f"slot-{name}") for name in names),  # type: ignore[arg-type]
        mechanisms=tuple(
            AuthenticationMechanism(
                authenticator=_HeaderAuthenticator(name=name, slot=f"slot-{name}"),  # type: ignore[arg-type]
                resolver=_HeaderResolver(),
                scheme_name=name,
                security_scheme=SecurityScheme(type="http", scheme="bearer"),
            )
            for name in names
        ),
        exclude=exclude,
    )


@get("/api/thing", sync_to_thread=False)
def _api_thing() -> str:
    return "thing"


@get("/assets/manifest", sync_to_thread=False)
def _assets_manifest() -> str:
    return "manifest"


@get("/assets/report", auth=required(), sync_to_thread=False)
def _declared_http() -> str:
    return "report"


@websocket("/assets/socket", auth=required())
async def _declared_socket(socket: WebSocket[Any, Any, Any]) -> None:
    del socket


@asgi("/assets/mount", auth=required(), copy_scope=True)
async def _declared_asgi(scope: Scope, receive: Receive, send: Send) -> None:
    del scope, receive, send


def _plan(app: Litestar, route_type: type[BaseRoute], path: str) -> SecurityRuntimePlan:
    route = next(value for value in app.routes if isinstance(value, route_type) and value.path == path)
    handler = cast("BaseRouteHandler", route.route_handler)  # type: ignore[attr-defined]
    return cast("SecurityRuntimePlan", handler.opt["litestar_security_plan"])


@pytest.fixture(name="static_directory")
def fixture_static_directory(tmp_path: Path) -> Path:
    """Write one asset into a request-local static directory."""
    (tmp_path / "app.css").write_text("body{}")
    return tmp_path


def test_excluded_static_assets_serve_anonymously_while_application_routes_authenticate(static_directory: Path) -> None:
    app = Litestar(
        route_handlers=[_api_thing, create_static_files_router(path="/static", directories=[static_directory])],
        plugins=[SecurityPlugin(_api_team_config(exclude=["^/static"]))],
        openapi_config=OpenAPIConfig(title="Exclusion", version="1.0"),
    )

    with TestClient(app) as client:
        assert client.get("/static/app.css").status_code == 200
        assert client.get("/api/thing").status_code == 401


def test_uncompilable_exclusion_pattern_is_rejected_at_startup() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="exclude patterns"):
        Litestar(route_handlers=[_api_thing], plugins=[SecurityPlugin(_api_team_config(exclude=["["]))])


def test_exclusion_pattern_matching_every_path_warns() -> None:
    with pytest.warns(LitestarWarning, match="greedily matches all paths"):
        Litestar(route_handlers=[_api_thing], plugins=[SecurityPlugin(_api_team_config(exclude=["^/"]))])


def test_excluded_websocket_and_asgi_routes_bypass_authentication() -> None:
    @websocket("/assets/socket")
    async def socket_handler(socket: WebSocket[Any, Any, Any]) -> None:
        await socket.accept()
        await socket.close()

    @asgi("/assets/mount", copy_scope=True)
    async def mounted(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive, send

    app = Litestar(
        route_handlers=[socket_handler, mounted, _api_thing],
        openapi_config=None,
        plugins=[SecurityPlugin(_api_team_config(exclude=["^/assets"]))],
    )
    socket_plan = _plan(app, WebSocketRoute, "/assets/socket")
    asgi_plan = _plan(app, ASGIRoute, "/assets/mount")

    assert (socket_plan.authenticate, socket_plan.bypass_authentication) == (False, True)
    assert (asgi_plan.authenticate, asgi_plan.bypass_authentication) == (False, True)
    with TestClient(app) as client, client.websocket_connect("/assets/socket"):
        pass


@pytest.mark.parametrize(
    ("handlers", "expected"),
    [
        pytest.param([_declared_http], "GET /assets/report", id="http"),
        pytest.param([_declared_socket], "websocket /assets/socket", id="websocket"),
        pytest.param([_declared_asgi], "asgi /assets/mount", id="asgi"),
    ],
)
def test_route_declaring_auth_and_matching_an_exclusion_pattern_is_rejected(handlers: list[Any], expected: str) -> None:
    message = rf"Route declares auth but matches a security exclusion pattern for {expected}"
    with pytest.raises(ImproperlyConfiguredException, match=message):
        Litestar(
            route_handlers=handlers,
            openapi_config=None,
            plugins=[SecurityPlugin(_api_team_config(exclude=["^/assets"]))],
        )


def test_excluded_operation_documents_anonymous_access_while_others_document_schemes() -> None:
    app = Litestar(
        route_handlers=[_api_thing, _assets_manifest],
        plugins=[SecurityPlugin(_api_team_config(exclude=["^/assets"]))],
        openapi_config=OpenAPIConfig(title="Exclusion", version="1.0"),
    )
    excluded = app.openapi_schema.paths["/assets/manifest"].get
    included = app.openapi_schema.paths["/api/thing"].get
    assert excluded is not None
    assert included is not None

    assert excluded.security == [{}]
    assert included.security == [{"api-key": []}, {"service-jwt": []}]


def test_router_level_exclude_from_auth_is_still_rejected(static_directory: Path) -> None:
    static_router = create_static_files_router(
        path="/static", directories=[static_directory], opt={"exclude_from_auth": True}
    )

    with pytest.raises(ImproperlyConfiguredException, match="only on individual route handlers"):
        Litestar(route_handlers=[static_router], plugins=[SecurityPlugin(_api_team_config())])
