"""Integration tests for WebSocket and application-owned admin examples."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from examples.app import ExampleSecurityAdmin, create_app
from litestar.config.csrf import CSRFConfig
from litestar.exceptions import WebSocketDisconnect
from litestar.testing import TestClient

if TYPE_CHECKING:
    from examples.support import ExampleAccountStore

    from litestar_security import SecurityPlugin


def test_websocket_mode_accepts_exact_origin_session_and_rejects_url_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LITESTAR_SECURITY_EXAMPLE", "websocket")
    app = create_app()
    plugin = cast("SecurityPlugin[object]", app.plugins.init[0])
    local_auth = plugin.config.local_auth
    assert local_auth is not None
    store = cast("ExampleAccountStore", local_auth.accounts)
    csrf = local_auth.csrf
    assert isinstance(csrf, CSRFConfig)
    password = "example password 123"  # noqa: S105 - local example credential

    with TestClient(app) as client:
        assert client.get("/csrf").status_code == 200
        csrf_headers = {csrf.header_name: cast("str", client.cookies.get(csrf.cookie_name))}
        assert (
            client.post("/auth/register", json={"identifier": "user@example.com", "password": password}).status_code
            == 202
        )
        assert store.verification_token is not None
        assert client.post("/auth/verification/confirm", json={"token": store.verification_token}).status_code == 200
        assert (
            client.post(
                "/auth/login", json={"identifier": "user@example.com", "password": password}, headers=csrf_headers
            ).status_code
            == 200
        )
        with client.websocket_connect("/ws", headers={"Origin": "http://testserver.local"}) as socket:
            assert socket.receive_json() == {"id": "account-1"}

    anonymous_app = create_app()
    with (
        TestClient(anonymous_app) as client,
        pytest.raises(WebSocketDisconnect) as exc,
        client.websocket_connect("/ws?token=forbidden", headers={"Origin": "http://testserver.local"}),
    ):
        pass
    assert exc.value.code == 4401


def test_custom_admin_controller_is_application_owned_and_guarded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LITESTAR_SECURITY_EXAMPLE", "custom-admin")
    app = create_app()

    with TestClient(app) as client:
        response = client.post("/admin/security/disable")

    assert response.status_code == 401
    assert any(
        isinstance(getattr(route_handler.fn, "__self__", None), ExampleSecurityAdmin)
        for route in app.routes
        if route.path.startswith("/admin/security")
        for route_handler in getattr(route, "route_handlers", ())
    )


def test_admin_routes_are_absent_from_other_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LITESTAR_SECURITY_EXAMPLE", "no-session")
    app = create_app()

    with TestClient(app) as client:
        response = client.post("/admin/security/disable")

    assert response.status_code == 404
