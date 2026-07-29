"""Integration tests for runnable local-auth example modes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, cast

import pytest
from examples.app import create_app
from litestar.middleware import DefineMiddleware
from litestar.middleware.session.base import SessionMiddleware
from litestar.routes import HTTPRoute
from litestar.testing import TestClient

from litestar_security.accounts import LocalAuthMode

if TYPE_CHECKING:
    from examples.support import ExampleAccountStore

    from litestar_security import SecurityPlugin


@pytest.mark.parametrize(
    ("mode", "profile", "session_kind", "required_routes"),
    [
        ("local-session", LocalAuthMode.SESSION, "native", {"/auth/login", "/auth/logout"}),
        ("local-token", LocalAuthMode.TOKENS, "none", {"/auth/token", "/auth/token/refresh"}),
        (
            "local-hybrid",
            LocalAuthMode.HYBRID,
            "native",
            {"/auth/login", "/auth/logout", "/auth/token", "/auth/token/refresh"},
        ),
        ("no-session", None, "none", set()),
    ],
)
def test_local_example_modes_boot_with_explicit_transports(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    profile: LocalAuthMode | None,
    session_kind: Literal["native", "none"],
    required_routes: set[str],
) -> None:
    monkeypatch.setenv("LITESTAR_SECURITY_EXAMPLE", mode)
    app = create_app()
    plugin = cast("SecurityPlugin[object]", app.plugins.init[0])

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    has_session = session_kind == "native"
    assert response.json()["session"] == ("LitestarSessionHandle" if has_session else "NullSessionHandle")
    assert (plugin.config.local_auth.mode if plugin.config.local_auth is not None else None) is profile
    assert (
        any(
            isinstance(item, DefineMiddleware)
            and isinstance(item.middleware, type)
            and issubclass(item.middleware, SessionMiddleware)
            for item in app.middleware
        )
        is has_session
    )
    paths = {route.path for route in app.routes if isinstance(route, HTTPRoute)}
    assert required_routes <= paths


def test_unknown_example_mode_fails_before_application_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LITESTAR_SECURITY_EXAMPLE", "automatic")

    with pytest.raises(ValueError, match="Unknown LITESTAR_SECURITY_EXAMPLE"):
        create_app()


def test_local_session_example_completes_registration_login_and_logout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LITESTAR_SECURITY_EXAMPLE", "local-session")
    app = create_app()
    plugin = cast("SecurityPlugin[object]", app.plugins.init[0])
    local_auth = plugin.config.local_auth
    assert local_auth is not None
    store = cast("ExampleAccountStore", local_auth.accounts)
    csrf = app.csrf_config
    assert csrf is not None
    password = "example password 123"  # noqa: S105 - local example credential

    with TestClient(app) as client:
        assert client.get("/csrf").status_code == 200
        csrf_headers = {csrf.header_name: cast("str", client.cookies.get(csrf.cookie_name))}
        registration = client.post(
            "/auth/register", json={"identifier": "user@example.com", "password": password, "display_name": "User"}
        )
        assert registration.status_code == 202
        assert store.verification_token is not None
        assert client.post("/auth/verification/confirm", json={"token": store.verification_token}).status_code == 200
        assert (
            client.post(
                "/auth/login", json={"identifier": "user@example.com", "password": password}, headers=csrf_headers
            ).status_code
            == 200
        )
        assert client.get("/auth/sessions").status_code == 200
        assert client.post("/auth/logout", headers=csrf_headers).status_code == 200
        assert client.get("/auth/sessions").status_code == 401


def test_local_token_example_rotates_and_revokes_refresh_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LITESTAR_SECURITY_EXAMPLE", "local-token")
    app = create_app()
    plugin = cast("SecurityPlugin[object]", app.plugins.init[0])
    local_auth = plugin.config.local_auth
    assert local_auth is not None
    store = cast("ExampleAccountStore", local_auth.accounts)
    password = "example password 123"  # noqa: S105 - local example credential

    with TestClient(app) as client:
        assert (
            client.post("/auth/register", json={"identifier": "user@example.com", "password": password}).status_code
            == 202
        )
        assert store.verification_token is not None
        assert client.post("/auth/verification/confirm", json={"token": store.verification_token}).status_code == 200
        login = client.post("/auth/token", json={"identifier": "user@example.com", "password": password})
        assert login.status_code == 200
        first = login.json()
        rotated = client.post(
            "/auth/token/refresh",
            json={"token": first["refresh_token"]},
            headers={"Idempotency-Key": "aWlpaWlpaWlpaWlpaWlpaQ"},
        )
        assert rotated.status_code == 200
        second = rotated.json()
        revoked = client.post(
            "/auth/token/revoke",
            json={"token": second["refresh_token"]},
            headers={"Authorization": f"Bearer {second['access_token']}"},
        )

    assert revoked.status_code == 200
    assert any(state.revoked for state in store.refresh_tokens.values())
