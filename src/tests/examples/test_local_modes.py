"""Integration tests for runnable local-auth example modes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

import pytest
from examples import app as example_app
from examples.app import create_app
from examples.support import build_local_auth
from litestar.middleware import DefineMiddleware
from litestar.middleware.session.base import SessionMiddleware
from litestar.routes import HTTPRoute
from litestar.testing import TestClient

from litestar_security import MFAConfig, SecurityConfig
from litestar_security.accounts import (
    LocalAuthMode,
    LoginMethod,
    ProtectedSecret,
    RecoveryCodePepper,
    RevokeLoginMethodOutcome,
    RevokeLoginMethodStatus,
    SecurityEvent,
)
from litestar_security.testing import InMemoryMFALoginChallengeStore, InMemoryMFAStore

if TYPE_CHECKING:
    from litestar_security import SecurityPlugin


@dataclass(slots=True)
class _MFASecretProtector:
    """Minimal reversible protector for the example route-registration matrix."""

    active_key_version: str = "example-mfa"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedSecret:
        return ProtectedSecret(ciphertext=associated_data + secret, key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedSecret, *, associated_data: bytes) -> bytes:
        assert protected.ciphertext.startswith(associated_data)
        return protected.ciphertext.removeprefix(associated_data)


class _MFAStore(InMemoryMFAStore):
    """Supply the login-method port required when the example opts into login MFA."""

    __slots__ = ()

    async def list_methods(self, _account_id: str) -> tuple[LoginMethod, ...]:
        return tuple(self.login_methods.values())

    async def register_login_method(self, _account_id: str, method: LoginMethod, *, event: SecurityEvent) -> None:
        self.login_methods[method.method_id] = method
        self.events.append(event)

    async def revoke_login_method(
        self, _account_id: str, _method_id: str, *, require_remaining: bool = True, event: SecurityEvent
    ) -> RevokeLoginMethodOutcome:
        del require_remaining, event
        return RevokeLoginMethodOutcome(RevokeLoginMethodStatus.NOT_FOUND)


def _mfa_config(*, require_at_login: bool) -> MFAConfig:
    store = _MFAStore()
    return MFAConfig(
        store=store,
        secret_protector=_MFASecretProtector(),
        recovery_peppers=(RecoveryCodePepper("example-mfa", b"m" * 32),),
        login_methods=store,
        login_challenge_store=InMemoryMFALoginChallengeStore(),
        require_at_login=require_at_login,
        register_routes=False,
    )


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


@pytest.mark.parametrize(
    ("profile", "completion_paths"), [("legacy", set()), ("mfa", {"/auth/login/mfa", "/auth/token/mfa"})]
)
def test_local_hybrid_example_adds_mfa_completion_paths_only_when_enabled(
    monkeypatch: pytest.MonkeyPatch, profile: Literal["legacy", "mfa"], completion_paths: set[str]
) -> None:
    """The opt-in hybrid profile exposes both completion transports on distinct paths."""
    monkeypatch.setenv("LITESTAR_SECURITY_EXAMPLE", "local-hybrid")
    local_auth = build_local_auth("local-hybrid")
    monkeypatch.setattr(
        example_app,
        "_build_security_config",
        lambda _mode: SecurityConfig(local_auth=local_auth, mfa=_mfa_config(require_at_login=profile == "mfa")),
    )

    app = create_app()
    paths = {route.path for route in app.routes if isinstance(route, HTTPRoute)}

    assert paths & {"/auth/login/mfa", "/auth/token/mfa"} == completion_paths


def test_local_session_example_completes_registration_login_and_logout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LITESTAR_SECURITY_EXAMPLE", "local-session")
    app = create_app()
    plugin = cast("SecurityPlugin[object]", app.plugins.init[0])
    local_auth = plugin.config.local_auth
    assert local_auth is not None
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
    password = "example password 123"  # noqa: S105 - local example credential

    with TestClient(app) as client:
        assert (
            client.post("/auth/register", json={"identifier": "user@example.com", "password": password}).status_code
            == 202
        )
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
        replayed = client.post(
            "/auth/token/refresh",
            json={"token": first["refresh_token"]},
            headers={"Idempotency-Key": "bWlpaWlpaWlpaWlpaWlpaQ"},
        )
        revoked = client.post(
            "/auth/token/revoke",
            json={"token": second["refresh_token"]},
            headers={"Authorization": f"Bearer {second['access_token']}"},
        )

    assert revoked.status_code == 200
    assert replayed.status_code == 400
