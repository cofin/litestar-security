"""Environment-selected Litestar Security example application."""

from __future__ import annotations

import os
from typing import Any

from litestar import Controller, Litestar, WebSocket, get, post, websocket
from litestar.openapi import OpenAPIConfig

from examples.support import (
    build_api_team_config,
    build_iap_config,
    build_local_auth,
    build_oauth_config,
    build_websocket_config,
    example_session_backend,
)
from litestar_security import (
    SecurityConfig,
    SecurityContextDependency,
    SecurityPlugin,
    any_of,
    public,
    required,
    security,
)
from litestar_security.guards import requires_role

__all__ = ("EXAMPLE_MODES", "create_app")

EXAMPLE_MODES = (
    "api-team-service",
    "github-oauth",
    "google-iap",
    "google-oauth",
    "keycloak",
    "local-hybrid",
    "local-session",
    "local-token",
    "no-session",
    "websocket",
    "custom-admin",
)


@get("/", sync_to_thread=False, **security(public()))
def example_home(security_context: SecurityContextDependency) -> dict[str, object]:
    """Describe the active request-local security boundary."""
    return {"authenticated": bool(security_context.evidence), "session": type(security_context.session).__name__}


@get("/csrf", sync_to_thread=False, **security(public(), csrf_required=True))
def csrf_seed() -> None:
    """Issue the native CSRF cookie for browser example clients."""


@websocket("/ws", **security(any_of("session", "bearer")))
async def example_socket(socket: WebSocket[Any, Any, Any]) -> None:
    """Echo the authenticated principal over a short-lived socket."""
    await socket.accept()
    await socket.send_json({"id": socket.user.id})
    await socket.close()


class ExampleSecurityAdmin(Controller):
    """Application-owned security administration surface."""

    path = "/admin/security"

    @post("/disable", guards=[requires_role("security-admin")], sync_to_thread=False, **security(required()))
    def disable_account(self) -> dict[str, str]:
        """Demonstrate application-owned account disable orchestration."""
        return {"detail": "Account disabled by application service."}

    @post("/force-reset", guards=[requires_role("security-admin")], sync_to_thread=False, **security(required()))
    def force_reset(self) -> dict[str, str]:
        """Demonstrate application-owned forced password reset."""
        return {"detail": "Password reset required by application service."}

    @post("/revoke", guards=[requires_role("security-admin")], sync_to_thread=False, **security(required()))
    def revoke_security_state(self) -> dict[str, str]:
        """Demonstrate factor, session, and key revocation."""
        return {"detail": "Application security state revoked."}


def create_app() -> Litestar:
    """Create the mode selected by ``LITESTAR_SECURITY_EXAMPLE``.

    Returns:
        A complete local-only example application.

    Raises:
        ValueError: If the selected mode is unknown.
    """
    mode = os.getenv("LITESTAR_SECURITY_EXAMPLE", "local-session")
    if mode not in EXAMPLE_MODES:
        choices = ", ".join(EXAMPLE_MODES)
        message = f"Unknown LITESTAR_SECURITY_EXAMPLE {mode!r}; choose one of: {choices}"
        raise ValueError(message)
    config = _build_security_config(mode)
    route_handlers: list[Any] = [example_home, csrf_seed] if config.session_backend is not None else [example_home]
    if mode == "websocket":
        route_handlers.append(example_socket)
    elif mode == "custom-admin":
        route_handlers.append(ExampleSecurityAdmin)
    return Litestar(
        route_handlers=route_handlers,
        openapi_config=OpenAPIConfig(title=f"Litestar Security: {mode}", version="1.0.0"),
        plugins=[SecurityPlugin[object](config)],
    )


def _build_security_config(mode: str) -> SecurityConfig[object]:
    config = SecurityConfig[object](default_policy=public())
    if mode != "no-session":
        if mode.startswith("local-"):
            config.local_auth = build_local_auth(mode)
        elif mode == "google-iap":
            config.iap = build_iap_config()
        elif mode in {"google-oauth", "github-oauth", "keycloak"}:
            config.local_auth = build_local_auth("local-session")
            config.session_backend = example_session_backend()  # type: ignore[assignment]  # Litestar exposes it untyped
            config.oauth = build_oauth_config(mode)
        elif mode == "api-team-service":
            config.api_key, config.service_token = build_api_team_config()
        elif mode == "websocket":
            config.local_auth = build_local_auth("local-hybrid")
            config.session_backend = example_session_backend()  # type: ignore[assignment]  # Litestar exposes it untyped
            config.websocket = build_websocket_config()
        elif mode == "custom-admin":
            config.local_auth = build_local_auth("local-session")
            config.session_backend = example_session_backend()  # type: ignore[assignment]  # Litestar exposes it untyped
    if mode in {"local-session", "local-hybrid"}:
        config.session_backend = example_session_backend()  # type: ignore[assignment]  # Litestar exposes it untyped
    return config
