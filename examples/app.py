"""Environment-selected Litestar Security example application."""

from __future__ import annotations

import os
from secrets import token_hex
from typing import Any

from litestar import Controller, Litestar, WebSocket, get, post, websocket
from litestar.config.csrf import CSRFConfig
from litestar.di import NamedDependency  # noqa: TC002 - Litestar resolves handler annotations at runtime
from litestar.openapi import OpenAPIConfig

from examples.support import (
    build_api_tenant_config,
    build_iap_config,
    build_local_auth,
    build_oauth_config,
    build_websocket_config,
    example_session_config,
)
from litestar_security import SecurityConfig, SecurityContext, SecurityPlugin, any_of, public, required, requires_role

__all__ = ("EXAMPLE_MODES", "create_app")

EXAMPLE_MODES = (
    "api-tenant-service",
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


@get("/", auth=public(), sync_to_thread=False)
def example_home(security_context: NamedDependency[SecurityContext]) -> dict[str, object]:
    """Describe the active request-local security boundary."""
    return {"authenticated": bool(security_context.evidence), "session": type(security_context.session).__name__}


@get("/csrf", sync_to_thread=False, auth=public(), csrf_required=True)
def csrf_seed() -> None:
    """Issue the native CSRF cookie for browser example clients."""


@websocket("/ws", auth=any_of("session", "bearer"))
async def example_socket(socket: WebSocket[Any, Any, Any]) -> None:
    """Echo the authenticated principal over a short-lived socket."""
    await socket.accept()
    await socket.send_json({"id": socket.user.id})
    await socket.close()


class ExampleSecurityAdmin(Controller):
    """Application-owned security administration surface."""

    path = "/admin/security"

    @post("/disable", auth=required(), guards=[requires_role("security-admin")], sync_to_thread=False)
    def disable_account(self) -> dict[str, str]:
        """Demonstrate application-owned account disable orchestration."""
        return {"detail": "Account disabled by application service."}

    @post("/force-reset", auth=required(), guards=[requires_role("security-admin")], sync_to_thread=False)
    def force_reset(self) -> dict[str, str]:
        """Demonstrate application-owned forced password reset."""
        return {"detail": "Password reset required by application service."}

    @post("/revoke", auth=required(), guards=[requires_role("security-admin")], sync_to_thread=False)
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
    session_config = example_session_config() if _uses_session(mode) else None
    route_handlers: list[Any] = [example_home, csrf_seed] if session_config is not None else [example_home]
    if mode == "websocket":
        route_handlers.append(example_socket)
    elif mode == "custom-admin":
        route_handlers.append(ExampleSecurityAdmin)
    return Litestar(
        route_handlers=route_handlers,
        csrf_config=CSRFConfig(secret=token_hex()) if session_config is not None else None,
        middleware=[session_config.middleware] if session_config is not None else None,
        openapi_config=OpenAPIConfig(title=f"Litestar Security: {mode}", version="0.1.0"),
        opt={"auth": public()},
        plugins=[SecurityPlugin[object](config)],
    )


def _build_security_config(mode: str) -> SecurityConfig[object]:
    config = SecurityConfig[object]()
    if mode != "no-session":
        if mode.startswith("local-"):
            config.local_auth = build_local_auth(mode)
        elif mode == "google-iap":
            config.iap = build_iap_config()
        elif mode in {"google-oauth", "github-oauth", "keycloak"}:
            config.local_auth = build_local_auth("local-session")
            config.oauth = build_oauth_config(mode)
        elif mode == "api-tenant-service":
            config.api_key, config.service_token = build_api_tenant_config()
        elif mode == "websocket":
            config.local_auth = build_local_auth("local-hybrid")
            config.websocket = build_websocket_config()
        elif mode == "custom-admin":
            config.local_auth = build_local_auth("local-session")
    return config


def _uses_session(mode: str) -> bool:
    return mode in {
        "custom-admin",
        "github-oauth",
        "google-oauth",
        "keycloak",
        "local-hybrid",
        "local-session",
        "websocket",
    }
