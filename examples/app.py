"""Environment-selected Litestar Security example application."""

from __future__ import annotations

import os

from litestar import Litestar, get
from litestar.openapi import OpenAPIConfig

from examples.support import (
    build_api_team_config,
    build_iap_config,
    build_local_auth,
    build_oauth_config,
    example_session_backend,
)
from litestar_security import SecurityConfig, SecurityContextDependency, SecurityPlugin, public, security

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
)


@get("/", opt=security(public()), sync_to_thread=False)
def example_home(security_context: SecurityContextDependency) -> dict[str, object]:
    """Describe the active request-local security boundary."""
    return {"authenticated": bool(security_context.evidence), "session": type(security_context.session).__name__}


@get("/csrf", opt=security(public(), csrf_required=True), sync_to_thread=False)
def csrf_seed() -> None:
    """Issue the native CSRF cookie for browser example clients."""


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
    if mode in {"local-session", "local-hybrid"}:
        config.session_backend = example_session_backend()  # type: ignore[assignment]  # Litestar exposes it untyped
    route_handlers = [example_home, csrf_seed] if config.session_backend is not None else [example_home]
    return Litestar(
        route_handlers=route_handlers,
        openapi_config=OpenAPIConfig(title=f"Litestar Security: {mode}", version="1.0.0"),
        plugins=[SecurityPlugin[object](config)],
    )
