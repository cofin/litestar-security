"""Integration tests for path-pattern route exclusion."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast

import pytest
from litestar import Litestar, Router, get
from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi import OpenAPIConfig
from litestar.openapi.spec import SecurityScheme
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
    public,
)
from litestar_security.context import Principal

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


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


@pytest.fixture(name="static_directory")
def fixture_static_directory(tmp_path: Path) -> Path:
    """Write one asset into a request-local static directory."""
    (tmp_path / "app.css").write_text("body{}")
    return tmp_path


def test_excluded_static_assets_serve_anonymously_while_application_routes_authenticate(
    static_directory: Path,
) -> None:
    app = Litestar(
        route_handlers=[_api_thing, create_static_files_router(path="/static", directories=[static_directory])],
        plugins=[SecurityPlugin(_api_team_config(exclude=["^/static"]))],
        openapi_config=OpenAPIConfig(title="Exclusion", version="1.0"),
    )

    with TestClient(app) as client:
        assert client.get("/static/app.css").status_code == 200
        assert client.get("/api/thing").status_code == 401
