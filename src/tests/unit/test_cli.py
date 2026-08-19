"""Unit contracts for the security CLI command group."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from click.testing import CliRunner
from litestar import Litestar, Router, get
from litestar.cli._utils import LitestarEnv
from litestar.cli.main import litestar_group
from litestar.openapi.spec import SecurityScheme

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security.authentication import (
    Authenticated,
    AuthenticationEvidence,
    AuthenticationMechanism,
    NoCredentials,
    PresentedCredential,
    public,
)
from litestar_security.context import Principal
from litestar_security.guards import requires_role


class _Slot:
    name = "slot-api-key"

    def extract(self, connection: Any) -> object:
        value = cast("str | None", connection.headers.get("x-api-key"))
        return PresentedCredential("user") if value else NoCredentials()


class _Authenticator:
    participates_by_default = True
    name = "api-key"
    slot = "slot-api-key"

    async def authenticate(self, credential: object, _connection: object) -> "Authenticated[str]":
        return Authenticated(
            claims=cast("str", credential),
            evidence=AuthenticationEvidence(
                mechanism=self.name, slot=self.slot, authenticated_at=datetime(2026, 8, 4, tzinfo=timezone.utc)
            ),
        )


class _Resolver:
    async def resolve(self, claims: str) -> "Principal[object]":
        return Principal(id=claims)


def _config(**kwargs: Any) -> SecurityConfig[object]:
    return SecurityConfig(
        slots=(_Slot(),),  # type: ignore[arg-type]
        mechanisms=(
            AuthenticationMechanism(
                authenticator=_Authenticator(),  # type: ignore[arg-type]
                resolver=_Resolver(),
                scheme_name="api-key",
                security_scheme=SecurityScheme(type="http", scheme="bearer"),
            ),
        ),
        **kwargs,
    )


@get("/api/me", sync_to_thread=False)
def _protected() -> str:
    return "me"


@get("/login", auth=public(), sync_to_thread=False)
def _public_route() -> str:
    return "login"


@get("/assets/app.css", opt={"exclude_from_auth": True}, sync_to_thread=False)
def _asset() -> str:
    return "css"


@get("/guarded/asset.css", opt={"exclude_from_auth": True}, sync_to_thread=False)
def _guarded_asset() -> str:
    return "css"


def _app(**kwargs: Any) -> Litestar:
    return Litestar(
        route_handlers=[
            _protected,
            _public_route,
            _asset,
            Router(path="/guarded", route_handlers=[_guarded_asset], guards=[requires_role("admin")]),
        ],
        openapi_config=None,
        plugins=[SecurityPlugin(_config(**kwargs))],
    )


def _run(app: Litestar, *args: str) -> Any:
    runner = CliRunner()
    env = LitestarEnv(app_path="", app=app, cwd=Path.cwd(), is_app_factory=False)
    return runner.invoke(litestar_group, ["security", *args], obj=env)


def test_routes_command_reports_compiled_posture_for_every_route() -> None:
    result = _run(_app(), "routes")

    assert result.exit_code == 0, result.output
    assert "/api/me" in result.output
    assert "required" in result.output
    assert "/login" in result.output
    assert "public" in result.output
    assert "/assets/app.css" in result.output
    assert "exclude" in result.output


def test_routes_command_flags_an_excluded_route_that_inherits_guards() -> None:
    """Guards are cumulative, so an excluded route under a guard is still denied."""
    result = _run(_app(), "routes")

    assert result.exit_code == 0, result.output
    assert "1 excluded route carries inherited guards" in result.output


def test_routes_command_summary_counts_routes_and_exclusions() -> None:
    result = _run(_app(), "routes")

    assert result.exit_code == 0, result.output
    assert "2 excluded" in result.output


def test_routes_command_runs_without_configured_mechanisms() -> None:
    app = Litestar(route_handlers=[_protected], openapi_config=None, plugins=[SecurityPlugin(SecurityConfig())])

    result = _run(app, "routes")

    assert result.exit_code == 0, result.output
    assert "public" in result.output


def test_routes_command_receives_the_application_from_the_root_cli_group() -> None:
    """The group is a `litestar.commands` entry point, so Litestar injects `app`."""
    app = _app()

    result = _run(app, "routes")

    assert result.exit_code == 0, result.output
    assert "/api/me" in result.output
