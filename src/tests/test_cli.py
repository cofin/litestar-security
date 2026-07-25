from importlib.metadata import entry_points

import click
from click.testing import CliRunner

from litestar_security import SecurityPlugin
from litestar_security._cli import register, security_group


def _root_group() -> click.Group:
    return click.Group(name="litestar")


def test_cli_entry_point_is_discoverable() -> None:
    entry_point = next(
        candidate for candidate in entry_points(group="litestar.commands") if candidate.name == "security"
    )

    assert entry_point.load() is security_group


def test_plugin_lazily_registers_security_group() -> None:
    cli = _root_group()

    SecurityPlugin().on_cli_init(cli)

    assert cli.commands["security"] is security_group


def test_security_help_output() -> None:
    cli = _root_group()
    register(cli)

    result = CliRunner().invoke(cli, ["security", "--help"])

    assert result.exit_code == 0
    assert "Litestar Security operations." in result.output
    assert "--version" in result.output


def test_security_version_output() -> None:
    cli = _root_group()
    register(cli)

    result = CliRunner().invoke(cli, ["security", "--version"])

    assert result.exit_code == 0
    assert result.output == "litestar-security, version 0.1.0\n"


def test_cli_registration_is_idempotent() -> None:
    cli = _root_group()

    register(cli)
    register(cli)
    SecurityPlugin().on_cli_init(cli)

    assert list(cli.commands) == ["security"]
