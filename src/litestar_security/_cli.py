"""CLI commands for Litestar Security."""

from typing import TYPE_CHECKING

import click

from litestar_security.__metadata__ import __project__, __version__

if TYPE_CHECKING:
    from click import Group

__all__ = ("register", "security_group")


@click.group(name="security", help="Litestar Security operations.", no_args_is_help=True)
@click.version_option(version=__version__, prog_name=__project__)
def security_group() -> None:
    """Manage Litestar Security integrations."""


def register(cli: "Group") -> None:
    """Attach the security command group to a Click group once.

    Args:
        cli: The Click group to attach to. Calling this repeatedly is safe.
    """
    if security_group.name not in cli.commands:
        cli.add_command(security_group)
