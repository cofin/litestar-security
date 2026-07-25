"""Litestar Security plugin integration."""

from typing import TYPE_CHECKING

from litestar.plugins import CLIPlugin, InitPlugin

from litestar_security.config import SecurityConfig

if TYPE_CHECKING:
    from click import Group as ClickGroup
    from litestar.config.app import AppConfig

__all__ = ("SecurityPlugin",)


class SecurityPlugin(InitPlugin, CLIPlugin):
    """Expose the Litestar Security configuration and CLI integration points."""

    __slots__ = ("config",)

    def __init__(self, config: SecurityConfig | None = None) -> None:
        """Initialize the plugin."""
        self.config = config if config is not None else SecurityConfig()

    def on_app_init(self, app_config: "AppConfig") -> "AppConfig":
        """Return the application configuration unchanged."""
        return app_config

    def on_cli_init(self, cli: "ClickGroup") -> None:
        """Attach the security command group to the Litestar CLI."""
        from litestar_security._cli import register  # noqa: PLC0415

        register(cli)
