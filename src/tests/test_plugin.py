import sys

from litestar import Litestar
from litestar.config.app import AppConfig
from litestar.plugins import CLIPlugin, CLIPluginProtocol, InitPlugin

from litestar_security import SecurityConfig, SecurityPlugin


def test_plugin_constructs_default_config() -> None:
    plugin = SecurityPlugin()

    assert isinstance(plugin.config, SecurityConfig)


def test_plugin_preserves_supplied_config_by_identity() -> None:
    config = SecurityConfig()

    assert SecurityPlugin(config).config is config


def test_plugin_is_an_init_and_cli_plugin() -> None:
    plugin = SecurityPlugin()
    app = Litestar(plugins=[plugin])

    assert isinstance(plugin, InitPlugin)
    assert isinstance(plugin, CLIPlugin)
    assert isinstance(plugin, CLIPluginProtocol)
    assert any(registered is plugin for registered in app.plugins.cli)


def test_plugin_returns_app_config_unchanged() -> None:
    plugin = SecurityPlugin()
    app_config = AppConfig()

    assert plugin.on_app_init(app_config) is app_config


def test_importing_plugin_does_not_import_private_cli() -> None:
    sys.modules.pop("litestar_security._cli", None)

    SecurityPlugin()

    assert "litestar_security._cli" not in sys.modules
