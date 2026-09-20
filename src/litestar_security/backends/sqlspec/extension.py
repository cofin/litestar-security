"""SQLSpec migration extension configuration for Litestar Security."""

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from litestar_security.backends.sqlspec._typing import SQLSpecConfig
    from litestar_security.backends.sqlspec.config import SQLSpecSecurityBackendConfig

__all__ = ("SECURITY_EXTENSION_NAME", "configure_security_migration_extension", "security_migration_directory")

SECURITY_EXTENSION_NAME = "litestar_security"


def security_migration_directory() -> "Path":
    """Return the security extension migration directory."""
    return Path(__file__).parent / "migrations"


def configure_security_migration_extension(
    sqlspec_config: "SQLSpecConfig", security_config: "SQLSpecSecurityBackendConfig"
) -> "None":
    """Register or remove the packaged security migrations with SQLSpec's extension runner.

    When security_config.manage_schema is True, registers the migration path and settings
    so that SQLSpec executes migrations during migrate-up.
    When security_config.manage_schema is False, declares that the application owns its
    database schema, removing any registered extension migrations for litestar_security.

    Args:
        sqlspec_config: The SQLSpec configuration object.
        security_config: The SQLSpec security backend configuration.
    """
    if not security_config.manage_schema:
        if hasattr(sqlspec_config, "remove_extension_migrations"):
            sqlspec_config.remove_extension_migrations(SECURITY_EXTENSION_NAME)
        return

    settings = {
        "table_prefix": security_config.table_prefix,
        "tables": security_config.all_table_names(),
        "column_map": dict(security_config.column_map),
        "native_json_columns": security_config.native_json_columns,
    }
    extension_config = dict(getattr(sqlspec_config, "extension_config", None) or {})
    extension_config[SECURITY_EXTENSION_NAME] = settings
    sqlspec_config.extension_config = extension_config
    if hasattr(sqlspec_config, "add_extension_migrations"):
        sqlspec_config.add_extension_migrations(SECURITY_EXTENSION_NAME, security_migration_directory(), settings)
