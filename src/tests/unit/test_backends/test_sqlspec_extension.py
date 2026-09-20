"""Unit tests for SQLSpec migration extension and schema generation."""

from __future__ import annotations

import importlib
from unittest.mock import MagicMock

import pytest

from litestar_security.backends.sqlspec import (
    SECURITY_EXTENSION_NAME,
    TABLE_ACCOUNTS,
    TABLE_API_KEYS,
    TABLE_REFRESH_TOKENS,
    TABLE_SESSIONS,
    SQLSpecSecurityBackendConfig,
    configure_security_migration_extension,
    get_create_table_statements,
    get_drop_table_statements,
    security_migration_directory,
)

migration = importlib.import_module("litestar_security.backends.sqlspec.migrations.20260401000000_litestar_security")


def test_security_migration_directory_exists() -> None:
    """Verify the migration directory exists and contains the migration file."""
    mig_dir = security_migration_directory()
    assert mig_dir.is_dir()
    assert (mig_dir / "20260401000000_litestar_security.py").is_file()


def test_configure_security_migration_extension_registers() -> None:
    """Verify configure_security_migration_extension registers migrations when manage_schema is True."""
    mock_sqlspec_config = MagicMock()
    mock_sqlspec_config.extension_config = {}

    security_config = SQLSpecSecurityBackendConfig(table_prefix="sec_")
    configure_security_migration_extension(mock_sqlspec_config, security_config)

    mock_sqlspec_config.add_extension_migrations.assert_called_once()
    args, _ = mock_sqlspec_config.add_extension_migrations.call_args
    assert args[0] == SECURITY_EXTENSION_NAME
    assert args[1] == security_migration_directory()
    settings = args[2]
    assert settings["table_prefix"] == "sec_"
    assert settings["tables"][TABLE_ACCOUNTS] == "sec_user_account"
    assert mock_sqlspec_config.extension_config[SECURITY_EXTENSION_NAME] == settings


def test_configure_security_migration_extension_removes_when_unmanaged() -> None:
    """Verify configure_security_migration_extension removes registrations when manage_schema is False."""
    mock_sqlspec_config = MagicMock()
    security_config = SQLSpecSecurityBackendConfig(manage_schema=False)
    configure_security_migration_extension(mock_sqlspec_config, security_config)

    mock_sqlspec_config.remove_extension_migrations.assert_called_once_with(SECURITY_EXTENSION_NAME)


@pytest.mark.anyio
async def test_migration_up_and_down_sqlite() -> None:
    """Verify migration up and down functions produce valid SQLite DDL."""
    mock_context = MagicMock()
    mock_context.dialect = "sqlite"
    mock_context.extension_config = {}

    statements = await migration.up(mock_context)
    assert len(statements) >= 20
    joined = "\n".join(statements)
    assert "CREATE TABLE IF NOT EXISTS user_account (" in joined
    assert "CREATE TABLE IF NOT EXISTS user_account_auth_session (" in joined
    assert "CREATE TABLE IF NOT EXISTS refresh_token (" in joined

    drop_statements = await migration.down(mock_context)
    assert len(drop_statements) == 14
    assert drop_statements[0] == "DROP TABLE IF EXISTS refresh_token;"
    assert drop_statements[-1] == "DROP TABLE IF EXISTS user_account;"


@pytest.mark.anyio
async def test_migration_up_and_down_postgres() -> None:
    """Verify migration up and down functions produce valid PostgreSQL DDL with JSONB and CASCADE."""
    mock_context = MagicMock()
    mock_context.dialect = "postgresql"
    mock_context.extension_config = {
        SECURITY_EXTENSION_NAME: {
            "table_prefix": "test_",
            "tables": {
                TABLE_ACCOUNTS: "test_user_account",
                TABLE_SESSIONS: "test_user_account_auth_session",
                TABLE_API_KEYS: "test_user_account_api_key",
                TABLE_REFRESH_TOKENS: "test_refresh_token",
            },
            "native_json_columns": True,
        }
    }

    statements = await migration.up(mock_context)
    joined = "\n".join(statements)
    assert "CREATE TABLE IF NOT EXISTS test_user_account (" in joined
    assert "UUID PRIMARY KEY" in joined
    assert "JSONB" in joined
    assert "TIMESTAMPTZ" in joined

    drop_statements = await migration.down(mock_context)
    assert len(drop_statements) == 14
    assert drop_statements[0] == "DROP TABLE IF EXISTS test_refresh_token CASCADE;"
    assert drop_statements[-1] == "DROP TABLE IF EXISTS test_user_account CASCADE;"


def test_schema_get_create_and_drop_statements() -> None:
    """Verify direct calls to get_create_table_statements and get_drop_table_statements."""
    config = SQLSpecSecurityBackendConfig()
    create_stmts = get_create_table_statements(config, dialect="sqlite")
    assert len(create_stmts) >= 20

    drop_stmts = get_drop_table_statements(config, dialect="sqlite")
    assert len(drop_stmts) == 14
