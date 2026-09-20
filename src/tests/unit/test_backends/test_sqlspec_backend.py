"""Unit tests for SQLSpecSecurityBackend, session bridging, and schema bootstrap."""

from __future__ import annotations

import sqlite3
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest

from litestar_security.backends.sqlspec import SQLSpecSecurityBackend, SQLSpecSecurityBackendConfig, bridge_session


class _SyncSqliteDriver:
    """Minimal sync driver adapter wrapping sqlite3.Connection for bridging tests."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.dialect = "sqlite"

    def execute(self, statement: str, *parameters: object) -> object:
        cursor = self.connection.cursor()
        return cursor.execute(statement, parameters)

    def execute_script(self, statement: str) -> object:
        return self.connection.executescript(statement)

    def select(self, statement: str, *parameters: object) -> list[object]:
        cursor = self.connection.cursor()
        cursor.execute(statement, parameters)
        return list(cursor.fetchall())

    def select_one_or_none(self, statement: str, *parameters: object) -> object | None:
        cursor = self.connection.cursor()
        cursor.execute(statement, parameters)
        return cast("object | None", cursor.fetchone())



class _AsyncMockDriver:
    """Async mock driver fulfilling SQLSpecDriver protocol."""

    def __init__(self) -> None:
        self.dialect = "postgresql"
        self.execute = AsyncMock(return_value=None)
        self.execute_script = AsyncMock(return_value=None)
        self.select = AsyncMock(return_value=[])
        self.select_one_or_none = AsyncMock(return_value=None)


def test_backend_initialization_defaults() -> None:
    """Verify backend initializes dialect and configuration defaults."""
    driver = MagicMock()
    driver.dialect = "sqlite"
    backend = SQLSpecSecurityBackend(driver)
    assert backend.dialect == "sqlite"
    assert backend.config.table_prefix == ""

    pg_driver = MagicMock()
    pg_driver.dialect = "postgresql"
    pg_backend = SQLSpecSecurityBackend(pg_driver, SQLSpecSecurityBackendConfig(table_prefix="auth_"))
    assert pg_backend.dialect == "postgresql"
    assert pg_backend.config.table_prefix == "auth_"


@pytest.mark.anyio
async def test_bridge_session_with_async_driver() -> None:
    """Verify bridge_session yields an async driver directly."""
    driver = _AsyncMockDriver()
    async with bridge_session(driver) as session:
        await session.execute("SELECT 1")
        driver.execute.assert_awaited_once_with("SELECT 1")


@pytest.mark.anyio
async def test_bridge_session_with_async_context_manager() -> None:
    """Verify bridge_session enters and exits async context manager driver."""
    inner_driver = _AsyncMockDriver()
    cm = AsyncMock()
    cm.__aenter__.return_value = inner_driver

    async with bridge_session(cm) as session:
        await session.execute("SELECT 2")
        inner_driver.execute.assert_awaited_once_with("SELECT 2")

    cm.__aenter__.assert_awaited_once()
    cm.__aexit__.assert_awaited_once()


@pytest.mark.anyio
async def test_bridge_session_with_sync_driver() -> None:
    """Verify bridge_session wraps sync driver in managed async driver."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    sync_driver = _SyncSqliteDriver(conn)

    async with bridge_session(sync_driver) as session:
        await session.execute("CREATE TABLE test_sync (id INTEGER PRIMARY KEY, val TEXT)")
        await session.execute("INSERT INTO test_sync (val) VALUES (?)", "sample")
        rows = await session.select("SELECT val FROM test_sync")
        assert len(rows) == 1
        assert rows[0] == ("sample",)

        row = await session.select_one_or_none("SELECT val FROM test_sync WHERE id = ?", 1)
        assert row == ("sample",)


@pytest.mark.anyio
async def test_backend_create_schema_in_memory_sqlite() -> None:
    """Verify SQLSpecSecurityBackend.create_schema creates valid SQLite tables without errors."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    sync_driver = _SyncSqliteDriver(conn)
    backend = SQLSpecSecurityBackend(sync_driver)

    await backend.create_schema()

    async with backend.session() as session:
        rows = await session.select("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        table_names = [
            str(cast("tuple[object, ...]", r)[0])
            for r in rows
            if not str(cast("tuple[object, ...]", r)[0]).startswith("sqlite_")
        ]
        assert "user_account" in table_names
        assert "user_account_auth_session" in table_names
        assert "user_account_api_key" in table_names
        assert "refresh_token" in table_names
        assert len(table_names) == 14

    await backend.create_schema(drop_existing=True)

    async with backend.session() as session:
        rows = await session.select("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        table_names = [
            str(cast("tuple[object, ...]", r)[0])
            for r in rows
            if not str(cast("tuple[object, ...]", r)[0]).startswith("sqlite_")
        ]
        assert len(table_names) == 14

