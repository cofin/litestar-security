"""Async SQLite behavior with driver-owned transaction initiation."""

from litestar_security.backends.sqlspec.stores.sqlite import SQLiteSecurityDialect

__all__ = ("AiosqliteSecurityDialect",)


class AiosqliteSecurityDialect(SQLiteSecurityDialect):
    """Let the aiosqlite driver issue its own BEGIN IMMEDIATE."""

    __slots__ = ()
    begin_statement = None
