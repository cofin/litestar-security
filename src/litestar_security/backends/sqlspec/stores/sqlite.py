"""SQLite SQL and value binding for security persistence."""

from typing import ClassVar

from litestar_security.backends.sqlspec.stores.base import SecurityDialect

__all__ = ("SQLiteSecurityDialect",)


class SQLiteSecurityDialect(SecurityDialect):
    """Use text timestamps and reserve the writer before transactional work."""

    __slots__ = ()
    data_dictionary_dialect = "sqlite"
    max_identifier_length = None
    bind_datetime_as_text = True
    supports_dml_returning = True
    begin_statement: ClassVar[str | None] = "BEGIN IMMEDIATE"

    def _uuid_type(self) -> str:
        """Store UUIDs using SQLite text affinity."""
        return "TEXT"

    def _id_type(self) -> str:
        """Store opaque identifiers using text affinity."""
        return "TEXT"

    def _string_type(self, length: int | None) -> str:
        """Use text affinity without claiming SQLite enforces a length."""
        del length
        return "TEXT"

    def _bool_type(self) -> str:
        """Store boolean values as integers."""
        return "INTEGER"

    def _timestamp_type(self) -> str:
        """Store normalized UTC timestamp strings."""
        return "TEXT"
