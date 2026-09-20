"""SQLite SQL and value binding for security persistence."""

from typing import TYPE_CHECKING, ClassVar

from sqlspec.utils.text import split_qualified_identifier

from litestar_security.backends.sqlspec.schema import SecurityConfigurationError
from litestar_security.backends.sqlspec.stores.base import SecurityDialect

if TYPE_CHECKING:
    from litestar_security.backends.sqlspec.schema import ColumnSpec, TableSpec

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

    def _column_definition(self, table: "TableSpec", column: "ColumnSpec") -> tuple[str, str | None]:
        """Reject references that SQLite cannot enforce across databases."""
        if column.references is not None:
            source = split_qualified_identifier(self.config.table_name(table.key))
            target = split_qualified_identifier(self.config.table_name(column.references))
            source_schema = source[0] if len(source) > 1 else "main"
            target_schema = target[0] if len(target) > 1 else "main"
            if source_schema.casefold() != target_schema.casefold():
                msg = "SQLite security tables cannot use cross-database foreign keys."
                raise SecurityConfigurationError(msg)
        return super()._column_definition(table, column)

    def _foreign_key_fragment(self, column: "ColumnSpec") -> str:
        """Reference a table within the owning SQLite database."""
        if column.references is None:
            return ""
        target = split_qualified_identifier(self.config.table_name(column.references))[-1]
        clause = f" REFERENCES {self._quote_identifier(target)} ({self.column(column.references, 'id')})"
        return f"{clause} ON DELETE CASCADE" if self.supports_fk_cascade else clause

    def _create_index_statement(self, table: "TableSpec", suffix: str, columns: tuple[str, ...]) -> str:
        """Qualify the index rather than its target table, as SQLite requires."""
        target = split_qualified_identifier(self.config.table_name(table.key))
        target_table = self._quote_identifier(target[-1])
        index = self._quote_identifier(self.index_name(table.key, suffix))
        if len(target) > 1:
            index = f"{self._quote_identifier(target[0])}.{index}"
        rendered = ", ".join(self.column(table.key, name) for name in columns)
        return f"CREATE INDEX {self._if_not_exists_fragment()}{index} ON {target_table} ({rendered});"
