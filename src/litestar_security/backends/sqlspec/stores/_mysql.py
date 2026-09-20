"""Shared MySQL and MariaDB security SQL behavior."""

from typing import TYPE_CHECKING

from litestar_security.backends.sqlspec.stores.base import CounterStatement, SecurityDialect

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar_security.backends.sqlspec.schema import ColumnSpec, TableSpec

__all__ = ("MySQLSecurityDialect",)


class MySQLSecurityDialect(SecurityDialect):
    """Render InnoDB tables, explicit foreign keys, and atomic counter upserts."""

    __slots__ = ()
    data_dictionary_dialect = "mysql"
    identifier_quote_style = "backtick"
    max_identifier_length = 64
    bind_datetime_as_naive_utc = True
    native_json = True
    supports_for_update = True

    def increment_counter_sql(
        self, table_key: str, key_columns: "Sequence[str]", counter_column: str
    ) -> CounterStatement:
        """Increment without deprecated VALUES accessors, then select the count."""
        table = self.table(table_key)
        counter = self.column(table_key, counter_column)
        keys = [self.column(table_key, name) for name in key_columns]
        columns = ", ".join([*keys, counter])
        values = ", ".join([*(f":{name}" for name in key_columns), ":cost"])
        predicate = " AND ".join(f"{self.column(table_key, name)} = :{name}" for name in key_columns)
        return CounterStatement(
            sql=(
                f"INSERT INTO {table} ({columns}) VALUES ({values}) "
                f"ON DUPLICATE KEY UPDATE {counter} = {counter} + :cost;"
            ),
            returns_value=False,
            followup_select=f"SELECT {counter} FROM {table} WHERE {predicate};",
        )

    def _binary_type(self, column: "ColumnSpec") -> str:
        """Use an indexable bounded type for unique digests."""
        return "VARBINARY(255)" if column.unique else "BLOB"

    def _timestamp_type(self) -> str:
        """Preserve microsecond precision in naive UTC values."""
        return "DATETIME(6)"

    def _default_sql(self, column: "ColumnSpec") -> str | None:
        """Require callers to bind JSON rather than using literal defaults."""
        return None if column.kind == "json" else super()._default_sql(column)

    def _table_constraints(self, table: "TableSpec") -> tuple[str, ...]:
        """Use enforced foreign-key constraints instead of ignored inline references."""
        return tuple(
            f"FOREIGN KEY ({self.column(table.key, column.name)}) "
            f"REFERENCES {self.table(column.references)} ({self.column(column.references, 'id')}) ON DELETE CASCADE"
            for column in table.columns
            if column.references is not None
        )

    def _foreign_key_fragment(self, column: "ColumnSpec") -> str:
        """Suppress inline references; table-level constraints enforce them."""
        del column
        return ""

    def _create_table_statement(self, table: "TableSpec") -> tuple[str, list[str]]:
        """Select InnoDB and utf8mb4 while retaining idempotent table creation."""
        statement, indexes = super()._create_table_statement(table)
        return f"{statement.removesuffix(';')} ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;", indexes

    def _create_index_statement(self, table: "TableSpec", suffix: str, columns: tuple[str, ...]) -> str:
        """Omit unsupported index-level IF NOT EXISTS."""
        statement = super()._create_index_statement(table, suffix, columns)
        return statement.replace("CREATE INDEX IF NOT EXISTS ", "CREATE INDEX ", 1)
