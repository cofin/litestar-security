"""Shared PostgreSQL and CockroachDB security SQL behavior."""

from typing import TYPE_CHECKING

from litestar_security.backends.sqlspec.schema import TABLE_API_KEYS, TABLE_SESSIONS, TABLE_TOTP_METHODS
from litestar_security.backends.sqlspec.stores.base import SecurityDialect

if TYPE_CHECKING:
    from litestar_security.backends.sqlspec.schema import ColumnSpec, TableSpec

__all__ = ("CockroachSecurityDialect", "PostgresSecurityDialect")


class PostgresSecurityDialect(SecurityDialect):
    """Use PostgreSQL native values, row locks, and selective security indexes."""

    __slots__ = ()
    data_dictionary_dialect = "postgres"
    max_identifier_length = 63
    native_json = True
    native_bool = True
    native_uuid = True
    supports_dml_returning = True
    supports_for_update = True

    def create_statements(self) -> list[str]:
        """Include partial indexes for unrevoked keys and active TOTP methods."""
        statements = super().create_statements()
        for table_key, suffix, predicate in (
            (TABLE_API_KEYS, "active_user", f"{self.column(TABLE_API_KEYS, 'revoked_at')} IS NULL"),
            (TABLE_TOTP_METHODS, "active_user", f"{self.column(TABLE_TOTP_METHODS, 'status')} = 'active'"),
        ):
            statements.append(
                f"CREATE INDEX IF NOT EXISTS {self._quote_identifier(self.index_name(table_key, suffix))} "
                f"ON {self.table(table_key)} ({self.column(table_key, 'user_id')}) WHERE {predicate};"
            )
        return statements

    def _binary_type(self, column: "ColumnSpec") -> str:
        """Use BYTEA for binary values, including unique digests."""
        del column
        return "BYTEA"

    def _json_type(self) -> str:
        """Store structured values in JSONB."""
        return "JSONB"

    def _timestamp_type(self) -> str:
        """Store timezone-aware instants."""
        return "TIMESTAMPTZ"

    def _create_index_statement(self, table: "TableSpec", suffix: str, columns: tuple[str, ...]) -> str:
        """Render the declared session expiry index in descending expiry order."""
        if table.key != TABLE_SESSIONS or suffix != "user_exp":
            return super()._create_index_statement(table, suffix, columns)
        rendered = ", ".join(
            f"{self.column(table.key, name)} DESC" if name == "expires_at" else self.column(table.key, name)
            for name in columns
        )
        return (
            f"CREATE INDEX IF NOT EXISTS {self._quote_identifier(self.index_name(table.key, suffix))} "
            f"ON {self.table(table.key)} ({rendered});"
        )


class CockroachSecurityDialect(PostgresSecurityDialect):
    """Retain PostgreSQL SQL and conservatively retry serialization conflicts."""

    __slots__ = ()
    retry_serialization = True
