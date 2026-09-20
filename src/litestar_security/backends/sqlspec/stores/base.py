"""Dialect base that owns every database-specific SQL text and value binding."""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from sqlspec.utils.text import split_qualified_identifier

from litestar_security.backends.sqlspec.schema import SECURITY_TABLES, SecurityConfigurationError, resolve_column

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar_security.backends.sqlspec.config import SQLSpecSecurityBackendConfig
    from litestar_security.backends.sqlspec.schema import ColumnSpec, TableSpec

__all__ = ("CounterStatement", "SecurityDialect")

_QUOTE_PAIRS: dict[str, tuple[str, str]] = {"double": ('"', '"'), "backtick": ("`", "`"), "bracket": ("[", "]")}
_DATETIME_TEXT_FORMAT = "%Y-%m-%d %H:%M:%S.%f+00:00"


@dataclass(frozen=True, slots=True)
class CounterStatement:
    """One dialect's way of atomically incrementing a counter column."""

    sql: str
    returns_value: bool
    followup_select: str | None = None
    fallback_insert: str | None = None
    """Run when `sql` affected zero rows."""
    retry_on_unique_violation: bool = False
    """First-insert race, as Oracle MERGE produces."""


class SecurityDialect:
    """Build the SQL text and bind the values one database understands.

    A dialect owns types, quoting, value binding, DDL, upsert, and row-lock SQL.
    Domain stores hold a resolved dialect and never branch on dialect names.
    """

    __slots__ = ("_config", "_sql_cache")

    data_dictionary_dialect: ClassVar[str | None] = None
    identifier_quote_style: ClassVar[Literal["double", "backtick", "bracket"]] = "double"
    max_identifier_length: ClassVar[int | None] = 63
    """Identifier budget in bytes, or None when the database has no practical limit.

    Each adapter declares its identifier budget or overrides index naming
    when the database uses another rule.
    """
    native_json: ClassVar[bool] = False
    native_bool: ClassVar[bool] = False
    native_uuid: ClassVar[bool] = False
    bind_datetime_as_text: ClassVar[bool] = False
    bind_datetime_as_naive_utc: ClassVar[bool] = False
    datetime_text_format: ClassVar[str] = _DATETIME_TEXT_FORMAT
    supports_dml_returning: ClassVar[bool] = False
    supports_for_update: ClassVar[bool] = False
    supports_if_not_exists: ClassVar[bool] = True
    supports_fk_cascade: ClassVar[bool] = True
    inline_unique: ClassVar[bool] = True
    begin_statement: ClassVar[str | None] = None
    """Replaces `driver.begin()` when set."""
    skip_explicit_begin: ClassVar[bool] = False
    skip_cleanup_rollback: ClassVar[bool] = False
    retry_serialization: ClassVar[bool] = False

    def __init__(self, config: "SQLSpecSecurityBackendConfig") -> None:
        """Bind the dialect to one backend configuration.

        Args:
            config: The SQLSpec security backend configuration.
        """
        self._config = config
        self._sql_cache: dict[str, Any] = {}

    @property
    def config(self) -> "SQLSpecSecurityBackendConfig":
        """Return the bound backend configuration."""
        return self._config

    def table(self, key: str) -> str:
        """Resolve and quote the physical table name for a logical table key.

        Args:
            key: Logical key identifying the target table.

        Returns:
            The quoted, possibly schema-qualified table name.

        Raises:
            SecurityConfigurationError: If the table key is unknown.
        """
        physical = self._config.table_name(key)
        return ".".join(self._quote_identifier(part) for part in split_qualified_identifier(physical))

    def column(self, key: str, logical: str) -> str:
        """Resolve and quote a physical column name for a logical column.

        Args:
            key: Logical key identifying the target table.
            logical: The logical column name used by litestar-security.

        Returns:
            The quoted physical column name.
        """
        return self._quote_identifier(resolve_column(self._config, key, logical))

    def index_name(self, table_key: str, suffix: str) -> str:
        """Build the physical index name for one declared index.

        Args:
            table_key: Logical key identifying the indexed table.
            suffix: The declared index suffix, such as "user_exp".

        Returns:
            An index name within the dialect's UTF-8 byte budget, with a stable
            digest suffix when truncation is needed.
        """
        name = f"idx_{self._config.table_name(table_key).replace('.', '_')}_{suffix}"
        encoded = name.encode("utf-8")
        limit = self.max_identifier_length
        if limit is None or len(encoded) <= limit:
            return name
        prefix = encoded[: limit - 9].decode("utf-8", errors="ignore")
        return f"{prefix}_{self._digest_suffix(name)}"

    def unique_constraint_sql(self, table: "TableSpec", column: "ColumnSpec") -> tuple[str | None, str | None]:
        """Render a single-column unique constraint.

        Args:
            table: The declared table owning the column.
            column: The declared unique column.

        Returns:
            A pair of the inline column fragment and a separate index statement.
            Exactly one element is set, so a dialect that cannot express a
            nullable unique column inline can emit a filtered index instead.
        """
        if self.inline_unique:
            return "UNIQUE", None
        index = (
            f"CREATE UNIQUE INDEX {self._if_not_exists_fragment()}"
            f"{self._quote_identifier(self.index_name(table.key, f'uq_{column.name}'))} "
            f"ON {self.table(table.key)} ({self.column(table.key, column.name)});"
        )
        return None, index

    def create_statements(self) -> list[str]:
        """Render every DDL statement that creates the security schema.

        Returns:
            The CREATE TABLE and CREATE INDEX statements in dependency order.
        """
        cached: list[str] | None = self._sql_cache.get("create")
        if cached is not None:
            return list(cached)

        statements: list[str] = []
        for table in SECURITY_TABLES:
            create, separate_indexes = self._create_table_statement(table)
            statements.append(create)
            statements.extend(separate_indexes)
            statements.extend(self._create_index_statement(table, suffix, columns) for suffix, columns in table.indexes)
        self._sql_cache["create"] = statements
        return list(statements)

    def drop_statements(self) -> list[str]:
        """Render every DDL statement that drops the security schema.

        Returns:
            The DROP TABLE statements in reverse dependency order.
        """
        cached: list[str] | None = self._sql_cache.get("drop")
        if cached is not None:
            return list(cached)

        exists = "IF EXISTS " if self.supports_if_not_exists else ""
        statements = [f"DROP TABLE {exists}{self.table(table.key)};" for table in reversed(SECURITY_TABLES)]
        self._sql_cache["drop"] = statements
        return list(statements)

    async def create_schema(self, driver: Any) -> None:  # noqa: ANN401 - SQLSpec adapters expose heterogeneous execute signatures
        """Execute every create statement one by one.

        Override for databases whose DDL cannot run on a session.

        Args:
            driver: The SQLSpec driver to execute against.
        """
        for statement in self.create_statements():
            await driver.execute(statement)

    async def drop_schema(self, driver: Any) -> None:  # noqa: ANN401 - SQLSpec adapters expose heterogeneous execute signatures
        """Execute every drop statement one by one.

        Override for databases whose DDL cannot run on a session.

        Args:
            driver: The SQLSpec driver to execute against.
        """
        for statement in self.drop_statements():
            await driver.execute(statement)

    def bind_datetime(self, value: datetime) -> datetime | str:
        """Convert an aware timestamp into the value this database stores.

        Args:
            value: The timestamp to bind.

        Returns:
            The bound value, normalized to UTC.

        Raises:
            SecurityConfigurationError: If the timestamp is naive.
        """
        if value.tzinfo is None or value.utcoffset() is None:
            msg = "Security timestamps must be timezone aware."
            raise SecurityConfigurationError(msg)
        utc_value = value.astimezone(timezone.utc)
        if self.bind_datetime_as_text:
            return utc_value.strftime(self.datetime_text_format)
        if self.bind_datetime_as_naive_utc:
            return utc_value.replace(tzinfo=None)
        return utc_value

    def read_datetime(self, value: object) -> datetime:
        """Convert a stored timestamp back into an aware UTC timestamp.

        Args:
            value: The stored value.

        Returns:
            The timestamp as aware UTC.

        Raises:
            SecurityConfigurationError: If the stored value is not a timestamp.
        """
        if isinstance(value, str):
            return datetime.strptime(value, self.datetime_text_format).replace(tzinfo=timezone.utc)
        if not isinstance(value, datetime):
            msg = f"Expected a stored timestamp, got {type(value).__name__}."
            raise SecurityConfigurationError(msg)
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def bind_json(self, value: object) -> object:
        """Convert a Python container into the value this database stores.

        Args:
            value: The container to bind.

        Returns:
            The bound value.
        """
        return value if self.native_json else json.dumps(value)

    def read_json(self, value: object) -> object:
        """Convert a stored JSON document back into a Python container.

        Args:
            value: The stored value.

        Returns:
            The decoded container.
        """
        if isinstance(value, (str, bytes)):
            return json.loads(value)
        return value

    def bind_bool(self, value: bool) -> bool | int:  # noqa: FBT001 - value conversion, not a behavior flag
        """Convert a boolean into the value this database stores.

        Args:
            value: The boolean to bind.

        Returns:
            The bound value.
        """
        return value if self.native_bool else int(value)

    def read_bool(self, value: object) -> bool:
        """Convert a stored boolean back into a Python boolean.

        Args:
            value: The stored value.

        Returns:
            The decoded boolean.
        """
        return bool(value)

    def read_bytes(self, value: bytes | bytearray | memoryview | str) -> bytes:
        """Convert a stored binary column back into bytes.

        Args:
            value: The stored value.

        Returns:
            The decoded bytes.
        """
        if isinstance(value, bytes):
            return value
        if isinstance(value, memoryview):
            return value.tobytes()
        if isinstance(value, str):
            return value.encode("utf-8")
        return bytes(value)

    def increment_counter_sql(
        self, table_key: str, key_columns: "Sequence[str]", counter_column: str
    ) -> CounterStatement:
        """Render the atomic counter increment for one table.

        Args:
            table_key: Logical key identifying the counter table.
            key_columns: The logical columns identifying one counter row.
            counter_column: The logical counter column to increment.

        Returns:
            The dialect's counter statement.
        """
        table = self.table(table_key)
        counter = self.column(table_key, counter_column)
        keys = [self.column(table_key, name) for name in key_columns]
        insert_columns = ", ".join([*keys, counter])
        insert_values = ", ".join([*(f":{name}" for name in key_columns), ":cost"])
        conflict = ", ".join(keys)
        return CounterStatement(
            sql=(
                f"INSERT INTO {table} ({insert_columns}) VALUES ({insert_values}) "
                f"ON CONFLICT ({conflict}) DO UPDATE SET {counter} = {table}.{counter} + :cost "
                f"RETURNING {counter};"
            ),
            returns_value=True,
        )

    def lock_clause(self) -> str:
        """Return the row-lock clause appended to a SELECT."""
        return " FOR UPDATE" if self.supports_for_update else ""

    def lock_table_hint(self) -> str:
        """Return the table hint that locks selected rows, where one is needed."""
        return ""

    def _quote_identifier(self, name: str) -> str:
        """Quote one unqualified identifier part in this dialect's style.

        Args:
            name: The identifier part to quote.

        Returns:
            The quoted identifier.
        """
        opening, closing = _QUOTE_PAIRS[self.identifier_quote_style]
        return f"{opening}{name.replace(closing, closing * 2)}{closing}"

    def _uuid_type(self) -> str:
        """Return the column type for account identifiers."""
        return "UUID" if self.native_uuid else "VARCHAR(36)"

    def _id_type(self) -> str:
        """Return the column type for opaque string identifiers."""
        return "VARCHAR(64)"

    def _string_type(self, length: int | None) -> str:
        """Return the column type for a bounded string.

        Args:
            length: The declared maximum length, if any.

        Returns:
            The column type.
        """
        return f"VARCHAR({length})" if length is not None else self._text_type()

    def _text_type(self) -> str:
        """Return the column type for unbounded text."""
        return "TEXT"

    def _integer_type(self) -> str:
        """Return the column type for 32-bit integers."""
        return "INTEGER"

    def _bigint_type(self) -> str:
        """Return the column type for 64-bit integers."""
        return "BIGINT"

    def _bool_type(self) -> str:
        """Return the column type for booleans."""
        return "BOOLEAN" if self.native_bool else "SMALLINT"

    def _binary_type(self, column: "ColumnSpec") -> str:
        """Return the column type for binary digests and ciphertext.

        Args:
            column: The declared column, so a dialect can pick an indexable type
                for unique digests.

        Returns:
            The column type.
        """
        del column
        return "BLOB"

    def _json_type(self) -> str:
        """Return the column type for JSON documents."""
        return "JSON" if self.native_json else "TEXT"

    def _timestamp_type(self) -> str:
        """Return the column type for timestamps."""
        return "TIMESTAMP"

    def _default_sql(self, column: "ColumnSpec") -> str | None:
        """Return the DEFAULT expression for one declared column.

        Args:
            column: The declared column.

        Returns:
            The default expression, or None when the column has no default.
        """
        if column.default is None:
            return None
        if column.default == "now":
            return "CURRENT_TIMESTAMP"
        if column.default == "true":
            return "TRUE" if self.native_bool else "1"
        if column.default == "false":
            return "FALSE" if self.native_bool else "0"
        if column.default == "zero":
            return "0"
        if column.default == "one":
            return "1"
        if column.default == "five":
            return "5"
        if column.default == "empty_object":
            return "'{}'"
        if column.default == "empty_array":
            return "'[]'"
        return f"'{column.default}'"

    def _table_constraints(self, table: "TableSpec") -> tuple[str, ...]:
        """Return additional table-level constraints required by the dialect."""
        del table
        return ()

    def _digest_suffix(self, value: str) -> str:
        """Return a stable 8-character hexadecimal digest of an identifier.

        Args:
            value: The full, untruncated identifier.

        Returns:
            The first 8 hexadecimal characters of its SHA-256 digest.
        """
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]

    def _column_type(self, column: "ColumnSpec") -> str:
        """Return the rendered type for one declared column.

        Args:
            column: The declared column.

        Returns:
            The dialect's column type.
        """
        if column.kind == "uuid":
            return self._uuid_type()
        if column.kind == "id":
            return self._id_type()
        if column.kind == "string":
            return self._string_type(column.length)
        if column.kind == "text":
            return self._text_type()
        if column.kind == "int":
            return self._integer_type()
        if column.kind == "bigint":
            return self._bigint_type()
        if column.kind == "bool":
            return self._bool_type()
        if column.kind == "binary":
            return self._binary_type(column)
        if column.kind == "json":
            return self._json_type()
        return self._timestamp_type()

    def _if_not_exists_fragment(self) -> str:
        """Return the IF NOT EXISTS fragment when the dialect supports it."""
        return "IF NOT EXISTS " if self.supports_if_not_exists else ""

    def _foreign_key_fragment(self, column: "ColumnSpec") -> str:
        """Render the inline foreign key clause for one column.

        Args:
            column: The declared column carrying a reference.

        Returns:
            The rendered clause, or an empty string when the column has none.
        """
        if column.references is None:
            return ""
        clause = f" REFERENCES {self.table(column.references)} ({self.column(column.references, 'id')})"
        return f"{clause} ON DELETE CASCADE" if self.supports_fk_cascade else clause

    def _column_definition(self, table: "TableSpec", column: "ColumnSpec") -> tuple[str, str | None]:
        """Render one column definition line.

        Args:
            table: The declared table owning the column.
            column: The declared column.

        Returns:
            A pair of the definition line and any separate unique index statement.
        """
        parts = [self.column(table.key, column.name), self._column_type(column)]
        if not column.nullable:
            parts.append("NOT NULL")
        if column.primary_key:
            parts.append("PRIMARY KEY")

        separate_index: str | None = None
        if column.unique:
            inline, separate_index = self.unique_constraint_sql(table, column)
            if inline is not None:
                parts.append(inline)

        default = self._default_sql(column)
        if default is not None:
            parts.append(f"DEFAULT {default}")

        foreign_key = self._foreign_key_fragment(column)
        return f"{' '.join(parts)}{foreign_key}", separate_index

    def _create_table_statement(self, table: "TableSpec") -> tuple[str, list[str]]:
        """Render the CREATE TABLE statement for one declared table.

        Args:
            table: The declared table.

        Returns:
            A pair of the statement and any separate unique index statements.
        """
        entries: list[str] = []
        separate_indexes: list[str] = []
        for column in table.columns:
            definition, separate_index = self._column_definition(table, column)
            entries.append(definition)
            if separate_index is not None:
                separate_indexes.append(separate_index)

        if table.primary_key:
            columns = ", ".join(self.column(table.key, name) for name in table.primary_key)
            entries.append(f"PRIMARY KEY ({columns})")
        for unique_columns in table.unique:
            columns = ", ".join(self.column(table.key, name) for name in unique_columns)
            entries.append(f"UNIQUE ({columns})")
        entries.extend(self._table_constraints(table))

        body = ",\n    ".join(entries)
        statement = f"CREATE TABLE {self._if_not_exists_fragment()}{self.table(table.key)} (\n    {body}\n);"
        return statement, separate_indexes

    def _create_index_statement(self, table: "TableSpec", suffix: str, columns: tuple[str, ...]) -> str:
        """Render one declared secondary index.

        Args:
            table: The declared table.
            suffix: The declared index suffix.
            columns: The logical column names to index.

        Returns:
            The CREATE INDEX statement.
        """
        rendered = ", ".join(self.column(table.key, name) for name in columns)
        return (
            f"CREATE INDEX {self._if_not_exists_fragment()}"
            f"{self._quote_identifier(self.index_name(table.key, suffix))} "
            f"ON {self.table(table.key)} ({rendered});"
        )
