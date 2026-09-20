"""Unit tests for the SQLSpec security dialect base and declarative table specs."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo
from hashlib import sha256
from types import SimpleNamespace

import pytest
from sqlglot import parse

from litestar_security.backends.sqlspec.config import SQLSpecSecurityBackendConfig
from litestar_security.backends.sqlspec.schema import (
    DEFAULT_TABLE_NAMES,
    SECURITY_TABLES,
    TABLE_ACCOUNTS,
    TABLE_OVERRIDE_FIELDS,
    TABLE_SESSIONS,
    SecurityConfigurationError,
    get_create_table_statements,
)
from litestar_security.backends.sqlspec.stores.base import SecurityDialect
from litestar_security.backends.sqlspec.stores.factory import adapter_name, create_security_dialect

_CREATE_TABLE = re.compile(r"CREATE TABLE(?: IF NOT EXISTS)? (?P<name>\S+) \((?P<body>.*?)\);", re.DOTALL)
_CONSTRAINT_PREFIXES = ("PRIMARY KEY", "UNIQUE", "FOREIGN KEY", "CONSTRAINT", "CHECK")


def _unquote(identifier: str) -> str:
    return identifier.strip('"`[]')


def _parsed_tables(statements: list[str]) -> dict[str, set[str]]:
    """Map each created table to the set of column names it declares."""
    tables: dict[str, set[str]] = {}
    for statement in statements:
        match = _CREATE_TABLE.search(statement)
        if match is None:
            continue
        columns: set[str] = set()
        for line in match.group("body").splitlines():
            entry = line.strip().rstrip(",").strip()
            if not entry or entry.upper().startswith(_CONSTRAINT_PREFIXES):
                continue
            columns.add(_unquote(entry.split()[0]))
        tables[_unquote(match.group("name"))] = columns
    return tables


class _TextDatetimeDialect(SecurityDialect):
    """Dialect that stores timestamps as ISO-like text, as SQLite does."""

    __slots__ = ()
    bind_datetime_as_text = True


class _NaiveDatetimeDialect(SecurityDialect):
    """Dialect that stores timestamps as naive UTC, as DuckDB and MySQL do."""

    __slots__ = ()
    bind_datetime_as_naive_utc = True


@pytest.fixture(scope="session")
def default_config() -> SQLSpecSecurityBackendConfig:
    """Return the immutable default backend configuration."""
    return SQLSpecSecurityBackendConfig()


@pytest.fixture
def dialect(default_config: SQLSpecSecurityBackendConfig) -> SecurityDialect:
    """Return the base dialect over default configuration."""
    return SecurityDialect(default_config)


def test_security_tables_cover_every_default_table_key() -> None:
    """Every declarative table spec corresponds to exactly one default table key."""
    assert {spec.key for spec in SECURITY_TABLES} == set(DEFAULT_TABLE_NAMES)
    assert len({spec.key for spec in SECURITY_TABLES}) == len(SECURITY_TABLES)


def test_table_override_fields_name_a_real_config_field(default_config: SQLSpecSecurityBackendConfig) -> None:
    """Every table key maps to an override attribute that exists on the config."""
    assert set(TABLE_OVERRIDE_FIELDS) == set(DEFAULT_TABLE_NAMES)
    for spec in SECURITY_TABLES:
        assert hasattr(default_config, TABLE_OVERRIDE_FIELDS[spec.key])


def test_every_table_renders_quoted(dialect: SecurityDialect, default_config: SQLSpecSecurityBackendConfig) -> None:
    """Each declared table renders as a quoted identifier."""
    for spec in SECURITY_TABLES:
        rendered = dialect.table(spec.key)
        assert rendered == f'"{default_config.table_name(spec.key)}"'


def test_unknown_table_key_raises(dialect: SecurityDialect) -> None:
    """An unknown logical table key fails closed."""
    with pytest.raises(SecurityConfigurationError):
        dialect.table("not_a_security_table")


def test_prefix_and_qualified_override_render_qualified_and_quoted() -> None:
    """A schema-qualified override quotes each part separately; a prefix is applied to defaults."""
    config = SQLSpecSecurityBackendConfig(table_prefix="app_", session_table_name="security.app_sessions")
    dialect = SecurityDialect(config)
    assert dialect.table(TABLE_SESSIONS) == '"security"."app_sessions"'
    assert dialect.table(TABLE_ACCOUNTS) == '"app_user_account"'


def test_column_map_applies_to_column_and_ddl() -> None:
    """A mapped column name is used by column() and appears in the rendered DDL."""
    config = SQLSpecSecurityBackendConfig(column_map={TABLE_ACCOUNTS: {"email": "email_address"}})
    dialect = SecurityDialect(config)
    assert dialect.column(TABLE_ACCOUNTS, "email") == '"email_address"'
    assert dialect.column(TABLE_ACCOUNTS, "name") == '"name"'

    accounts_table = config.table_name(TABLE_ACCOUNTS)
    accounts_ddl = next(stmt for stmt in dialect.create_statements() if accounts_table in stmt)
    assert '"email_address"' in accounts_ddl
    assert '"email"' not in accounts_ddl


def test_long_index_names_truncate_and_stay_unique() -> None:
    """Index names respect the identifier limit while staying distinct per table and suffix."""
    long_prefix = "extremely_long_tenant_scoped_deployment_prefix_for_testing_"
    config = SQLSpecSecurityBackendConfig(table_prefix=long_prefix)
    dialect = SecurityDialect(config)

    sessions_user = dialect.index_name(TABLE_SESSIONS, "user")
    sessions_user_exp = dialect.index_name(TABLE_SESSIONS, "user_exp")
    accounts_user = dialect.index_name(TABLE_ACCOUNTS, "user")

    for name in (sessions_user, sessions_user_exp, accounts_user):
        assert len(name.encode("utf-8")) <= 63
    assert len({sessions_user, sessions_user_exp, accounts_user}) == 3


def test_index_names_are_unique_across_every_declared_index() -> None:
    """No two declared indexes collide after truncation."""
    config = SQLSpecSecurityBackendConfig(table_prefix="extremely_long_tenant_scoped_deployment_prefix_")
    dialect = SecurityDialect(config)
    names = [dialect.index_name(spec.key, suffix) for spec in SECURITY_TABLES for suffix, _columns in spec.indexes]
    assert len(names) == len(set(names))


@pytest.mark.parametrize(
    "dialect_type", [SecurityDialect, _TextDatetimeDialect, _NaiveDatetimeDialect], ids=["native", "text", "naive_utc"]
)
def test_datetime_round_trips_as_aware_utc(
    dialect_type: type[SecurityDialect], default_config: SQLSpecSecurityBackendConfig
) -> None:
    """A bound timestamp reads back as the same aware UTC instant in every binding mode."""
    dialect = dialect_type(default_config)
    moment = datetime(2026, 9, 20, 15, 4, 5, 123456, tzinfo=timezone.utc)

    assert dialect.read_datetime(dialect.bind_datetime(moment)) == moment


@pytest.mark.parametrize(
    "dialect_type", [SecurityDialect, _TextDatetimeDialect, _NaiveDatetimeDialect], ids=["native", "text", "naive_utc"]
)
def test_datetime_binding_normalizes_offset_aware_input(
    dialect_type: type[SecurityDialect], default_config: SQLSpecSecurityBackendConfig
) -> None:
    """A non-UTC aware timestamp is normalized to UTC before binding."""
    dialect = dialect_type(default_config)
    offset_moment = datetime(2026, 9, 20, 17, 4, 5, tzinfo=timezone(timedelta(hours=2)))

    assert dialect.read_datetime(dialect.bind_datetime(offset_moment)) == offset_moment.astimezone(timezone.utc)


def test_create_statements_match_legacy_table_and_column_coverage(
    dialect: SecurityDialect, default_config: SQLSpecSecurityBackendConfig
) -> None:
    """The declarative DDL covers exactly the tables and columns the legacy SQLite DDL emits."""
    legacy = _parsed_tables(get_create_table_statements(default_config, "sqlite"))
    declarative = _parsed_tables(dialect.create_statements())

    assert set(declarative) == set(legacy)
    for table, columns in legacy.items():
        assert declarative[table] == columns


def test_drop_statements_reverse_the_create_order(dialect: SecurityDialect) -> None:
    """Tables drop in reverse creation order so foreign keys resolve."""
    created = [
        _unquote(match.group("name")) for stmt in dialect.create_statements() if (match := _CREATE_TABLE.search(stmt))
    ]
    dropped = [_unquote(stmt.split()[-1].rstrip(";")) for stmt in dialect.drop_statements()]

    assert dropped == list(reversed(created))


@pytest.mark.parametrize("key", TABLE_OVERRIDE_FIELDS)
@pytest.mark.parametrize("mode", ["default", "prefix", "override"])
def test_every_table_name_resolution(key: str, mode: str) -> None:
    options = {"table_prefix": "tenant_"} if mode == "prefix" else {}
    if mode == "override":
        options[TABLE_OVERRIDE_FIELDS[key]] = "security.custom_table"
    config = SQLSpecSecurityBackendConfig(**options)
    expected = (
        '"security"."custom_table"'
        if mode == "override"
        else f'"{"tenant_" if mode == "prefix" else ""}{DEFAULT_TABLE_NAMES[key]}"'
    )
    assert SecurityDialect(config).table(key) == expected


@pytest.mark.parametrize("suffix", ["fits", "é" * 40, "long_" * 40])
@pytest.mark.parametrize("unlimited", [False, True])
def test_index_name_byte_budget(suffix: str, default_config: SQLSpecSecurityBackendConfig, *, unlimited: bool) -> None:
    dialect = (_UnlimitedDialect if unlimited else SecurityDialect)(default_config)
    full = f"idx_{default_config.table_name(TABLE_SESSIONS)}_{suffix}"
    result = dialect.index_name(TABLE_SESSIONS, suffix)
    if unlimited or len(full.encode("utf-8")) <= 63:
        assert result == full
    else:
        prefix, digest = result.rsplit("_", 1)
        assert prefix == full.encode("utf-8")[:54].decode("utf-8", errors="ignore")
        assert digest == sha256(full.encode("utf-8")).hexdigest()[:8]
        assert len(result.encode("utf-8")) <= 63


@pytest.mark.parametrize("offset_missing", [False, True])
def test_reject_naive_datetime(dialect: SecurityDialect, *, offset_missing: bool) -> None:
    value = datetime(2026, 1, 1, tzinfo=_MissingOffset() if offset_missing else None)
    with pytest.raises(SecurityConfigurationError, match="timezone aware"):
        dialect.bind_datetime(value)


def test_primary_key_nullability_matches_legacy(dialect: SecurityDialect) -> None:
    def primary_keys(statements: list[str]) -> dict[tuple[str, str], bool]:
        result = {}
        for statement in statements:
            match = _CREATE_TABLE.search(statement)
            if match is None:
                continue
            for line in match.group("body").splitlines():
                if "PRIMARY KEY" in line and not line.strip().startswith("PRIMARY KEY"):
                    result[(_unquote(match.group("name")), _unquote(line.split()[0]))] = "NOT NULL" in line
        return result

    assert primary_keys(dialect.create_statements()) == primary_keys(
        get_create_table_statements(dialect.config, "sqlite")
    )


class _UnlimitedDialect(SecurityDialect):
    __slots__ = ()
    max_identifier_length = None


class _MissingOffset(tzinfo):
    def utcoffset(self, dt: datetime | None) -> None:
        del dt


@pytest.mark.parametrize("adapter", ["sqlite", "aiosqlite", "duckdb"])
@pytest.mark.parametrize("subclass", [False, True])
def test_factory_resolves_config_mro(adapter: str, *, subclass: bool) -> None:
    config_type = type("Config", (), {"__module__": f"sqlspec.adapters.{adapter}.config"})
    if subclass:
        config_type = type("ApplicationConfig", (config_type,), {})
    sqlspec_config = config_type()
    dialect = create_security_dialect(sqlspec_config, SQLSpecSecurityBackendConfig())
    assert adapter_name(sqlspec_config) == adapter
    assert dialect.data_dictionary_dialect == ("sqlite" if adapter == "aiosqlite" else adapter)
    assert dialect.begin_statement == ("BEGIN IMMEDIATE" if adapter == "sqlite" else None)


@pytest.mark.parametrize("adapter", ["bigquery", "", "made_up"])
def test_factory_rejects_unsupported_adapter(adapter: str) -> None:
    config_type = type("Config", (), {"__module__": f"sqlspec.adapters.{adapter}.config" if adapter else "application"})
    with pytest.raises(SecurityConfigurationError, match="Supported adapters"):
        create_security_dialect(config_type(), SQLSpecSecurityBackendConfig())


@pytest.mark.parametrize("dialect_name", ["sqlite", "duckdb", "mysql", "postgres", "unknown", None])
def test_adbc_selects_sql_behavior_without_overriding_begin(dialect_name: str | None) -> None:
    config_type = type("Config", (), {"__module__": "sqlspec.adapters.adbc.config"})
    sqlspec_config = config_type()
    sqlspec_config.statement_config = SimpleNamespace(dialect=dialect_name)
    if dialect_name not in {"sqlite", "duckdb"}:
        with pytest.raises(SecurityConfigurationError, match="ADBC"):
            create_security_dialect(sqlspec_config, SQLSpecSecurityBackendConfig())
        return
    dialect = create_security_dialect(sqlspec_config, SQLSpecSecurityBackendConfig())
    assert dialect.data_dictionary_dialect == dialect_name
    assert dialect.begin_statement is None
    assert dialect.max_identifier_length is None
    assert dialect.bind_datetime_as_text == (dialect_name == "sqlite")
    assert dialect.bind_datetime_as_naive_utc == (dialect_name == "duckdb")


@pytest.mark.parametrize("adapter", ["sqlite", "aiosqlite", "duckdb"])
def test_embedded_dialect_ddl_values_and_counter(adapter: str) -> None:
    config_type = type("Config", (), {"__module__": f"sqlspec.adapters.{adapter}.config"})
    config = SQLSpecSecurityBackendConfig(table_prefix="long_tenant_" * 12)
    dialect = create_security_dialect(config_type(), config)
    assert dialect.index_name(TABLE_SESSIONS, "user") == f"idx_{config.table_name(TABLE_SESSIONS)}_user"
    statements = dialect.create_statements()
    for statement in statements:
        assert parse(statement, read=dialect.data_dictionary_dialect)
    ddl = "\n".join(statements)
    assert ("REFERENCES" in ddl) == (adapter != "duckdb")
    assert ("ON DELETE" in ddl) == (adapter != "duckdb")
    assert ('"id" UUID PRIMARY KEY' if adapter == "duckdb" else '"id" TEXT PRIMARY KEY') in ddl
    assert ('"is_active" BOOLEAN' if adapter == "duckdb" else '"is_active" INTEGER') in ddl
    assert dialect.lock_clause() == dialect.lock_table_hint() == ""
    moment = datetime(2026, 9, 20, tzinfo=timezone(timedelta(hours=2)))
    bound = dialect.bind_datetime(moment)
    assert isinstance(bound, datetime if adapter == "duckdb" else str)
    assert dialect.read_datetime(bound) == moment.astimezone(timezone.utc)
    assert dialect.read_json(dialect.bind_json({"key": [1, True]})) == {"key": [1, True]}
    for value in (True, False):
        assert dialect.read_bool(dialect.bind_bool(value)) is value
    counter = dialect.increment_counter_sql("rate_limit_buckets", ("bucket_key", "window_start"), "count")
    table = dialect.table("rate_limit_buckets")
    assert counter.sql == (
        f'INSERT INTO {table} ("bucket_key", "window_start", "count") '  # noqa: S608 - expected quoted SQL snapshot
        'VALUES (:bucket_key, :window_start, :cost) ON CONFLICT ("bucket_key", "window_start") '
        f'DO UPDATE SET "count" = {table}."count" + :cost RETURNING "count";'
    )
    assert counter.returns_value is True
    assert parse(counter.sql, read=dialect.data_dictionary_dialect)
