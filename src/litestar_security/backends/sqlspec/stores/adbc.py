"""Resolve ADBC SQL behavior without importing an ADBC driver."""

from typing import TYPE_CHECKING

from litestar_security.backends.sqlspec.schema import SecurityConfigurationError
from litestar_security.backends.sqlspec.stores._postgres import PostgresSecurityDialect
from litestar_security.backends.sqlspec.stores.duckdb import DuckDBSecurityDialect
from litestar_security.backends.sqlspec.stores.sqlite import SQLiteSecurityDialect

if TYPE_CHECKING:
    from litestar_security.backends.sqlspec.config import SQLSpecSecurityBackendConfig
    from litestar_security.backends.sqlspec.stores.base import SecurityDialect

__all__ = ("create_adbc_dialect",)


def create_adbc_dialect(sqlspec_config: object, config: "SQLSpecSecurityBackendConfig") -> "SecurityDialect":
    """Select explicit ADBC statement dialect behavior, or reject it."""
    statement_config = getattr(sqlspec_config, "statement_config", None)
    dialect = getattr(statement_config, "dialect", None)
    dialect_type = _ADBC_DIALECTS.get(dialect) if isinstance(dialect, str) else None
    if dialect_type is None:
        supported = ", ".join(sorted(_ADBC_DIALECTS))
        msg = f"ADBC dialect {dialect!r} is not supported by the security backend. Supported dialects: {supported}."
        raise SecurityConfigurationError(msg)
    return dialect_type(config)


class _ADBCSQLiteDialect(SQLiteSecurityDialect):
    __slots__ = ()
    begin_statement = None


class _ADBCDuckDBDialect(DuckDBSecurityDialect):
    __slots__ = ()
    begin_statement = None


class _ADBCPostgresDialect(PostgresSecurityDialect):
    __slots__ = ()
    begin_statement = None


_ADBC_DIALECTS: "dict[str, type[SecurityDialect]]" = {
    "sqlite": _ADBCSQLiteDialect,
    "duckdb": _ADBCDuckDBDialect,
    "postgres": _ADBCPostgresDialect,
}
