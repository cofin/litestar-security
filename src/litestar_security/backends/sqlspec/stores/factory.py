"""Fail-closed dispatch from SQLSpec config identity to security SQL behavior."""

from typing import TYPE_CHECKING

from litestar_security.backends.sqlspec.schema import SecurityConfigurationError
from litestar_security.backends.sqlspec.stores.adbc import create_adbc_dialect
from litestar_security.backends.sqlspec.stores.aiosqlite import AiosqliteSecurityDialect
from litestar_security.backends.sqlspec.stores.asyncpg import AsyncpgSecurityDialect
from litestar_security.backends.sqlspec.stores.base import SecurityDialect
from litestar_security.backends.sqlspec.stores.cockroach_asyncpg import CockroachAsyncpgSecurityDialect
from litestar_security.backends.sqlspec.stores.cockroach_psycopg import (
    CockroachPsycopgAsyncSecurityDialect,
    CockroachPsycopgSyncSecurityDialect,
)
from litestar_security.backends.sqlspec.stores.duckdb import DuckDBSecurityDialect
from litestar_security.backends.sqlspec.stores.psqlpy import PsqlpySecurityDialect
from litestar_security.backends.sqlspec.stores.psycopg import PsycopgAsyncSecurityDialect, PsycopgSyncSecurityDialect
from litestar_security.backends.sqlspec.stores.sqlite import SQLiteSecurityDialect

if TYPE_CHECKING:
    from litestar_security.backends.sqlspec.config import SQLSpecSecurityBackendConfig

__all__ = ("adapter_name", "create_security_dialect")


def adapter_name(config: object) -> str:
    """Find the adapter in the config MRO, including application subclasses."""
    for config_type in type(config).__mro__:
        if config_type.__module__.startswith("sqlspec.adapters."):
            return config_type.__module__.split(".")[2]
    return ""


def create_security_dialect(sqlspec_config: object, config: "SQLSpecSecurityBackendConfig") -> SecurityDialect:
    """Resolve a supported config without guessing from an unknown adapter."""
    name = adapter_name(sqlspec_config)
    if name == "adbc":
        return create_adbc_dialect(sqlspec_config, config)
    dialect_type = _DIALECTS.get(name)
    if dialect_type is None:
        supported = ", ".join(sorted((*_DIALECTS, "adbc")))
        msg = f"SQLSpec adapter {name!r} is not supported by the security backend. Supported adapters: {supported}."
        raise SecurityConfigurationError(msg)
    if isinstance(dialect_type, tuple):
        dialect_type = dialect_type[0] if getattr(sqlspec_config, "is_async", False) else dialect_type[1]
    return dialect_type(config)


_DIALECTS: dict[str, type[SecurityDialect] | tuple[type[SecurityDialect], type[SecurityDialect]]] = {
    "sqlite": SQLiteSecurityDialect,
    "aiosqlite": AiosqliteSecurityDialect,
    "duckdb": DuckDBSecurityDialect,
    "asyncpg": AsyncpgSecurityDialect,
    "psycopg": (PsycopgAsyncSecurityDialect, PsycopgSyncSecurityDialect),
    "psqlpy": PsqlpySecurityDialect,
    "cockroach_asyncpg": CockroachAsyncpgSecurityDialect,
    "cockroach_psycopg": (CockroachPsycopgAsyncSecurityDialect, CockroachPsycopgSyncSecurityDialect),
}
