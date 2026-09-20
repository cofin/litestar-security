"""Security SQL behavior for the psycopg adapter."""

from litestar_security.backends.sqlspec.stores._postgres import PostgresSecurityDialect

__all__ = ("PsycopgAsyncSecurityDialect", "PsycopgSyncSecurityDialect")


class PsycopgAsyncSecurityDialect(PostgresSecurityDialect):
    """Apply shared SQL and native value binding for psycopg."""

    __slots__ = ()


class PsycopgSyncSecurityDialect(PostgresSecurityDialect):
    """Apply shared SQL and native value binding for psycopg."""

    __slots__ = ()
