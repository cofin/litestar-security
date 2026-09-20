"""Security SQL behavior for the cockroach_psycopg adapter."""

from litestar_security.backends.sqlspec.stores._postgres import CockroachSecurityDialect

__all__ = ("CockroachPsycopgAsyncSecurityDialect", "CockroachPsycopgSyncSecurityDialect")


class CockroachPsycopgAsyncSecurityDialect(CockroachSecurityDialect):
    """Apply shared SQL and native value binding for cockroach_psycopg."""

    __slots__ = ()


class CockroachPsycopgSyncSecurityDialect(CockroachSecurityDialect):
    """Apply shared SQL and native value binding for cockroach_psycopg."""

    __slots__ = ()
