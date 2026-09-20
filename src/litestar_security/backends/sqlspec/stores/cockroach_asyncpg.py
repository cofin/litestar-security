"""Security SQL behavior for the cockroach_asyncpg adapter."""

from litestar_security.backends.sqlspec.stores._postgres import CockroachSecurityDialect

__all__ = ("CockroachAsyncpgSecurityDialect",)


class CockroachAsyncpgSecurityDialect(CockroachSecurityDialect):
    """Apply shared SQL and native value binding for cockroach_asyncpg."""

    __slots__ = ()
