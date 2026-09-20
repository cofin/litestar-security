"""Security SQL behavior for the asyncpg adapter."""

from litestar_security.backends.sqlspec.stores._postgres import PostgresSecurityDialect

__all__ = ("AsyncpgSecurityDialect",)


class AsyncpgSecurityDialect(PostgresSecurityDialect):
    """Apply shared SQL and native value binding for asyncpg."""

    __slots__ = ()
