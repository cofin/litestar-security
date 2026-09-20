"""Security SQL behavior for the asyncmy adapter."""

from litestar_security.backends.sqlspec.stores._mysql import MySQLSecurityDialect

__all__ = ("AsyncmySecurityDialect",)


class AsyncmySecurityDialect(MySQLSecurityDialect):
    """Apply shared MySQL SQL and value binding for asyncmy."""

    __slots__ = ()
