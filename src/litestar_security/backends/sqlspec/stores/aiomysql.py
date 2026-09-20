"""Security SQL behavior for the aiomysql adapter."""

from litestar_security.backends.sqlspec.stores._mysql import MySQLSecurityDialect

__all__ = ("AiomysqlSecurityDialect",)


class AiomysqlSecurityDialect(MySQLSecurityDialect):
    """Apply shared MySQL SQL and value binding for aiomysql."""

    __slots__ = ()
