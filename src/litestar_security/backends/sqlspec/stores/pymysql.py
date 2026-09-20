"""Security SQL behavior for the pymysql adapter."""

from litestar_security.backends.sqlspec.stores._mysql import MySQLSecurityDialect

__all__ = ("PymysqlSecurityDialect",)


class PymysqlSecurityDialect(MySQLSecurityDialect):
    """Apply shared MySQL SQL and value binding for pymysql."""

    __slots__ = ()
