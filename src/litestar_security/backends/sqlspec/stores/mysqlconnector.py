"""Security SQL behavior for the mysqlconnector adapter."""

from litestar_security.backends.sqlspec.stores._mysql import MySQLSecurityDialect

__all__ = ("MysqlConnectorAsyncSecurityDialect", "MysqlConnectorSyncSecurityDialect")


class MysqlConnectorAsyncSecurityDialect(MySQLSecurityDialect):
    """Apply shared MySQL SQL and value binding for mysqlconnector."""

    __slots__ = ()


class MysqlConnectorSyncSecurityDialect(MySQLSecurityDialect):
    """Apply shared MySQL SQL and value binding for mysqlconnector."""

    __slots__ = ()
