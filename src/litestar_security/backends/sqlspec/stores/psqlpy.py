"""Security SQL behavior for the psqlpy adapter."""

from litestar_security.backends.sqlspec.stores._postgres import PostgresSecurityDialect

__all__ = ("PsqlpySecurityDialect",)


class PsqlpySecurityDialect(PostgresSecurityDialect):
    """Apply shared SQL and native value binding for psqlpy."""

    __slots__ = ()
