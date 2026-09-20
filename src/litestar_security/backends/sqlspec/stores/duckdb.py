"""DuckDB SQL and value binding for security persistence."""

from typing import TYPE_CHECKING

from litestar_security.backends.sqlspec.stores.base import SecurityDialect

if TYPE_CHECKING:
    from litestar_security.backends.sqlspec.schema import ColumnSpec

__all__ = ("DuckDBSecurityDialect",)


class DuckDBSecurityDialect(SecurityDialect):
    """Use native values and omit foreign keys that restrict parent updates."""

    __slots__ = ()
    data_dictionary_dialect = "duckdb"
    max_identifier_length = None
    bind_datetime_as_naive_utc = True
    native_json = True
    native_bool = True
    native_uuid = True
    supports_dml_returning = True
    supports_fk_cascade = False

    def _foreign_key_fragment(self, column: "ColumnSpec") -> str:
        """Omit references because DuckDB restricts referenced-row updates."""
        del column
        return ""
