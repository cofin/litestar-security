"""Configuration structures for the SQLSpec persistence backend."""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from litestar_security.backends.sqlspec.schema import (
    DEFAULT_TABLE_NAMES,
    resolve_column,
    resolve_table_name,
    validate_table_name,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = ("SQLSpecSecurityBackendConfig",)


def _default_column_map() -> "dict[str, Mapping[str, str]]":
    """Return an empty column mapping dictionary."""
    return {}


@dataclass(frozen=True, slots=True)
class SQLSpecSecurityBackendConfig:
    """Configuration for the SQLSpec security persistence backend."""

    table_prefix: "str" = ""
    account_table_name: "str | None" = None
    session_table_name: "str | None" = None
    api_key_table_name: "str | None" = None
    purpose_token_table_name: "str | None" = None
    totp_method_table_name: "str | None" = None
    mfa_recovery_code_table_name: "str | None" = None
    mfa_login_challenge_table_name: "str | None" = None
    step_up_grant_table_name: "str | None" = None
    rate_limit_bucket_table_name: "str | None" = None
    oauth_account_table_name: "str | None" = None
    user_role_table_name: "str | None" = None
    role_table_name: "str | None" = None
    audit_log_table_name: "str | None" = None
    refresh_token_table_name: "str | None" = None
    column_map: "Mapping[str, Mapping[str, str]]" = field(default_factory=_default_column_map)
    manage_schema: "bool" = True
    native_json_columns: "bool" = True
    statement_timeout_seconds: "float" = 30.0

    def __post_init__(self) -> "None":
        """Validate configured table overrides and prefix."""
        if self.table_prefix:
            validate_table_name(f"{self.table_prefix}test")
        for key in (
            self.account_table_name,
            self.session_table_name,
            self.api_key_table_name,
            self.purpose_token_table_name,
            self.totp_method_table_name,
            self.mfa_recovery_code_table_name,
            self.mfa_login_challenge_table_name,
            self.step_up_grant_table_name,
            self.rate_limit_bucket_table_name,
            self.oauth_account_table_name,
            self.user_role_table_name,
            self.role_table_name,
            self.audit_log_table_name,
            self.refresh_token_table_name,
        ):
            if key is not None:
                validate_table_name(key)

    def table_name(self, table_key: "str") -> "str":
        """Resolve the physical table name for the specified logical table key.

        Args:
            table_key: Logical key identifying the target table.

        Returns:
            The resolved physical table name.
        """
        return resolve_table_name(self, table_key)

    def column_name(self, table_key: "str", logical_column: "str") -> "str":
        """Resolve the physical column name for a given table and logical column.

        Args:
            table_key: Logical key identifying the target table.
            logical_column: Logical attribute name.

        Returns:
            The resolved physical column name.
        """
        return resolve_column(self, table_key, logical_column)

    def all_table_names(self) -> "dict[str, str]":
        """Resolve all physical table names configured for the backend.

        Returns:
            A mapping of logical table keys to resolved physical table names.
        """
        return {key: self.table_name(key) for key in DEFAULT_TABLE_NAMES}
