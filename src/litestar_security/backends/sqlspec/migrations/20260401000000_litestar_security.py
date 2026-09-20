"""Create all Litestar Security database tables.

This revision is discoverable when the security extension is registered with
SQLSpec's migration engine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_security.backends.sqlspec.config import SQLSpecSecurityBackendConfig
from litestar_security.backends.sqlspec.extension import SECURITY_EXTENSION_NAME
from litestar_security.backends.sqlspec.schema import get_create_table_statements, get_drop_table_statements

if TYPE_CHECKING:
    from sqlspec.migrations.context import MigrationContext

__all__ = ("down", "up")


def _resolve_config_and_dialect(context: MigrationContext | None) -> tuple[SQLSpecSecurityBackendConfig, str]:
    """Resolve backend config and target dialect from migration context.

    Args:
        context: The migration context provided by SQLSpec.

    Returns:
        A tuple of (SQLSpecSecurityBackendConfig, dialect_name).
    """
    dialect = "sqlite"
    if context is not None and getattr(context, "dialect", None):
        dialect = str(context.dialect)

    if context is not None and getattr(context, "extension_config", None) is not None:
        ext_cfg = context.extension_config
        if ext_cfg is not None:
            ext_settings: dict[str, Any] = ext_cfg.get(SECURITY_EXTENSION_NAME, {})
            tables = ext_settings.get("tables", {})
            config = SQLSpecSecurityBackendConfig(
                table_prefix=ext_settings.get("table_prefix", ""),
                account_table_name=tables.get("accounts"),
                session_table_name=tables.get("sessions"),
                api_key_table_name=tables.get("api_keys"),
                purpose_token_table_name=tables.get("purpose_tokens"),
                totp_method_table_name=tables.get("totp_methods"),
                mfa_recovery_code_table_name=tables.get("mfa_recovery_codes"),
                mfa_login_challenge_table_name=tables.get("mfa_login_challenges"),
                step_up_grant_table_name=tables.get("step_up_grants"),
                rate_limit_bucket_table_name=tables.get("rate_limit_buckets"),
                oauth_account_table_name=tables.get("oauth_accounts"),
                user_role_table_name=tables.get("user_roles"),
                role_table_name=tables.get("roles"),
                audit_log_table_name=tables.get("audit_logs"),
                refresh_token_table_name=tables.get("refresh_tokens"),
                column_map=ext_settings.get("column_map", {}),
                native_json_columns=ext_settings.get("native_json_columns", True),
            )
            return config, dialect

    return SQLSpecSecurityBackendConfig(), dialect


async def up(context: MigrationContext | None = None) -> list[str]:
    """Return SQL DDL statements that provision all security tables.

    Args:
        context: Optional migration context provided by SQLSpec.

    Returns:
        List of executable SQL DDL strings.
    """
    config, dialect = _resolve_config_and_dialect(context)
    return get_create_table_statements(config, dialect=dialect)


async def down(context: MigrationContext | None = None) -> list[str]:
    """Return SQL DDL statements that drop all security tables.

    Args:
        context: Optional migration context provided by SQLSpec.

    Returns:
        List of executable SQL drop strings.
    """
    config, dialect = _resolve_config_and_dialect(context)
    return get_drop_table_statements(config, dialect=dialect)
