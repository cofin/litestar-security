"""SQLSpec persistence backend and extensions for Litestar Security."""

from __future__ import annotations

from litestar_security.backends.sqlspec.backend import SQLSpecSecurityBackend, bridge_session
from litestar_security.backends.sqlspec.config import SQLSpecSecurityBackendConfig
from litestar_security.backends.sqlspec.extension import (
    SECURITY_EXTENSION_NAME,
    configure_security_migration_extension,
    security_migration_directory,
)
from litestar_security.backends.sqlspec.schema import (
    DEFAULT_TABLE_NAMES,
    TABLE_ACCOUNTS,
    TABLE_API_KEYS,
    TABLE_AUDIT_LOGS,
    TABLE_MFA_LOGIN_CHALLENGES,
    TABLE_MFA_RECOVERY_CODES,
    TABLE_OAUTH_ACCOUNTS,
    TABLE_PURPOSE_TOKENS,
    TABLE_RATE_LIMIT_BUCKETS,
    TABLE_REFRESH_TOKENS,
    TABLE_ROLES,
    TABLE_SESSIONS,
    TABLE_STEP_UP_GRANTS,
    TABLE_TOTP_METHODS,
    TABLE_USER_ROLES,
    SecurityConfigurationError,
    get_create_table_statements,
    get_drop_table_statements,
    quote_identifier,
    resolve_column,
    resolve_table_name,
    split_qualified_identifier,
    validate_table_name,
)

__all__ = (
    "DEFAULT_TABLE_NAMES",
    "SECURITY_EXTENSION_NAME",
    "TABLE_ACCOUNTS",
    "TABLE_API_KEYS",
    "TABLE_AUDIT_LOGS",
    "TABLE_MFA_LOGIN_CHALLENGES",
    "TABLE_MFA_RECOVERY_CODES",
    "TABLE_OAUTH_ACCOUNTS",
    "TABLE_PURPOSE_TOKENS",
    "TABLE_RATE_LIMIT_BUCKETS",
    "TABLE_REFRESH_TOKENS",
    "TABLE_ROLES",
    "TABLE_SESSIONS",
    "TABLE_STEP_UP_GRANTS",
    "TABLE_TOTP_METHODS",
    "TABLE_USER_ROLES",
    "SQLSpecSecurityBackend",
    "SQLSpecSecurityBackendConfig",
    "SecurityConfigurationError",
    "bridge_session",
    "configure_security_migration_extension",
    "get_create_table_statements",
    "get_drop_table_statements",
    "quote_identifier",
    "resolve_column",
    "resolve_table_name",
    "security_migration_directory",
    "split_qualified_identifier",
    "validate_table_name",
)
