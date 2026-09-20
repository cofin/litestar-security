"""Unit tests for SQLSpec backend configuration and schema resolution."""

from __future__ import annotations

import pytest

from litestar_security.backends.sqlspec import (
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
    SQLSpecSecurityBackendConfig,
    resolve_column,
    validate_table_name,
)


def test_default_table_names() -> None:
    """Verify the default application table naming scheme."""
    config = SQLSpecSecurityBackendConfig()
    expected = {
        TABLE_ACCOUNTS: "user_account",
        TABLE_SESSIONS: "user_account_auth_session",
        TABLE_API_KEYS: "user_account_api_key",
        TABLE_PURPOSE_TOKENS: "user_account_purpose_token",
        TABLE_TOTP_METHODS: "user_account_totp_method",
        TABLE_MFA_RECOVERY_CODES: "user_account_mfa_recovery_code",
        TABLE_MFA_LOGIN_CHALLENGES: "user_account_mfa_login_challenge",
        TABLE_STEP_UP_GRANTS: "user_account_step_up_grant",
        TABLE_RATE_LIMIT_BUCKETS: "user_account_rate_limit_bucket",
        TABLE_OAUTH_ACCOUNTS: "user_account_oauth",
        TABLE_USER_ROLES: "user_account_role",
        TABLE_ROLES: "role",
        TABLE_AUDIT_LOGS: "audit_log",
        TABLE_REFRESH_TOKENS: "refresh_token",
    }
    for key, name in expected.items():
        assert config.table_name(key) == name
    assert config.all_table_names() == expected


def test_table_prefix_applies_to_defaults() -> None:
    """Verify table prefix modifies default table names."""
    config = SQLSpecSecurityBackendConfig(table_prefix="app_")
    assert config.table_name(TABLE_ACCOUNTS) == "app_user_account"
    assert config.table_name(TABLE_SESSIONS) == "app_user_account_auth_session"
    assert config.table_name(TABLE_API_KEYS) == "app_user_account_api_key"


def test_explicit_table_override_takes_precedence() -> None:
    """Verify individual table overrides take precedence over prefix and defaults."""
    config = SQLSpecSecurityBackendConfig(
        table_prefix="app_", account_table_name="custom_users", session_table_name="custom_sessions"
    )
    assert config.table_name(TABLE_ACCOUNTS) == "custom_users"
    assert config.table_name(TABLE_SESSIONS) == "custom_sessions"
    assert config.table_name(TABLE_API_KEYS) == "app_user_account_api_key"


def test_identifier_validation_rejects_malformed_names() -> None:
    """Verify malformed and unsafe table identifiers are rejected."""
    with pytest.raises(SecurityConfigurationError):
        validate_table_name("user; DROP TABLE user_account; --")

    with pytest.raises(SecurityConfigurationError):
        validate_table_name("")

    with pytest.raises(SecurityConfigurationError):
        validate_table_name("user table")

    with pytest.raises(SecurityConfigurationError):
        SQLSpecSecurityBackendConfig(account_table_name="invalid name with space")

    with pytest.raises(SecurityConfigurationError):
        SQLSpecSecurityBackendConfig(table_prefix="prefix;--")


def test_schema_qualified_table_names_accepted() -> None:
    """Verify schema-qualified identifiers are accepted and parsed."""
    assert validate_table_name("auth.user_account") == "auth.user_account"
    config = SQLSpecSecurityBackendConfig(account_table_name="auth.user_account")
    assert config.table_name(TABLE_ACCOUNTS) == "auth.user_account"


def test_column_mapping_resolution() -> None:
    """Verify custom column mappings resolve properly with fallback."""
    config = SQLSpecSecurityBackendConfig(column_map={TABLE_ACCOUNTS: {"id": "account_id", "email": "contact_email"}})
    assert config.column_name(TABLE_ACCOUNTS, "id") == "account_id"
    assert config.column_name(TABLE_ACCOUNTS, "email") == "contact_email"
    assert config.column_name(TABLE_ACCOUNTS, "is_active") == "is_active"
    assert resolve_column(config, TABLE_ACCOUNTS, "avatar_url") == "avatar_url"


def test_unknown_table_key_raises() -> None:
    """Verify querying an unknown table key raises SecurityConfigurationError."""
    config = SQLSpecSecurityBackendConfig()
    with pytest.raises(SecurityConfigurationError):
        config.table_name("non_existent_key")
