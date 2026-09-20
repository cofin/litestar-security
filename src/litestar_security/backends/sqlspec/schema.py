"""Schema, table, and column resolution helpers for the SQLSpec backend."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sqlspec.utils.text import quote_identifier, split_qualified_identifier

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar_security.backends.sqlspec.config import SQLSpecSecurityBackendConfig

__all__ = (
    "DEFAULT_TABLE_NAMES",
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
    "SecurityConfigurationError",
    "get_create_table_statements",
    "get_drop_table_statements",
    "quote_identifier",
    "resolve_column",
    "resolve_table_name",
    "split_qualified_identifier",
    "validate_table_name",
)

TABLE_ACCOUNTS = "accounts"
TABLE_SESSIONS = "sessions"
TABLE_API_KEYS = "api_keys"
TABLE_PURPOSE_TOKENS = "purpose_tokens"
TABLE_TOTP_METHODS = "totp_methods"
TABLE_MFA_RECOVERY_CODES = "mfa_recovery_codes"
TABLE_MFA_LOGIN_CHALLENGES = "mfa_login_challenges"
TABLE_STEP_UP_GRANTS = "step_up_grants"
TABLE_RATE_LIMIT_BUCKETS = "rate_limit_buckets"
TABLE_OAUTH_ACCOUNTS = "oauth_accounts"
TABLE_USER_ROLES = "user_roles"
TABLE_ROLES = "roles"
TABLE_AUDIT_LOGS = "audit_logs"
TABLE_REFRESH_TOKENS = "refresh_tokens"

DEFAULT_TABLE_NAMES: dict[str, str] = {
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

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")


class SecurityConfigurationError(ValueError):
    """Raised when backend configuration or schema naming is invalid."""


def validate_table_name(name: str) -> str:
    """Validate that a table identifier conforms to safe SQL naming conventions.

    Args:
        name: The table name or qualified schema.table name to validate.

    Returns:
        The validated table name stripped of leading/trailing whitespace.

    Raises:
        SecurityConfigurationError: If the table identifier contains invalid characters.
    """
    stripped = name.strip()
    if not stripped or not _IDENTIFIER_PATTERN.match(stripped):
        msg = f"Invalid SQL table identifier: {name!r}. Must be a valid identifier or schema.identifier."
        raise SecurityConfigurationError(msg)
    return stripped


def resolve_table_name(config: SQLSpecSecurityBackendConfig, table_key: str) -> str:
    """Resolve physical table name honoring configuration overrides, prefix, and defaults.

    Args:
        config: The SQLSpec security backend configuration.
        table_key: Logical key identifying the target table.

    Returns:
        The physical table name.

    Raises:
        SecurityConfigurationError: If the table key is unknown or the configured name is invalid.
    """
    override = getattr(config, f"{table_key.removesuffix('s')}_table_name", None)
    if override is None and table_key == TABLE_TOTP_METHODS:
        override = config.totp_method_table_name
    elif override is None and table_key == TABLE_AUDIT_LOGS:
        override = config.audit_log_table_name
    elif override is None and table_key == TABLE_REFRESH_TOKENS:
        override = config.refresh_token_table_name

    if override is not None:
        return validate_table_name(override)

    if table_key not in DEFAULT_TABLE_NAMES:
        msg = f"Unknown SQLSpec security table key: {table_key!r}. Expected one of {sorted(DEFAULT_TABLE_NAMES)}."
        raise SecurityConfigurationError(msg)

    base_name = DEFAULT_TABLE_NAMES[table_key]
    if config.table_prefix:
        if "." in base_name:
            schema_part, table_part = base_name.split(".", 1)
            return validate_table_name(f"{schema_part}.{config.table_prefix}{table_part}")
        return validate_table_name(f"{config.table_prefix}{base_name}")

    return base_name


def resolve_column(config: SQLSpecSecurityBackendConfig, table_key: str, logical_column: str) -> str:
    """Resolve physical column name using configured column mappings.

    Args:
        config: The SQLSpec security backend configuration.
        table_key: Logical key identifying the target table.
        logical_column: The standard logical column name used by litestar-security.

    Returns:
        The mapped physical column name, or logical_column if no mapping exists.
    """
    table_map: Mapping[str, str] | None = config.column_map.get(table_key)
    if table_map is not None and logical_column in table_map:
        return table_map[logical_column]
    return logical_column


def get_create_table_statements(config: SQLSpecSecurityBackendConfig, dialect: str = "sqlite") -> list[str]:
    """Generate dialect-aware CREATE TABLE and CREATE INDEX DDL statements for all security tables.

    Args:
        config: The SQLSpec security backend configuration.
        dialect: The database dialect (e.g. 'sqlite', 'postgres', 'postgresql').

    Returns:
        A list of DDL strings.
    """
    is_pg = dialect.lower() in ("postgres", "postgresql", "asyncpg", "psycopg")
    json_type = "JSONB" if (is_pg and config.native_json_columns) else ("JSON" if is_pg else "TEXT")
    uuid_type = "UUID" if is_pg else "TEXT"
    timestamp_type = "TIMESTAMPTZ" if is_pg else "TEXT"
    now_default = "CURRENT_TIMESTAMP" if is_pg else "(CURRENT_TIMESTAMP)"
    int_bool_true = "TRUE" if is_pg else "1"
    int_bool_false = "FALSE" if is_pg else "0"
    bool_type = "BOOLEAN" if is_pg else "INTEGER"
    id_varchar = "VARCHAR(64)" if is_pg else "TEXT"
    bigint_type = "BIGINT" if is_pg else "INTEGER"
    blob_type = "BYTEA" if is_pg else "BLOB"

    t_accounts = config.table_name(TABLE_ACCOUNTS)
    t_sessions = config.table_name(TABLE_SESSIONS)
    t_api_keys = config.table_name(TABLE_API_KEYS)
    t_purpose_tokens = config.table_name(TABLE_PURPOSE_TOKENS)
    t_totp_methods = config.table_name(TABLE_TOTP_METHODS)
    t_mfa_recovery_codes = config.table_name(TABLE_MFA_RECOVERY_CODES)
    t_mfa_login_challenges = config.table_name(TABLE_MFA_LOGIN_CHALLENGES)
    t_step_up_grants = config.table_name(TABLE_STEP_UP_GRANTS)
    t_rate_limit_buckets = config.table_name(TABLE_RATE_LIMIT_BUCKETS)
    t_oauth_accounts = config.table_name(TABLE_OAUTH_ACCOUNTS)
    t_roles = config.table_name(TABLE_ROLES)
    t_user_roles = config.table_name(TABLE_USER_ROLES)
    t_audit_logs = config.table_name(TABLE_AUDIT_LOGS)
    t_refresh_tokens = config.table_name(TABLE_REFRESH_TOKENS)

    clean_t_sessions = t_sessions.replace(".", "_")
    clean_t_api_keys = t_api_keys.replace(".", "_")
    clean_t_purpose_tokens = t_purpose_tokens.replace(".", "_")
    clean_t_totp_methods = t_totp_methods.replace(".", "_")
    clean_t_mfa_recovery = t_mfa_recovery_codes.replace(".", "_")
    clean_t_mfa_challenges = t_mfa_login_challenges.replace(".", "_")
    clean_t_step_up = t_step_up_grants.replace(".", "_")
    clean_t_oauth = t_oauth_accounts.replace(".", "_")
    clean_t_audit = t_audit_logs.replace(".", "_")
    clean_t_refresh = t_refresh_tokens.replace(".", "_")

    statements: list[str] = [
        f"""CREATE TABLE IF NOT EXISTS {t_accounts} (
    id {uuid_type} PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255),
    avatar_url VARCHAR(1024),
    is_active {bool_type} NOT NULL DEFAULT {int_bool_true},
    is_verified {bool_type} NOT NULL DEFAULT {int_bool_false},
    is_superuser {bool_type} NOT NULL DEFAULT {int_bool_false},
    password_hash VARCHAR(255),
    security_epoch INTEGER NOT NULL DEFAULT 1,
    login_count INTEGER NOT NULL DEFAULT 0,
    last_login_at {timestamp_type},
    joined_at {timestamp_type} NOT NULL DEFAULT {now_default},
    created_at {timestamp_type} NOT NULL DEFAULT {now_default},
    updated_at {timestamp_type} NOT NULL DEFAULT {now_default}
);""",
        f"""CREATE TABLE IF NOT EXISTS {t_sessions} (
    id {id_varchar} PRIMARY KEY,
    session_id VARCHAR(128) NOT NULL UNIQUE,
    binding_id VARCHAR(128) NOT NULL UNIQUE,
    binding_digest {blob_type} NOT NULL,
    user_id {uuid_type} NOT NULL REFERENCES {t_accounts}(id) ON DELETE CASCADE,
    security_epoch INTEGER NOT NULL DEFAULT 1,
    created_at {timestamp_type} NOT NULL DEFAULT {now_default},
    authenticated_at {timestamp_type} NOT NULL DEFAULT {now_default},
    last_seen_at {timestamp_type} NOT NULL DEFAULT {now_default},
    expires_at {timestamp_type} NOT NULL,
    display_metadata {json_type} NOT NULL DEFAULT ('{{}}')
);""",
        f"CREATE INDEX IF NOT EXISTS idx_{clean_t_sessions}_user_exp ON {t_sessions}(user_id, expires_at);",
        f"""CREATE TABLE IF NOT EXISTS {t_api_keys} (
    id {id_varchar} PRIMARY KEY,
    key_id VARCHAR(64) NOT NULL UNIQUE,
    digest {blob_type} NOT NULL,
    user_id {uuid_type} NOT NULL REFERENCES {t_accounts}(id) ON DELETE CASCADE,
    restrictions {json_type} NOT NULL DEFAULT ('{{}}'),
    created_at {timestamp_type} NOT NULL DEFAULT {now_default},
    expires_at {timestamp_type},
    revoked_at {timestamp_type},
    overlap_until {timestamp_type},
    last_used_at {timestamp_type}
);""",
        f"CREATE INDEX IF NOT EXISTS idx_{clean_t_api_keys}_user ON {t_api_keys}(user_id);",
        f"""CREATE TABLE IF NOT EXISTS {t_purpose_tokens} (
    id {id_varchar} PRIMARY KEY,
    token_id VARCHAR(64) NOT NULL UNIQUE,
    digest {blob_type} NOT NULL,
    purpose VARCHAR(64) NOT NULL,
    user_id {uuid_type} NOT NULL REFERENCES {t_accounts}(id) ON DELETE CASCADE,
    issued_security_epoch INTEGER,
    maximum_attempts INTEGER NOT NULL DEFAULT 5,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    payload {json_type},
    created_at {timestamp_type} NOT NULL DEFAULT {now_default},
    expires_at {timestamp_type} NOT NULL,
    consumed_at {timestamp_type}
);""",
        (
            f"CREATE INDEX IF NOT EXISTS idx_{clean_t_purpose_tokens}_user_purpose "
            f"ON {t_purpose_tokens}(user_id, purpose);"
        ),
        f"""CREATE TABLE IF NOT EXISTS {t_totp_methods} (
    id {id_varchar} PRIMARY KEY,
    method_id VARCHAR(64) NOT NULL UNIQUE,
    user_id {uuid_type} NOT NULL REFERENCES {t_accounts}(id) ON DELETE CASCADE,
    secret_ciphertext {blob_type} NOT NULL,
    key_version VARCHAR(32) NOT NULL DEFAULT 'v1',
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    enrollment_id VARCHAR(64) UNIQUE,
    policy {json_type} NOT NULL DEFAULT ('{{}}'),
    last_counter {bigint_type} NOT NULL DEFAULT 0,
    confirmed_at {timestamp_type},
    created_at {timestamp_type} NOT NULL DEFAULT {now_default},
    updated_at {timestamp_type} NOT NULL DEFAULT {now_default},
    expires_at {timestamp_type},
    last_used_at {timestamp_type}
);""",
        f"CREATE INDEX IF NOT EXISTS idx_{clean_t_totp_methods}_user ON {t_totp_methods}(user_id);",
        f"""CREATE TABLE IF NOT EXISTS {t_mfa_recovery_codes} (
    id {id_varchar} PRIMARY KEY,
    user_id {uuid_type} NOT NULL REFERENCES {t_accounts}(id) ON DELETE CASCADE,
    pepper_version VARCHAR(32) NOT NULL DEFAULT 'v1',
    digest {blob_type} NOT NULL UNIQUE,
    consumed_at {timestamp_type},
    created_at {timestamp_type} NOT NULL DEFAULT {now_default}
);""",
        f"CREATE INDEX IF NOT EXISTS idx_{clean_t_mfa_recovery}_user ON {t_mfa_recovery_codes}(user_id);",
        f"""CREATE TABLE IF NOT EXISTS {t_mfa_login_challenges} (
    id {id_varchar} PRIMARY KEY,
    challenge_digest {blob_type} NOT NULL UNIQUE,
    user_id {uuid_type} NOT NULL REFERENCES {t_accounts}(id) ON DELETE CASCADE,
    security_epoch INTEGER NOT NULL DEFAULT 1,
    client_key VARCHAR(255),
    issued_at {timestamp_type} NOT NULL DEFAULT {now_default},
    expires_at {timestamp_type} NOT NULL,
    consumed_at {timestamp_type}
);""",
        f"CREATE INDEX IF NOT EXISTS idx_{clean_t_mfa_challenges}_user ON {t_mfa_login_challenges}(user_id);",
        f"""CREATE TABLE IF NOT EXISTS {t_step_up_grants} (
    id {id_varchar} PRIMARY KEY,
    grant_digest {blob_type} NOT NULL UNIQUE,
    transport_digest {blob_type} NOT NULL,
    user_id {uuid_type} NOT NULL REFERENCES {t_accounts}(id) ON DELETE CASCADE,
    security_epoch INTEGER NOT NULL DEFAULT 1,
    purpose VARCHAR(255) NOT NULL,
    methods {json_type} NOT NULL DEFAULT ('[]'),
    traits {json_type} NOT NULL DEFAULT ('[]'),
    authenticated_at {timestamp_type} NOT NULL DEFAULT {now_default},
    expires_at {timestamp_type} NOT NULL
);""",
        f"CREATE INDEX IF NOT EXISTS idx_{clean_t_step_up}_user ON {t_step_up_grants}(user_id);",
        f"""CREATE TABLE IF NOT EXISTS {t_rate_limit_buckets} (
    bucket_key VARCHAR(255) NOT NULL,
    window_start {timestamp_type} NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (bucket_key, window_start)
);""",
        f"""CREATE TABLE IF NOT EXISTS {t_oauth_accounts} (
    id {id_varchar} PRIMARY KEY,
    user_id {uuid_type} NOT NULL REFERENCES {t_accounts}(id) ON DELETE CASCADE,
    provider VARCHAR(64) NOT NULL,
    subject_id VARCHAR(255) NOT NULL,
    profile_data {json_type},
    created_at {timestamp_type} NOT NULL DEFAULT {now_default},
    updated_at {timestamp_type} NOT NULL DEFAULT {now_default},
    UNIQUE (provider, subject_id)
);""",
        f"CREATE INDEX IF NOT EXISTS idx_{clean_t_oauth}_user ON {t_oauth_accounts}(user_id);",
        f"""CREATE TABLE IF NOT EXISTS {t_roles} (
    id {id_varchar} PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(255),
    permissions {json_type} NOT NULL DEFAULT ('[]')
);""",
        f"""CREATE TABLE IF NOT EXISTS {t_user_roles} (
    user_id {uuid_type} NOT NULL REFERENCES {t_accounts}(id) ON DELETE CASCADE,
    role_id {id_varchar} NOT NULL REFERENCES {t_roles}(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);""",
        f"""CREATE TABLE IF NOT EXISTS {t_audit_logs} (
    id {id_varchar} PRIMARY KEY,
    event_type VARCHAR(128) NOT NULL,
    actor_id {id_varchar},
    target_id {id_varchar},
    ip_address VARCHAR(45),
    user_agent VARCHAR(512),
    data {json_type},
    occurred_at {timestamp_type} NOT NULL DEFAULT {now_default}
);""",
        f"CREATE INDEX IF NOT EXISTS idx_{clean_t_audit}_event ON {t_audit_logs}(event_type, occurred_at);",
        f"""CREATE TABLE IF NOT EXISTS {t_refresh_tokens} (
    id {id_varchar} PRIMARY KEY,
    token_id VARCHAR(64) NOT NULL UNIQUE,
    token_digest {blob_type} NOT NULL,
    family_id VARCHAR(64) NOT NULL,
    user_id {uuid_type} NOT NULL REFERENCES {t_accounts}(id) ON DELETE CASCADE,
    security_epoch INTEGER NOT NULL DEFAULT 1,
    token_expires_at {timestamp_type} NOT NULL,
    family_expires_at {timestamp_type} NOT NULL,
    scopes {json_type} NOT NULL DEFAULT ('[]'),
    consumed {bool_type} NOT NULL DEFAULT {int_bool_false},
    revoked {bool_type} NOT NULL DEFAULT {int_bool_false},
    idempotency_digest {blob_type},
    sealed_receipt {blob_type},
    created_at {timestamp_type} NOT NULL DEFAULT {now_default}
);""",
        f"CREATE INDEX IF NOT EXISTS idx_{clean_t_refresh}_family ON {t_refresh_tokens}(family_id);",
        f"CREATE INDEX IF NOT EXISTS idx_{clean_t_refresh}_user ON {t_refresh_tokens}(user_id);",
    ]
    return statements



def get_drop_table_statements(config: SQLSpecSecurityBackendConfig, dialect: str = "sqlite") -> list[str]:
    """Generate DROP TABLE DDL statements in reverse foreign key order.

    Args:
        config: The SQLSpec security backend configuration.
        dialect: The database dialect (e.g. 'sqlite', 'postgres', 'postgresql').

    Returns:
        A list of DDL drop strings.
    """
    is_pg = dialect.lower() in ("postgres", "postgresql", "asyncpg", "psycopg")
    cascade = " CASCADE" if is_pg else ""

    ordered_keys = (
        TABLE_REFRESH_TOKENS,
        TABLE_AUDIT_LOGS,
        TABLE_USER_ROLES,
        TABLE_ROLES,
        TABLE_OAUTH_ACCOUNTS,
        TABLE_RATE_LIMIT_BUCKETS,
        TABLE_STEP_UP_GRANTS,
        TABLE_MFA_LOGIN_CHALLENGES,
        TABLE_MFA_RECOVERY_CODES,
        TABLE_TOTP_METHODS,
        TABLE_PURPOSE_TOKENS,
        TABLE_API_KEYS,
        TABLE_SESSIONS,
        TABLE_ACCOUNTS,
    )
    return [f"DROP TABLE IF EXISTS {config.table_name(key)}{cascade};" for key in ordered_keys]

