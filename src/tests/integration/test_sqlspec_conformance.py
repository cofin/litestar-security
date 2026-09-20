"""Integration conformance test suite for SQLSpec persistence backend across store protocols."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import TYPE_CHECKING, cast

import pytest

from litestar_security.accounts import (
    PasswordChangeOutcome,
    PasswordCredentialState,
    RateLimiter,
    RateLimitPolicy,
    RefreshTokenFamilyStore,
    RefreshTokenProof,
    RegistrationCommand,
    RegistrationOutcome,
    RegistrationStore,
    SecurityEvent,
)
from litestar_security.backends.sqlspec import SQLSpecSecurityBackend, SQLSpecSecurityBackendConfig
from litestar_security.backends.sqlspec.schema import (
    TABLE_ACCOUNTS,
    TABLE_API_KEYS,
    SecurityConfigurationError,
    get_create_table_statements,
)
from litestar_security.backends.sqlspec.stores import (
    SQLSpecAccountStore,
    SQLSpecAPIKeyStore,
    SQLSpecMFALoginChallengeStore,
    SQLSpecOAuthAccountStore,
    SQLSpecOAuthTransactionStore,
    SQLSpecRateLimiter,
    SQLSpecSessionStore,
    SQLSpecStepUpStore,
    SQLSpecTOTPStore,
)
from litestar_security.backends.sqlspec.stores.aiosqlite import AiosqliteSecurityDialect
from litestar_security.backends.sqlspec.stores.sqlite import SQLiteSecurityDialect
from litestar_security.providers.oauth import ProtectedOAuthSecret
from litestar_security.testing.conformance import (
    StoreConformanceFactories,
    assert_api_key_store_conformance,
    assert_local_account_store_conformance,
    assert_mfa_login_challenge_store_conformance,
    assert_mfa_store_conformance,
    assert_oauth_account_store_conformance,
    assert_oauth_transaction_store_conformance,
    assert_rate_limiter_conformance,
    assert_refresh_family_store_conformance,
    assert_security_backend_conformance,
    assert_session_registry_conformance,
    assert_step_up_store_conformance,
)

if TYPE_CHECKING:
    from litestar_security.accounts import (
        CreateRefreshFamilyCommand,
        PurposeTokenDelivery,
        RefreshFamilyContext,
        RefreshPreflightOutcome,
        RefreshReceiptReplay,
        RefreshRotationOutcome,
        RotateRefreshCommand,
    )

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class _SyncSqliteDriver:
    """Minimal thread-safe sync driver adapter wrapping sqlite3.Connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.dialect = "sqlite"
        self._lock = threading.Lock()

    def execute(self, statement: str, *parameters: object) -> object:
        with self._lock:
            cursor = self.connection.cursor()
            return cursor.execute(statement, parameters)

    def execute_script(self, statement: str) -> object:
        with self._lock:
            return self.connection.executescript(statement)

    def select(self, statement: str, *parameters: object) -> list[object]:
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute(statement, parameters)
            return list(cursor.fetchall())

    def select_one_or_none(self, statement: str, *parameters: object) -> object | None:
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute(statement, parameters)
            return cast("object | None", cursor.fetchone())

    def select_value(self, statement: str, *parameters: object) -> object | None:
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute(statement, parameters)
            row = cursor.fetchone()
            if row is None:
                return None
            return cast("object | None", row[0])


def _create_isolated_backend(config: SQLSpecSecurityBackendConfig | None = None) -> SQLSpecSecurityBackend:
    """Create an isolated in-memory SQLite backend with initialized schema."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    driver = _SyncSqliteDriver(conn)
    backend_config = config or SQLSpecSecurityBackendConfig()
    backend = SQLSpecSecurityBackend(driver, config=backend_config)
    ddl_statements = get_create_table_statements(backend_config, dialect="sqlite")
    driver.execute_script("\n".join(ddl_statements))
    return backend


class _DeterministicProtector:
    """Deterministic token protector for test OAuth transactions."""

    active_key_version: str = "test-v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        prefix = sha256(associated_data).digest()
        return ProtectedOAuthSecret(ciphertext=prefix + secret[::-1], key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        prefix = sha256(associated_data).digest()
        if not protected.ciphertext.startswith(prefix):
            message = "Protected test secret has different associated data"
            raise ValueError(message)
        return protected.ciphertext[len(prefix) :][::-1]


class _ConformanceSQLSpecRefreshStore(RefreshTokenFamilyStore, RegistrationStore[object]):
    """Bridge adapter combining SQLSpec refresh and account stores for conformance testing."""

    def __init__(self, backend: SQLSpecSecurityBackend) -> None:
        self._backend = backend
        self._refresh = backend.refresh_token_store
        self._account = backend.account_store

    async def register(
        self,
        command: RegistrationCommand,
        password_hash: str,
        *,
        invitation_digest: bytes | None,
        verification: PurposeTokenDelivery | None,
        now: datetime,
        event: SecurityEvent,
    ) -> RegistrationOutcome[object]:
        return await self._account.register(
            command, password_hash, invitation_digest=invitation_digest, verification=verification, now=now, event=event
        )

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        return await self._account.get_password_state(account_id)

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeOutcome:
        return await self._account.replace_password_and_bump_epoch(
            account_id, password_hash, expected_epoch=expected_epoch, event=event
        )

    async def create_family(self, command: CreateRefreshFamilyCommand, *, event: SecurityEvent) -> bool:
        return await self._refresh.create_family(command, event=event)

    async def prepare_rotation(
        self, proof: RefreshTokenProof, idempotency_digest: bytes | None, *, now: datetime, event: SecurityEvent
    ) -> RefreshFamilyContext | RefreshReceiptReplay | RefreshPreflightOutcome:
        return await self._refresh.prepare_rotation(proof, idempotency_digest, now=now, event=event)

    async def rotate(
        self, command: RotateRefreshCommand, *, now: datetime, event: SecurityEvent
    ) -> RefreshRotationOutcome:
        return await self._refresh.rotate(command, now=now, event=event)

    async def revoke_family(self, family_id: str, *, event: SecurityEvent) -> bool:
        return await self._refresh.revoke_family(family_id, event=event)

    async def revoke_token(self, token_id: str, token_digest: bytes, *, event: SecurityEvent) -> bool:
        return await self._refresh.revoke_token(token_id, token_digest, event=event)

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, *, event: SecurityEvent
    ) -> bool:
        return await self._refresh.revoke_token_for_account(account_id, token_id, token_digest, event=event)

    async def revoke_for_account(self, account_id: str, *, event: SecurityEvent) -> int:
        return await self._refresh.revoke_for_account(account_id, event=event)


@pytest.mark.anyio
async def test_api_key_store_conformance() -> None:
    """Verify SQLSpecAPIKeyStore conforms to API key protocol requirements."""

    def make_store() -> SQLSpecAPIKeyStore:
        return _create_isolated_backend().api_key_store

    await assert_api_key_store_conformance(make_store)


@pytest.mark.anyio
async def test_session_registry_conformance() -> None:
    """Verify SQLSpecSessionStore conforms to session registry protocol requirements."""

    def make_store() -> SQLSpecSessionStore:
        backend = _create_isolated_backend()
        return SQLSpecSessionStore(backend, clock=lambda: _NOW)

    await assert_session_registry_conformance(make_store, now=_NOW)


@pytest.mark.anyio
async def test_mfa_login_challenge_conformance() -> None:
    """Verify SQLSpecMFALoginChallengeStore conforms to burn-on-reveal requirements."""

    def make_store() -> SQLSpecMFALoginChallengeStore:
        return _create_isolated_backend().mfa_login_challenge_store

    await assert_mfa_login_challenge_store_conformance(make_store)


@pytest.mark.anyio
async def test_mfa_totp_store_conformance() -> None:
    """Verify SQLSpecTOTPStore conforms to TOTP and recovery-code requirements."""

    def make_store() -> SQLSpecTOTPStore:
        return _create_isolated_backend().totp_store

    await assert_mfa_store_conformance(make_store)


@pytest.mark.anyio
async def test_step_up_store_conformance() -> None:
    """Verify SQLSpecStepUpStore conforms to step-up grant requirements."""

    def make_store() -> SQLSpecStepUpStore:
        return _create_isolated_backend().step_up_store

    await assert_step_up_store_conformance(make_store)


@pytest.mark.anyio
async def test_oauth_transaction_store_conformance() -> None:
    """Verify SQLSpecOAuthTransactionStore conforms to transaction requirements."""

    def make_store() -> SQLSpecOAuthTransactionStore:
        return SQLSpecOAuthTransactionStore(_create_isolated_backend(), protector=_DeterministicProtector())

    await assert_oauth_transaction_store_conformance(make_store)


@pytest.mark.anyio
async def test_oauth_account_store_conformance() -> None:
    """Verify SQLSpecOAuthAccountStore conforms to account linkage requirements."""

    def make_store() -> SQLSpecOAuthAccountStore:
        return SQLSpecOAuthAccountStore(_create_isolated_backend())

    await assert_oauth_account_store_conformance(make_store)


@pytest.mark.anyio
async def test_local_account_store_conformance() -> None:
    """Verify SQLSpecAccountStore conforms to account capabilities and registration."""

    def make_store() -> SQLSpecAccountStore:
        return _create_isolated_backend().account_store

    await assert_local_account_store_conformance(make_store)


@pytest.mark.anyio
async def test_refresh_family_store_conformance() -> None:
    """Verify SQLSpec refresh family bridge conforms to rotation and replay invariants."""

    def make_store() -> _ConformanceSQLSpecRefreshStore:
        backend = _create_isolated_backend()
        return _ConformanceSQLSpecRefreshStore(backend)

    await assert_refresh_family_store_conformance(make_store)


@pytest.mark.anyio
async def test_rate_limiter_conformance() -> None:
    """Verify SQLSpecRateLimiter enforces atomic admission under concurrency."""

    def make_limiter(limit: int) -> RateLimiter:
        backend = _create_isolated_backend()
        policy = RateLimitPolicy(limit=limit, window=timedelta(minutes=1))
        return SQLSpecRateLimiter(backend, policies={"conformance.rate_limit": policy})

    await assert_rate_limiter_conformance(make_limiter, limit=5, concurrency=20)


@pytest.mark.anyio
async def test_security_backend_conformance_suite() -> None:
    """Run full combined security backend conformance across all enabled stores."""
    protector = _DeterministicProtector()
    factories = StoreConformanceFactories(
        api_key_store=lambda: _create_isolated_backend().api_key_store,
        mfa_login_challenge_store=lambda: _create_isolated_backend().mfa_login_challenge_store,
        mfa_store=lambda: _create_isolated_backend().totp_store,
        step_up_store=lambda: _create_isolated_backend().step_up_store,
        oauth_transaction_store=lambda: SQLSpecOAuthTransactionStore(_create_isolated_backend(), protector=protector),
        oauth_account_store=lambda: SQLSpecOAuthAccountStore(_create_isolated_backend()),
    )

    await assert_security_backend_conformance(factories)


@pytest.mark.anyio
async def test_custom_prefix_and_column_map_conformance() -> None:
    """Verify backend supports customized table prefix and column mapping."""
    config = SQLSpecSecurityBackendConfig(
        table_prefix="app_",
        column_map={TABLE_ACCOUNTS: {"email": "account_email"}, TABLE_API_KEYS: {"key_id": "public_key_id"}},
    )
    backend = _create_isolated_backend(config)

    assert backend.config.table_name(TABLE_ACCOUNTS) == "app_user_account"
    assert backend.config.table_name(TABLE_API_KEYS) == "app_user_account_api_key"

    api_key_store = backend.api_key_store
    assert api_key_store is not None


@pytest.mark.parametrize("schema", ["main", "tenant"])
@pytest.mark.parametrize("dialect_type", [SQLiteSecurityDialect, AiosqliteSecurityDialect])
def test_sqlite_qualified_schema_lifecycle(schema: str, dialect_type: type[SQLiteSecurityDialect]) -> None:
    """Qualified tables retain working indexes and mapped foreign keys."""
    config = SQLSpecSecurityBackendConfig(
        table_prefix=f"{schema}.",
        account_table_name=f"{schema}.renamed_accounts",
        session_table_name=f"{schema}.renamed_sessions",
        column_map={"accounts": {"id": "account_key"}, "sessions": {"user_id": "owner_key"}},
    )
    dialect = dialect_type(config)
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        if schema == "tenant":
            connection.execute("ATTACH DATABASE ':memory:' AS tenant")
        for _ in range(2):
            for statement in dialect.create_statements():
                connection.execute(statement)
        connection.execute(
            f'INSERT INTO "{schema}".renamed_accounts (account_key, email) VALUES (?, ?)',  # noqa: S608 - schema is a fixed test parameter
            ("account-1", "user@example.com"),
        )
        insert_key = f'INSERT INTO "{schema}".user_account_api_key (id, key_id, digest, user_id) VALUES (?, ?, ?, ?)'  # noqa: S608 - fixed test schema
        connection.execute(insert_key, ("key-1", "public-1", b"digest", "account-1"))
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            connection.execute(insert_key, ("key-2", "public-2", b"digest", "missing-account"))
        references = connection.execute(f'PRAGMA "{schema}".foreign_key_list("renamed_sessions")').fetchall()
        assert [row[2:5] for row in references] == [("renamed_accounts", "owner_key", "account_key")]
        indexes = connection.execute(f'PRAGMA "{schema}".index_list("renamed_sessions")').fetchall()
        assert dialect.index_name("sessions", "user_exp") in {row[1] for row in indexes}
        for statement in dialect.drop_statements():
            connection.execute(statement)
        count_sql = f'SELECT count(*) FROM "{schema}".sqlite_master WHERE type = ?'  # noqa: S608 - fixed test schema
        assert connection.execute(count_sql, ("table",)).fetchone() == (0,)


def test_sqlite_rejects_cross_database_foreign_keys() -> None:
    """Never silently bind a cross-database reference to a local table."""
    dialect = SQLiteSecurityDialect(
        SQLSpecSecurityBackendConfig(table_prefix="tenant.", account_table_name="main.accounts")
    )
    with pytest.raises(SecurityConfigurationError, match="cross-database"):
        dialect.create_statements()
