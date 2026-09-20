"""Unit tests for SQLSpec core store adapters and protocol conformance."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import cast

import pytest

from litestar_security.accounts import (
    AccountLookup,
    CreateRefreshFamilyCommand,
    LocalAccountCapabilities,
    LoginMethod,
    LoginMethodStore,
    NativeSessionStore,
    PasswordCredentialStore,
    RateLimitAttempt,
    RateLimiter,
    RateLimitPolicy,
    RecoveryTokenStore,
    RefreshTokenFamilyStore,
    RefreshTokenProof,
    RegistrationCommand,
    RegistrationStatus,
    RotateRefreshCommand,
    SecurityEpochStore,
    SecurityEvent,
    SessionRegistry,
    VerificationTokenStore,
)
from litestar_security.backends.sqlspec import SQLSpecSecurityBackend, SQLSpecSecurityBackendConfig
from litestar_security.backends.sqlspec.stores import SQLSpecAPIKeyStore, SQLSpecRateLimiter, SQLSpecSessionStore
from litestar_security.providers.api_key import APIKeyStore
from litestar_security.testing.conformance import assert_api_key_store_conformance, assert_session_registry_conformance

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class _SyncSqliteDriver:
    """Minimal sync driver adapter wrapping sqlite3.Connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.dialect = "sqlite"

    def execute(self, statement: str, *parameters: object) -> object:
        cursor = self.connection.cursor()
        return cursor.execute(statement, parameters)

    def execute_script(self, statement: str) -> object:
        return self.connection.executescript(statement)

    def select(self, statement: str, *parameters: object) -> list[object]:
        cursor = self.connection.cursor()
        cursor.execute(statement, parameters)
        return list(cursor.fetchall())

    def select_one_or_none(self, statement: str, *parameters: object) -> object | None:
        cursor = self.connection.cursor()
        cursor.execute(statement, parameters)
        return cast("object | None", cursor.fetchone())

    def select_value(self, statement: str, *parameters: object) -> object | None:
        cursor = self.connection.cursor()
        cursor.execute(statement, parameters)
        row = cursor.fetchone()
        if row is None:
            return None
        return cast("object | None", row[0])


async def _create_sqlite_backend(config: SQLSpecSecurityBackendConfig | None = None) -> SQLSpecSecurityBackend:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    driver = _SyncSqliteDriver(conn)
    backend = SQLSpecSecurityBackend(driver, config=config)
    await backend.create_schema()
    return backend


def test_core_stores_fulfill_runtime_checkable_protocols() -> None:
    """Verify core store adapters satisfy their respective runtime checkable protocols."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    driver = _SyncSqliteDriver(conn)
    backend = SQLSpecSecurityBackend(driver)

    api_key_store = backend.api_key_store
    assert isinstance(api_key_store, APIKeyStore)

    session_store = backend.session_store
    assert isinstance(session_store, NativeSessionStore)
    assert isinstance(session_store, SessionRegistry)

    rate_limiter = backend.rate_limiter
    assert isinstance(rate_limiter, RateLimiter)

    refresh_store = backend.refresh_token_store
    assert isinstance(refresh_store, RefreshTokenFamilyStore)

    account_store = backend.account_store
    assert isinstance(account_store, LocalAccountCapabilities)
    assert isinstance(account_store, AccountLookup)
    assert isinstance(account_store, PasswordCredentialStore)
    assert isinstance(account_store, LoginMethodStore)
    assert isinstance(account_store, VerificationTokenStore)
    assert isinstance(account_store, RecoveryTokenStore)
    assert isinstance(account_store, SecurityEpochStore)


@pytest.mark.anyio
async def test_api_key_store_conformance() -> None:
    """Verify SQLSpecAPIKeyStore satisfies full API-key conformance requirements."""

    def make_store() -> SQLSpecAPIKeyStore:
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        driver = _SyncSqliteDriver(conn)
        backend = SQLSpecSecurityBackend(driver)
        driver.execute_script(
            """
            CREATE TABLE user_account (id TEXT PRIMARY KEY, email TEXT UNIQUE);
            CREATE TABLE user_account_api_key (
                id TEXT PRIMARY KEY,
                key_id TEXT NOT NULL UNIQUE,
                digest BLOB NOT NULL,
                user_id TEXT NOT NULL,
                restrictions TEXT NOT NULL DEFAULT ('{}'),
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked_at TEXT,
                overlap_until TEXT,
                last_used_at TEXT
            );
            """
        )
        return SQLSpecAPIKeyStore(backend)

    await assert_api_key_store_conformance(make_store)


@pytest.mark.anyio
async def test_session_store_conformance() -> None:
    """Verify SQLSpecSessionStore satisfies session registry conformance requirements."""

    def make_store() -> SQLSpecSessionStore:
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        driver = _SyncSqliteDriver(conn)
        backend = SQLSpecSecurityBackend(driver)
        driver.execute_script(
            """
            CREATE TABLE user_account_auth_session (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL UNIQUE,
                binding_id TEXT NOT NULL UNIQUE,
                binding_digest BLOB NOT NULL,
                user_id TEXT NOT NULL,
                security_epoch INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                authenticated_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                display_metadata TEXT NOT NULL DEFAULT ('{}')
            );
            """
        )
        return SQLSpecSessionStore(backend, clock=lambda: _NOW)

    await assert_session_registry_conformance(make_store, now=_NOW)


@pytest.mark.anyio
async def test_rate_limiter_operations() -> None:
    """Verify SQLSpecRateLimiter handles atomic counting and rate-limit violations."""
    backend = await _create_sqlite_backend()
    policy = RateLimitPolicy(limit=3, window=timedelta(minutes=1))
    limiter = SQLSpecRateLimiter(backend, policies={"login": policy}, clock=lambda: _NOW)

    attempt1 = RateLimitAttempt(operation="login", cost=1, client_key="127.0.0.1", subject_digest=None)
    decision1 = await limiter.acquire(attempt1)
    assert decision1.allowed is True
    assert decision1.retry_after is None

    attempt2 = RateLimitAttempt(operation="login", cost=2, client_key="127.0.0.1", subject_digest=None)
    decision2 = await limiter.acquire(attempt2)
    assert decision2.allowed is True

    attempt3 = RateLimitAttempt(operation="login", cost=1, client_key="127.0.0.1", subject_digest=None)
    decision3 = await limiter.acquire(attempt3)
    assert decision3.allowed is False
    assert decision3.retry_after is not None
    assert decision3.retry_after > 0


@pytest.mark.anyio
async def test_refresh_token_store_lifecycle() -> None:
    """Verify refresh token creation, rotation, and replay detection."""
    backend = await _create_sqlite_backend()
    account_store = backend.account_store
    refresh_store = backend.refresh_token_store

    event = SecurityEvent(event_id="evt-1", occurred_at=_NOW, operation="refresh.create", outcome="accepted")
    reg_cmd = RegistrationCommand(normalized_identifier="refresh-test@example.com", display_name="Test")
    reg_outcome = await account_store.register(
        reg_cmd, "hash", invitation_digest=None, verification=None, now=_NOW, event=event
    )
    assert reg_outcome.status is RegistrationStatus.CREATED
    assert reg_outcome.account is not None
    account_id = reg_outcome.account.account_id

    create_cmd = CreateRefreshFamilyCommand(
        token_id="rt_aWlpaWlpaWlpaWlpaWlpaQ",
        token_digest=b"d" * 32,
        account_id=account_id,
        family_id="rf_a2tra2tra2tra2tra2traw",
        security_epoch=1,
        created_at=_NOW,
        token_expires_at=_NOW + timedelta(days=1),
        family_expires_at=_NOW + timedelta(days=30),
        scopes=frozenset({"read"}),
    )
    assert await refresh_store.create_family(create_cmd, event=event) is True

    proof = RefreshTokenProof(token_id="rt_aWlpaWlpaWlpaWlpaWlpaQ", digest=b"d" * 32)
    context = await refresh_store.prepare_rotation(proof, idempotency_digest=None, now=_NOW, event=event)
    assert hasattr(context, "family_id")
    assert context.family_id == "rf_a2tra2tra2tra2tra2traw"

    rotate_cmd = RotateRefreshCommand(
        token_id="rt_aWlpaWlpaWlpaWlpaWlpaQ",
        token_digest=b"d" * 32,
        account_id=account_id,
        family_id="rf_a2tra2tra2tra2tra2traw",
        security_epoch=1,
        successor_id="rt_ampqampqampqampqampqag",
        successor_digest=b"s" * 32,
        successor_expires_at=_NOW + timedelta(days=1),
        family_expires_at=_NOW + timedelta(days=30),
        scopes=frozenset({"read"}),
        idempotency_digest=b"k" * 32,
        sealed_receipt=b"receipt-1",
        receipt_expires_at=_NOW + timedelta(days=30),
    )
    rotate_outcome = await refresh_store.rotate(rotate_cmd, now=_NOW, event=event)
    assert rotate_outcome.status.value == "rotated"
    assert rotate_outcome.sealed_receipt == b"receipt-1"

    replay_ctx = await refresh_store.prepare_rotation(proof, idempotency_digest=b"k" * 32, now=_NOW, event=event)
    assert hasattr(replay_ctx, "sealed_receipt")

    attack_ctx = await refresh_store.prepare_rotation(proof, idempotency_digest=b"x" * 32, now=_NOW, event=event)
    assert getattr(attack_ctx, "family_revoked", False) is True


@pytest.mark.anyio
async def test_account_store_credentials_and_login_methods() -> None:
    """Verify SQLSpecAccountStore password change, epoch progression, and login methods."""
    backend = await _create_sqlite_backend()
    store = backend.account_store
    event = SecurityEvent(event_id="evt-2", occurred_at=_NOW, operation="account.register", outcome="accepted")

    reg_cmd = RegistrationCommand(normalized_identifier="user@example.com", display_name="User")
    outcome = await store.register(
        reg_cmd, "initial-hash", invitation_digest=None, verification=None, now=_NOW, event=event
    )
    assert outcome.status is RegistrationStatus.CREATED
    assert outcome.account is not None
    account_id = outcome.account.account_id

    account = await store.find_for_login("user@example.com")
    assert account is not None
    assert account.account_id == account_id
    assert account.security_epoch == 1

    pw_state = await store.get_password_state(account_id)
    assert pw_state is not None
    assert pw_state.password_hash == "initial-hash"
    assert pw_state.security_epoch == 1

    cas_fail = await store.compare_and_replace_password(account_id, "wrong-hash", "new-hash", event=event)
    assert cas_fail is False

    cas_ok = await store.compare_and_replace_password(account_id, "initial-hash", "new-hash", event=event)
    assert cas_ok is True

    pw_state2 = await store.get_password_state(account_id)
    assert pw_state2 is not None
    assert pw_state2.password_hash == "new-hash"

    bump_outcome = await store.replace_password_and_bump_epoch(account_id, "bumped-hash", expected_epoch=1, event=event)
    assert bump_outcome.status.value == "changed"
    assert bump_outcome.security_epoch == 2

    assert await store.current_epoch(account_id) == 2

    method = LoginMethod("method-1", "password", _NOW)
    await store.register_login_method(account_id, method, event=event)
    methods = await store.list_methods(account_id)
    assert len(methods) == 1
    assert methods[0].method_id == "method-1"

    revoke_final = await store.revoke_login_method(account_id, "method-1", require_remaining=True, event=event)
    assert revoke_final.status.value == "final_method"

    method2 = LoginMethod("method-2", "totp", _NOW)
    await store.register_login_method(account_id, method2, event=event)
    revoke_ok = await store.revoke_login_method(account_id, "method-1", require_remaining=True, event=event)
    assert revoke_ok.status.value == "revoked"
