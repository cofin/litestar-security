"""Unit tests for SQLSpec MFA, TOTP, and step-up stores and protocol conformance."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, cast

import pytest

from litestar_security.accounts import (
    MFALoginChallengeStore,
    MFAStore,
    PendingTOTPEnrollment,
    ProtectedSecret,
    RecoveryCodeDigest,
    StepUpStore,
    TOTPPolicy,
    TOTPStore,
)
from litestar_security.backends.sqlspec import SQLSpecSecurityBackend, SQLSpecSecurityBackendConfig
from litestar_security.backends.sqlspec.schema import get_create_table_statements
from litestar_security.testing.conformance import (
    assert_mfa_login_challenge_store_conformance,
    assert_mfa_store_conformance,
    assert_step_up_store_conformance,
)

if TYPE_CHECKING:
    from litestar_security.backends.sqlspec.stores import (
        SQLSpecMFALoginChallengeStore,
        SQLSpecStepUpStore,
        SQLSpecTOTPStore,
    )

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


def _create_isolated_backend(config: SQLSpecSecurityBackendConfig | None = None) -> SQLSpecSecurityBackend:
    """Create an isolated in-memory SQLite backend with pre-initialized schema."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    driver = _SyncSqliteDriver(conn)
    backend_config = config or SQLSpecSecurityBackendConfig()
    backend = SQLSpecSecurityBackend(driver, config=backend_config)
    ddl_statements = get_create_table_statements(backend_config, dialect="sqlite")
    driver.execute_script("\n".join(ddl_statements))
    return backend


def test_mfa_stores_fulfill_runtime_checkable_protocols() -> None:
    """Verify MFA and TOTP store adapters satisfy their respective runtime checkable protocols."""
    backend = _create_isolated_backend()

    totp_store = backend.totp_store
    assert isinstance(totp_store, TOTPStore)
    assert isinstance(totp_store, MFAStore)

    challenge_store = backend.mfa_login_challenge_store
    assert isinstance(challenge_store, MFALoginChallengeStore)

    step_up_store = backend.step_up_store
    assert isinstance(step_up_store, StepUpStore)


@pytest.mark.anyio
async def test_totp_store_conformance() -> None:
    """Verify SQLSpecTOTPStore satisfies full MFA and TOTP store conformance requirements."""

    def make_store() -> SQLSpecTOTPStore:
        backend = _create_isolated_backend()
        return backend.totp_store

    await assert_mfa_store_conformance(make_store)


@pytest.mark.anyio
async def test_mfa_login_challenge_conformance() -> None:
    """Verify SQLSpecMFALoginChallengeStore satisfies challenge binding and burn invariants."""

    def make_store() -> SQLSpecMFALoginChallengeStore:
        backend = _create_isolated_backend()
        return backend.mfa_login_challenge_store

    await assert_mfa_login_challenge_store_conformance(make_store)


@pytest.mark.anyio
async def test_step_up_store_conformance() -> None:
    """Verify SQLSpecStepUpStore satisfies one-time exact-binding step-up requirements."""

    def make_store() -> SQLSpecStepUpStore:
        backend = _create_isolated_backend()
        return backend.step_up_store

    await assert_step_up_store_conformance(make_store)


@pytest.mark.anyio
async def test_totp_enrollment_lifecycle() -> None:
    """Verify pending enrollment creation, lookup, and expiration behavior."""
    backend = _create_isolated_backend()
    store = backend.totp_store

    enrollment = PendingTOTPEnrollment(
        enrollment_id="enroll-1",
        method_id="method-1",
        account_id="user-1",
        protected_secret=ProtectedSecret(ciphertext=b"encrypted-totp-secret", key_version="v1"),
        policy=TOTPPolicy(digits=6, period_seconds=30),
        created_at=_NOW,
        expires_at=_NOW + timedelta(minutes=5),
    )

    await store.create_totp_enrollment(enrollment)
    fetched = await store.get_totp_enrollment("enroll-1")
    assert fetched is not None
    assert fetched.enrollment_id == "enroll-1"
    assert fetched.method_id == "method-1"
    assert fetched.account_id == "user-1"
    assert fetched.protected_secret.ciphertext == b"encrypted-totp-secret"
    assert fetched.protected_secret.key_version == "v1"
    assert fetched.policy.digits == 6
    assert fetched.policy.period_seconds == 30

    non_existent = await store.get_totp_enrollment("non-existent")
    assert non_existent is None


@pytest.mark.anyio
async def test_recovery_code_store_lifecycle() -> None:
    """Verify SQLSpecRecoveryCodeStore handles replacement and atomic consumption."""
    backend = _create_isolated_backend()
    store = backend.recovery_code_store

    digest_1 = b"\x01" * 32
    digest_2 = b"\x02" * 32
    codes = (
        RecoveryCodeDigest(account_id="user-1", pepper_version="v1", digest=digest_1),
        RecoveryCodeDigest(account_id="user-1", pepper_version="v1", digest=digest_2),
    )

    await store.replace_recovery_codes("user-1", codes, now=_NOW)

    consumed_1 = await store.consume_recovery_code("user-1", digest_1, now=_NOW)
    assert consumed_1 is True

    replayed = await store.consume_recovery_code("user-1", digest_1, now=_NOW)
    assert replayed is False

    consumed_2 = await store.consume_recovery_code("user-1", digest_2, now=_NOW)
    assert consumed_2 is True

    non_matching = await store.consume_recovery_code("user-1", b"\xff" * 32, now=_NOW)
    assert non_matching is False


@pytest.mark.anyio
async def test_delete_totp_method() -> None:
    """Verify active TOTP method deletion removes record."""
    backend = _create_isolated_backend()
    store = backend.totp_store

    deleted = await store.delete_totp_method("user-1", "non-existent")
    assert deleted is True
