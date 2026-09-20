"""SQLSpec persistence adapters for MFA login challenges, step-up grants, and recovery codes."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from hmac import compare_digest
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from litestar_security.accounts import MFALoginChallenge, RecoveryCodeDigest, StepUpGrantState
from litestar_security.backends.sqlspec.schema import (
    TABLE_MFA_LOGIN_CHALLENGES,
    TABLE_MFA_RECOVERY_CODES,
    TABLE_STEP_UP_GRANTS,
    quote_identifier,
    resolve_column,
    resolve_table_name,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from litestar_security.backends.sqlspec.backend import SQLSpecSecurityBackend

__all__ = (
    "SQLSpecMFALoginChallengeStore",
    "SQLSpecRecoveryCodeStore",
    "SQLSpecStepUpStore",
)


def _row_val(row: object, idx: int, key: str) -> object:
    """Safely extract field from tuple or dict row representation."""
    if isinstance(row, (tuple, list)):
        seq = cast("Sequence[object]", row)
        return seq[idx] if idx < len(seq) else None
    if isinstance(row, dict):
        mapping = cast("Mapping[str, object]", row)
        return mapping.get(key)
    return None


def _parse_datetime(val: object) -> datetime:
    """Parse ISO8601 string or datetime into UTC-aware datetime."""
    if isinstance(val, datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
    dt = datetime.fromisoformat(str(val))
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class SQLSpecMFALoginChallengeStore:
    """SQLSpec-backed atomic store for burn-on-reveal MFA login challenges."""

    __slots__ = ("_backend", "_lock", "_table_name")

    def __init__(self, backend: SQLSpecSecurityBackend) -> None:
        """Initialize with parent backend and configured table name."""
        self._backend = backend
        self._lock = asyncio.Lock()
        self._table_name = resolve_table_name(backend.config, TABLE_MFA_LOGIN_CHALLENGES)

    async def put(self, challenge: MFALoginChallenge) -> None:
        """Persist one pending challenge."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "id"))
        col_digest = quote_identifier(
            resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "challenge_digest")
        )
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "user_id"))
        col_epoch = quote_identifier(
            resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "security_epoch")
        )
        col_client_key = quote_identifier(
            resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "client_key")
        )
        col_issued_at = quote_identifier(
            resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "issued_at")
        )
        col_expires_at = quote_identifier(
            resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "expires_at")
        )

        insert_query = (
            f"INSERT INTO {self._table_name} ("
            f"{col_id}, {col_digest}, {col_user_id}, {col_epoch}, {col_client_key}, {col_issued_at}, {col_expires_at}) "
            f"VALUES (?, ?, ?, ?, ?, ?, ?)"
        )

        async with self._backend.session() as session:
            await session.execute(
                insert_query,
                str(uuid4()),
                challenge.challenge_digest,
                challenge.account_id,
                challenge.security_epoch,
                challenge.client_key,
                challenge.issued_at.isoformat(),
                challenge.expires_at.isoformat(),
            )

    async def consume(
        self,
        challenge_digest: bytes,
        *,
        account_id: str,
        security_epoch: int,
        now: datetime,
    ) -> MFALoginChallenge | None:
        """Atomically burn and return one exact, unexpired challenge binding."""
        col_digest = quote_identifier(
            resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "challenge_digest")
        )
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "user_id"))
        col_epoch = quote_identifier(
            resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "security_epoch")
        )
        col_client_key = quote_identifier(
            resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "client_key")
        )
        col_issued_at = quote_identifier(
            resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "issued_at")
        )
        col_expires_at = quote_identifier(
            resolve_column(self._backend.config, TABLE_MFA_LOGIN_CHALLENGES, "expires_at")
        )

        select_query = (
            f"SELECT {col_digest}, {col_user_id}, {col_epoch}, {col_client_key}, {col_issued_at}, {col_expires_at} "
            f"FROM {self._table_name} WHERE {col_digest} = ?"
        )
        delete_query = f"DELETE FROM {self._table_name} WHERE {col_digest} = ?"

        async with self._lock, self._backend.session() as session:
            row = await session.select_one_or_none(select_query, challenge_digest)
            if row is None:
                return None

            await session.execute(delete_query, challenge_digest)

            stored_digest = bytes(cast("bytes", _row_val(row, 0, "challenge_digest")))
            stored_account_id = str(_row_val(row, 1, "user_id"))
            stored_epoch = int(cast("int | str", _row_val(row, 2, "security_epoch") or 0))
            stored_client_key = _row_val(row, 3, "client_key")
            stored_issued_at = _parse_datetime(_row_val(row, 4, "issued_at"))
            stored_expires_at = _parse_datetime(_row_val(row, 5, "expires_at"))

            if not compare_digest(stored_digest, challenge_digest):
                return None
            if stored_account_id != account_id:
                return None
            if stored_epoch != security_epoch:
                return None
            if stored_expires_at <= now:
                return None

            return MFALoginChallenge(
                challenge_digest=challenge_digest,
                account_id=account_id,
                security_epoch=security_epoch,
                client_key=str(stored_client_key) if stored_client_key is not None else None,
                issued_at=stored_issued_at,
                expires_at=stored_expires_at,
            )


class SQLSpecStepUpStore:
    """SQLSpec-backed atomic store for digest-only step-up grants."""

    __slots__ = ("_backend", "_lock", "_table_name")

    def __init__(self, backend: SQLSpecSecurityBackend) -> None:
        """Initialize with parent backend and configured table name."""
        self._backend = backend
        self._lock = asyncio.Lock()
        self._table_name = resolve_table_name(backend.config, TABLE_STEP_UP_GRANTS)

    async def put(self, record: StepUpGrantState) -> None:
        """Persist one unconsumed grant."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "id"))
        col_grant_digest = quote_identifier(
            resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "grant_digest")
        )
        col_transport_digest = quote_identifier(
            resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "transport_digest")
        )
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "user_id"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "security_epoch"))
        col_purpose = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "purpose"))
        col_methods = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "methods"))
        col_traits = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "traits"))
        col_auth_at = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "authenticated_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "expires_at"))

        insert_query = (
            f"INSERT INTO {self._table_name} ("
            f"{col_id}, {col_grant_digest}, {col_transport_digest}, {col_user_id}, {col_epoch}, "
            f"{col_purpose}, {col_methods}, {col_traits}, {col_auth_at}, {col_expires_at}) "
            f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )

        async with self._backend.session() as session:
            await session.execute(
                insert_query,
                str(uuid4()),
                record.grant_digest,
                record.transport_digest,
                record.principal_id,
                record.security_epoch,
                record.purpose,
                json.dumps(sorted(record.methods)),
                json.dumps(sorted(record.traits)),
                record.authenticated_at.isoformat(),
                record.expires_at.isoformat(),
            )

    async def consume(
        self,
        grant_digest: bytes,
        *,
        principal_id: str,
        security_epoch: int,
        purpose: str,
        transport_digest: bytes,
        now: datetime,
    ) -> StepUpGrantState | None:
        """Atomically consume only an exact, current binding match."""
        col_grant_digest = quote_identifier(
            resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "grant_digest")
        )
        col_transport_digest = quote_identifier(
            resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "transport_digest")
        )
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "user_id"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "security_epoch"))
        col_purpose = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "purpose"))
        col_methods = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "methods"))
        col_traits = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "traits"))
        col_auth_at = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "authenticated_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_STEP_UP_GRANTS, "expires_at"))

        select_query = (
            f"SELECT {col_grant_digest}, {col_transport_digest}, {col_user_id}, {col_epoch}, "
            f"{col_purpose}, {col_methods}, {col_traits}, {col_auth_at}, {col_expires_at} "
            f"FROM {self._table_name} WHERE {col_grant_digest} = ?"
        )
        delete_query = f"DELETE FROM {self._table_name} WHERE {col_grant_digest} = ?"

        async with self._lock, self._backend.session() as session:
            row = await session.select_one_or_none(select_query, grant_digest)
            if row is None:
                return None

            stored_grant_digest = bytes(cast("bytes", _row_val(row, 0, "grant_digest")))
            stored_transport_digest = bytes(cast("bytes", _row_val(row, 1, "transport_digest")))
            stored_user_id = str(_row_val(row, 2, "user_id"))
            stored_epoch = int(cast("int | str", _row_val(row, 3, "security_epoch") or 0))
            stored_purpose = str(_row_val(row, 4, "purpose"))
            stored_methods_raw = _row_val(row, 5, "methods")
            stored_traits_raw = _row_val(row, 6, "traits")
            stored_auth_at = _parse_datetime(_row_val(row, 7, "authenticated_at"))
            stored_expires_at = _parse_datetime(_row_val(row, 8, "expires_at"))

            if not compare_digest(stored_grant_digest, grant_digest):
                return None
            if stored_user_id != principal_id:
                return None
            if stored_epoch != security_epoch:
                return None
            if stored_purpose != purpose:
                return None
            if not compare_digest(stored_transport_digest, transport_digest):
                return None
            if stored_expires_at <= now:
                return None

            await session.execute(delete_query, grant_digest)

            methods = frozenset(
                cast("list[str]", json.loads(stored_methods_raw))
                if isinstance(stored_methods_raw, (str, bytes))
                else cast("list[str]", stored_methods_raw or [])
            )
            traits = frozenset(
                cast("list[str]", json.loads(stored_traits_raw))
                if isinstance(stored_traits_raw, (str, bytes))
                else cast("list[str]", stored_traits_raw or [])
            )

            return StepUpGrantState(
                grant_digest=grant_digest,
                transport_digest=transport_digest,
                principal_id=principal_id,
                security_epoch=security_epoch,
                purpose=purpose,
                methods=methods,
                traits=traits,
                authenticated_at=stored_auth_at,
                expires_at=stored_expires_at,
            )


class SQLSpecRecoveryCodeStore:
    """SQLSpec-backed store for multi-factor recovery codes."""

    __slots__ = ("_backend", "_lock", "_table_name")

    def __init__(self, backend: SQLSpecSecurityBackend) -> None:
        """Initialize with parent backend and configured table name."""
        self._backend = backend
        self._lock = asyncio.Lock()
        self._table_name = resolve_table_name(backend.config, TABLE_MFA_RECOVERY_CODES)

    async def replace_recovery_codes(
        self, account_id: str, codes: tuple[RecoveryCodeDigest, ...], *, now: datetime
    ) -> None:
        """Atomically replace every recovery code for an account."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_MFA_RECOVERY_CODES, "id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_MFA_RECOVERY_CODES, "user_id"))
        col_pepper = quote_identifier(
            resolve_column(self._backend.config, TABLE_MFA_RECOVERY_CODES, "pepper_version")
        )
        col_digest = quote_identifier(resolve_column(self._backend.config, TABLE_MFA_RECOVERY_CODES, "digest"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_MFA_RECOVERY_CODES, "created_at"))

        delete_query = f"DELETE FROM {self._table_name} WHERE {col_user_id} = ?"
        insert_query = (
            f"INSERT INTO {self._table_name} ("
            f"{col_id}, {col_user_id}, {col_pepper}, {col_digest}, {col_created_at}) "
            f"VALUES (?, ?, ?, ?, ?)"
        )

        now_iso = now.isoformat()

        async with self._lock, self._backend.session() as session:
            await session.execute(delete_query, account_id)
            for code in codes:
                if code.account_id == account_id:
                    await session.execute(
                        insert_query,
                        str(uuid4()),
                        account_id,
                        code.pepper_version,
                        code.digest,
                        now_iso,
                    )

    async def consume_recovery_code(self, account_id: str, digest: bytes, *, now: datetime) -> bool:
        """Atomically compare in constant time and consume one digest."""
        del now
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_MFA_RECOVERY_CODES, "id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_MFA_RECOVERY_CODES, "user_id"))
        col_digest = quote_identifier(resolve_column(self._backend.config, TABLE_MFA_RECOVERY_CODES, "digest"))

        select_query = f"SELECT {col_id}, {col_digest} FROM {self._table_name} WHERE {col_user_id} = ?"
        delete_query = f"DELETE FROM {self._table_name} WHERE {col_id} = ?"

        async with self._lock, self._backend.session() as session:
            rows = await session.select(select_query, account_id)
            match_id: str | None = None
            for row in rows:
                stored_digest = bytes(cast("bytes", _row_val(row, 1, "digest")))
                if compare_digest(stored_digest, digest):
                    match_id = str(_row_val(row, 0, "id"))
                    break

            if match_id is None:
                return False

            await session.execute(delete_query, match_id)
            return True
