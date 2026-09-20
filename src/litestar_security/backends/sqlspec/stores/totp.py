"""SQLSpec persistence adapter for TOTP lifecycle and recovery codes."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from hmac import compare_digest
from typing import TYPE_CHECKING, Literal, cast
from uuid import uuid4

from litestar_security.accounts import (
    PendingTOTPEnrollment,
    ProtectedSecret,
    RecoveryCodeDigest,
    TOTPMethod,
    TOTPPolicy,
)
from litestar_security.backends.sqlspec.schema import (
    TABLE_MFA_RECOVERY_CODES,
    TABLE_TOTP_METHODS,
    quote_identifier,
    resolve_column,
    resolve_table_name,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from litestar_security.accounts import LoginMethod, SecurityEvent
    from litestar_security.backends.sqlspec.backend import SQLSpecSecurityBackend

__all__ = ("SQLSpecTOTPStore",)


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


_DEFAULT_DIGITS: Literal[6] = 6
_EIGHT_DIGITS: Literal[8] = 8


def _parse_policy(val: object) -> TOTPPolicy:
    """Parse JSON or dict representation into a validated TOTPPolicy."""
    data: dict[str, object]
    if isinstance(val, dict):
        data = cast("dict[str, object]", val)
    elif isinstance(val, (str, bytes)):
        data = cast("dict[str, object]", json.loads(val))
    else:
        return TOTPPolicy()

    raw_digits = int(cast("int | str", data.get("digits", _DEFAULT_DIGITS)))
    digits: Literal[6, 8] = _EIGHT_DIGITS if raw_digits > _DEFAULT_DIGITS else _DEFAULT_DIGITS
    raw_algo = str(data.get("algorithm", "SHA1")).upper()
    algo: Literal["SHA1", "SHA256", "SHA512"]
    if raw_algo == "SHA256":
        algo = "SHA256"
    elif raw_algo == "SHA512":
        algo = "SHA512"
    else:
        algo = "SHA1"
    period = int(cast("int | str", data.get("period_seconds", 30)))
    drift = int(cast("int | str", data.get("allowed_drift_steps", 1)))
    ttl_seconds = float(cast("int | float | str", data.get("enrollment_ttl", 600)))

    return TOTPPolicy(
        digits=digits,
        period_seconds=period,
        algorithm=algo,
        allowed_drift_steps=drift,
        enrollment_ttl=timedelta(seconds=ttl_seconds),
    )


class SQLSpecTOTPStore:
    """SQLSpec-backed atomic store for TOTP enrollments, active methods, and recovery codes."""

    __slots__ = ("_backend", "_lock", "_t_recovery_codes", "_t_totp_methods")

    def __init__(self, backend: SQLSpecSecurityBackend) -> None:
        """Initialize store with parent backend and configured table names."""
        self._backend = backend
        self._lock = asyncio.Lock()
        self._t_totp_methods = resolve_table_name(backend.config, TABLE_TOTP_METHODS)
        self._t_recovery_codes = resolve_table_name(backend.config, TABLE_MFA_RECOVERY_CODES)

    async def create_totp_enrollment(self, enrollment: PendingTOTPEnrollment) -> None:
        """Store one pending enrollment."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "id"))
        col_method_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "method_id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "user_id"))
        col_secret = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "secret_ciphertext"))
        col_key_version = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "key_version"))
        col_status = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "status"))
        col_enrollment_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "enrollment_id"))
        col_policy = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "policy"))
        col_last_counter = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "last_counter"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "created_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "expires_at"))

        policy_dict = {
            "digits": enrollment.policy.digits,
            "period_seconds": enrollment.policy.period_seconds,
            "algorithm": enrollment.policy.algorithm,
            "allowed_drift_steps": enrollment.policy.allowed_drift_steps,
            "enrollment_ttl": enrollment.policy.enrollment_ttl.total_seconds(),
        }

        insert_query = (
            f"INSERT INTO {self._t_totp_methods} ("
            f"{col_id}, {col_method_id}, {col_user_id}, {col_secret}, {col_key_version}, "
            f"{col_status}, {col_enrollment_id}, {col_policy}, {col_last_counter}, "
            f"{col_created_at}, {col_expires_at}) "
            f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )

        async with self._backend.session() as session:
            await session.execute(
                insert_query,
                str(uuid4()),
                enrollment.method_id,
                enrollment.account_id,
                enrollment.protected_secret.ciphertext,
                enrollment.protected_secret.key_version,
                "pending",
                enrollment.enrollment_id,
                json.dumps(policy_dict),
                0,
                enrollment.created_at.isoformat(),
                enrollment.expires_at.isoformat(),
            )

    async def get_totp_enrollment(self, enrollment_id: str) -> PendingTOTPEnrollment | None:
        """Load one pending enrollment by its opaque identifier."""
        col_enrollment_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "enrollment_id"))
        col_method_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "method_id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "user_id"))
        col_secret = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "secret_ciphertext"))
        col_key_version = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "key_version"))
        col_status = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "status"))
        col_policy = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "policy"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "created_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "expires_at"))

        query = (
            f"SELECT {col_enrollment_id}, {col_method_id}, {col_user_id}, {col_secret}, "
            f"{col_key_version}, {col_policy}, {col_created_at}, {col_expires_at} "
            f"FROM {self._t_totp_methods} "
            f"WHERE {col_enrollment_id} = ? AND {col_status} = 'pending'"
        )

        async with self._backend.session() as session:
            row = await session.select_one_or_none(query, enrollment_id)
            if row is None:
                return None

            raw_eid = str(_row_val(row, 0, "enrollment_id"))
            raw_mid = str(_row_val(row, 1, "method_id"))
            raw_uid = str(_row_val(row, 2, "user_id"))
            raw_secret = bytes(cast("bytes", _row_val(row, 3, "secret_ciphertext")))
            raw_kver = str(_row_val(row, 4, "key_version"))
            raw_policy = _row_val(row, 5, "policy")
            raw_created = _row_val(row, 6, "created_at")
            raw_expires = _row_val(row, 7, "expires_at")

            return PendingTOTPEnrollment(
                enrollment_id=raw_eid,
                method_id=raw_mid,
                account_id=raw_uid,
                protected_secret=ProtectedSecret(ciphertext=raw_secret, key_version=raw_kver),
                policy=_parse_policy(raw_policy),
                created_at=_parse_datetime(raw_created),
                expires_at=_parse_datetime(raw_expires),
            )

    async def activate_totp(
        self,
        account_id: str,
        enrollment_id: str,
        *,
        accepted_counter: int,
        login_method: LoginMethod,
        event: SecurityEvent,
        now: datetime,
    ) -> TOTPMethod | None:
        """Atomically consume an enrollment and register its active login method."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "id"))
        col_enrollment_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "enrollment_id"))
        col_method_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "method_id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "user_id"))
        col_secret = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "secret_ciphertext"))
        col_key_version = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "key_version"))
        col_status = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "status"))
        col_policy = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "policy"))
        col_last_counter = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "last_counter"))
        col_confirmed_at = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "confirmed_at"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "created_at"))
        col_updated_at = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "updated_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "expires_at"))

        select_query = (
            f"SELECT {col_id}, {col_method_id}, {col_secret}, {col_key_version}, {col_policy}, {col_expires_at} "
            f"FROM {self._t_totp_methods} "
            f"WHERE {col_enrollment_id} = ? AND {col_user_id} = ? AND {col_status} = 'pending'"
        )

        update_query = (
            f"UPDATE {self._t_totp_methods} "
            f"SET {col_status} = 'active', {col_enrollment_id} = NULL, {col_expires_at} = NULL, "
            f"{col_last_counter} = ?, {col_confirmed_at} = ?, {col_created_at} = ?, {col_updated_at} = ? "
            f"WHERE {col_id} = ? AND {col_status} = 'pending'"
        )

        now_iso = now.isoformat()

        async with self._lock, self._backend.session() as session:
            row = await session.select_one_or_none(select_query, enrollment_id, account_id)
            if row is None:
                return None

            expires_at = _parse_datetime(_row_val(row, 5, "expires_at"))
            if expires_at <= now:
                return None

            row_id = str(_row_val(row, 0, "id"))
            method_id = str(_row_val(row, 1, "method_id"))
            secret_ciphertext = bytes(cast("bytes", _row_val(row, 2, "secret_ciphertext")))
            key_version = str(_row_val(row, 3, "key_version"))
            raw_policy = _row_val(row, 4, "policy")

            await session.execute(
                update_query,
                accepted_counter,
                now_iso,
                now_iso,
                now_iso,
                row_id,
            )

            await self._backend.account_store.register_login_method(account_id, login_method, event=event)

            return TOTPMethod(
                method_id=method_id,
                account_id=account_id,
                protected_secret=ProtectedSecret(ciphertext=secret_ciphertext, key_version=key_version),
                policy=_parse_policy(raw_policy),
                last_accepted_counter=accepted_counter,
                created_at=now,
            )

    async def activate_totp_with_recovery_codes(
        self,
        account_id: str,
        enrollment_id: str,
        *,
        accepted_counter: int,
        codes: tuple[RecoveryCodeDigest, ...],
        login_method: LoginMethod,
        event: SecurityEvent,
        now: datetime,
    ) -> TOTPMethod | None:
        """Atomically activate TOTP and replace the complete recovery-code set."""
        method = await self.activate_totp(
            account_id,
            enrollment_id,
            accepted_counter=accepted_counter,
            login_method=login_method,
            event=event,
            now=now,
        )
        if method is None:
            return None
        await self.replace_recovery_codes(account_id, codes, now=now)
        return method

    async def get_totp_method(self, account_id: str, method_id: str) -> TOTPMethod | None:
        """Load an active method only for its owner."""
        col_method_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "method_id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "user_id"))
        col_secret = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "secret_ciphertext"))
        col_key_version = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "key_version"))
        col_status = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "status"))
        col_policy = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "policy"))
        col_last_counter = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "last_counter"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "created_at"))
        col_last_used_at = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "last_used_at"))

        query = (
            f"SELECT {col_method_id}, {col_user_id}, {col_secret}, {col_key_version}, {col_policy}, "
            f"{col_last_counter}, {col_created_at}, {col_last_used_at} "
            f"FROM {self._t_totp_methods} "
            f"WHERE {col_method_id} = ? AND {col_user_id} = ? AND {col_status} = 'active'"
        )

        async with self._backend.session() as session:
            row = await session.select_one_or_none(query, method_id, account_id)
            if row is None:
                return None

            raw_mid = str(_row_val(row, 0, "method_id"))
            raw_uid = str(_row_val(row, 1, "user_id"))
            raw_secret = bytes(cast("bytes", _row_val(row, 2, "secret_ciphertext")))
            raw_kver = str(_row_val(row, 3, "key_version"))
            raw_policy = _row_val(row, 4, "policy")
            raw_counter = int(cast("int | str", _row_val(row, 5, "last_counter") or 0))
            raw_created = _row_val(row, 6, "created_at")
            raw_used = _row_val(row, 7, "last_used_at")

            return TOTPMethod(
                method_id=raw_mid,
                account_id=raw_uid,
                protected_secret=ProtectedSecret(ciphertext=raw_secret, key_version=raw_kver),
                policy=_parse_policy(raw_policy),
                last_accepted_counter=raw_counter,
                created_at=_parse_datetime(raw_created),
                last_used_at=_parse_datetime(raw_used) if raw_used is not None else None,
            )

    async def advance_totp_counter(self, method_id: str, *, accepted_counter: int, now: datetime) -> bool:
        """Atomically advance only to a strictly greater accepted counter."""
        col_method_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "method_id"))
        col_status = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "status"))
        col_last_counter = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "last_counter"))
        col_last_used_at = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "last_used_at"))

        select_query = (
            f"SELECT {col_last_counter} FROM {self._t_totp_methods} "
            f"WHERE {col_method_id} = ? AND {col_status} = 'active'"
        )

        update_query = (
            f"UPDATE {self._t_totp_methods} "
            f"SET {col_last_counter} = ?, {col_last_used_at} = ? "
            f"WHERE {col_method_id} = ? AND {col_status} = 'active' AND {col_last_counter} < ?"
        )

        async with self._lock, self._backend.session() as session:
            row = await session.select_one_or_none(select_query, method_id)
            if row is None:
                return False

            curr_counter = int(cast("int | str", _row_val(row, 0, "last_counter") or 0))
            if accepted_counter <= curr_counter:
                return False

            await session.execute(update_query, accepted_counter, now.isoformat(), method_id, accepted_counter)
            return True

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

        delete_query = f"DELETE FROM {self._t_recovery_codes} WHERE {col_user_id} = ?"
        insert_query = (
            f"INSERT INTO {self._t_recovery_codes} ("
            f"{col_id}, {col_user_id}, {col_pepper}, {col_digest}, {col_created_at}) "
            f"VALUES (?, ?, ?, ?, ?)"
        )

        now_iso = now.isoformat()

        async with self._lock, self._backend.session() as session:
            await session.execute(delete_query, account_id)
            for code in codes:
                if code.account_id == account_id:
                    code_id = str(uuid4())
                    await session.execute(
                        insert_query,
                        code_id,
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

        select_query = f"SELECT {col_id}, {col_digest} FROM {self._t_recovery_codes} WHERE {col_user_id} = ?"
        delete_query = f"DELETE FROM {self._t_recovery_codes} WHERE {col_id} = ?"

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

    async def delete_totp_method(self, account_id: str, method_id: str) -> bool:
        """Delete an active TOTP method by identifier."""
        col_method_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "method_id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_TOTP_METHODS, "user_id"))
        query = f"DELETE FROM {self._t_totp_methods} WHERE {col_method_id} = ? AND {col_user_id} = ?"

        async with self._lock, self._backend.session() as session:
            await session.execute(query, method_id, account_id)
            return True
