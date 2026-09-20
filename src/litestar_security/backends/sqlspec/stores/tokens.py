"""SQLSpec persistence adapters for refresh tokens and purpose tokens."""

import json
from datetime import datetime, timezone
from hmac import compare_digest
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from litestar_security.accounts import (
    CreateRefreshFamilyCommand,
    NotificationCommand,
    PasswordResetOutcome,
    PasswordResetStatus,
    RefreshFamilyContext,
    RefreshPreflightOutcome,
    RefreshReceiptReplay,
    RefreshRotationOutcome,
    RefreshRotationStatus,
    RefreshTokenProof,
    RotateRefreshCommand,
    SecurityEvent,
    TokenIssue,
    TokenPurpose,
    VerificationOutcome,
    VerificationStatus,
)
from litestar_security.backends.sqlspec.schema import (
    TABLE_ACCOUNTS,
    TABLE_PURPOSE_TOKENS,
    TABLE_REFRESH_TOKENS,
    quote_identifier,
    resolve_column,
    resolve_table_name,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar_security.backends.sqlspec.backend import SQLSpecSecurityBackend

__all__ = ("SQLSpecPurposeTokenStore", "SQLSpecRefreshTokenStore")


def _extract_epoch(row: "object") -> "int":
    """Safely extract security epoch integer from driver row representation."""
    if isinstance(row, (tuple, list)):
        seq = cast("Sequence[object]", row)
        return int(cast("int | str", seq[0]))
    if isinstance(row, dict):
        dict_row = cast("dict[str, object]", row)
        val = dict_row.get("security_epoch", 1)
        return int(cast("int | str", val if val is not None else 1))
    return 1


def _extract_rowcount(result: "object") -> "int | None":
    """Safely extract affected rowcount from driver execution result."""
    if result is None:
        return None
    for attr in ("data_row_count", "rowcount_override", "rowcount", "rows_affected"):
        val = getattr(result, attr, None)
        if isinstance(val, int) and val >= 0:
            return val
    cursor = getattr(result, "cursor_result", None)
    if cursor is not None:
        val = getattr(cursor, "rowcount", None)
        if isinstance(val, int) and val >= 0:
            return val
    return None


class SQLSpecRefreshTokenStore:
    """SQLSpec-backed atomic refresh token family store."""

    __slots__ = ("_backend", "_t_accounts", "_t_refresh")

    def __init__(self, backend: "SQLSpecSecurityBackend") -> "None":
        """Initialize with parent security backend."""
        self._backend = backend
        self._t_refresh = resolve_table_name(backend.config, TABLE_REFRESH_TOKENS)
        self._t_accounts = resolve_table_name(backend.config, TABLE_ACCOUNTS)

    async def create_family(self, command: "CreateRefreshFamilyCommand", *, event: "SecurityEvent") -> "bool":
        """Atomically create a new refresh token family."""
        del event
        col_acc_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_acc_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "security_epoch"))

        col_ref_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "id"))
        col_token_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_id"))
        col_token_digest = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_digest"))
        col_family_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "family_id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "user_id"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "security_epoch"))
        col_token_exp = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_expires_at"))
        col_family_exp = quote_identifier(
            resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "family_expires_at")
        )
        col_scopes = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "scopes"))
        col_consumed = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "consumed"))
        col_revoked = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "revoked"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "created_at"))

        account_query = f"SELECT {col_acc_epoch} FROM {self._t_accounts} WHERE {col_acc_id} = ?"
        check_query = f"SELECT 1 FROM {self._t_refresh} WHERE {col_token_id} = ? OR {col_family_id} = ?"
        insert_query = (
            f"INSERT INTO {self._t_refresh} ("
            f"{col_ref_id}, {col_token_id}, {col_token_digest}, {col_family_id}, {col_user_id}, "
            f"{col_epoch}, {col_token_exp}, {col_family_exp}, {col_scopes}, "
            f"{col_consumed}, {col_revoked}, {col_created_at}"
            f") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)"
        )

        async with self._backend.session() as session:
            acc_row = await session.select_one_or_none(account_query, command.account_id)
            if acc_row is None:
                return False
            curr_epoch = _extract_epoch(acc_row)
            if curr_epoch != command.security_epoch:
                return False

            existing = await session.select_one_or_none(check_query, command.token_id, command.family_id)
            if existing is not None:
                return False

            row_id = str(uuid4())
            now_iso = datetime.now(timezone.utc).isoformat()
            scopes_json = json.dumps(sorted(command.scopes))
            await session.execute(
                insert_query,
                row_id,
                command.token_id,
                bytes(command.token_digest),
                command.family_id,
                command.account_id,
                command.security_epoch,
                command.token_expires_at.isoformat(),
                command.family_expires_at.isoformat(),
                scopes_json,
                now_iso,
            )
            return True

    async def prepare_rotation(
        self, proof: "RefreshTokenProof", idempotency_digest: "bytes | None", *, now: "datetime", event: "SecurityEvent"
    ) -> "RefreshFamilyContext | RefreshReceiptReplay | RefreshPreflightOutcome":
        """Resolve and validate a refresh token before rotation."""
        del event
        col_acc_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_acc_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "security_epoch"))

        col_token_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_id"))
        col_token_digest = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_digest"))
        col_family_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "family_id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "user_id"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "security_epoch"))
        col_token_exp = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_expires_at"))
        col_family_exp = quote_identifier(
            resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "family_expires_at")
        )
        col_scopes = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "scopes"))
        col_consumed = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "consumed"))
        col_revoked = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "revoked"))
        col_idemp = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "idempotency_digest"))
        col_receipt = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "sealed_receipt"))

        select_query = (
            f"SELECT {col_token_id}, {col_token_digest}, {col_family_id}, {col_user_id}, {col_epoch}, "
            f"{col_token_exp}, {col_family_exp}, {col_scopes}, {col_consumed}, {col_revoked}, "
            f"{col_idemp}, {col_receipt} "
            f"FROM {self._t_refresh} WHERE {col_token_id} = ?"
        )
        revoke_family_query = f"UPDATE {self._t_refresh} SET {col_revoked} = 1 WHERE {col_family_id} = ?"
        account_query = f"SELECT {col_acc_epoch} FROM {self._t_accounts} WHERE {col_acc_id} = ?"

        async with self._backend.session() as session:
            row = await session.select_one_or_none(select_query, proof.token_id)
            if row is None:
                return RefreshPreflightOutcome(RefreshRotationStatus.INVALID)

            d = self._row_to_refresh_dict(row)
            stored_digest = bytes(cast("bytes", d["token_digest"]))
            if not compare_digest(stored_digest, proof.digest):
                return RefreshPreflightOutcome(RefreshRotationStatus.INVALID)

            if bool(d["revoked"]):
                return RefreshPreflightOutcome(RefreshRotationStatus.REVOKED, family_revoked=True)

            token_exp = self._parse_dt(d["token_expires_at"])
            family_exp = self._parse_dt(d["family_expires_at"])
            context = RefreshFamilyContext(
                account_id=str(d["user_id"]),
                family_id=str(d["family_id"]),
                security_epoch=int(cast("int | str", d["security_epoch"])),
                token_expires_at=token_exp,
                family_expires_at=family_exp,
                scopes=self._parse_scopes(d["scopes"]),
            )

            if bool(d["consumed"]):
                stored_idemp = bytes(cast("bytes", d["idempotency_digest"])) if d["idempotency_digest"] else None
                stored_receipt = bytes(cast("bytes", d["sealed_receipt"])) if d["sealed_receipt"] else None
                replay_match = (
                    stored_idemp is not None
                    and idempotency_digest is not None
                    and compare_digest(stored_idemp, idempotency_digest)
                    and stored_receipt is not None
                )
                if replay_match and stored_receipt is not None:
                    return RefreshReceiptReplay(context, stored_receipt)
                await session.execute(revoke_family_query, str(d["family_id"]))
                return RefreshPreflightOutcome(RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True)

            if token_exp <= now or family_exp <= now:
                return RefreshPreflightOutcome(RefreshRotationStatus.EXPIRED)

            acc_row = await session.select_one_or_none(account_query, str(d["user_id"]))
            if acc_row is None:
                return RefreshPreflightOutcome(RefreshRotationStatus.EPOCH_MISMATCH)
            acc_epoch = _extract_epoch(acc_row)
            if acc_epoch != int(cast("int | str", d["security_epoch"])):
                return RefreshPreflightOutcome(RefreshRotationStatus.EPOCH_MISMATCH)

            return context

    async def rotate(
        self, command: "RotateRefreshCommand", *, now: "datetime", event: "SecurityEvent"
    ) -> "RefreshRotationOutcome":
        """Atomically consume predecessor and register successor refresh token."""
        del event
        col_acc_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_acc_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "security_epoch"))

        col_ref_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "id"))
        col_token_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_id"))
        col_token_digest = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_digest"))
        col_family_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "family_id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "user_id"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "security_epoch"))
        col_token_exp = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_expires_at"))
        col_family_exp = quote_identifier(
            resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "family_expires_at")
        )
        col_scopes = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "scopes"))
        col_consumed = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "consumed"))
        col_revoked = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "revoked"))
        col_idemp = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "idempotency_digest"))
        col_receipt = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "sealed_receipt"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "created_at"))

        select_query = (
            f"SELECT {col_token_id}, {col_token_digest}, {col_family_id}, {col_user_id}, {col_epoch}, "
            f"{col_token_exp}, {col_family_exp}, {col_scopes}, {col_consumed}, {col_revoked} "
            f"FROM {self._t_refresh} WHERE {col_token_id} = ?"
        )
        check_succ_query = f"SELECT 1 FROM {self._t_refresh} WHERE {col_token_id} = ?"
        consume_query = (
            f"UPDATE {self._t_refresh} SET {col_consumed} = 1, {col_idemp} = ?, {col_receipt} = ? "
            f"WHERE {col_token_id} = ? AND {col_consumed} = 0"
        )
        insert_query = (
            f"INSERT INTO {self._t_refresh} ("
            f"{col_ref_id}, {col_token_id}, {col_token_digest}, {col_family_id}, {col_user_id}, "
            f"{col_epoch}, {col_token_exp}, {col_family_exp}, {col_scopes}, "
            f"{col_consumed}, {col_revoked}, {col_created_at}"
            f") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)"
        )
        account_query = f"SELECT {col_acc_epoch} FROM {self._t_accounts} WHERE {col_acc_id} = ?"

        async with self._backend.session() as session:
            row = await session.select_one_or_none(select_query, command.token_id)
            if row is None:
                return RefreshRotationOutcome(RefreshRotationStatus.INVALID)
            d = self._row_to_refresh_dict(row)
            stored_digest = bytes(cast("bytes", d["token_digest"]))
            if (
                bool(d["consumed"])
                or bool(d["revoked"])
                or not compare_digest(stored_digest, command.token_digest)
                or str(d["user_id"]) != command.account_id
                or str(d["family_id"]) != command.family_id
                or int(cast("int | str", d["security_epoch"])) != command.security_epoch
            ):
                return RefreshRotationOutcome(RefreshRotationStatus.INVALID)

            succ_exists = await session.select_one_or_none(check_succ_query, command.successor_id)
            if succ_exists is not None:
                return RefreshRotationOutcome(RefreshRotationStatus.INVALID)

            token_exp = self._parse_dt(d["token_expires_at"])
            family_exp = self._parse_dt(d["family_expires_at"])
            if token_exp <= now or family_exp <= now:
                return RefreshRotationOutcome(RefreshRotationStatus.EXPIRED)

            acc_row = await session.select_one_or_none(account_query, command.account_id)
            if acc_row is None:
                return RefreshRotationOutcome(RefreshRotationStatus.INVALID)
            acc_epoch = _extract_epoch(acc_row)
            if acc_epoch != command.security_epoch:
                return RefreshRotationOutcome(RefreshRotationStatus.INVALID)

            consume_res = await session.execute(
                consume_query,
                bytes(command.idempotency_digest) if command.idempotency_digest else None,
                bytes(command.sealed_receipt) if command.sealed_receipt else None,
                command.token_id,
            )
            affected = _extract_rowcount(consume_res)
            if affected is not None and affected == 0:
                return RefreshRotationOutcome(RefreshRotationStatus.INVALID)
            if affected is None:
                verify_row = await session.select_one_or_none(
                    f"SELECT {col_receipt} FROM {self._t_refresh} WHERE {col_token_id} = ?", command.token_id
                )
                if verify_row is not None:
                    db_dict = self._row_to_refresh_dict(verify_row)
                    db_receipt = (
                        bytes(cast("bytes", db_dict.get("sealed_receipt") or b""))
                        if isinstance(verify_row, dict)
                        else bytes(cast("bytes", verify_row[0] if isinstance(verify_row, (tuple, list)) else b""))
                    )
                    expected_receipt = bytes(command.sealed_receipt) if command.sealed_receipt else b""
                    if not compare_digest(db_receipt, expected_receipt):
                        return RefreshRotationOutcome(RefreshRotationStatus.INVALID)

            row_id = str(uuid4())
            now_iso = datetime.now(timezone.utc).isoformat()
            scopes_json = json.dumps(sorted(command.scopes))
            try:
                await session.execute(
                    insert_query,
                    row_id,
                    command.successor_id,
                    bytes(command.successor_digest),
                    command.family_id,
                    command.account_id,
                    command.security_epoch,
                    command.successor_expires_at.isoformat(),
                    command.family_expires_at.isoformat(),
                    scopes_json,
                    now_iso,
                )
            except Exception as exc:
                exc_type = type(exc).__name__.lower()
                exc_msg = str(exc).lower()
                if "unique" in exc_msg or "duplicate" in exc_msg or "integrity" in exc_type:
                    return RefreshRotationOutcome(RefreshRotationStatus.INVALID)
                raise
            return RefreshRotationOutcome(RefreshRotationStatus.ROTATED, command.sealed_receipt)

    async def revoke_family(self, family_id: "str", *, event: "SecurityEvent") -> "bool":
        """Revoke all refresh tokens in a family."""
        del event
        col_family_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "family_id"))
        col_revoked = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "revoked"))
        update_query = f"UPDATE {self._t_refresh} SET {col_revoked} = 1 WHERE {col_family_id} = ?"
        async with self._backend.session() as session:
            await session.execute(update_query, family_id)
            return True

    async def revoke_token(self, token_id: "str", token_digest: "bytes", *, event: "SecurityEvent") -> "bool":
        """Revoke the family owning a presented token."""
        col_token_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_id"))
        col_token_digest = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_digest"))
        col_family_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "family_id"))
        select_query = f"SELECT {col_family_id}, {col_token_digest} FROM {self._t_refresh} WHERE {col_token_id} = ?"
        async with self._backend.session() as session:
            row = await session.select_one_or_none(select_query, token_id)
            if row is None:
                return False
            if isinstance(row, (tuple, list)):
                seq = cast("Sequence[object]", row)
                family_id = str(seq[0])
                stored_digest = bytes(cast("bytes", seq[1]))
            elif isinstance(row, dict):
                dict_row = cast("dict[str, object]", row)
                family_id = str(dict_row["family_id"])
                stored_digest = bytes(cast("bytes", dict_row["token_digest"]))
            else:
                return False
            if not compare_digest(stored_digest, token_digest):
                return False
            return await self.revoke_family(family_id, event=event)

    async def revoke_token_for_account(
        self, account_id: "str", token_id: "str", token_digest: "bytes", *, event: "SecurityEvent"
    ) -> "bool":
        """Revoke one exact token only when its family belongs to the caller account."""
        col_token_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_id"))
        col_token_digest = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "token_digest"))
        col_family_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "family_id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "user_id"))
        select_query = (
            f"SELECT {col_family_id}, {col_token_digest}, {col_user_id} FROM {self._t_refresh} WHERE {col_token_id} = ?"
        )
        async with self._backend.session() as session:
            row = await session.select_one_or_none(select_query, token_id)
            if row is None:
                return False
            if isinstance(row, (tuple, list)):
                seq = cast("Sequence[object]", row)
                family_id = str(seq[0])
                stored_digest = bytes(cast("bytes", seq[1]))
                user_id = str(seq[2])
            elif isinstance(row, dict):
                dict_row = cast("dict[str, object]", row)
                family_id = str(dict_row["family_id"])
                stored_digest = bytes(cast("bytes", dict_row["token_digest"]))
                user_id = str(dict_row["user_id"])
            else:
                return False
            if user_id != account_id:
                return False
            if not compare_digest(stored_digest, token_digest):
                return False
            return await self.revoke_family(family_id, event=event)

    async def revoke_for_account(self, account_id: "str", *, event: "SecurityEvent") -> "int":
        """Revoke every refresh family for an account."""
        del event
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "user_id"))
        col_revoked = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "revoked"))
        col_family_id = quote_identifier(resolve_column(self._backend.config, TABLE_REFRESH_TOKENS, "family_id"))
        count_query = (
            f"SELECT COUNT(DISTINCT {col_family_id}) FROM {self._t_refresh} "
            f"WHERE {col_user_id} = ? AND {col_revoked} = 0"
        )
        update_query = f"UPDATE {self._t_refresh} SET {col_revoked} = 1 WHERE {col_user_id} = ? AND {col_revoked} = 0"
        async with self._backend.session() as session:
            val = await session.select_value(count_query, account_id)
            count = int(cast("int | str", val)) if val is not None else 0
            await session.execute(update_query, account_id)
            return count

    @staticmethod
    def _parse_dt(val: "object") -> "datetime":
        if isinstance(val, datetime):
            return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
        if isinstance(val, str):
            dt = datetime.fromisoformat(val)
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)

    @staticmethod
    def _parse_scopes(val: "object") -> "frozenset[str]":
        if isinstance(val, (list, tuple, set, frozenset)):
            seq = cast("Sequence[object]", val)
            return frozenset(str(x) for x in seq)
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                if isinstance(parsed, list):
                    parsed_seq = cast("list[object]", parsed)
                    return frozenset(str(x) for x in parsed_seq)
            except Exception:
                pass
        return frozenset()

    @staticmethod
    def _row_to_refresh_dict(row: "object") -> "dict[str, object]":
        if isinstance(row, dict):
            return cast("dict[str, object]", row)
        if isinstance(row, (tuple, list)):
            seq = cast("Sequence[object]", row)
            keys = (
                "token_id",
                "token_digest",
                "family_id",
                "user_id",
                "security_epoch",
                "token_expires_at",
                "family_expires_at",
                "scopes",
                "consumed",
                "revoked",
                "idempotency_digest",
                "sealed_receipt",
            )
            return {k: seq[idx] for idx, k in enumerate(keys) if idx < len(seq)}
        msg = f"Unexpected row representation: {type(row)!r}"
        raise TypeError(msg)


class SQLSpecPurposeTokenStore:
    """SQLSpec-backed atomic purpose token store for verification and password recovery."""

    __slots__ = ("_backend", "_t_accounts", "_t_tokens")

    def __init__(self, backend: "SQLSpecSecurityBackend") -> "None":
        """Initialize with parent security backend."""
        self._backend = backend
        self._t_tokens = resolve_table_name(backend.config, TABLE_PURPOSE_TOKENS)
        self._t_accounts = resolve_table_name(backend.config, TABLE_ACCOUNTS)

    async def issue(
        self, issue: "TokenIssue", notification: "NotificationCommand", *, event: "SecurityEvent"
    ) -> "None":
        """Persist one purpose token issue."""
        del notification, event
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "id"))
        col_token_id = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "token_id"))
        col_digest = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "digest"))
        col_purpose = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "purpose"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "user_id"))
        col_epoch = quote_identifier(
            resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "issued_security_epoch")
        )
        col_max_att = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "maximum_attempts"))
        col_fail_att = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "failed_attempts"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "created_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "expires_at"))

        check_query = f"SELECT 1 FROM {self._t_tokens} WHERE {col_token_id} = ?"
        insert_query = (
            f"INSERT INTO {self._t_tokens} ("
            f"{col_id}, {col_token_id}, {col_digest}, {col_purpose}, {col_user_id}, "
            f"{col_epoch}, {col_max_att}, {col_fail_att}, {col_created_at}, {col_expires_at}"
            f") VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)"
        )

        async with self._backend.session() as session:
            existing = await session.select_one_or_none(check_query, issue.token_id)
            if existing is not None:
                msg = "Purpose token identifier collision"
                raise ValueError(msg)
            row_id = str(uuid4())
            now_iso = datetime.now(timezone.utc).isoformat()
            await session.execute(
                insert_query,
                row_id,
                issue.token_id,
                bytes(issue.digest),
                issue.purpose.value,
                issue.account_id,
                issue.issued_security_epoch,
                issue.maximum_attempts,
                now_iso,
                issue.expires_at.isoformat(),
            )

    async def issue_absent(self) -> "None":
        """Perform durable round trip without committing state."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "id"))
        query = f"SELECT 1 FROM {self._t_tokens} WHERE {col_id} = ?"
        async with self._backend.session() as session:
            await session.select_one_or_none(query, "absent")

    async def consume_and_verify(
        self, token_id: "str", digest: "bytes", *, now: "datetime", event: "SecurityEvent"
    ) -> "VerificationOutcome":
        """Atomically consume verification token and mark account verified."""
        del event
        col_acc_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_acc_verified = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "is_verified"))
        col_acc_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "security_epoch"))

        col_token_id = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "token_id"))
        col_digest = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "digest"))
        col_purpose = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "purpose"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "user_id"))
        col_max_att = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "maximum_attempts"))
        col_fail_att = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "failed_attempts"))
        col_epoch = quote_identifier(
            resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "issued_security_epoch")
        )
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "expires_at"))
        col_consumed_at = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "consumed_at"))

        select_query = (
            f"SELECT {col_digest}, {col_purpose}, {col_user_id}, {col_epoch}, {col_max_att}, {col_fail_att}, "
            f"{col_expires_at}, {col_consumed_at} "
            f"FROM {self._t_tokens} WHERE {col_token_id} = ?"
        )
        bump_fail_query = f"UPDATE {self._t_tokens} SET {col_fail_att} = {col_fail_att} + 1 WHERE {col_token_id} = ?"
        consume_query = (
            f"UPDATE {self._t_tokens} SET {col_consumed_at} = ? WHERE {col_token_id} = ? AND {col_consumed_at} IS NULL"
        )
        account_query = f"SELECT {col_acc_epoch} FROM {self._t_accounts} WHERE {col_acc_id} = ?"
        update_account_query = f"UPDATE {self._t_accounts} SET {col_acc_verified} = 1 WHERE {col_acc_id} = ?"

        async with self._backend.session() as session:
            row = await session.select_one_or_none(select_query, token_id)
            if row is None:
                return VerificationOutcome(VerificationStatus.INVALID)
            d = self._row_to_token_dict(row)
            if str(d["purpose"]) != TokenPurpose.VERIFICATION.value:
                return VerificationOutcome(VerificationStatus.INVALID)

            if d["consumed_at"] is not None:
                return VerificationOutcome(VerificationStatus.USED)

            max_att = int(cast("int | str", d["maximum_attempts"]))
            fail_att = int(cast("int | str", d["failed_attempts"]))
            if fail_att >= max_att:
                return VerificationOutcome(VerificationStatus.USED)

            stored_digest = bytes(cast("bytes", d["digest"]))
            if not compare_digest(stored_digest, digest):
                await session.execute(bump_fail_query, token_id)
                return VerificationOutcome(VerificationStatus.INVALID)

            expires_at = self._parse_dt(d["expires_at"])
            if expires_at <= now:
                return VerificationOutcome(VerificationStatus.EXPIRED)

            user_id = str(d["user_id"])
            acc_row = await session.select_one_or_none(account_query, user_id)
            if acc_row is None:
                return VerificationOutcome(VerificationStatus.INVALID)
            epoch = _extract_epoch(acc_row)
            issued_epoch = (
                int(cast("int | str", d["issued_security_epoch"]))
                if d.get("issued_security_epoch") is not None
                else epoch
            )
            if epoch != issued_epoch:
                return VerificationOutcome(VerificationStatus.INVALID)

            consume_res = await session.execute(consume_query, now.isoformat(), token_id)
            affected = _extract_rowcount(consume_res)
            if affected is not None and affected == 0:
                return VerificationOutcome(VerificationStatus.INVALID)
            await session.execute(update_account_query, user_id)
            return VerificationOutcome(VerificationStatus.CONSUMED, user_id, epoch)

    async def consume_and_reset(
        self, token_id: "str", digest: "bytes", new_password_hash: "str", *, now: "datetime", event: "SecurityEvent"
    ) -> "PasswordResetOutcome":
        """Atomically consume recovery token and reset account password advancing epoch."""
        del event
        col_acc_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_acc_pass = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "password_hash"))
        col_acc_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "security_epoch"))

        col_token_id = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "token_id"))
        col_digest = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "digest"))
        col_purpose = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "purpose"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "user_id"))
        col_epoch = quote_identifier(
            resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "issued_security_epoch")
        )
        col_max_att = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "maximum_attempts"))
        col_fail_att = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "failed_attempts"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "expires_at"))
        col_consumed_at = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "consumed_at"))

        select_query = (
            f"SELECT {col_digest}, {col_purpose}, {col_user_id}, {col_epoch}, {col_max_att}, {col_fail_att}, "
            f"{col_expires_at}, {col_consumed_at} "
            f"FROM {self._t_tokens} WHERE {col_token_id} = ?"
        )
        bump_fail_query = f"UPDATE {self._t_tokens} SET {col_fail_att} = {col_fail_att} + 1 WHERE {col_token_id} = ?"
        consume_query = (
            f"UPDATE {self._t_tokens} SET {col_consumed_at} = ? WHERE {col_token_id} = ? AND {col_consumed_at} IS NULL"
        )
        account_query = f"SELECT {col_acc_epoch} FROM {self._t_accounts} WHERE {col_acc_id} = ?"
        update_account_query = (
            f"UPDATE {self._t_accounts} SET {col_acc_pass} = ?, {col_acc_epoch} = {col_acc_epoch} + 1 "
            f"WHERE {col_acc_id} = ? AND {col_acc_epoch} = ?"
        )

        async with self._backend.session() as session:
            row = await session.select_one_or_none(select_query, token_id)
            if row is None:
                return PasswordResetOutcome(PasswordResetStatus.INVALID)
            d = self._row_to_token_dict(row)
            if str(d["purpose"]) != TokenPurpose.RECOVERY.value:
                return PasswordResetOutcome(PasswordResetStatus.INVALID)

            if d["consumed_at"] is not None:
                return PasswordResetOutcome(PasswordResetStatus.USED)

            max_att = int(cast("int | str", d["maximum_attempts"]))
            fail_att = int(cast("int | str", d["failed_attempts"]))
            if fail_att >= max_att:
                return PasswordResetOutcome(PasswordResetStatus.USED)

            stored_digest = bytes(cast("bytes", d["digest"]))
            if not compare_digest(stored_digest, digest):
                await session.execute(bump_fail_query, token_id)
                return PasswordResetOutcome(PasswordResetStatus.INVALID)

            expires_at = self._parse_dt(d["expires_at"])
            if expires_at <= now:
                return PasswordResetOutcome(PasswordResetStatus.EXPIRED)

            user_id = str(d["user_id"])
            acc_row = await session.select_one_or_none(account_query, user_id)
            if acc_row is None:
                return PasswordResetOutcome(PasswordResetStatus.CONFLICT)
            curr_epoch = _extract_epoch(acc_row)
            issued_epoch = (
                int(cast("int | str", d["issued_security_epoch"]))
                if d["issued_security_epoch"] is not None
                else curr_epoch
            )
            if curr_epoch != issued_epoch:
                return PasswordResetOutcome(PasswordResetStatus.CONFLICT)

            consume_res = await session.execute(consume_query, now.isoformat(), token_id)
            affected = _extract_rowcount(consume_res)
            if affected is not None and affected == 0:
                return PasswordResetOutcome(PasswordResetStatus.INVALID)
            next_epoch = curr_epoch + 1
            await session.execute(update_account_query, new_password_hash, user_id, curr_epoch)
            return PasswordResetOutcome(PasswordResetStatus.RESET, user_id, next_epoch)

    @staticmethod
    def _parse_dt(val: "object") -> "datetime":
        if isinstance(val, datetime):
            return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
        if isinstance(val, str):
            dt = datetime.fromisoformat(val)
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)

    @staticmethod
    def _row_to_token_dict(row: "object") -> "dict[str, object]":
        if isinstance(row, dict):
            return cast("dict[str, object]", row)
        if isinstance(row, (tuple, list)):
            seq = cast("Sequence[object]", row)
            keys = (
                "digest",
                "purpose",
                "user_id",
                "issued_security_epoch",
                "maximum_attempts",
                "failed_attempts",
                "expires_at",
                "consumed_at",
            )
            return {k: seq[idx] for idx, k in enumerate(keys) if idx < len(seq)}
        msg = f"Unexpected row representation: {type(row)!r}"
        raise TypeError(msg)
