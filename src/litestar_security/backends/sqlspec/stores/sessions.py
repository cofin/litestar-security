"""SQLSpec persistence adapter for user sessions."""

import asyncio
import json
from datetime import datetime, timezone
from types import MappingProxyType
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from litestar_security.accounts import CreateSessionCommand, LocalAccountState, SecurityEvent, UserAuthSession
from litestar_security.backends.sqlspec.schema import (
    TABLE_SESSIONS,
    quote_identifier,
    resolve_column,
    resolve_table_name,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from litestar_security.backends.sqlspec.backend import SQLSpecSecurityBackend

__all__ = ("SQLSpecSessionStore",)


class SQLSpecSessionStore:
    """SQLSpec-backed atomic session store and registry."""

    __slots__ = ("_backend", "_clock", "_lock", "_table_name")

    def __init__(self, backend: "SQLSpecSecurityBackend", *, clock: "Callable[[], datetime] | None" = None) -> "None":
        """Initialize with parent security backend and optional clock."""
        self._backend = backend
        self._table_name = resolve_table_name(backend.config, TABLE_SESSIONS)
        self._clock = clock if clock is not None else (lambda: datetime.now(timezone.utc))
        self._lock = asyncio.Lock()

    async def get_by_id(self, account_id: "str") -> "LocalAccountState[object] | None":
        """Load one local account projection delegating to account store."""
        return await self._backend.account_store.get_by_id(account_id)

    async def current_epoch(self, account_id: "str") -> "int | None":
        """Load the authoritative account security epoch delegating to account store."""
        return await self._backend.account_store.current_epoch(account_id)

    async def create(self, command: "CreateSessionCommand", *, event: "SecurityEvent") -> "UserAuthSession":
        """Atomically persist one new session."""
        del event
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "id"))
        col_session_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "session_id"))
        col_binding_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "binding_id"))
        col_binding_digest = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "binding_digest"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "user_id"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "security_epoch"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "created_at"))
        col_auth_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "authenticated_at"))
        col_last_seen = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "last_seen_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "expires_at"))
        col_metadata = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "display_metadata"))

        check_query = f"SELECT 1 FROM {self._table_name} WHERE {col_session_id} = ? OR {col_binding_id} = ?"
        insert_query = (
            f"INSERT INTO {self._table_name} ("
            f"{col_id}, {col_session_id}, {col_binding_id}, {col_binding_digest}, {col_user_id}, "
            f"{col_epoch}, {col_created_at}, {col_auth_at}, {col_last_seen}, {col_expires_at}, {col_metadata}"
            f") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )

        async with self._lock, self._backend.session() as session:
            existing = await session.select_one_or_none(check_query, command.session_id, command.binding_id)
            if existing is not None:
                msg = "Session identifier or binding collision"
                raise ValueError(msg)

            row_id = str(uuid4())
            metadata_json = json.dumps(dict(command.display_metadata))
            await session.execute(
                insert_query,
                row_id,
                command.session_id,
                command.binding_id,
                bytes(command.binding_digest),
                command.account_id,
                command.security_epoch,
                command.created_at.isoformat(),
                command.authenticated_at.isoformat(),
                command.created_at.isoformat(),
                command.expires_at.isoformat(),
                metadata_json,
            )

        return UserAuthSession(
            session_id=command.session_id,
            binding_id=command.binding_id,
            binding_digest=command.binding_digest,
            account_id=command.account_id,
            security_epoch=command.security_epoch,
            created_at=command.created_at,
            authenticated_at=command.authenticated_at,
            last_seen_at=command.created_at,
            expires_at=command.expires_at,
            display_metadata=command.display_metadata,
        )

    async def get(self, session_id: "str") -> "UserAuthSession | None":
        """Load one current session record."""
        col_session_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "session_id"))
        col_binding_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "binding_id"))
        col_binding_digest = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "binding_digest"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "user_id"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "security_epoch"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "created_at"))
        col_auth_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "authenticated_at"))
        col_last_seen = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "last_seen_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "expires_at"))
        col_metadata = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "display_metadata"))

        query = (
            f"SELECT {col_session_id}, {col_binding_id}, {col_binding_digest}, {col_user_id}, "
            f"{col_epoch}, {col_created_at}, {col_auth_at}, {col_last_seen}, {col_expires_at}, {col_metadata} "
            f"FROM {self._table_name} WHERE {col_session_id} = ?"
        )

        async with self._backend.session() as session:
            row = await session.select_one_or_none(query, session_id)
            if row is None:
                return None
            record = self._row_to_session(row)
            now = self._clock()
            if record.expires_at <= now:
                return None
            return record

    async def list_for_account(self, account_id: "str") -> "Sequence[UserAuthSession]":
        """List active sessions owned by an account."""
        col_session_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "session_id"))
        col_binding_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "binding_id"))
        col_binding_digest = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "binding_digest"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "user_id"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "security_epoch"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "created_at"))
        col_auth_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "authenticated_at"))
        col_last_seen = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "last_seen_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "expires_at"))
        col_metadata = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "display_metadata"))

        query = (
            f"SELECT {col_session_id}, {col_binding_id}, {col_binding_digest}, {col_user_id}, "
            f"{col_epoch}, {col_created_at}, {col_auth_at}, {col_last_seen}, {col_expires_at}, {col_metadata} "
            f"FROM {self._table_name} WHERE {col_user_id} = ? ORDER BY {col_expires_at} DESC"
        )

        async with self._backend.session() as session:
            rows = await session.select(query, account_id)
            now = self._clock()
            results: list[UserAuthSession] = []
            for row in rows:
                rec = self._row_to_session(row)
                if rec.expires_at > now:
                    results.append(rec)
            return tuple(results)

    async def touch(self, session_id: "str", *, now: "datetime") -> "UserAuthSession | None":
        """Update session last seen timestamp."""
        col_session_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "session_id"))
        col_last_seen = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "last_seen_at"))

        select_query = f"SELECT 1 FROM {self._table_name} WHERE {col_session_id} = ?"
        update_query = f"UPDATE {self._table_name} SET {col_last_seen} = ? WHERE {col_session_id} = ?"

        async with self._lock:
            async with self._backend.session() as session:
                row = await session.select_one_or_none(select_query, session_id)
                if row is None:
                    return None
                await session.execute(update_query, now.isoformat(), session_id)
            return await self.get(session_id)

    async def revoke_session_for_account(
        self, account_id: "str", session_id: "str", *, event: "SecurityEvent"
    ) -> "bool":
        """Revoke one session only when owned by the specified account."""
        del event
        col_session_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "session_id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "user_id"))

        select_query = f"SELECT 1 FROM {self._table_name} WHERE {col_session_id} = ? AND {col_user_id} = ?"
        delete_query = f"DELETE FROM {self._table_name} WHERE {col_session_id} = ? AND {col_user_id} = ?"

        async with self._lock, self._backend.session() as session:
            row = await session.select_one_or_none(select_query, session_id, account_id)
            if row is None:
                return False
            await session.execute(delete_query, session_id, account_id)
            return True

    async def revoke_sessions_for_account(self, account_id: "str", *, event: "SecurityEvent") -> "int":
        """Revoke all sessions owned by an account."""
        del event
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "user_id"))
        count_query = f"SELECT COUNT(*) FROM {self._table_name} WHERE {col_user_id} = ?"
        delete_query = f"DELETE FROM {self._table_name} WHERE {col_user_id} = ?"

        async with self._lock, self._backend.session() as session:
            count_val = await session.select_value(count_query, account_id)
            count = int(cast("int | str", count_val)) if count_val is not None else 0
            await session.execute(delete_query, account_id)
            return count

    async def revoke_other_sessions(self, account_id: "str", session_id: "str", *, event: "SecurityEvent") -> "int":
        """Revoke all account sessions other than the current session."""
        del event
        col_session_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "session_id"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "user_id"))
        count_query = f"SELECT COUNT(*) FROM {self._table_name} WHERE {col_user_id} = ? AND {col_session_id} != ?"
        delete_query = f"DELETE FROM {self._table_name} WHERE {col_user_id} = ? AND {col_session_id} != ?"

        async with self._lock, self._backend.session() as session:
            count_val = await session.select_value(count_query, account_id, session_id)
            count = int(cast("int | str", count_val)) if count_val is not None else 0
            await session.execute(delete_query, account_id, session_id)
            return count

    async def rebind(
        self, prior_session_id: "str", command: "CreateSessionCommand", *, event: "SecurityEvent"
    ) -> "UserAuthSession | None":
        """Atomically replace a prior session with its successor."""
        del event
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "id"))
        col_session_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "session_id"))
        col_binding_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "binding_id"))
        col_binding_digest = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "binding_digest"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "user_id"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "security_epoch"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "created_at"))
        col_auth_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "authenticated_at"))
        col_last_seen = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "last_seen_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "expires_at"))
        col_metadata = quote_identifier(resolve_column(self._backend.config, TABLE_SESSIONS, "display_metadata"))

        check_prior = f"SELECT 1 FROM {self._table_name} WHERE {col_session_id} = ?"
        delete_prior = f"DELETE FROM {self._table_name} WHERE {col_session_id} = ?"
        insert_query = (
            f"INSERT INTO {self._table_name} ("
            f"{col_id}, {col_session_id}, {col_binding_id}, {col_binding_digest}, {col_user_id}, "
            f"{col_epoch}, {col_created_at}, {col_auth_at}, {col_last_seen}, {col_expires_at}, {col_metadata}"
            f") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )

        async with self._lock, self._backend.session() as session:
            prior_row = await session.select_one_or_none(check_prior, prior_session_id)
            if prior_row is None:
                return None
            await session.execute(delete_prior, prior_session_id)

            row_id = str(uuid4())
            metadata_json = json.dumps(dict(command.display_metadata))
            await session.execute(
                insert_query,
                row_id,
                command.session_id,
                command.binding_id,
                bytes(command.binding_digest),
                command.account_id,
                command.security_epoch,
                command.created_at.isoformat(),
                command.authenticated_at.isoformat(),
                command.created_at.isoformat(),
                command.expires_at.isoformat(),
                metadata_json,
            )

        return UserAuthSession(
            session_id=command.session_id,
            binding_id=command.binding_id,
            binding_digest=command.binding_digest,
            account_id=command.account_id,
            security_epoch=command.security_epoch,
            created_at=command.created_at,
            authenticated_at=command.authenticated_at,
            last_seen_at=command.created_at,
            expires_at=command.expires_at,
            display_metadata=command.display_metadata,
        )

    def _row_to_session(self, row: "object") -> "UserAuthSession":
        mapping: dict[str, object]
        if isinstance(row, dict):
            mapping = cast("dict[str, object]", row)
        elif isinstance(row, (tuple, list)):
            keys = (
                "session_id",
                "binding_id",
                "binding_digest",
                "user_id",
                "security_epoch",
                "created_at",
                "authenticated_at",
                "last_seen_at",
                "expires_at",
                "display_metadata",
            )
            seq = cast("Sequence[object]", row)
            mapping = {k: seq[idx] for idx, k in enumerate(keys) if idx < len(seq)}
        else:
            msg = f"Unexpected row representation: {type(row)!r}"
            raise TypeError(msg)

        raw_digest = mapping.get("binding_digest")
        binding_digest = bytes(cast("bytes", raw_digest)) if raw_digest is not None else b""

        raw_meta = mapping.get("display_metadata")
        meta_dict: dict[str, str] = {}
        if isinstance(raw_meta, dict):
            dict_meta = cast("dict[object, object]", raw_meta)
            meta_dict = {str(k): str(v) for k, v in dict_meta.items()}
        elif isinstance(raw_meta, str):
            try:
                parsed = json.loads(raw_meta)
                if isinstance(parsed, dict):
                    parsed_dict = cast("dict[object, object]", parsed)
                    meta_dict = {str(k): str(v) for k, v in parsed_dict.items()}
            except Exception:
                pass

        return UserAuthSession(
            session_id=str(mapping["session_id"]),
            binding_id=str(mapping["binding_id"]),
            binding_digest=binding_digest,
            account_id=str(mapping["user_id"]),
            security_epoch=int(cast("int | str", mapping["security_epoch"])),
            created_at=self._parse_dt(mapping["created_at"]),
            authenticated_at=self._parse_dt(mapping["authenticated_at"]),
            last_seen_at=self._parse_dt(mapping["last_seen_at"]),
            expires_at=self._parse_dt(mapping["expires_at"]),
            display_metadata=MappingProxyType(meta_dict),
        )

    @staticmethod
    def _parse_dt(val: "object") -> "datetime":
        if isinstance(val, datetime):
            return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
        if isinstance(val, str):
            dt = datetime.fromisoformat(val)
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)
