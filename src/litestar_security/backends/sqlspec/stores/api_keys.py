"""SQLSpec persistence adapter for API keys."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from litestar_security.backends.sqlspec.schema import (
    TABLE_API_KEYS,
    quote_identifier,
    resolve_column,
    resolve_table_name,
)
from litestar_security.context import CredentialRestrictions
from litestar_security.providers.api_key import APIKeyState

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from litestar_security.backends.sqlspec.backend import SQLSpecSecurityBackend

__all__ = ("SQLSpecAPIKeyStore",)


class SQLSpecAPIKeyStore:
    """SQLSpec-backed atomic API-key store."""

    __slots__ = ("_backend", "_clock", "_lock", "_table_name")

    def __init__(
        self,
        backend: SQLSpecSecurityBackend,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize with parent security backend and optional clock."""
        self._backend = backend
        self._table_name = resolve_table_name(backend.config, TABLE_API_KEYS)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = asyncio.Lock()

    async def get(self, key_id: str) -> APIKeyState | None:
        """Return one record by its public lookup."""
        col_key_id = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "key_id"))
        col_digest = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "digest"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "user_id"))
        col_restrictions = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "restrictions"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "created_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "expires_at"))
        col_revoked_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "revoked_at"))
        col_overlap_until = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "overlap_until"))
        col_last_used_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "last_used_at"))

        query = (
            f"SELECT {col_key_id}, {col_digest}, {col_user_id}, {col_restrictions}, "
            f"{col_created_at}, {col_expires_at}, {col_revoked_at}, {col_overlap_until}, {col_last_used_at} "
            f"FROM {self._table_name} WHERE {col_key_id} = ?"
        )

        async with self._backend.session() as session:
            row = await session.select_one_or_none(query, key_id)
            if row is None:
                return None
            return self._row_to_state(row)

    async def create(self, record: APIKeyState) -> None:
        """Persist one new record and reject duplicate key_id atomically."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "id"))
        col_key_id = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "key_id"))
        col_digest = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "digest"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "user_id"))
        col_restrictions = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "restrictions"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "created_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "expires_at"))
        col_revoked_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "revoked_at"))
        col_overlap_until = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "overlap_until"))
        col_last_used_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "last_used_at"))

        check_query = f"SELECT 1 FROM {self._table_name} WHERE {col_key_id} = ?"
        insert_query = (
            f"INSERT INTO {self._table_name} ("
            f"{col_id}, {col_key_id}, {col_digest}, {col_user_id}, {col_restrictions}, "
            f"{col_created_at}, {col_expires_at}, {col_revoked_at}, {col_overlap_until}, {col_last_used_at}"
            f") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )

        async with self._lock, self._backend.session() as session:
            existing = await session.select_one_or_none(check_query, record.key_id)
            if existing is not None:
                msg = "API-key ID already exists"
                raise ValueError(msg)
            row_id = str(uuid4())
            now_str = self._format_dt(self._clock())
            await session.execute(
                insert_query,
                row_id,
                record.key_id,
                bytes(record.digest),
                record.subject_id,
                self._serialize_restrictions(record.restrictions),
                now_str,
                self._format_dt(record.expires_at),
                self._format_dt(record.revoked_at),
                self._format_dt(record.overlap_until),
                None,
            )

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyState, overlap_until: datetime | None, now: datetime
    ) -> None:
        """Atomically revoke the current record and create its replacement."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "id"))
        col_key_id = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "key_id"))
        col_digest = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "digest"))
        col_user_id = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "user_id"))
        col_restrictions = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "restrictions"))
        col_created_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "created_at"))
        col_expires_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "expires_at"))
        col_revoked_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "revoked_at"))
        col_overlap_until = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "overlap_until"))
        col_last_used_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "last_used_at"))

        select_query = (
            f"SELECT {col_key_id}, {col_digest}, {col_user_id}, {col_restrictions}, "
            f"{col_created_at}, {col_expires_at}, {col_revoked_at}, {col_overlap_until}, {col_last_used_at} "
            f"FROM {self._table_name} WHERE {col_key_id} = ?"
        )
        check_replacement_query = f"SELECT 1 FROM {self._table_name} WHERE {col_key_id} = ?"
        update_query = (
            f"UPDATE {self._table_name} SET {col_revoked_at} = ?, {col_overlap_until} = ? "
            f"WHERE {col_key_id} = ? AND {col_revoked_at} IS NULL"
        )
        insert_query = (
            f"INSERT INTO {self._table_name} ("
            f"{col_id}, {col_key_id}, {col_digest}, {col_user_id}, {col_restrictions}, "
            f"{col_created_at}, {col_expires_at}, {col_revoked_at}, {col_overlap_until}, {col_last_used_at}"
            f") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )

        async with self._lock, self._backend.session() as session:
            current_row = await session.select_one_or_none(select_query, current_key_id)
            if current_row is None:
                msg = "API-key rotation conflict"
                raise ValueError(msg)
            current = self._row_to_state(current_row)
            if current.revoked_at is not None:
                msg = "API-key rotation conflict"
                raise ValueError(msg)

            existing_rep = await session.select_one_or_none(check_replacement_query, replacement.key_id)
            if existing_rep is not None:
                msg = "API-key rotation conflict"
                raise ValueError(msg)

            bounded_overlap = (
                min(overlap_until, current.expires_at)
                if overlap_until is not None and current.expires_at is not None
                else overlap_until
            )
            await session.execute(
                update_query,
                self._format_dt(now),
                self._format_dt(bounded_overlap),
                current_key_id,
            )
            row_id = str(uuid4())
            await session.execute(
                insert_query,
                row_id,
                replacement.key_id,
                bytes(replacement.digest),
                replacement.subject_id,
                self._serialize_restrictions(replacement.restrictions),
                self._format_dt(now),
                self._format_dt(replacement.expires_at),
                self._format_dt(replacement.revoked_at),
                self._format_dt(replacement.overlap_until),
                None,
            )

    async def revoke(self, *, key_id: str, now: datetime) -> None:
        """Atomically revoke one key."""
        col_key_id = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "key_id"))
        col_revoked_at = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "revoked_at"))
        col_overlap_until = quote_identifier(resolve_column(self._backend.config, TABLE_API_KEYS, "overlap_until"))

        select_query = f"SELECT 1 FROM {self._table_name} WHERE {col_key_id} = ?"
        update_query = (
            f"UPDATE {self._table_name} SET {col_revoked_at} = ?, {col_overlap_until} = NULL "
            f"WHERE {col_key_id} = ?"
        )

        async with self._lock, self._backend.session() as session:
            existing = await session.select_one_or_none(select_query, key_id)
            if existing is None:
                msg = "API-key does not exist"
                raise ValueError(msg)
            await session.execute(update_query, self._format_dt(now), key_id)

    @staticmethod
    def _format_dt(dt: datetime | None) -> str | None:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    @staticmethod
    def _parse_dt(val: object) -> datetime | None:
        if val is None:
            return None
        if isinstance(val, datetime):
            return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
        if isinstance(val, str):
            dt = datetime.fromisoformat(val)
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        return None

    @staticmethod
    def _serialize_restrictions(restrictions: CredentialRestrictions | None) -> str:
        if restrictions is None:
            return "{}"
        data: dict[str, list[str]] = {}
        if restrictions.scopes is not None:
            data["scopes"] = sorted(restrictions.scopes)
        if restrictions.roles is not None:
            data["roles"] = sorted(restrictions.roles)
        if restrictions.capabilities is not None:
            data["capabilities"] = sorted(restrictions.capabilities)
        if restrictions.tenant_ids is not None:
            data["tenant_ids"] = sorted(restrictions.tenant_ids)
        return json.dumps(data)

    @staticmethod
    def _deserialize_restrictions(val: object) -> CredentialRestrictions:
        if isinstance(val, str):
            try:
                data = json.loads(val)
                if isinstance(data, dict):
                    dict_data = cast("dict[str, object]", data)
                    scopes_raw = dict_data.get("scopes")
                    roles_raw = dict_data.get("roles")
                    caps_raw = dict_data.get("capabilities")
                    tenants_raw = dict_data.get("tenant_ids")
                    return CredentialRestrictions(
                        scopes=frozenset(cast("list[str]", scopes_raw)) if scopes_raw is not None else None,
                        roles=frozenset(cast("list[str]", roles_raw)) if roles_raw is not None else None,
                        capabilities=frozenset(cast("list[str]", caps_raw)) if caps_raw is not None else None,
                        tenant_ids=frozenset(cast("list[str]", tenants_raw)) if tenants_raw is not None else None,
                    )
            except Exception:
                pass
        return CredentialRestrictions()

    def _row_to_state(self, row: object) -> APIKeyState:
        mapping: dict[str, object]
        if isinstance(row, dict):
            mapping = cast("dict[str, object]", row)
        elif isinstance(row, (tuple, list)):
            keys = (
                "key_id",
                "digest",
                "user_id",
                "restrictions",
                "created_at",
                "expires_at",
                "revoked_at",
                "overlap_until",
                "last_used_at",
            )
            seq = cast("Sequence[object]", row)
            mapping = {k: seq[idx] for idx, k in enumerate(keys) if idx < len(seq)}
        else:
            msg = f"Unexpected row representation: {type(row)!r}"
            raise TypeError(msg)

        raw_digest = mapping.get("digest")
        digest_bytes = bytes(cast("bytes", raw_digest)) if raw_digest is not None else b""

        return APIKeyState(
            key_id=str(mapping["key_id"]),
            subject_id=str(mapping["user_id"]),
            digest=digest_bytes,
            restrictions=self._deserialize_restrictions(mapping.get("restrictions")),
            expires_at=self._parse_dt(mapping.get("expires_at")),
            revoked_at=self._parse_dt(mapping.get("revoked_at")),
            overlap_until=self._parse_dt(mapping.get("overlap_until")),
        )
