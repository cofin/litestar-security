"""SQLSpec persistence adapter for local accounts and credentials."""

from __future__ import annotations

from datetime import datetime, timezone
from hmac import compare_digest
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from litestar_security.accounts import (
    LocalAccountState,
    LoginMethod,
    NotificationCommand,
    PasswordChangeOutcome,
    PasswordChangeStatus,
    PasswordCredentialState,
    PasswordResetOutcome,
    RegistrationCommand,
    RegistrationOutcome,
    RegistrationStatus,
    RevokeLoginMethodOutcome,
    RevokeLoginMethodStatus,
    SecurityEvent,
    TokenIssue,
    TokenPurpose,
    VerificationOutcome,
)
from litestar_security.backends.sqlspec.schema import (
    TABLE_ACCOUNTS,
    TABLE_PURPOSE_TOKENS,
    quote_identifier,
    resolve_column,
    resolve_table_name,
)
from litestar_security.backends.sqlspec.stores.tokens import SQLSpecPurposeTokenStore

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from litestar_security.accounts import PurposeTokenDelivery
    from litestar_security.backends.sqlspec.backend import SQLSpecSecurityBackend


def _default_identifier(_: str) -> str:
    """Generate a random UUID4 identifier."""
    return str(uuid4())


def _row_val(row: object, idx: int, key: str) -> object:
    """Safely extract field from tuple or dict row representation."""
    if isinstance(row, (tuple, list)):
        seq = cast("Sequence[object]", row)
        return seq[idx] if idx < len(seq) else None
    if isinstance(row, dict):
        mapping = cast("Mapping[str, object]", row)
        return mapping.get(key)
    return None


def _extract_rowcount(result: object) -> int | None:
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


class SQLSpecAccountStore:
    """SQLSpec-backed atomic account and credential store."""

    __slots__ = (
        "_backend",
        "_clock",
        "_identifiers",
        "_login_methods",
        "_purpose_store",
        "_t_accounts",
        "_t_tokens",
    )

    def __init__(
        self,
        backend: SQLSpecSecurityBackend,
        *,
        clock: Callable[[], datetime] | None = None,
        identifiers: Callable[[str], str] | None = None,
    ) -> None:
        """Initialize with parent backend, optional clock, and identifier generator."""
        self._backend = backend
        self._t_accounts = resolve_table_name(backend.config, TABLE_ACCOUNTS)
        self._t_tokens = resolve_table_name(backend.config, TABLE_PURPOSE_TOKENS)
        self._clock = clock if clock is not None else (lambda: datetime.now(timezone.utc))
        self._identifiers = identifiers if identifiers is not None else _default_identifier
        self._purpose_store = SQLSpecPurposeTokenStore(backend)
        self._login_methods: dict[str, dict[str, LoginMethod]] = {}

    async def find_for_login(self, normalized_identifier: str) -> LocalAccountState[object] | None:
        """Find an account by normalized identifier."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_email = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "email"))
        col_name = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "name"))
        col_active = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "is_active"))
        col_verified = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "is_verified"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "security_epoch"))

        query = (
            f"SELECT {col_id}, {col_email}, {col_name}, {col_active}, {col_verified}, {col_epoch} "
            f"FROM {self._t_accounts} WHERE {col_email} = ?"
        )

        async with self._backend.session() as session:
            row = await session.select_one_or_none(query, normalized_identifier)
            if row is None:
                return None
            return self._row_to_account(row)

    async def get_by_id(self, account_id: str) -> LocalAccountState[object] | None:
        """Resolve an account by stable identifier."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_email = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "email"))
        col_name = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "name"))
        col_active = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "is_active"))
        col_verified = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "is_verified"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "security_epoch"))

        query = (
            f"SELECT {col_id}, {col_email}, {col_name}, {col_active}, {col_verified}, {col_epoch} "
            f"FROM {self._t_accounts} WHERE {col_id} = ?"
        )

        async with self._backend.session() as session:
            row = await session.select_one_or_none(query, account_id)
            if row is None:
                return None
            return self._row_to_account(row)

    async def current_epoch(self, account_id: str) -> int | None:
        """Return the authoritative security epoch."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "security_epoch"))

        query = f"SELECT {col_epoch} FROM {self._t_accounts} WHERE {col_id} = ?"

        async with self._backend.session() as session:
            row = await session.select_one_or_none(query, account_id)
            if row is None:
                return None
            val = _row_val(row, 0, "security_epoch")
            return int(cast("int | str", val)) if val is not None else None

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        """Return one atomic password, account-state, and epoch snapshot."""
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_pass = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "password_hash"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "security_epoch"))
        col_active = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "is_active"))
        col_verified = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "is_verified"))

        query = (
            f"SELECT {col_pass}, {col_epoch}, {col_active}, {col_verified} "
            f"FROM {self._t_accounts} WHERE {col_id} = ?"
        )

        async with self._backend.session() as session:
            row = await session.select_one_or_none(query, account_id)
            if row is None:
                return None
            pass_val = _row_val(row, 0, "password_hash")
            if pass_val is None:
                return None
            epoch_val = int(cast("int | str", _row_val(row, 1, "security_epoch") or 1))
            active_val = bool(_row_val(row, 2, "is_active"))
            verified_val = bool(_row_val(row, 3, "is_verified"))

            return PasswordCredentialState(
                password_hash=str(pass_val),
                security_epoch=epoch_val,
                active=active_val,
                verified=verified_val,
            )

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, *, event: SecurityEvent
    ) -> bool:
        """Atomically replace password hash if expected hash matches."""
        del event
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_pass = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "password_hash"))

        check_query = f"SELECT {col_pass} FROM {self._t_accounts} WHERE {col_id} = ?"
        update_query = (
            f"UPDATE {self._t_accounts} SET {col_pass} = ? "
            f"WHERE {col_id} = ? AND {col_pass} = ?"
        )

        async with self._backend.session() as session:
            row = await session.select_one_or_none(check_query, account_id)
            if row is None:
                return False
            curr = str(_row_val(row, 0, "password_hash") or "")
            if curr != expected_hash:
                return False
            res = await session.execute(update_query, password_hash, account_id, expected_hash)
            affected = _extract_rowcount(res)
            if affected is not None:
                return affected > 0
            check_after = await session.select_one_or_none(check_query, account_id)
            if check_after is None:
                return False
            return str(_row_val(check_after, 0, "password_hash") or "") == password_hash

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeOutcome:
        """Atomically replace password and increment security epoch."""
        del event
        col_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_pass = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "password_hash"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "security_epoch"))

        check_query = f"SELECT {col_epoch} FROM {self._t_accounts} WHERE {col_id} = ?"
        update_query = (
            f"UPDATE {self._t_accounts} SET {col_pass} = ?, {col_epoch} = {col_epoch} + 1 "
            f"WHERE {col_id} = ? AND {col_epoch} = ?"
        )

        async with self._backend.session() as session:
            row = await session.select_one_or_none(check_query, account_id)
            if row is None:
                return PasswordChangeOutcome(PasswordChangeStatus.NOT_FOUND)
            curr_epoch = int(cast("int | str", _row_val(row, 0, "security_epoch") or 0))
            if curr_epoch != expected_epoch:
                return PasswordChangeOutcome(PasswordChangeStatus.CONFLICT)

            res = await session.execute(update_query, password_hash, account_id, expected_epoch)
            affected = _extract_rowcount(res)
            if affected is not None and affected == 0:
                return PasswordChangeOutcome(PasswordChangeStatus.CONFLICT)
            if affected is None:
                check_after = await session.select_one_or_none(check_query, account_id)
                if check_after is not None:
                    after_epoch = int(cast("int | str", _row_val(check_after, 0, "security_epoch") or 0))
                    if after_epoch != expected_epoch + 1:
                        return PasswordChangeOutcome(PasswordChangeStatus.CONFLICT)
            return PasswordChangeOutcome(PasswordChangeStatus.CHANGED, expected_epoch + 1)

    async def list_methods(self, account_id: str) -> tuple[LoginMethod, ...]:
        """Return every login method recorded for an account."""
        return tuple(self._login_methods.get(account_id, {}).values())

    async def register_login_method(self, account_id: str, method: LoginMethod, *, event: SecurityEvent) -> None:
        """Record one login method for an existing account."""
        del event
        self._login_methods.setdefault(account_id, {})[method.method_id] = method

    async def revoke_login_method(
        self, account_id: str, method_id: str, *, require_remaining: bool = True, event: SecurityEvent
    ) -> RevokeLoginMethodOutcome:
        """Revoke one login method preserving final method invariant."""
        del event
        methods = self._login_methods.get(account_id)
        if methods is None or method_id not in methods:
            return RevokeLoginMethodOutcome(RevokeLoginMethodStatus.NOT_FOUND)
        if require_remaining and len(methods) == 1:
            return RevokeLoginMethodOutcome(RevokeLoginMethodStatus.FINAL_METHOD)
        del methods[method_id]
        return RevokeLoginMethodOutcome(RevokeLoginMethodStatus.REVOKED)

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
        """Atomically create account and handle optional invitation and verification."""
        col_acc_id = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "id"))
        col_email = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "email"))
        col_name = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "name"))
        col_pass = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "password_hash"))
        col_active = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "is_active"))
        col_verified = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "is_verified"))
        col_epoch = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "security_epoch"))
        col_created = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "created_at"))
        col_joined = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "joined_at"))
        col_updated = quote_identifier(resolve_column(self._backend.config, TABLE_ACCOUNTS, "updated_at"))

        col_tok_id = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "id"))
        col_tok_digest = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "digest"))
        col_tok_purpose = quote_identifier(resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "purpose"))
        col_tok_expires = quote_identifier(
            resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "expires_at")
        )
        col_tok_consumed = quote_identifier(
            resolve_column(self._backend.config, TABLE_PURPOSE_TOKENS, "consumed_at")
        )

        check_email = f"SELECT 1 FROM {self._t_accounts} WHERE {col_email} = ?"
        select_invitation = (
            f"SELECT {col_tok_id}, {col_tok_digest}, {col_tok_expires}, {col_tok_consumed} "
            f"FROM {self._t_tokens} WHERE {col_tok_purpose} = ? AND {col_tok_consumed} IS NULL"
        )
        consume_invitation = (
            f"UPDATE {self._t_tokens} SET {col_tok_consumed} = ? WHERE {col_tok_id} = ?"
        )
        insert_account = (
            f"INSERT INTO {self._t_accounts} ("
            f"{col_acc_id}, {col_email}, {col_name}, {col_pass}, {col_active}, {col_verified}, "
            f"{col_epoch}, {col_created}, {col_joined}, {col_updated}"
            f") VALUES (?, ?, ?, ?, 1, ?, 1, ?, ?, ?)"
        )

        async with self._backend.session() as session:
            existing = await session.select_one_or_none(check_email, command.normalized_identifier)
            if existing is not None:
                return RegistrationOutcome(RegistrationStatus.DUPLICATE)

            invitation_row_id: str | None = None
            if invitation_digest is not None:
                rows = await session.select(select_invitation, TokenPurpose.INVITATION.value)
                matched: object | None = None
                for r in rows:
                    stored_d = bytes(cast("bytes", _row_val(r, 1, "digest") or b""))
                    if compare_digest(stored_d, invitation_digest):
                        matched = r
                        break
                if matched is None:
                    return RegistrationOutcome(RegistrationStatus.INVALID_INVITATION)
                raw_exp = _row_val(matched, 2, "expires_at")
                inv_exp = self._parse_dt(raw_exp)
                if inv_exp <= now:
                    return RegistrationOutcome(RegistrationStatus.INVALID_INVITATION)
                invitation_row_id = str(_row_val(matched, 0, "id") or "")


            account_id = self._identifiers("account")
            is_verified = 1 if verification is None else 0
            now_iso = now.isoformat()

            try:
                await session.execute(
                    insert_account,
                    account_id,
                    command.normalized_identifier,
                    command.display_name,
                    password_hash,
                    is_verified,
                    now_iso,
                    now_iso,
                    now_iso,
                )
            except Exception as exc:
                exc_type = type(exc).__name__.lower()
                exc_msg = str(exc).lower()
                if "unique" in exc_msg or "duplicate" in exc_msg or "integrity" in exc_type:
                    return RegistrationOutcome(RegistrationStatus.DUPLICATE)
                raise

            if verification is not None:
                issue, notification = verification.bind(account_id)
                await self._purpose_store.issue(issue, notification, event=event)

            if invitation_row_id is not None:
                await session.execute(consume_invitation, now_iso, invitation_row_id)

            account = cast(
                "LocalAccountState[object]",
                LocalAccountState(
                    account_id=account_id,
                    normalized_identifier=command.normalized_identifier,
                    display_name=command.display_name,
                    active=True,
                    verified=verification is None,
                    security_epoch=1,
                    user=None,
                ),
            )
            return RegistrationOutcome(RegistrationStatus.CREATED, account)

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        """Issue a verification or recovery token."""
        await self._purpose_store.issue(issue, notification, event=event)

    async def issue_absent(self) -> None:
        """Perform durable round trip without committing state."""
        await self._purpose_store.issue_absent()

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: datetime, event: SecurityEvent
    ) -> VerificationOutcome:
        """Consume verification token and mark account verified."""
        return await self._purpose_store.consume_and_verify(token_id, digest, now=now, event=event)

    async def consume_and_reset(
        self, token_id: str, digest: bytes, new_password_hash: str, *, now: datetime, event: SecurityEvent
    ) -> PasswordResetOutcome:
        """Consume recovery token and reset password advancing epoch."""
        return await self._purpose_store.consume_and_reset(
            token_id, digest, new_password_hash, now=now, event=event
        )

    def _row_to_account(self, row: object) -> LocalAccountState[object]:
        mapping: dict[str, object]
        if isinstance(row, dict):
            mapping = cast("dict[str, object]", row)
        elif isinstance(row, (tuple, list)):
            keys = ("id", "email", "name", "is_active", "is_verified", "security_epoch")
            mapping = {k: row[idx] for idx, k in enumerate(keys)}
        else:
            msg = f"Unexpected row representation: {type(row)!r}"
            raise TypeError(msg)

        return cast(
            "LocalAccountState[object]",
            LocalAccountState(
                account_id=str(mapping["id"]),
                normalized_identifier=str(mapping["email"]),
                display_name=str(mapping["name"]) if mapping["name"] is not None else None,
                active=bool(mapping["is_active"]),
                verified=bool(mapping["is_verified"]),
                security_epoch=int(cast("int", mapping["security_epoch"])),
                user=None,
            ),
        )

    @staticmethod
    def _parse_dt(val: object) -> datetime:
        if isinstance(val, datetime):
            return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
        if isinstance(val, str):
            dt = datetime.fromisoformat(val)
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)
