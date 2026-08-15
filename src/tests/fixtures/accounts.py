"""Reusable account test collaborators and configuration builders."""

from __future__ import annotations

import asyncio
import base64
import hmac
from collections.abc import Callable, Iterator, Mapping
from collections.abc import Set as AbstractSet
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from time import sleep
from types import SimpleNamespace
from typing import Any, cast

from anyio.lowlevel import checkpoint
from litestar.connection import ASGIConnection
from litestar.stores.base import Store  # noqa: TC002
from litestar.stores.memory import MemoryStore

import litestar_security.accounts as accounts_module
from litestar_security.authentication import Authenticated, InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence

_MFA_VECTOR_NOW = datetime.fromtimestamp(59, tz=timezone.utc)
_MFA_ENCODED_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
_MFA_POLICY = accounts_module.TOTPPolicy()


class _PasswordStore:
    def __init__(  # noqa: PLR0913
        self,
        encoded_hash: str | None = "current-hash",
        *,
        fail_read: bool = False,
        fail_replace: bool = False,
        fail_bump: bool = False,
        replace_result: object = True,
        security_epoch: int = 1,
        active: bool = True,
        verified: bool = True,
        bump_result: accounts_module.PasswordChangeOutcome | None = None,
    ) -> None:
        self.encoded_hash = encoded_hash
        self.fail_read = fail_read
        self.fail_replace = fail_replace
        self.fail_bump = fail_bump
        self.replace_result = replace_result
        self.security_epoch = security_epoch
        self.active = active
        self.verified = verified
        self.bump_result = bump_result
        self.replacements: list[tuple[str, str, str, accounts_module.SecurityEvent]] = []
        self.bump_calls: list[tuple[str, str, int, accounts_module.SecurityEvent]] = []
        self._mutation_lock = asyncio.Lock()

    async def get_password_state(self, _account_id: str) -> accounts_module.PasswordCredentialState | None:
        if self.fail_read:
            raise OSError
        return (
            accounts_module.PasswordCredentialState(
                self.encoded_hash, self.security_epoch, active=self.active, verified=self.verified
            )
            if self.encoded_hash is not None
            else None
        )

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, *, event: accounts_module.SecurityEvent
    ) -> bool:
        if self.fail_replace:
            raise OSError
        self.replacements.append((account_id, expected_hash, password_hash, event))
        return cast("bool", self.replace_result)

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: accounts_module.SecurityEvent
    ) -> accounts_module.PasswordChangeOutcome:
        self.bump_calls.append((account_id, password_hash, expected_epoch, event))
        if self.fail_bump:
            raise OSError
        if self.bump_result is not None:
            return self.bump_result
        async with self._mutation_lock:
            if expected_epoch != self.security_epoch:
                return accounts_module.PasswordChangeOutcome(accounts_module.PasswordChangeStatus.CONFLICT)
            if expected_epoch == 9_223_372_036_854_775_807:
                return accounts_module.PasswordChangeOutcome(accounts_module.PasswordChangeStatus.EPOCH_EXHAUSTED)
            self.encoded_hash = password_hash
            self.security_epoch += 1
            return accounts_module.PasswordChangeOutcome(
                accounts_module.PasswordChangeStatus.CHANGED, security_epoch=self.security_epoch
            )

    async def current_epoch(self, _account_id: str) -> int | None:
        if self.fail_read:
            raise OSError
        return self.security_epoch


class _PasswordHasher:
    def __init__(
        self, result: accounts_module.PasswordVerificationOutcome | None = None, *, unavailable: bool = False
    ) -> None:
        self.result = result or accounts_module.PasswordVerificationOutcome(
            accounts_module.PasswordVerificationStatus.INVALID
        )
        self.unavailable = unavailable
        self.calls: list[tuple[str | None, str]] = []
        self.hash_calls: list[str] = []

    async def hash(self, password: str) -> str:
        self.hash_calls.append(password)
        if self.unavailable:
            raise accounts_module.PasswordHashingUnavailableError
        return f"hashed:{password}"

    async def verify(self, encoded_hash: str | None, password: str) -> accounts_module.PasswordVerificationOutcome:
        self.calls.append((encoded_hash, password))
        if self.unavailable:
            raise accounts_module.PasswordHashingUnavailableError
        return self.result


class _SecurityEvents:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.events: list[accounts_module.SecurityEvent] = []

    async def emit(self, event: accounts_module.SecurityEvent) -> None:
        if self.fail:
            raise OSError
        self.events.append(event)


class _CredentialCleanup:
    def __init__(self, *, failures: frozenset[str] = frozenset()) -> None:
        self.failures = failures
        self.session_revocations: list[tuple[str, accounts_module.SecurityEvent]] = []
        self.other_revocations: list[tuple[str, str, accounts_module.SecurityEvent]] = []
        self.rebinds: list[tuple[str, accounts_module.CreateSessionCommand, accounts_module.SecurityEvent]] = []
        self.refresh_revocations: list[tuple[str, accounts_module.SecurityEvent]] = []

    async def create(
        self, command: accounts_module.CreateSessionCommand, *, event: accounts_module.SecurityEvent
    ) -> accounts_module.UserAuthSession:
        raise NotImplementedError

    async def create_family(
        self, command: accounts_module.CreateRefreshFamilyCommand, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del command, event
        return False

    async def get(self, session_id: str) -> accounts_module.UserAuthSession | None:
        del session_id
        return None

    async def list_for_account(self, account_id: str) -> list[accounts_module.UserAuthSession]:
        del account_id
        return []

    async def touch(self, session_id: str, *, now: datetime) -> accounts_module.UserAuthSession | None:
        del session_id, now
        return None

    async def revoke(self, session_id: str, *, event: accounts_module.SecurityEvent) -> bool:
        del session_id, event
        return False

    async def revoke_session_for_account(
        self, account_id: str, session_id: str, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del account_id, session_id, event
        return False

    async def revoke_sessions_for_account(self, account_id: str, *, event: accounts_module.SecurityEvent) -> int:
        self.session_revocations.append((account_id, event))
        if "sessions" in self.failures:
            raise OSError
        return 1

    async def revoke_other_sessions(
        self, account_id: str, session_id: str, *, event: accounts_module.SecurityEvent
    ) -> int:
        self.other_revocations.append((account_id, session_id, event))
        if "others" in self.failures:
            raise OSError
        return 1

    async def rebind(
        self,
        prior_session_id: str,
        command: accounts_module.CreateSessionCommand,
        *,
        event: accounts_module.SecurityEvent,
    ) -> accounts_module.UserAuthSession | None:
        self.rebinds.append((prior_session_id, command, event))
        if "rebind" in self.failures:
            raise OSError
        return None

    async def prepare_rotation(
        self,
        proof: accounts_module.RefreshTokenProof,
        idempotency_digest: bytes | None,
        *,
        now: datetime,
        event: accounts_module.SecurityEvent,
    ) -> (
        accounts_module.RefreshFamilyContext
        | accounts_module.RefreshReceiptReplay
        | accounts_module.RefreshPreflightOutcome
    ):
        del proof, idempotency_digest, now, event
        return accounts_module.RefreshPreflightOutcome(accounts_module.RefreshRotationStatus.INVALID)

    async def rotate(
        self, command: accounts_module.RotateRefreshCommand, *, now: datetime, event: accounts_module.SecurityEvent
    ) -> accounts_module.RefreshRotationOutcome:
        raise NotImplementedError

    async def revoke_family(self, family_id: str, *, event: accounts_module.SecurityEvent) -> bool:
        del family_id, event
        return False

    async def revoke_token(self, token_id: str, token_digest: bytes, *, event: accounts_module.SecurityEvent) -> bool:
        del token_id, token_digest, event
        return False

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del account_id, token_id, token_digest, event
        return False

    async def revoke_for_account(self, account_id: str, *, event: accounts_module.SecurityEvent) -> int:
        self.refresh_revocations.append((account_id, event))
        if "refresh" in self.failures:
            raise OSError
        return 1


class _LifecycleStore:
    def __init__(
        self,
        *,
        account: accounts_module.LocalAccountState[object] | None = None,
        registration_status: accounts_module.RegistrationStatus = accounts_module.RegistrationStatus.CREATED,
        consume_status: accounts_module.VerificationStatus = accounts_module.VerificationStatus.CONSUMED,
        reset_status: accounts_module.PasswordResetStatus = accounts_module.PasswordResetStatus.RESET,
        fail: bool = False,
    ) -> None:
        self.account = account
        self.registration_status = registration_status
        self.consume_status = consume_status
        self.reset_status = reset_status
        self.fail = fail
        self.registrations: list[tuple[object, ...]] = []
        self.absent_probes: list[None] = []
        self.issues: list[
            tuple[accounts_module.TokenIssue, accounts_module.NotificationCommand, accounts_module.SecurityEvent]
        ] = []
        self.consumptions: list[tuple[str, bytes, datetime, accounts_module.SecurityEvent]] = []
        self.resets: list[tuple[str, bytes, str, datetime, accounts_module.SecurityEvent]] = []

    async def find_for_login(self, _normalized_identifier: str) -> accounts_module.LocalAccountState[object] | None:
        return self.account

    async def get_by_id(self, _account_id: str) -> accounts_module.LocalAccountState[object] | None:
        return self.account

    async def register(  # noqa: PLR0913
        self,
        command: accounts_module.RegistrationCommand,
        password_hash: str,
        *,
        invitation_digest: bytes | None,
        verification: accounts_module.PurposeTokenDelivery | None,
        now: datetime,
        event: accounts_module.SecurityEvent,
    ) -> accounts_module.RegistrationOutcome[object]:
        self.registrations.append((command, password_hash, invitation_digest, verification, now, event))
        if self.fail:
            raise OSError
        account = (
            accounts_module.LocalAccountState(
                account_id="account-1",
                normalized_identifier="user@example.com",
                display_name=None,
                active=True,
                verified=verification is None,
                security_epoch=1,
            )
            if self.registration_status is accounts_module.RegistrationStatus.CREATED
            else None
        )
        return accounts_module.RegistrationOutcome(self.registration_status, account)

    async def issue(
        self,
        issue: accounts_module.TokenIssue,
        notification: accounts_module.NotificationCommand,
        *,
        event: accounts_module.SecurityEvent,
    ) -> None:
        self.issues.append((issue, notification, event))
        if self.fail:
            raise OSError

    async def issue_absent(self) -> None:
        self.absent_probes.append(None)
        if self.fail:
            raise OSError

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: datetime, event: accounts_module.SecurityEvent
    ) -> accounts_module.VerificationOutcome:
        self.consumptions.append((token_id, digest, now, event))
        if self.fail:
            raise OSError
        if self.consume_status is accounts_module.VerificationStatus.CONSUMED:
            return accounts_module.VerificationOutcome(self.consume_status, "account-1", 1)
        return accounts_module.VerificationOutcome(self.consume_status)

    async def consume_and_reset(
        self,
        token_id: str,
        digest: bytes,
        new_password_hash: str,
        *,
        now: datetime,
        event: accounts_module.SecurityEvent,
    ) -> accounts_module.PasswordResetOutcome:
        self.resets.append((token_id, digest, new_password_hash, now, event))
        if self.fail:
            raise OSError
        if self.reset_status is accounts_module.PasswordResetStatus.RESET:
            return accounts_module.PasswordResetOutcome(self.reset_status, "account-1", 2)
        return accounts_module.PasswordResetOutcome(self.reset_status)


class _NativeSessionStore:
    def __init__(self) -> None:
        self.account: accounts_module.LocalAccountState[object] | None = accounts_module.LocalAccountState(
            account_id="account-1",
            normalized_identifier="user@example.com",
            display_name="User",
            active=True,
            verified=True,
            security_epoch=1,
            user=object(),
        )
        self.epoch: int | None = 1
        self.records: dict[str, accounts_module.UserAuthSession] = {}
        self.commands: list[accounts_module.CreateSessionCommand] = []
        self.rebinds: list[tuple[str, accounts_module.CreateSessionCommand]] = []
        self.revocations: list[tuple[str, str]] = []
        self.touches: list[tuple[str, datetime]] = []
        self.failures: set[str] = set()
        self.mismatch_create = False

    @staticmethod
    def record(command: accounts_module.CreateSessionCommand) -> accounts_module.UserAuthSession:
        return accounts_module.UserAuthSession(
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

    async def create(
        self, command: accounts_module.CreateSessionCommand, *, event: accounts_module.SecurityEvent
    ) -> accounts_module.UserAuthSession:
        del event
        if "create" in self.failures:
            raise OSError
        self.commands.append(command)
        record = self.record(command)
        if self.mismatch_create:
            return accounts_module.UserAuthSession(
                session_id=record.session_id,
                binding_id=record.binding_id,
                binding_digest=b"x" * 32,
                account_id=record.account_id,
                security_epoch=record.security_epoch,
                created_at=record.created_at,
                authenticated_at=record.authenticated_at,
                last_seen_at=record.last_seen_at,
                expires_at=record.expires_at,
            )
        self.records[record.session_id] = record
        return record

    async def get(self, session_id: str) -> accounts_module.UserAuthSession | None:
        if "get" in self.failures:
            raise OSError
        return self.records.get(session_id)

    async def get_by_id(self, account_id: str) -> accounts_module.LocalAccountState[object] | None:
        if "account" in self.failures:
            raise OSError
        return self.account if self.account is not None and self.account.account_id == account_id else None

    async def current_epoch(self, account_id: str) -> int | None:
        if "epoch" in self.failures:
            raise OSError
        return self.epoch if account_id == "account-1" else None

    async def list_for_account(self, account_id: str) -> list[accounts_module.UserAuthSession]:
        if "list" in self.failures:
            raise OSError
        return list(self.records.values()) if account_id == "account-1" else []

    async def touch(self, session_id: str, *, now: datetime) -> accounts_module.UserAuthSession | None:
        if "touch" in self.failures:
            raise OSError
        self.touches.append((session_id, now))
        record = self.records.get(session_id)
        if record is None:
            return None
        touched = accounts_module.UserAuthSession(
            session_id=record.session_id,
            binding_id=record.binding_id,
            binding_digest=record.binding_digest,
            account_id=record.account_id,
            security_epoch=record.security_epoch,
            created_at=record.created_at,
            authenticated_at=record.authenticated_at,
            last_seen_at=now,
            expires_at=record.expires_at,
            display_metadata=record.display_metadata,
        )
        self.records[session_id] = touched
        return touched

    async def revoke_session_for_account(
        self, account_id: str, session_id: str, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del event
        if "revoke" in self.failures:
            raise OSError
        self.revocations.append((account_id, session_id))
        record = self.records.get(session_id)
        if record is None or record.account_id != account_id:
            return False
        del self.records[session_id]
        return True

    async def revoke_sessions_for_account(self, account_id: str, *, event: accounts_module.SecurityEvent) -> int:
        del event
        matches = tuple(key for key, record in self.records.items() if record.account_id == account_id)
        for key in matches:
            del self.records[key]
        return len(matches)

    async def revoke_other_sessions(
        self, account_id: str, session_id: str, *, event: accounts_module.SecurityEvent
    ) -> int:
        del event
        matches = tuple(
            key for key, record in self.records.items() if record.account_id == account_id and key != session_id
        )
        for key in matches:
            del self.records[key]
        return len(matches)

    async def rebind(
        self,
        prior_session_id: str,
        command: accounts_module.CreateSessionCommand,
        *,
        event: accounts_module.SecurityEvent,
    ) -> accounts_module.UserAuthSession | None:
        del event
        if "rebind" in self.failures or prior_session_id not in self.records:
            return None
        self.rebinds.append((prior_session_id, command))
        del self.records[prior_session_id]
        record = self.record(command)
        self.records[record.session_id] = record
        return record


class _SessionEntropy:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, length: int) -> bytes:
        self.calls += 1
        return bytes([self.calls]) * length


def _native_session_connection(
    session: dict[str, object],
    *,
    binding_token: str | None = None,
    scope_type: str = "http",
    cookie_name: str = "__Host-litestar-security-binding",
) -> ASGIConnection[Any, Any, Any, Any]:
    headers = [] if binding_token is None else [(b"cookie", f"{cookie_name}={binding_token}".encode())]
    return ASGIConnection(
        cast(
            "Any",
            {
                "type": scope_type,
                "asgi": {"spec_version": "2.0", "version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "https" if scope_type == "http" else "wss",
                "path": "/",
                "raw_path": b"/",
                "query_string": b"",
                "root_path": "",
                "headers": headers,
                "client": ("test", 50000),
                "server": ("testserver", 443),
                "session": session,
            },
        )
    )


def _queued_binding_token(connection: ASGIConnection[Any, Any, Any, Any]) -> str:
    headers = cast("list[tuple[bytes, bytes]]", connection.scope["_litestar_security_response_headers"])
    name_value = headers[-1][1].decode().partition(";")[0]
    return name_value.partition("=")[2].strip('"')


def _copy_native_session(session: dict[str, object]) -> dict[str, object]:
    return {key: dict(value) if isinstance(value, dict) else value for key, value in session.items()}


class _LocalAccessStore(_PasswordStore):
    def __init__(
        self,
        account: accounts_module.LocalAccountState[object] | None,
        *,
        fail_lookup: bool = False,
        fail_password_read: bool = False,
        fail_epoch: bool = False,
    ) -> None:
        super().__init__(
            fail_read=fail_password_read, security_epoch=account.security_epoch if account is not None else 1
        )
        self.account = account
        self.fail_lookup = fail_lookup
        self.fail_epoch = fail_epoch
        self.login_lookups: list[str] = []
        self.id_lookups: list[str] = []

    async def find_for_login(self, normalized_identifier: str) -> accounts_module.LocalAccountState[object] | None:
        self.login_lookups.append(normalized_identifier)
        if self.fail_lookup:
            raise OSError
        return self.account

    async def get_by_id(self, account_id: str) -> accounts_module.LocalAccountState[object] | None:
        self.id_lookups.append(account_id)
        if self.fail_lookup:
            raise OSError
        return self.account if self.account is not None and self.account.account_id == account_id else None

    async def current_epoch(self, account_id: str) -> int | None:
        if self.fail_epoch:
            raise OSError
        return await super().current_epoch(account_id)


def _local_access_account(
    *, active: bool = True, verified: bool = True, security_epoch: int = 3
) -> accounts_module.LocalAccountState[object]:
    return accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Local Person",
        active=active,
        verified=verified,
        security_epoch=security_epoch,
        user={"safe": "application object"},
    )


class _AccessSigner:
    def __init__(self, token: str = "e30.e30.YQ", *, fail: bool = False) -> None:  # noqa: S107
        self.token = token
        self.fail = fail
        self.claims: list[Mapping[str, object]] = []

    async def sign(self, claims: Mapping[str, object], *, now: datetime) -> str:
        del now
        if self.fail:
            raise OSError
        self.claims.append(claims)
        return self.token


class _RefreshEntropy:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, length: int) -> bytes:
        self.value += 1
        return self.value.to_bytes(length, "big")


PasswordStore = _PasswordStore
PasswordHasher = _PasswordHasher
SecurityEvents = _SecurityEvents
CredentialCleanup = _CredentialCleanup
LifecycleStore = _LifecycleStore
LocalAccessStore = _LocalAccessStore
local_access_account = _local_access_account


class InvalidAssuranceVerifier:
    def __init__(self, outcome: Authenticated) -> None:
        self.outcome = outcome

    async def verify(self, _token: str, *, now: datetime) -> object:
        del now
        return replace(
            self.outcome, claims=replace(self.outcome.claims, raw={**self.outcome.claims.raw, "amr": ["bad value"]})
        )


class PasswordLogin:
    def __init__(self, account: accounts_module.LocalAccountState[object]) -> None:
        self.account = account

    async def authenticate(self, *_args: object, **_kwargs: object) -> accounts_module.LocalAccountState[object]:
        return self.account


class RefreshTokens:
    def __init__(
        self,
        *,
        issued_at: datetime | None = None,
        account: accounts_module.LocalAccountState[object] | None = None,
        response: accounts_module.TokenPair | None = None,
        clock_failure: bool = False,
    ) -> None:
        self.issued_at = issued_at
        self.account = account
        self.response = response
        self.clock_failure = clock_failure
        self.evidence: AuthenticationEvidence | None = None

    def clock(self) -> datetime:
        if self.clock_failure or self.issued_at is None:
            raise RuntimeError
        return self.issued_at

    async def issue(
        self, issued_for: object, *, evidence: AuthenticationEvidence | None = None, now: datetime | None = None
    ) -> accounts_module.TokenPair:
        if self.account is not None:
            assert issued_for is self.account
        assert now == self.issued_at
        self.evidence = evidence
        if self.response is None:
            msg = "token issuance must not run"
            raise AssertionError(msg)
        return self.response


class AsyncOutcome:
    def __init__(self, *outcomes: object) -> None:
        self.outcomes = list(outcomes)

    async def __call__(self, *_args: object, **_kwargs: object) -> object:
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _local_auth_secrets(*, refresh: bool = False) -> accounts_module.LocalAuthSecrets:
    return accounts_module.LocalAuthSecrets(
        purpose_tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        refresh_codec=accounts_module.RefreshTokenCodec(pepper=b"q" * 32) if refresh else None,
        refresh_receipts=(
            accounts_module.RefreshReceiptSealer(active_key=accounts_module.RefreshReceiptKey("test-key", b"r" * 32))
            if refresh
            else None
        ),
    )


_BASE_LOCAL_CAPABILITIES = {
    "compare_and_replace_password",
    "consume_and_reset",
    "consume_and_verify",
    "current_epoch",
    "find_for_login",
    "get_by_id",
    "get_password_state",
    "issue",
    "issue_absent",
    "list_methods",
    "register_login_method",
    "replace_password_and_bump_epoch",
    "revoke_login_method",
}
_SESSION_CAPABILITIES = {
    "create",
    "get",
    "list_for_account",
    "rebind",
    "revoke_other_sessions",
    "revoke_session_for_account",
    "revoke_sessions_for_account",
    "touch",
}


def _structural_capabilities(*method_names: str) -> object:
    def method(*_args: object, **_kwargs: object) -> None:
        return None

    return type("StructuralCapabilities", (), dict.fromkeys(method_names, method))()


def _local_auth_rate_limit_config(**kwargs: Any) -> accounts_module.LocalAuthConfig[Any]:
    return accounts_module.LocalAuth.session(
        accounts=_structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES)),
        secrets=_local_auth_secrets(),
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        **kwargs,
    )


_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
_JWT_ISSUER = "https://issuer.example"
_JWT_AUDIENCE = "litestar-security"


def _refresh_identifier(prefix: str, value: int) -> str:
    return f"{prefix}{base64.urlsafe_b64encode(value.to_bytes(16, 'big')).rstrip(b'=').decode()}"


def _refresh_idempotency_key(value: int = 1) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(16, "big")).rstrip(b"=").decode()


class _AtomicRefreshStore:
    """Deterministic test-only implementation of the strict atomic store contract."""

    def __init__(
        self,
        accounts: _LocalAccessStore,
        *,
        expected_preparations: int = 0,
        expected_atomic_rotations: int = 0,
        before_atomic_rotate: Callable[[], None] | None = None,
    ) -> None:
        self.accounts = accounts
        self.tokens: dict[str, SimpleNamespace] = {}
        self.revoked_families: set[str] = set()
        self.rotations: list[accounts_module.RefreshRotationStatus] = []
        self.preparations: list[
            accounts_module.RefreshPreflightOutcome
            | accounts_module.RefreshFamilyContext
            | accounts_module.RefreshReceiptReplay
        ] = []
        self.preparation_events: list[accounts_module.SecurityEvent] = []
        self.override_receipt: bytes | None = None
        self._lock = asyncio.Lock()
        self._expected_preparations = expected_preparations
        self._prepared_count = 0
        self._preparation_gate = asyncio.Event()
        self._expected_atomic_rotations = expected_atomic_rotations
        self._atomic_rotation_count = 0
        self._atomic_rotation_gate = asyncio.Event()
        self._atomic_rotation_lock = asyncio.Lock()
        self._before_atomic_rotate = before_atomic_rotate

    async def create_family(
        self, command: accounts_module.CreateRefreshFamilyCommand, *, event: accounts_module.SecurityEvent
    ) -> bool:
        self.preparation_events.append(event)
        async with self._lock:
            if command.token_id in self.tokens or command.security_epoch != self.accounts.security_epoch:
                return False
            self.tokens[command.token_id] = SimpleNamespace(
                account_id=command.account_id,
                consumed=False,
                family_expires_at=command.family_expires_at,
                family_id=command.family_id,
                idempotency_digest=None,
                evidence=command.evidence,
                receipt_expires_at=None,
                scopes=command.scopes,
                sealed_receipt=None,
                security_epoch=command.security_epoch,
                token_digest=command.token_digest,
                token_expires_at=command.token_expires_at,
            )
            return True

    async def prepare_rotation(
        self,
        proof: accounts_module.RefreshTokenProof,
        idempotency_digest: bytes | None,
        *,
        now: datetime,
        event: accounts_module.SecurityEvent,
    ) -> (
        accounts_module.RefreshFamilyContext
        | accounts_module.RefreshReceiptReplay
        | accounts_module.RefreshPreflightOutcome
    ):
        self.preparation_events.append(event)
        async with self._lock:
            record = self.tokens.get(proof.token_id)
            if record is None or not hmac.compare_digest(record.token_digest, proof.digest):
                result: (
                    accounts_module.RefreshFamilyContext
                    | accounts_module.RefreshReceiptReplay
                    | accounts_module.RefreshPreflightOutcome
                ) = accounts_module.RefreshPreflightOutcome(accounts_module.RefreshRotationStatus.INVALID)
            elif record.family_id in self.revoked_families:
                result = accounts_module.RefreshPreflightOutcome(
                    accounts_module.RefreshRotationStatus.REVOKED, family_revoked=True
                )
            elif record.security_epoch != self.accounts.security_epoch:
                result = accounts_module.RefreshPreflightOutcome(accounts_module.RefreshRotationStatus.EPOCH_MISMATCH)
            elif now >= record.token_expires_at or now >= record.family_expires_at:
                result = accounts_module.RefreshPreflightOutcome(accounts_module.RefreshRotationStatus.EXPIRED)
            elif record.consumed:
                same_key = (
                    record.idempotency_digest is not None
                    and idempotency_digest is not None
                    and hmac.compare_digest(record.idempotency_digest, idempotency_digest)
                )
                if same_key and now < record.receipt_expires_at:
                    result = accounts_module.RefreshReceiptReplay(
                        context=accounts_module.RefreshFamilyContext(
                            account_id=record.account_id,
                            family_id=record.family_id,
                            security_epoch=record.security_epoch,
                            token_expires_at=record.token_expires_at,
                            family_expires_at=record.family_expires_at,
                            scopes=record.scopes,
                            evidence=record.evidence,
                        ),
                        sealed_receipt=record.sealed_receipt,
                    )
                else:
                    self.revoked_families.add(record.family_id)
                    result = accounts_module.RefreshPreflightOutcome(
                        accounts_module.RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True
                    )
            else:
                result = accounts_module.RefreshFamilyContext(
                    account_id=record.account_id,
                    family_id=record.family_id,
                    security_epoch=record.security_epoch,
                    token_expires_at=record.token_expires_at,
                    family_expires_at=record.family_expires_at,
                    scopes=record.scopes,
                    evidence=record.evidence,
                )
            self.preparations.append(result)
            if self._expected_preparations:
                self._prepared_count += 1
                if self._prepared_count == self._expected_preparations:
                    self._preparation_gate.set()
        if self._expected_preparations:
            await self._preparation_gate.wait()
        return result

    async def rotate(  # noqa: C901, PLR0911 - explicit atomic state-machine outcomes
        self, command: accounts_module.RotateRefreshCommand, *, now: datetime, event: accounts_module.SecurityEvent
    ) -> accounts_module.RefreshRotationOutcome:
        del event
        if self._expected_atomic_rotations:
            async with self._atomic_rotation_lock:
                self._atomic_rotation_count += 1
                if self._atomic_rotation_count == self._expected_atomic_rotations:
                    if self._before_atomic_rotate is not None:
                        self._before_atomic_rotate()
                    self._atomic_rotation_gate.set()
            await self._atomic_rotation_gate.wait()
        async with self._lock:
            record = self.tokens.get(command.token_id)
            if record is None or not hmac.compare_digest(record.token_digest, command.token_digest):
                return self._result(accounts_module.RefreshRotationStatus.INVALID)
            if record.family_id in self.revoked_families:
                return self._result(accounts_module.RefreshRotationStatus.REVOKED, family_revoked=True)
            if (
                command.account_id != record.account_id
                or command.family_id != record.family_id
                or command.security_epoch != record.security_epoch
                or command.family_expires_at != record.family_expires_at
                or command.scopes != record.scopes
                or command.evidence != record.evidence
            ):
                return self._result(accounts_module.RefreshRotationStatus.INVALID)
            if command.security_epoch != self.accounts.security_epoch:
                return self._result(accounts_module.RefreshRotationStatus.EPOCH_MISMATCH)
            if now >= record.token_expires_at or now >= record.family_expires_at:
                return self._result(accounts_module.RefreshRotationStatus.EXPIRED)
            if record.consumed:
                same_key = (
                    record.idempotency_digest is not None
                    and command.idempotency_digest is not None
                    and hmac.compare_digest(record.idempotency_digest, command.idempotency_digest)
                )
                if same_key and now < record.receipt_expires_at:
                    return self._result(
                        accounts_module.RefreshRotationStatus.IDEMPOTENT_REPLAY, sealed_receipt=record.sealed_receipt
                    )
                self.revoked_families.add(record.family_id)
                return self._result(accounts_module.RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True)
            record.consumed = True
            record.idempotency_digest = command.idempotency_digest
            record.receipt_expires_at = command.receipt_expires_at
            record.sealed_receipt = command.sealed_receipt
            self.tokens[command.successor_id] = SimpleNamespace(
                account_id=record.account_id,
                consumed=False,
                family_expires_at=record.family_expires_at,
                family_id=record.family_id,
                idempotency_digest=None,
                evidence=record.evidence,
                receipt_expires_at=None,
                scopes=record.scopes,
                sealed_receipt=None,
                security_epoch=record.security_epoch,
                token_digest=command.successor_digest,
                token_expires_at=command.successor_expires_at,
            )
            return self._result(
                accounts_module.RefreshRotationStatus.ROTATED,
                sealed_receipt=self.override_receipt or command.sealed_receipt,
            )

    async def revoke_family(self, family_id: str, *, event: accounts_module.SecurityEvent) -> bool:
        del event
        async with self._lock:
            exists = any(record.family_id == family_id for record in self.tokens.values())
            if not exists or family_id in self.revoked_families:
                return False
            self.revoked_families.add(family_id)
            return True

    async def revoke_token(self, token_id: str, token_digest: bytes, *, event: accounts_module.SecurityEvent) -> bool:
        del event
        async with self._lock:
            record = self.tokens.get(token_id)
            if (
                record is None
                or record.family_id in self.revoked_families
                or not hmac.compare_digest(record.token_digest, token_digest)
            ):
                return False
            self.revoked_families.add(record.family_id)
            return True

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, *, event: accounts_module.SecurityEvent
    ) -> bool:
        del event
        async with self._lock:
            record = self.tokens.get(token_id)
            if (
                record is None
                or record.account_id != account_id
                or record.family_id in self.revoked_families
                or not hmac.compare_digest(record.token_digest, token_digest)
            ):
                return False
            self.revoked_families.add(record.family_id)
            return True

    async def revoke_for_account(self, account_id: str, *, event: accounts_module.SecurityEvent) -> int:
        del event
        async with self._lock:
            families = {
                record.family_id
                for record in self.tokens.values()
                if record.account_id == account_id and record.family_id not in self.revoked_families
            }
            self.revoked_families.update(families)
            return len(families)

    def _result(
        self,
        status: accounts_module.RefreshRotationStatus,
        *,
        sealed_receipt: bytes | None = None,
        family_revoked: bool = False,
    ) -> accounts_module.RefreshRotationOutcome:
        self.rotations.append(status)
        return accounts_module.RefreshRotationOutcome(
            status=status, sealed_receipt=sealed_receipt, family_revoked=family_revoked
        )


def _refresh_service(
    *,
    expected_preparations: int = 0,
    expected_atomic_rotations: int = 0,
    before_atomic_rotate: Callable[[], None] | None = None,
    idle_lifetime: timedelta = timedelta(days=7),
    absolute_lifetime: timedelta = timedelta(days=30),
) -> tuple[
    accounts_module.RefreshTokenService[object],
    _AtomicRefreshStore,
    _LocalAccessStore,
    accounts_module.LocalAccountState[object],
]:
    account = _local_access_account()
    accounts = _LocalAccessStore(account)
    store = _AtomicRefreshStore(
        accounts,
        expected_preparations=expected_preparations,
        expected_atomic_rotations=expected_atomic_rotations,
        before_atomic_rotate=before_atomic_rotate,
    )
    codec = accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=_RefreshEntropy())
    receipts = accounts_module.RefreshReceiptSealer(
        active_key=accounts_module.RefreshReceiptKey("active", b"k" * 32), entropy=_RefreshEntropy()
    )
    access_tokens = accounts_module.LocalAccessTokenIssuer(
        signer=_AccessSigner(),
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        clock=lambda: _JWT_NOW,
        token_ids=lambda: "access-token",
    )
    return (
        accounts_module.RefreshTokenService(
            accounts=accounts,
            store=store,
            codec=codec,
            receipts=receipts,
            access_tokens=access_tokens,
            idle_lifetime=idle_lifetime,
            absolute_lifetime=absolute_lifetime,
            clock=lambda: _JWT_NOW,
            family_ids=lambda: _refresh_identifier("rf_", 1),
            event_ids=lambda: "refresh-event",
        ),
        store,
        accounts,
        account,
    )


class _CollectingSink:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def emit(self, event: Any) -> None:
        self.events.append(event)


class _FailingSink:
    async def emit(self, event: Any) -> None:
        del event
        msg = "sink down"
        raise RuntimeError(msg)


class _ScriptedLimiter:
    def __init__(self, *decisions: object) -> None:
        self.decisions = list(decisions)
        self.requests: list[Any] = []

    async def acquire(self, request: Any) -> Any:
        self.requests.append(request)
        return self.decisions.pop(0) if len(self.decisions) > 1 else self.decisions[0]


class _RaisingLimiter:
    async def acquire(self, request: Any) -> Any:
        del request
        msg = "limiter down"
        raise RuntimeError(msg)


def _guard(limiter: object, **kwargs: Any) -> Any:
    kwargs.setdefault("pepper", b"p" * 32)
    return accounts_module.RateLimitGuard(limiter=cast("Any", limiter), **kwargs)


def _memory_limiter(**kwargs: Any) -> Any:
    return accounts_module.StoreRateLimiter(store=MemoryStore(), **kwargs)


class _InterleavingStore(MemoryStore):
    """Yield after each rate-limit read to expose read-modify-write races."""

    async def get(self, key: str, renew_for: int | timedelta | None = None) -> bytes | None:
        """Read one counter, then let a competing acquire run before its write."""
        value = await super().get(key, renew_for)
        await checkpoint()
        return value


RefreshEntropy = _RefreshEntropy
refresh_identifier = _refresh_identifier
refresh_idempotency_key = _refresh_idempotency_key
refresh_service = _refresh_service
CollectingSink = _CollectingSink
FailingSink = _FailingSink
ScriptedLimiter = _ScriptedLimiter
RaisingLimiter = _RaisingLimiter
rate_limit_guard = _guard
memory_limiter = _memory_limiter
InterleavingStore = _InterleavingStore


class _MFALoginVerificationService(accounts_module.MFAService):
    """MFA port double recording exact MFA-login factor dispatch."""

    def __init__(self, *, fail: bool = False) -> None:
        super().__init__(store=_MFAStore(), secret_protector=_MFAProtector())
        self.calls: list[tuple[str, str, str | None, str]] = []
        self.fail = fail

    async def verify_totp(
        self, account_id: str, method_id: str, code: str
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        self.calls.append(("totp", account_id, method_id, code))
        if self.fail:
            raise OSError
        return AuthenticationEvidence(
            mechanism="totp", slot="mfa", authenticated_at=_JWT_NOW, methods=frozenset({"totp"})
        )

    async def consume_recovery_code(
        self, account_id: str, code: str
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        self.calls.append(("recovery-code", account_id, None, code))
        if self.fail:
            raise OSError
        return AuthenticationEvidence(
            mechanism="recovery-code", slot="mfa", authenticated_at=_JWT_NOW, methods=frozenset({"recovery-code"})
        )


class _MFAProtector:
    active_key_version = "test-key"

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.plaintexts: dict[bytes, bytes] = {}
        self.associated_data: list[bytes] = []

    async def protect(self, secret: bytes, *, associated_data: bytes) -> accounts_module.ProtectedSecret:
        if self.fail:
            raise OSError
        ciphertext = b"ciphertext-" + len(self.plaintexts).to_bytes(2, "big")
        self.plaintexts[ciphertext] = secret
        self.associated_data.append(associated_data)
        return accounts_module.ProtectedSecret(ciphertext=ciphertext, key_version=self.active_key_version)

    async def unprotect(self, protected: accounts_module.ProtectedSecret, *, associated_data: bytes) -> bytes:
        if self.fail:
            raise OSError
        self.associated_data.append(associated_data)
        return self.plaintexts[protected.ciphertext]


class _MFAStore:
    def __init__(self) -> None:
        self.enrollments: dict[str, accounts_module.PendingTOTPEnrollment] = {}
        self.methods: dict[str, accounts_module.TOTPMethod] = {}
        self.recovery_codes: dict[bytes, accounts_module.RecoveryCodeDigest] = {}
        self.login_methods: dict[str, accounts_module.LoginMethod] = {}
        self.events: list[accounts_module.SecurityEvent] = []
        self.lock = asyncio.Lock()
        self.fail = False

    async def create_totp_enrollment(self, enrollment: accounts_module.PendingTOTPEnrollment) -> None:
        if self.fail:
            raise OSError
        self.enrollments[enrollment.enrollment_id] = enrollment

    async def get_totp_enrollment(self, enrollment_id: str) -> accounts_module.PendingTOTPEnrollment | None:
        if self.fail:
            raise OSError
        return self.enrollments.get(enrollment_id)

    async def activate_totp(  # noqa: PLR0913 - mirrors the atomic application port
        self,
        account_id: str,
        enrollment_id: str,
        *,
        accepted_counter: int,
        login_method: accounts_module.LoginMethod,
        event: accounts_module.SecurityEvent,
        now: datetime,
    ) -> accounts_module.TOTPMethod | None:
        if self.fail:
            raise OSError
        async with self.lock:
            enrollment = self.enrollments.pop(enrollment_id, None)
            if enrollment is None or enrollment.account_id != account_id or enrollment.expires_at <= now:
                return None
            method = accounts_module.TOTPMethod(
                method_id=enrollment.method_id,
                account_id=account_id,
                protected_secret=enrollment.protected_secret,
                policy=enrollment.policy,
                last_accepted_counter=accepted_counter,
                created_at=now,
            )
            self.methods[method.method_id] = method
            self.login_methods[login_method.method_id] = login_method
            self.events.append(event)
            return method

    async def activate_totp_with_recovery_codes(  # noqa: PLR0913 - mirrors the atomic application port
        self,
        account_id: str,
        enrollment_id: str,
        *,
        accepted_counter: int,
        codes: tuple[accounts_module.RecoveryCodeDigest, ...],
        login_method: accounts_module.LoginMethod,
        event: accounts_module.SecurityEvent,
        now: datetime,
    ) -> accounts_module.TOTPMethod | None:
        async with self.lock:
            enrollment = self.enrollments.get(enrollment_id)
            if self.fail:
                raise OSError
            if enrollment is None or enrollment.account_id != account_id or enrollment.expires_at <= now:
                return None
            method = accounts_module.TOTPMethod(
                method_id=enrollment.method_id,
                account_id=account_id,
                protected_secret=enrollment.protected_secret,
                policy=enrollment.policy,
                last_accepted_counter=accepted_counter,
                created_at=now,
            )
            del self.enrollments[enrollment_id]
            self.methods[method.method_id] = method
            self.recovery_codes = {code.digest: code for code in codes}
            self.login_methods[login_method.method_id] = login_method
            self.events.append(event)
            return method

    async def get_totp_method(self, account_id: str, method_id: str) -> accounts_module.TOTPMethod | None:
        if self.fail:
            raise OSError
        method = self.methods.get(method_id)
        return method if method is not None and method.account_id == account_id else None

    async def advance_totp_counter(self, method_id: str, *, accepted_counter: int, now: datetime) -> bool:
        if self.fail:
            raise OSError
        async with self.lock:
            method = self.methods.get(method_id)
            if method is None or accepted_counter <= method.last_accepted_counter:
                return False
            self.methods[method_id] = replace(method, last_accepted_counter=accepted_counter, last_used_at=now)
            return True

    async def replace_recovery_codes(
        self, account_id: str, codes: tuple[accounts_module.RecoveryCodeDigest, ...], *, now: datetime
    ) -> None:
        del now
        if self.fail:
            raise OSError
        async with self.lock:
            self.recovery_codes = {code.digest: code for code in codes if code.account_id == account_id}

    async def consume_recovery_code(self, account_id: str, digest: bytes, *, now: datetime) -> bool:
        del now
        if self.fail:
            raise OSError
        async with self.lock:
            match = next(
                (
                    stored_digest
                    for stored_digest in self.recovery_codes
                    if hmac.compare_digest(stored_digest, digest)
                    and self.recovery_codes[stored_digest].account_id == account_id
                ),
                None,
            )
            if match is None:
                return False
            del self.recovery_codes[match]
            return True


class _RecoveryLoginMethods:
    def __init__(
        self, status: accounts_module.RevokeLoginMethodStatus = accounts_module.RevokeLoginMethodStatus.REVOKED
    ) -> None:
        self.status = status
        self.events: list[accounts_module.SecurityEvent] = []

    async def list_methods(self, account_id: str) -> tuple[accounts_module.LoginMethod, ...]:
        del account_id
        return ()

    async def register_login_method(
        self, account_id: str, method: accounts_module.LoginMethod, *, event: accounts_module.SecurityEvent
    ) -> None:
        del account_id, method
        self.events.append(event)

    async def revoke_login_method(
        self, account_id: str, method_id: str, *, require_remaining: bool = True, event: accounts_module.SecurityEvent
    ) -> accounts_module.RevokeLoginMethodOutcome:
        del account_id, method_id
        assert require_remaining
        self.events.append(event)
        return accounts_module.RevokeLoginMethodOutcome(self.status)


def _mfa_service(
    store: _MFAStore,
    protector: _MFAProtector,
    *,
    policy: accounts_module.TOTPPolicy = _MFA_POLICY,
    encoded_seed: str = _MFA_ENCODED_SEED,
    now: datetime = _MFA_VECTOR_NOW,
) -> accounts_module.MFAService:
    identifiers = iter(("enrollment-1", "method-1"))
    return accounts_module.MFAService(
        store=store,
        secret_protector=protector,
        policy=policy,
        issuer="Litestar Security",
        clock=lambda: now,
        secret_generator=lambda: encoded_seed,
        identifiers=lambda: next(identifiers),
    )


class _PasskeyStore:
    def __init__(self) -> None:
        self.credentials: dict[bytes, accounts_module.PasskeyCredential] = {}
        self.login_methods: dict[str, accounts_module.LoginMethod] = {}
        self.events: list[accounts_module.SecurityEvent] = []
        self.fail = False

    async def add_credential(
        self,
        credential: accounts_module.PasskeyCredential,
        *,
        login_method: accounts_module.LoginMethod,
        event: accounts_module.SecurityEvent,
    ) -> bool:
        if self.fail:
            raise OSError
        if credential.credential_id in self.credentials:
            return False
        self.credentials[credential.credential_id] = credential
        self.login_methods[login_method.method_id] = login_method
        self.events.append(event)
        return True

    async def get_credential(self, credential_id: bytes) -> accounts_module.PasskeyCredential | None:
        if self.fail:
            raise OSError
        return self.credentials.get(credential_id)

    async def record_assertion(  # noqa: PLR0913 - mirrors the explicit atomic application port
        self,
        credential_id: bytes,
        *,
        expected_version: int,
        sign_count: int,
        backup_eligible: bool,
        backup_state: bool,
        clone_risk: bool,
        now: datetime,
    ) -> accounts_module.PasskeyAssertionStatus:
        del now
        credential = self.credentials.get(credential_id)
        if self.fail:
            raise OSError
        if (
            credential is None
            or credential.version != expected_version
            or credential.backup_eligible != backup_eligible
        ):
            return accounts_module.PasskeyAssertionStatus.CONFLICT
        self.credentials[credential_id] = replace(
            credential,
            sign_count=sign_count,
            backup_state=backup_state,
            suspect=clone_risk,
            version=credential.version + 1,
            last_used_at=_JWT_NOW,
        )
        if clone_risk:
            return accounts_module.PasskeyAssertionStatus.CLONE_RISK
        return accounts_module.PasskeyAssertionStatus.RECORDED

    async def list_credentials(self, account_id: str) -> tuple[accounts_module.PasskeyCredential, ...]:
        if self.fail:
            raise OSError
        return tuple(credential for credential in self.credentials.values() if credential.account_id == account_id)

    async def rename_credential(
        self, account_id: str, credential_id: bytes, display_name: str
    ) -> accounts_module.PasskeyCredential | None:
        if self.fail:
            raise OSError
        credential = self.credentials.get(credential_id)
        if credential is None or credential.account_id != account_id:
            return None
        renamed = replace(credential, display_name=display_name, version=credential.version + 1)
        self.credentials[credential_id] = renamed
        return renamed


class _WebAuthnVerifier:
    challenge = b"c" * 32
    expected_credential_id = b"credential-1"

    def __init__(
        self,
        *,
        failure: str | None = None,
        user_verified: bool = True,
        sign_count: int = 1,
        backup_eligible: bool = False,
        backup_state: bool = False,
    ) -> None:
        self.failure = failure
        self.user_verified = user_verified
        self.sign_count = sign_count
        self.backup_eligible = backup_eligible
        self.backup_state = backup_state
        self.current_sign_counts: list[object] = []

    def registration_options(self, **kwargs: object) -> str:
        assert kwargs["challenge"] == self.challenge
        return '{"challenge":"Y2Nj"}'

    def authentication_options(self, **kwargs: object) -> str:
        assert kwargs["challenge"] == self.challenge
        return '{"challenge":"Y2Nj"}'

    def registration_challenge(self, response: str) -> bytes:
        del response
        return self.challenge

    def authentication_challenge(self, response: str) -> bytes:
        del response
        return self.challenge

    def credential_id(self, response: str) -> bytes:
        del response
        return self.expected_credential_id

    def verify_registration(self, **kwargs: object) -> accounts_module.RegistrationVerification:
        del kwargs
        if self.failure is not None:
            raise accounts_module.WebAuthnVerificationError
        return accounts_module.RegistrationVerification(
            credential_id=self.expected_credential_id,
            public_key=b"public-key",
            sign_count=self.sign_count,
            backup_eligible=self.backup_eligible,
            backup_state=self.backup_state,
            user_verified=self.user_verified,
            aaguid="00000000-0000-0000-0000-000000000000",
            attestation_format="none",
            attestation_chain_verified=False,
        )

    def verify_authentication(self, **kwargs: object) -> accounts_module.AuthenticationVerification:
        self.current_sign_counts.append(kwargs.get("current_sign_count"))
        if self.failure is not None:
            raise accounts_module.WebAuthnVerificationError
        return accounts_module.AuthenticationVerification(
            credential_id=self.expected_credential_id,
            sign_count=self.sign_count,
            backup_eligible=self.backup_eligible,
            backup_state=self.backup_state,
            user_verified=self.user_verified,
        )


def _passkey_service(  # noqa: PLR0913 - explicit service seam builder for ceremony matrices
    *,
    challenge_store: _ChallengeStore | None = None,
    store: _PasskeyStore | None = None,
    verifier: _WebAuthnVerifier | None = None,
    now: datetime = _JWT_NOW,
    attestation_trust: object | None = None,
    login_methods: object | None = None,
    worker_timeout: float = 10.0,
) -> accounts_module.PasskeyService:
    return accounts_module.PasskeyService(
        store=store or _PasskeyStore(),
        challenge_store=challenge_store or _ChallengeStore(),
        verifier=verifier or _WebAuthnVerifier(),
        rp_id="example.com",
        rp_name="Example",
        origins=("https://example.com",),
        user_verification=accounts_module.UserVerification.REQUIRED,
        clock=lambda: now,
        challenge_entropy=lambda length: b"c" * length,
        attestation_trust=cast("Any", attestation_trust),
        login_methods=cast("Any", login_methods),
        worker_timeout=worker_timeout,
    )


def _stored_passkey(
    *, sign_count: int = 0, backup_eligible: bool = False, backup_state: bool = False
) -> accounts_module.PasskeyCredential:
    return accounts_module.PasskeyCredential(
        credential_id=b"credential-1",
        account_id="account-1",
        public_key=b"public-key",
        sign_count=sign_count,
        backup_eligible=backup_eligible,
        backup_state=backup_state,
        user_verified=True,
        aaguid="00000000-0000-0000-0000-000000000000",
        attestation_format="none",
        created_at=_JWT_NOW,
    )


class _StepUpStore:
    def __init__(self) -> None:
        self.records: dict[bytes, accounts_module.StepUpGrantState] = {}

    async def put(self, record: accounts_module.StepUpGrantState) -> None:
        self.records[record.grant_digest] = record

    async def consume(  # noqa: PLR0913 - mirrors the exact atomic StepUpStore contract
        self,
        grant_digest: bytes,
        *,
        principal_id: str,
        security_epoch: int,
        purpose: str,
        transport_digest: bytes,
        now: datetime,
    ) -> accounts_module.StepUpGrantState | None:
        record = self.records.pop(grant_digest, None)
        if (
            record is None
            or record.principal_id != principal_id
            or record.security_epoch != security_epoch
            or record.purpose != purpose
            or record.transport_digest != transport_digest
            or record.expires_at <= now
        ):
            return None
        return record


class _BrokenRefreshScopes(AbstractSet[str]):
    def __contains__(self, _value: object) -> bool:
        return False

    def __len__(self) -> int:
        return 1

    def __iter__(self) -> Iterator[str]:
        raise TypeError


class _RefreshAccessOutcome:
    def __init__(self, outcome: object, *, fail: bool = False) -> None:
        self.outcome = outcome
        self.fail = fail

    async def issue(self, _account: object, *, scopes: object, evidence: object | None = None, now: datetime) -> object:
        del scopes, evidence, now
        if self.fail:
            raise OSError
        return self.outcome


MFALoginVerificationService = _MFALoginVerificationService
MFAProtector = _MFAProtector
MFAStore = _MFAStore
RecoveryLoginMethods = _RecoveryLoginMethods
build_mfa_service = _mfa_service
PasskeyStore = _PasskeyStore
WebAuthnVerifier = _WebAuthnVerifier
build_passkey_service = _passkey_service
stored_passkey = _stored_passkey
StepUpStore = _StepUpStore
BrokenRefreshScopes = _BrokenRefreshScopes
RefreshAccessOutcome = _RefreshAccessOutcome


class _ChallengeStore:
    def __init__(self) -> None:
        self.records: dict[bytes, accounts_module.WebAuthnChallenge] = {}
        self.lock = asyncio.Lock()
        self.fail = False

    async def put(self, challenge: accounts_module.WebAuthnChallenge) -> None:
        if self.fail:
            raise OSError
        self.records[challenge.challenge_digest] = challenge

    async def consume(
        self, challenge_digest: bytes, *, binding_digest: bytes, purpose: str, now: datetime
    ) -> accounts_module.WebAuthnChallenge | None:
        if self.fail:
            raise OSError
        async with self.lock:
            challenge = self.records.pop(challenge_digest, None)
            if (
                challenge is None
                or challenge.binding_digest != binding_digest
                or challenge.purpose != purpose
                or challenge.expires_at <= now
            ):
                return None
            return challenge


WebAuthnChallengeStore = _ChallengeStore


def lifecycle_account(*, active: bool = True, verified: bool = False) -> accounts_module.LocalAccountState[object]:
    return accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=active,
        verified=verified,
        security_epoch=1,
        user={"safe": "application object"},
    )


class ExplosiveHeaders:
    def get(self, _key: str) -> str:
        msg = "untrusted peer must not read a forwarding header"
        raise AssertionError(msg)


class RefreshKeyText(str):
    __slots__ = ()


class ObservingLimiter(accounts_module.StoreRateLimiter):
    def __init__(self, *args: object, consumed: list[str], **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.consumed = consumed

    async def _consume(  # noqa: PLR0913
        self,
        store: Store,
        request: accounts_module.RateLimitAttempt,
        policy: accounts_module.RateLimitPolicy,
        *,
        kind: str,
        value: str,
        now: datetime,
    ) -> int | None:
        self.consumed.append(value)
        return await super()._consume(store, request, policy, kind=kind, value=value, now=now)


class FailingMFALoginChallengeStore:
    """Challenge store that exposes sanitized persistence failure paths."""

    async def put(self, challenge: accounts_module.MFALoginChallenge) -> None:
        del challenge
        raise OSError

    async def consume(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError


class CombinedMFAStore(MFAStore, StepUpStore):
    """Combined factor and step-up store used by MFA configuration tests."""

    def __init__(self) -> None:
        MFAStore.__init__(self)
        StepUpStore.__init__(self)


class ScriptedTOTPVerificationService(accounts_module.MFAService):
    """MFA service double that records codes and accepts one configured value."""

    def __init__(self, *, accepted_code: str, now: datetime) -> None:
        super().__init__(store=MFAStore(), secret_protector=MFAProtector())
        self.accepted_code = accepted_code
        self.now = now
        self.codes: list[str] = []

    async def verify_totp(
        self, _account_id: str, _method_id: str, code: str
    ) -> AuthenticationEvidence | InvalidCredentials:
        self.codes.append(code)
        if code != self.accepted_code:
            return InvalidCredentials()
        return AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=self.now)


class WrongVersionMFAProtector(MFAProtector):
    async def protect(self, secret: bytes, *, associated_data: bytes) -> accounts_module.ProtectedSecret:
        protected = await super().protect(secret, associated_data=associated_data)
        return replace(protected, key_version="other")


class FailingRecoveryLoginMethods(RecoveryLoginMethods):
    async def revoke_login_method(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise OSError


class RejectingTOTPAdvanceStore(MFAStore):
    async def advance_totp_counter(self, method_id: str, *, accepted_counter: int, now: datetime) -> bool:
        del method_id, accepted_counter, now
        return False


class FailingStepUpStore(StepUpStore):
    async def put(self, record: accounts_module.StepUpGrantState) -> None:
        del record
        raise OSError


class RejectActivationMFAStore(MFAStore):
    async def activate_totp_with_recovery_codes(
        self, *args: object, **kwargs: object
    ) -> accounts_module.TOTPMethod | None:
        del args, kwargs
        return None


class RejectSingleActivationMFAStore(MFAStore):
    async def activate_totp(self, *args: object, **kwargs: object) -> accounts_module.TOTPMethod | None:
        del args, kwargs
        return None


class InvalidAttestationVerifier(WebAuthnVerifier):
    def verify_registration(self, **kwargs: object) -> accounts_module.RegistrationVerification:
        return replace(super().verify_registration(**kwargs), attestation_format="packed")


class ChainAttestationVerifier(InvalidAttestationVerifier):
    def verify_registration(self, **kwargs: object) -> accounts_module.RegistrationVerification:
        return replace(super().verify_registration(**kwargs), attestation_chain_verified=True)


class TrustedAttestation:
    def root_certificates(self) -> Mapping[str, tuple[bytes, ...]]:
        return {"packed": (b"trusted-root",)}

    def trusted(self, verification: accounts_module.RegistrationVerification) -> bool:
        return verification.attestation_format == "packed"


class UnanchoredAttestation(TrustedAttestation):
    def root_certificates(self) -> Mapping[str, tuple[bytes, ...]]:
        return {}


class MismatchedAttestation(TrustedAttestation):
    def root_certificates(self) -> Mapping[str, tuple[bytes, ...]]:
        return {"tpm": (b"trusted-root",)}


class ConflictingPasskeyStore(PasskeyStore):
    async def record_assertion(self, *args: object, **kwargs: object) -> accounts_module.PasskeyAssertionStatus:
        del args, kwargs
        return accounts_module.PasskeyAssertionStatus.CONFLICT


class SlowWebAuthnVerifier(WebAuthnVerifier):
    def authentication_options(self, **kwargs: object) -> str:
        sleep(0.05)
        return super().authentication_options(**kwargs)


class MutableAccountLookup:
    def __init__(self, value: object) -> None:
        self.value = value

    async def get_by_id(self, account_id: str) -> object:
        del account_id
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value


class StaticSessionIssuer:
    def __init__(self, result: object) -> None:
        self.result = result

    async def establish(self, request: object, projected: object, *, evidence: object) -> object:
        del request, projected, evidence
        return self.result


class RecordingTokenIssuer:
    def __init__(self, result: object) -> None:
        self.result = result
        self.evidence: object | None = None

    async def issue(self, projected: object, *, evidence: object) -> object:
        del projected
        self.evidence = evidence
        return self.result
