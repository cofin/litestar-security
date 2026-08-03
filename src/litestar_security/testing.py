"""Deterministic conformance helpers for security integration test suites."""

# ruff: noqa: EM101, TRY003  # conformance failures intentionally name their exact violated invariant

from base64 import urlsafe_b64encode
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from hmac import compare_digest
from types import MappingProxyType
from typing import Protocol, TypeVar, cast
from urllib.parse import parse_qsl

import httpx
from anyio import Event, Lock, create_task_group

from litestar_security.accounts import (
    AssertionRecordResult,
    ConsumeResult,
    ConsumeStatus,
    CreateRefreshFamilyCommand,
    CreateSessionCommand,
    LocalAccount,
    LocalAccountCapabilities,
    LoginMethod,
    MFALoginChallenge,
    MFALoginChallengeStore,
    MFAStore,
    NotificationCommand,
    PasskeyCredential,
    PasskeyStore,
    PasswordChangeResult,
    PasswordChangeStatus,
    PasswordCredentialState,
    PasswordResetResult,
    PasswordResetStatus,
    PendingTOTPEnrollment,
    PrepareRefreshResult,
    ProtectedSecret,
    PurposeTokenCodec,
    PurposeTokenDelivery,
    RecoveryCodeDigest,
    RefreshFamilyContext,
    RefreshReceiptReplay,
    RefreshRotationStatus,
    RefreshTokenFamilyStore,
    RefreshTokenProof,
    RegistrationCommand,
    RegistrationResult,
    RegistrationStatus,
    RegistrationStore,
    RevokeLoginMethodResult,
    RevokeLoginMethodStatus,
    RotateRefreshCommand,
    RotateRefreshResult,
    SecurityEvent,
    SessionRecord,
    SessionRegistry,
    StepUpRecord,
    TokenIssue,
    TokenPurpose,
    TOTPMethod,
    TOTPPolicy,
    UserVerification,
    WebAuthnChallenge,
    WebAuthnChallengeStore,
)
from litestar_security.context import CredentialRestrictions
from litestar_security.providers.api_key import APIKeyRecord, APIKeyStore
from litestar_security.providers.oauth import (
    MemoryOAuthAccountStore,
    MemoryOAuthTransactionStore,
    MemoryTokenVault,
    OAuthAccountStore,
    OAuthOperation,
    OAuthTransaction,
    OAuthTransactionProtector,
    OAuthTransactionStart,
    OAuthTransactionStore,
    ProtectedOAuthSecret,
    ProviderGrant,
    ProviderIdentity,
    ProviderTokenSet,
    SecretStr,
    UnlinkStatus,
)
from litestar_security.websocket import (
    InMemoryWebSocketConnectTokenStore,
    WebSocketConnectTokenRecord,
    WebSocketConnectTokenStore,
)

__all__ = (
    "BackendBarrier",
    "BackendEvent",
    "FakeClock",
    "FakeOAuthHTTPTransport",
    "FakeOAuthProvider",
    "InMemoryAPIKeyStore",
    "InMemoryLocalAccountStore",
    "InMemoryMFALoginChallengeStore",
    "InMemoryMFAStore",
    "InMemoryPasskeyStore",
    "InMemorySecurityBackend",
    "InMemoryStepUpStore",
    "InMemoryWebAuthnChallengeStore",
    "MemoryOAuthAccountStore",
    "MemoryOAuthTransactionStore",
    "MemoryTokenVault",
    "OAuthHTTPRequest",
    "StoreConformanceFactories",
    "assert_api_key_store_conformance",
    "assert_local_account_store_conformance",
    "assert_mfa_login_challenge_store_conformance",
    "assert_mfa_store_conformance",
    "assert_oauth_account_store_conformance",
    "assert_oauth_transaction_store_conformance",
    "assert_passkey_store_conformance",
    "assert_refresh_family_store_conformance",
    "assert_security_backend_conformance",
    "assert_session_registry_conformance",
    "assert_webauthn_challenge_store_conformance",
    "assert_websocket_connect_token_store_conformance",
)

_DEFAULT_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_DEFAULT_CREDENTIAL_HASH = "$litestar-security$deterministic-test-hash"
ResultT = TypeVar("ResultT")


def _default_identifier(namespace: str, sequence: int) -> str:
    return f"{namespace}-{sequence:04d}"


@dataclass(frozen=True, slots=True)
class OAuthHTTPRequest:
    """Secret-free projection of one provider HTTP request."""

    method: str
    url: str
    header_names: frozenset[str]
    form_fields: frozenset[str]


class FakeOAuthHTTPTransport(httpx.AsyncBaseTransport):
    """Deterministic queued HTTPX transport for provider conformance tests."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        """Initialize with responses consumed in order.

        Args:
            responses: Provider responses to return.
        """
        self.responses = list(responses)
        self.requests: list[OAuthHTTPRequest] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Record one request and return the next response."""
        self.requests.append(
            OAuthHTTPRequest(
                method=request.method,
                url=str(request.url),
                header_names=frozenset(name.lower() for name in request.headers if name.lower() != "authorization"),
                form_fields=frozenset(
                    key for key, _value in parse_qsl(request.content.decode(), keep_blank_values=True)
                ),
            )
        )
        if not self.responses:
            message = "Fake OAuth HTTP responses exhausted"
            raise AssertionError(message)
        response = self.responses.pop(0)
        return httpx.Response(response.status_code, headers=response.headers, content=response.content, request=request)


class FakeOAuthProvider:
    """Deterministic async provider with public lifecycle call history."""

    def __init__(self, *, name: str, tokens: ProviderTokenSet, identity: ProviderIdentity) -> None:
        """Initialize fixed provider results."""
        self.name = name
        self.tokens = tokens
        self.identity = identity
        self.calls: list[str] = []

    def build_authorization_url(self, start: OAuthTransactionStart) -> str:
        """Return a deterministic URL."""
        self.calls.append("authorize")
        return f"https://provider.example/authorize?state={start.state.get_secret_value()}"

    async def exchange_code(
        self, *, code: SecretStr, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Return configured exchange tokens."""
        del code, transaction, now
        self.calls.append("exchange")
        return self.tokens

    async def resolve_identity(
        self, tokens: ProviderTokenSet, *, transaction: OAuthTransaction, now: datetime | None = None
    ) -> ProviderIdentity:
        """Return the configured identity."""
        del tokens, transaction, now
        self.calls.append("identity")
        return self.identity

    async def refresh(
        self, refresh_token: SecretStr, *, current_scopes: frozenset[str] | None = None, now: datetime | None = None
    ) -> ProviderTokenSet:
        """Return configured refresh tokens."""
        del refresh_token, current_scopes, now
        self.calls.append("refresh")
        return self.tokens

    async def revoke(self, token: SecretStr, *, token_type_hint: str | None) -> None:
        """Record deterministic revocation."""
        del token, token_type_hint
        self.calls.append("revoke")


class FakeClock:
    """Mutable UTC clock owned by one test."""

    __slots__ = ("_now",)

    def __init__(self, now: datetime) -> None:
        """Initialize at one timezone-aware instant.

        Args:
            now: Initial time.

        Raises:
            ValueError: If ``now`` is naive.
        """
        if now.tzinfo is None or now.utcoffset() is None:
            message = "FakeClock requires a timezone-aware datetime"
            raise ValueError(message)
        self._now = now.astimezone(timezone.utc)

    def __call__(self) -> datetime:
        """Return the current instant.

        Returns:
            The current UTC datetime.
        """
        return self._now

    def advance(self, delta: timedelta) -> datetime:
        """Advance by a positive duration.

        Args:
            delta: Positive duration to add.

        Returns:
            The updated UTC datetime.

        Raises:
            ValueError: If ``delta`` is not positive.
        """
        if delta <= timedelta():
            message = "FakeClock advance must be positive"
            raise ValueError(message)
        self._now += delta
        return self._now


@dataclass(frozen=True, slots=True)
class BackendEvent:
    """One secret-free deterministic reference-backend operation."""

    sequence: int
    operation: str
    details: Mapping[str, str]

    def __post_init__(self) -> None:
        """Freeze copied diagnostic details."""
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))


@dataclass(slots=True)
class BackendBarrier:
    """Deterministically pause one named backend operation."""

    reached: Event = dataclass_field(default_factory=Event)
    release: Event = dataclass_field(default_factory=Event)


class InMemoryAPIKeyStore:
    """Atomic digest-only API-key store for tests and examples."""

    __slots__ = ("_lock", "_observe", "_records")

    def __init__(self, observe: "Callable[[str, Mapping[str, str]], Awaitable[None]]") -> None:
        """Initialize isolated records and an aggregate diagnostic callback.

        Args:
            observe: Async operation callback owned by the aggregate backend.
        """
        self._records: dict[str, APIKeyRecord] = {}
        self._lock = Lock()
        self._observe = observe

    @property
    def records(self) -> tuple[APIKeyRecord, ...]:
        """Return a stable immutable record snapshot."""
        return tuple(self._records[key_id] for key_id in sorted(self._records))

    async def get(self, key_id: str) -> APIKeyRecord | None:
        """Return one digest-only record."""
        await self._observe("api_key.get", {"key_id": key_id})
        async with self._lock:
            return self._records.get(key_id)

    async def create(self, record: APIKeyRecord) -> None:
        """Atomically create one unique digest-only record."""
        await self._observe("api_key.create", {"key_id": record.key_id})
        async with self._lock:
            if record.key_id in self._records:
                message = "API-key ID already exists"
                raise ValueError(message)
            self._records[record.key_id] = record

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyRecord, overlap_until: datetime | None, now: datetime
    ) -> None:
        """Atomically replace one current record with one successor."""
        await self._observe(
            "api_key.rotate", {"current_key_id": current_key_id, "replacement_key_id": replacement.key_id}
        )
        async with self._lock:
            current = self._records.get(current_key_id)
            if current is None or current.revoked_at is not None or replacement.key_id in self._records:
                message = "API-key rotation conflict"
                raise ValueError(message)
            bounded_overlap = (
                min(overlap_until, current.expires_at)
                if overlap_until is not None and current.expires_at is not None
                else overlap_until
            )
            self._records[current_key_id] = replace(current, revoked_at=now, overlap_until=bounded_overlap)
            self._records[replacement.key_id] = replacement

    async def revoke(self, *, key_id: str, now: datetime) -> None:
        """Atomically revoke one existing key."""
        await self._observe("api_key.revoke", {"key_id": key_id})
        async with self._lock:
            record = self._records.get(key_id)
            if record is None:
                message = "API-key does not exist"
                raise ValueError(message)
            self._records[key_id] = replace(record, revoked_at=now, overlap_until=None)


@dataclass(slots=True)
class _InMemoryRefreshState:
    """One opaque refresh token retained by the reference store."""

    token_id: str
    token_digest: bytes
    account_id: str
    family_id: str
    security_epoch: int
    token_expires_at: datetime
    family_expires_at: datetime
    scopes: frozenset[str]
    consumed: bool = False
    revoked: bool = False
    idempotency_digest: bytes | None = None
    sealed_receipt: bytes | None = None


class InMemoryLocalAccountStore:
    """Atomic in-memory local-account, session, and refresh reference store."""

    __slots__ = (
        "_accounts",
        "_clock",
        "_entropy",
        "_identifiers",
        "_lock",
        "_login_methods",
        "_observe",
        "_password_hashes",
        "_purpose_attempts",
        "_purpose_tokens",
        "_refresh_tokens",
        "_sessions",
        "_used_purpose_tokens",
    )

    def __init__(
        self,
        observe: "Callable[[str, Mapping[str, str]], Awaitable[None]]",
        *,
        clock: "Callable[[], datetime]",
        identifiers: "Callable[[str], str]",
        entropy: "Callable[[int], bytes]",
    ) -> None:
        """Initialize isolated state with aggregate deterministic sources."""
        self._accounts: dict[str, LocalAccount[object]] = {}
        self._password_hashes: dict[str, str] = {}
        self._login_methods: dict[str, dict[str, LoginMethod]] = {}
        self._purpose_attempts: dict[str, int] = {}
        self._purpose_tokens: dict[str, TokenIssue] = {}
        self._used_purpose_tokens: set[str] = set()
        self._sessions: dict[str, SessionRecord] = {}
        self._refresh_tokens: dict[str, _InMemoryRefreshState] = {}
        self._clock = clock
        self._identifiers = identifiers
        self._entropy = entropy
        self._lock = Lock()
        self._observe = observe

    async def find_for_login(self, normalized_identifier: str) -> LocalAccount[object] | None:
        """Find one account through its normalized identifier."""
        async with self._lock:
            return next(
                (
                    account
                    for account in self._accounts.values()
                    if account.normalized_identifier == normalized_identifier
                ),
                None,
            )

    async def get_by_id(self, account_id: str) -> LocalAccount[object] | None:
        """Return one account by its stable identifier."""
        async with self._lock:
            return self._accounts.get(account_id)

    async def current_epoch(self, account_id: str) -> int | None:
        """Return the authoritative account epoch."""
        async with self._lock:
            account = self._accounts.get(account_id)
            return account.security_epoch if account is not None else None

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        """Return one atomic password and account-state snapshot."""
        async with self._lock:
            account = self._accounts.get(account_id)
            password_hash = self._password_hashes.get(account_id)
            if account is None or password_hash is None:
                return None
            return PasswordCredentialState(
                password_hash=password_hash,
                security_epoch=account.security_epoch,
                active=account.active,
                verified=account.verified,
            )

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, *, event: SecurityEvent
    ) -> bool:
        """Replace one current password hash atomically."""
        del event
        await self._observe("accounts.compare_and_replace_password", {"account_id": account_id})
        async with self._lock:
            if account_id not in self._accounts or self._password_hashes.get(account_id) != expected_hash:
                return False
            self._password_hashes[account_id] = password_hash
            return True

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeResult:
        """Replace a password and advance its exact security epoch."""
        del event
        await self._observe("accounts.replace_password_and_bump_epoch", {"account_id": account_id})
        async with self._lock:
            account = self._accounts.get(account_id)
            if account is None:
                return PasswordChangeResult(PasswordChangeStatus.NOT_FOUND)
            if account.security_epoch != expected_epoch:
                return PasswordChangeResult(PasswordChangeStatus.CONFLICT)
            self._password_hashes[account_id] = password_hash
            self._accounts[account_id] = replace(account, security_epoch=expected_epoch + 1)
            return PasswordChangeResult(PasswordChangeStatus.CHANGED, expected_epoch + 1)

    async def register_login_method(self, account_id: str, method: LoginMethod, *, event: SecurityEvent) -> None:
        """Record a login method for an existing account."""
        del event
        await self._observe("accounts.register_login_method", {"account_id": account_id, "method_id": method.method_id})
        async with self._lock:
            self._login_methods.setdefault(account_id, {})[method.method_id] = method

    async def revoke_login_method(
        self, account_id: str, method_id: str, *, require_remaining: bool = True, event: SecurityEvent
    ) -> RevokeLoginMethodResult:
        """Revoke one login method while preserving the requested invariant."""
        del event
        await self._observe("accounts.revoke_login_method", {"account_id": account_id, "method_id": method_id})
        async with self._lock:
            methods = self._login_methods.get(account_id)
            if methods is None or method_id not in methods:
                return RevokeLoginMethodResult(RevokeLoginMethodStatus.NOT_FOUND)
            if require_remaining and len(methods) == 1:
                return RevokeLoginMethodResult(RevokeLoginMethodStatus.FINAL_METHOD)
            del methods[method_id]
            return RevokeLoginMethodResult(RevokeLoginMethodStatus.REVOKED)

    async def register(  # noqa: PLR0913 - protocol has explicit registration inputs
        self,
        command: RegistrationCommand,
        password_hash: str,
        *,
        invitation_digest: bytes | None,
        verification: PurposeTokenDelivery | None,
        now: datetime,
        event: SecurityEvent,
    ) -> RegistrationResult[object]:
        """Create one account and optional verification issue atomically."""
        del event
        await self._observe("accounts.register", {"normalized_identifier": command.normalized_identifier})
        async with self._lock:
            if any(
                account.normalized_identifier == command.normalized_identifier for account in self._accounts.values()
            ):
                return RegistrationResult(RegistrationStatus.DUPLICATE)
            invitation = (
                next(
                    (
                        issue
                        for issue in self._purpose_tokens.values()
                        if issue.purpose is TokenPurpose.INVITATION and compare_digest(issue.digest, invitation_digest)
                    ),
                    None,
                )
                if invitation_digest is not None
                else None
            )
            if invitation_digest is not None and (invitation is None or invitation.expires_at <= now):
                return RegistrationResult(RegistrationStatus.INVALID_INVITATION)
            if verification is not None and self._purpose_token_id_exists_locked(verification.issue.token_id):
                message = "In-memory purpose-token identifier collision"
                raise ValueError(message)
            account_id = self._identifiers("account")
            if account_id in self._accounts:
                message = "In-memory account identifier collision"
                raise ValueError(message)
            account = LocalAccount(
                account_id=account_id,
                normalized_identifier=command.normalized_identifier,
                display_name=command.display_name,
                active=True,
                verified=verification is None,
                security_epoch=1,
                user=object(),
            )
            if verification is not None:
                issue, _notification = verification.bind(account_id)
                self._purpose_tokens[issue.token_id] = issue
            self._accounts[account_id] = account
            self._password_hashes[account_id] = password_hash
            if invitation is not None:
                del self._purpose_tokens[invitation.token_id]
                self._used_purpose_tokens.add(invitation.token_id)
            return RegistrationResult(RegistrationStatus.CREATED, account)

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        """Store one purpose-token issue without retaining its delivery secret."""
        del notification, event
        await self._observe("accounts.issue", {"account_id": issue.account_id, "token_id": issue.token_id})
        async with self._lock:
            if self._purpose_token_id_exists_locked(issue.token_id):
                message = "In-memory purpose-token identifier collision"
                raise ValueError(message)
            self._purpose_tokens[issue.token_id] = issue

    async def issue_absent(self) -> None:
        """Perform the deterministic no-op used for absent accounts."""
        await self._observe("accounts.issue_absent", {})
        async with self._lock:
            return

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: datetime, event: SecurityEvent
    ) -> ConsumeResult:
        """Consume one verification token and mark its account verified."""
        del event
        await self._observe("accounts.consume_and_verify", {"token_id": token_id})
        async with self._lock:
            issue = self._purpose_tokens.get(token_id)
            if issue is None or issue.purpose is not TokenPurpose.VERIFICATION:
                status = ConsumeStatus.USED if token_id in self._used_purpose_tokens else ConsumeStatus.INVALID
                return ConsumeResult(status)
            if not compare_digest(issue.digest, digest):
                self._record_failed_purpose_proof_locked(issue)
                return ConsumeResult(ConsumeStatus.INVALID)
            if issue.expires_at <= now:
                return ConsumeResult(ConsumeStatus.EXPIRED)
            account = self._accounts.get(issue.account_id)
            if account is None:
                return ConsumeResult(ConsumeStatus.INVALID)
            del self._purpose_tokens[token_id]
            self._purpose_attempts.pop(token_id, None)
            self._used_purpose_tokens.add(token_id)
            self._accounts[account.account_id] = replace(account, verified=True)
            return ConsumeResult(ConsumeStatus.CONSUMED, account.account_id, account.security_epoch)

    async def consume_and_reset(
        self, token_id: str, digest: bytes, new_password_hash: str, *, now: datetime, event: SecurityEvent
    ) -> PasswordResetResult:
        """Consume one recovery token and reset its account password atomically."""
        del event
        await self._observe("accounts.consume_and_reset", {"token_id": token_id})
        async with self._lock:
            issue = self._purpose_tokens.get(token_id)
            if issue is None or issue.purpose is not TokenPurpose.RECOVERY:
                status = (
                    PasswordResetStatus.USED if token_id in self._used_purpose_tokens else PasswordResetStatus.INVALID
                )
                return PasswordResetResult(status)
            if not compare_digest(issue.digest, digest):
                self._record_failed_purpose_proof_locked(issue)
                return PasswordResetResult(PasswordResetStatus.INVALID)
            if issue.expires_at <= now:
                return PasswordResetResult(PasswordResetStatus.EXPIRED)
            account = self._accounts.get(issue.account_id)
            if account is None or issue.issued_security_epoch != account.security_epoch:
                return PasswordResetResult(PasswordResetStatus.CONFLICT)
            next_epoch = account.security_epoch + 1
            del self._purpose_tokens[token_id]
            self._purpose_attempts.pop(token_id, None)
            self._used_purpose_tokens.add(token_id)
            self._password_hashes[account.account_id] = new_password_hash
            self._accounts[account.account_id] = replace(account, security_epoch=next_epoch)
            return PasswordResetResult(PasswordResetStatus.RESET, account.account_id, next_epoch)

    async def create(self, command: CreateSessionCommand, *, event: SecurityEvent) -> SessionRecord:
        """Create one native session record."""
        del event
        await self._observe(
            "accounts.create_session", {"account_id": command.account_id, "session_id": command.session_id}
        )
        async with self._lock:
            if command.session_id in self._sessions:
                message = "In-memory session identifier collision"
                raise ValueError(message)
            record = SessionRecord(
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
            self._sessions[record.session_id] = record
            return record

    async def get(self, session_id: str) -> SessionRecord | None:
        """Return one currently stored native session."""
        async with self._lock:
            record = self._sessions.get(session_id)
            return record if record is not None and record.expires_at > self._clock() else None

    async def list_for_account(self, account_id: str) -> tuple[SessionRecord, ...]:
        """Return the account's current native-session records."""
        async with self._lock:
            current = self._clock()
            return tuple(
                record
                for record in self._sessions.values()
                if record.account_id == account_id and record.expires_at > current
            )

    async def touch(self, session_id: str, *, now: datetime) -> SessionRecord | None:
        """Advance one session's last-seen time."""
        await self._observe("accounts.touch_session", {"session_id": session_id})
        async with self._lock:
            record = self._sessions.get(session_id)
            if record is None or record.expires_at <= now or record.expires_at <= self._clock():
                return None
            updated = replace(record, last_seen_at=now)
            self._sessions[session_id] = updated
            return updated

    async def revoke_session_for_account(self, account_id: str, session_id: str, *, event: SecurityEvent) -> bool:
        """Revoke one account-owned native session."""
        del event
        await self._observe("accounts.revoke_session", {"account_id": account_id, "session_id": session_id})
        async with self._lock:
            record = self._sessions.get(session_id)
            if record is None or record.account_id != account_id:
                return False
            del self._sessions[session_id]
            return True

    async def revoke_sessions_for_account(self, account_id: str, *, event: SecurityEvent) -> int:
        """Revoke every native session owned by one account."""
        del event
        await self._observe("accounts.revoke_sessions", {"account_id": account_id})
        async with self._lock:
            session_ids = tuple(key for key, record in self._sessions.items() if record.account_id == account_id)
            for session_id in session_ids:
                del self._sessions[session_id]
            return len(session_ids)

    async def revoke_other_sessions(self, account_id: str, session_id: str, *, event: SecurityEvent) -> int:
        """Revoke all native sessions except the named current one."""
        del event
        await self._observe("accounts.revoke_other_sessions", {"account_id": account_id, "session_id": session_id})
        async with self._lock:
            session_ids = tuple(
                key for key, record in self._sessions.items() if record.account_id == account_id and key != session_id
            )
            for other_session_id in session_ids:
                del self._sessions[other_session_id]
            return len(session_ids)

    async def rebind(
        self, prior_session_id: str, command: CreateSessionCommand, *, event: SecurityEvent
    ) -> SessionRecord | None:
        """Replace one existing session with a successor atomically."""
        del event
        await self._observe(
            "accounts.rebind_session", {"prior_session_id": prior_session_id, "session_id": command.session_id}
        )
        async with self._lock:
            if prior_session_id not in self._sessions:
                return None
            if command.session_id in self._sessions:
                message = "In-memory session identifier collision"
                raise ValueError(message)
            del self._sessions[prior_session_id]
            record = SessionRecord(
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
            self._sessions[record.session_id] = record
            return record

    async def create_family(self, command: CreateRefreshFamilyCommand, *, event: SecurityEvent) -> bool:
        """Create a refresh family when its account epoch remains current."""
        del event
        await self._observe(
            "accounts.create_refresh_family",
            {"account_id": command.account_id, "family_id": command.family_id, "token_id": command.token_id},
        )
        async with self._lock:
            account = self._accounts.get(command.account_id)
            if (
                account is None
                or account.security_epoch != command.security_epoch
                or command.token_id in self._refresh_tokens
                or any(state.family_id == command.family_id for state in self._refresh_tokens.values())
            ):
                return False
            self._refresh_tokens[command.token_id] = _InMemoryRefreshState(
                token_id=command.token_id,
                token_digest=command.token_digest,
                account_id=command.account_id,
                family_id=command.family_id,
                security_epoch=command.security_epoch,
                token_expires_at=command.token_expires_at,
                family_expires_at=command.family_expires_at,
                scopes=command.scopes,
            )
            return True

    async def prepare_rotation(  # noqa: PLR0911 - explicit refresh-state outcomes are security critical
        self, proof: RefreshTokenProof, idempotency_digest: bytes | None, *, now: datetime, event: SecurityEvent
    ) -> RefreshFamilyContext | RefreshReceiptReplay | PrepareRefreshResult:
        """Resolve one exact refresh token for a later atomic rotation."""
        del event
        await self._observe("accounts.prepare_refresh_rotation", {"token_id": proof.token_id})
        async with self._lock:
            state = self._refresh_tokens.get(proof.token_id)
            if state is None or state.token_digest != proof.digest:
                return PrepareRefreshResult(RefreshRotationStatus.INVALID)
            if state.revoked:
                return PrepareRefreshResult(RefreshRotationStatus.REVOKED, family_revoked=True)
            if state.consumed:
                if state.idempotency_digest == idempotency_digest and state.sealed_receipt is not None:
                    return RefreshReceiptReplay(self._refresh_context(state), state.sealed_receipt)
                self._revoke_family_locked(state.family_id)
                return PrepareRefreshResult(RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True)
            if state.token_expires_at <= now or state.family_expires_at <= now:
                return PrepareRefreshResult(RefreshRotationStatus.EXPIRED)
            account = self._accounts.get(state.account_id)
            if account is None or account.security_epoch != state.security_epoch:
                return PrepareRefreshResult(RefreshRotationStatus.EPOCH_MISMATCH)
            return self._refresh_context(state)

    async def rotate(
        self, command: RotateRefreshCommand, *, now: datetime, event: SecurityEvent
    ) -> RotateRefreshResult:
        """Atomically rotate one prepared refresh token."""
        del event
        await self._observe("accounts.rotate_refresh", {"family_id": command.family_id, "token_id": command.token_id})
        async with self._lock:
            state = self._refresh_tokens.get(command.token_id)
            account = self._accounts.get(command.account_id)
            if (
                state is None
                or state.consumed
                or state.revoked
                or account is None
                or state.token_digest != command.token_digest
                or state.account_id != command.account_id
                or state.family_id != command.family_id
                or state.security_epoch != command.security_epoch
                or account.security_epoch != command.security_epoch
                or command.successor_id in self._refresh_tokens
            ):
                return RotateRefreshResult(RefreshRotationStatus.INVALID)
            if state.token_expires_at <= now or state.family_expires_at <= now:
                return RotateRefreshResult(RefreshRotationStatus.EXPIRED)
            state.consumed = True
            state.idempotency_digest = command.idempotency_digest
            state.sealed_receipt = command.sealed_receipt
            self._refresh_tokens[command.successor_id] = _InMemoryRefreshState(
                token_id=command.successor_id,
                token_digest=command.successor_digest,
                account_id=command.account_id,
                family_id=command.family_id,
                security_epoch=command.security_epoch,
                token_expires_at=command.successor_expires_at,
                family_expires_at=command.family_expires_at,
                scopes=command.scopes,
            )
            return RotateRefreshResult(RefreshRotationStatus.ROTATED, command.sealed_receipt)

    async def revoke_family(self, family_id: str, *, event: SecurityEvent) -> bool:
        """Revoke every token in one refresh family."""
        del event
        await self._observe("accounts.revoke_refresh_family", {"family_id": family_id})
        async with self._lock:
            return self._revoke_family_locked(family_id)

    async def revoke_token(self, token_id: str, token_digest: bytes, *, event: SecurityEvent) -> bool:
        """Revoke the family owning one exact presented token."""
        del event
        await self._observe("accounts.revoke_refresh_token", {"token_id": token_id})
        async with self._lock:
            state = self._refresh_tokens.get(token_id)
            return (
                state is not None and state.token_digest == token_digest and self._revoke_family_locked(state.family_id)
            )

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, *, event: SecurityEvent
    ) -> bool:
        """Revoke one exact refresh token only for its owning account."""
        del event
        await self._observe("accounts.revoke_refresh_token", {"account_id": account_id, "token_id": token_id})
        async with self._lock:
            state = self._refresh_tokens.get(token_id)
            return (
                state is not None
                and state.account_id == account_id
                and state.token_digest == token_digest
                and self._revoke_family_locked(state.family_id)
            )

    async def revoke_for_account(self, account_id: str, *, event: SecurityEvent) -> int:
        """Revoke every refresh family owned by one account."""
        del event
        await self._observe("accounts.revoke_refresh_for_account", {"account_id": account_id})
        async with self._lock:
            family_ids = {state.family_id for state in self._refresh_tokens.values() if state.account_id == account_id}
            return sum(1 for family_id in family_ids if self._revoke_family_locked(family_id))

    def _refresh_context(self, state: _InMemoryRefreshState) -> RefreshFamilyContext:
        return RefreshFamilyContext(
            account_id=state.account_id,
            family_id=state.family_id,
            security_epoch=state.security_epoch,
            token_expires_at=state.token_expires_at,
            family_expires_at=state.family_expires_at,
            scopes=state.scopes,
        )

    def _record_failed_purpose_proof_locked(self, issue: TokenIssue) -> None:
        attempts = self._purpose_attempts.get(issue.token_id, 0) + 1
        if attempts < issue.maximum_attempts:
            self._purpose_attempts[issue.token_id] = attempts
            return
        del self._purpose_tokens[issue.token_id]
        self._purpose_attempts.pop(issue.token_id, None)
        self._used_purpose_tokens.add(issue.token_id)

    def _purpose_token_id_exists_locked(self, token_id: str) -> bool:
        return token_id in self._purpose_tokens or token_id in self._used_purpose_tokens

    def _revoke_family_locked(self, family_id: str) -> bool:
        states = tuple(state for state in self._refresh_tokens.values() if state.family_id == family_id)
        if not states or all(state.revoked for state in states):
            return False
        for state in states:
            state.revoked = True
        return True


class InMemorySecurityBackend:
    """Deterministic aggregate backend intended only for tests and examples."""

    _clock: Callable[[], datetime]
    _entropy: Callable[[int], bytes] | None
    _identifiers: Callable[[str, int], str]

    __slots__ = (
        "_barriers",
        "_call_counts",
        "_clock",
        "_entropy",
        "_entropy_offset",
        "_event_sequence",
        "_events",
        "_failpoints",
        "_identifier_sequence",
        "_identifiers",
        "accounts",
        "api_keys",
        "challenges",
        "mfa",
        "mfa_login",
        "oauth_accounts",
        "oauth_tokens",
        "oauth_transactions",
        "passkeys",
        "password_hash",
        "step_up",
        "websocket_connect_tokens",
    )

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        identifiers: Callable[[str, int], str] | None = None,
        entropy: Callable[[int], bytes] | None = None,
        password_hash: str = _DEFAULT_CREDENTIAL_HASH,
        protector: OAuthTransactionProtector | None = None,
    ) -> None:
        """Create isolated deterministic stores and value sources.

        Args:
            clock: Injected timezone-aware clock.
            identifiers: Deterministic namespace and sequence formatter.
            entropy: Exact-length byte factory.
            password_hash: Precomputed test hash; plaintext passwords are never accepted.
            protector: Test protector for recoverable OAuth transaction secrets.

        Raises:
            ValueError: If a deterministic source is malformed.
        """
        clock_value = cast("object", clock)
        identifiers_value = cast("object", identifiers)
        entropy_value = cast("object", entropy)
        password_hash_value = cast("object", password_hash)
        if clock_value is not None and not callable(clock_value):
            message = "In-memory backend clock must be callable"
            raise TypeError(message)
        if identifiers_value is not None and not callable(identifiers_value):
            message = "In-memory backend identifier factory must be callable"
            raise TypeError(message)
        if entropy_value is not None and not callable(entropy_value):
            message = "In-memory backend entropy factory must be callable"
            raise TypeError(message)
        selected_clock = (lambda: _DEFAULT_NOW) if clock is None else clock
        selected_identifiers = _default_identifier if identifiers is None else identifiers
        if not isinstance(password_hash_value, str) or not password_hash_value.strip():
            message = "In-memory backend password hash must be non-empty"
            raise ValueError(message)
        self._clock = selected_clock
        self._identifiers = selected_identifiers
        self._entropy = entropy
        self._entropy_offset = 0
        self._identifier_sequence = 0
        self._event_sequence = 0
        self._call_counts: dict[str, int] = {}
        self._events: list[BackendEvent] = []
        self._barriers: dict[str, BackendBarrier] = {}
        self._failpoints: dict[str, Exception] = {}
        self.password_hash = password_hash
        selected_protector = _DeterministicProtector() if protector is None else protector
        self.mfa = InMemoryMFAStore()
        self.mfa_login = InMemoryMFALoginChallengeStore()
        self.challenges = InMemoryWebAuthnChallengeStore()
        self.passkeys = InMemoryPasskeyStore()
        self.step_up = InMemoryStepUpStore()
        self.oauth_accounts = MemoryOAuthAccountStore()
        self.oauth_transactions = MemoryOAuthTransactionStore(protector=selected_protector)
        self.oauth_tokens = MemoryTokenVault(provider="test", client_id="test-client", protector=selected_protector)
        self.accounts = InMemoryLocalAccountStore(
            self._observe, clock=self.clock, identifiers=self.next_identifier, entropy=self.entropy
        )
        self.api_keys = InMemoryAPIKeyStore(self._observe)
        self.websocket_connect_tokens = InMemoryWebSocketConnectTokenStore()

    @property
    def call_counts(self) -> Mapping[str, int]:
        """Return an immutable copy of operation counts."""
        return MappingProxyType(dict(self._call_counts))

    @property
    def events(self) -> tuple[BackendEvent, ...]:
        """Return the ordered secret-free diagnostic snapshot."""
        return tuple(self._events)

    def clock(self) -> datetime:
        """Return one timezone-aware UTC instant."""
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            message = "In-memory backend clock returned a naive datetime"
            raise ValueError(message)
        return value.astimezone(timezone.utc)

    def next_identifier(self, namespace: str) -> str:
        """Return the next deterministic identifier in one aggregate sequence."""
        self._identifier_sequence += 1
        value = self._identifiers(namespace, self._identifier_sequence)
        value_object = cast("object", value)
        if not isinstance(value_object, str) or not value_object.strip():
            message = "In-memory backend identifier factory returned an invalid value"
            raise ValueError(message)
        return value_object

    def entropy(self, length: int) -> bytes:
        """Return exact-length deterministic bytes."""
        if length.__class__ is not int or length < 1:
            message = "In-memory backend entropy length must be positive"
            raise ValueError(message)
        if self._entropy is None:
            start = self._entropy_offset
            value = bytes((start + offset) % 256 for offset in range(length))
            self._entropy_offset += length
        else:
            value = self._entropy(length)
        if value.__class__ is not bytes or len(value) != length:
            message = "In-memory backend entropy factory returned an invalid value"
            raise ValueError(message)
        return value

    def install_barrier(self, operation: str) -> BackendBarrier:
        """Install and return a deterministic operation barrier."""
        barrier = BackendBarrier()
        self._barriers[operation] = barrier
        return barrier

    def set_failpoint(self, operation: str, error: Exception) -> None:
        """Raise one injected error whenever the named operation is reached."""
        error_value = cast("object", error)
        if not isinstance(error_value, Exception):
            message = "In-memory backend failpoint requires an exception"
            raise TypeError(message)
        self._failpoints[operation] = error_value

    def clear_controls(self) -> None:
        """Remove every barrier and failpoint without changing stored state."""
        self._barriers.clear()
        self._failpoints.clear()

    async def _observe(self, operation: str, details: Mapping[str, str]) -> None:
        self._event_sequence += 1
        self._call_counts[operation] = self._call_counts.get(operation, 0) + 1
        self._events.append(BackendEvent(self._event_sequence, operation, details))
        barrier = self._barriers.get(operation)
        if barrier is not None:
            barrier.reached.set()
            await barrier.release.wait()
        error = self._failpoints.get(operation)
        if error is not None:
            raise error


@dataclass(frozen=True, slots=True)
class StoreConformanceFactories:
    """Isolated zero-argument factories for explicitly enabled capabilities."""

    api_key_store: Callable[[], APIKeyStore] | None = None


async def assert_api_key_store_conformance(factory: Callable[[], APIKeyStore]) -> None:
    """Assert API-key isolation and atomic rotation behavior.

    Args:
        factory: Isolated zero-argument store factory.

    Returns:
        None when every invariant holds.

    Raises:
        AssertionError: If ``APIKeyStore`` isolation, lookup, or atomic rotation is violated.
    """
    store = factory()
    isolated = factory()
    if store is isolated:
        message = "APIKeyStore factory invariant: each call must return isolated state"
        raise AssertionError(message)
    current = _conformance_api_key_record("a2tra2tra2tra2tr")
    replacements = (_conformance_api_key_record("ZmZmZmZmZmZmZmZm"), _conformance_api_key_record("Z2dnZ2dnZ2dnZ2dn"))
    await store.create(current)
    if await store.get(current.key_id) != current or await isolated.get(current.key_id) is not None:
        message = "APIKeyStore.create/get isolation invariant: created records must be exact and factory-local"
        raise AssertionError(message)

    async def rotate(replacement: APIKeyRecord) -> bool:
        return await _won_unless_raised(
            lambda: store.rotate(
                current_key_id=current.key_id,
                replacement=replacement,
                overlap_until=_DEFAULT_NOW + timedelta(seconds=30),
                now=_DEFAULT_NOW,
            )
        )

    contenders = tuple(lambda replacement=replacement: rotate(replacement) for replacement in replacements)
    winners = await _single_winner(contenders)
    if winners != 1:
        message = (
            "APIKeyStore.rotate atomicity invariant: two contenders must produce one atomic winner "
            f"(observed {winners})"
        )
        raise AssertionError(message)
    persisted_records: list[APIKeyRecord | None] = []
    for replacement in replacements:
        persisted_records.append(  # noqa: PERF401 - sequential awaited protocol calls
            await store.get(replacement.key_id)
        )
    persisted = tuple(persisted_records)
    if sum(record is not None for record in persisted) != 1:
        message = "APIKeyStore.rotate partial-write invariant: exactly one successor must be persisted"
        raise AssertionError(message)
    current_after = await store.get(current.key_id)
    if current_after is None or current_after.revoked_at != _DEFAULT_NOW:
        message = "APIKeyStore.rotate current-state invariant: the winning transition must revoke the current key"
        raise AssertionError(message)


class _ConformanceLocalAccountStore(LocalAccountCapabilities[object], RegistrationStore[object], Protocol):
    """Combined local-account protocol exercised by the conformance scenarios."""


async def assert_local_account_store_conformance(factory: Callable[[], _ConformanceLocalAccountStore]) -> None:
    """Assert local-account isolation and atomic security transitions.

    Args:
        factory: Isolated zero-argument local-account store factory.

    Returns:
        None when every local-account capability invariant holds.

    Raises:
        AssertionError: If a local-account capability violates an atomicity, replay, or final-method invariant.
    """
    store = factory()
    await _assert_local_account_factory_isolation(factory, store)
    account = await _conformance_register_account(store, "conformance@example.com")
    verification, verification_account = await _assert_registration_scenarios(store)
    await _assert_password_cas(store, account)
    await _assert_password_epoch_bump(store, account)
    await _assert_verification_scenarios(store, verification, verification_account)
    await _assert_recovery_epoch(store, account)
    await _assert_recovery_expiry(store, account)
    await _assert_recovery_attempt_exhaustion(store, account)
    await _assert_final_login_method(store, account)


async def _assert_local_account_factory_isolation(
    factory: Callable[[], _ConformanceLocalAccountStore], store: _ConformanceLocalAccountStore
) -> None:
    isolated = factory()
    if store is isolated:
        message = "LocalAccountCapabilities factory invariant: each call must return isolated state"
        raise AssertionError(message)
    account = await _conformance_register_account(store, "factory-isolation@example.com")
    if await isolated.get_by_id(account.account_id) is not None:
        message = "LocalAccountCapabilities factory isolation invariant: state must not cross factory calls"
        raise AssertionError(message)


async def _assert_registration_scenarios(
    store: _ConformanceLocalAccountStore,
) -> tuple[PurposeTokenDelivery, LocalAccount[object]]:
    command = _conformance_registration_command("atomic-registration@example.com")
    outcomes: list[RegistrationResult[object]] = []

    async def register() -> None:
        outcomes.append(
            await store.register(
                command,
                "conformance-password-hash",
                invitation_digest=None,
                verification=None,
                now=_DEFAULT_NOW,
                event=_conformance_event("register"),
            )
        )

    async with create_task_group() as task_group:
        task_group.start_soon(register)
        task_group.start_soon(register)
    statuses = tuple(result.status for result in outcomes)
    if statuses.count(RegistrationStatus.CREATED) != 1 or statuses.count(RegistrationStatus.DUPLICATE) != 1:
        message = (
            "RegistrationStore.register atomicity invariant: two contenders must return exactly CREATED and DUPLICATE"
        )
        raise AssertionError(message)

    invitation_delivery = _conformance_token_delivery(TokenPurpose.INVITATION, marker=1)
    invitation, notification = invitation_delivery.bind("conformance-invitation")
    await store.issue(invitation, notification, event=_conformance_event("issue-invitation"))
    duplicate_verification = _conformance_verification_delivery(_DEFAULT_NOW, marker=2)
    duplicate = await store.register(
        _conformance_registration_command("conformance@example.com"),
        "conformance-password-hash",
        invitation_digest=invitation.digest,
        verification=duplicate_verification,
        now=_DEFAULT_NOW,
        event=_conformance_event("duplicate-registration"),
    )
    duplicate_probe = await store.consume_and_verify(
        duplicate_verification.issue.token_id,
        duplicate_verification.issue.digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("probe-duplicate-verification"),
    )
    verification = _conformance_verification_delivery(_DEFAULT_NOW, marker=3)
    try:
        after_duplicate = await store.register(
            _conformance_registration_command("partial-write@example.com"),
            "conformance-password-hash",
            invitation_digest=invitation.digest,
            verification=verification,
            now=_DEFAULT_NOW,
            event=_conformance_event("partial-write-registration"),
        )
    except Exception as exc:
        message = (
            "RegistrationStore.register partial-write invariant: duplicate outcomes must not consume invitation "
            "or issue verification"
        )
        raise AssertionError(message) from exc
    if (
        duplicate.status is not RegistrationStatus.DUPLICATE
        or duplicate_probe.status is not ConsumeStatus.INVALID
        or after_duplicate.status is not RegistrationStatus.CREATED
        or after_duplicate.account is None
    ):
        message = (
            "RegistrationStore.register partial-write invariant: duplicate outcomes must not consume invitation "
            "or issue verification"
        )
        raise AssertionError(message)
    return verification, after_duplicate.account


async def _assert_password_cas(store: _ConformanceLocalAccountStore, account: LocalAccount[object]) -> None:
    account_before = await store.get_by_id(account.account_id)
    password_state = await store.get_password_state(account.account_id)
    if account_before is None or password_state is None:  # pragma: no cover - account was just registered
        message = (
            "PasswordCredentialStore.get_password_state invariant: registered accounts must retain their password state"
        )
        raise AssertionError(message)
    replacement_hashes = ("conformance-password-a", "conformance-password-b")

    async def replace_password(replacement_hash: str) -> bool:
        return await store.compare_and_replace_password(
            account.account_id,
            password_state.password_hash,
            replacement_hash,
            event=_conformance_event("compare-and-replace-password"),
        )

    outcomes: list[bool] = []

    async def record(replacement_hash: str) -> None:
        outcomes.append(await replace_password(replacement_hash))

    async with create_task_group() as task_group:
        for replacement_hash in replacement_hashes:
            task_group.start_soon(record, replacement_hash)
    if outcomes.count(True) != 1 or outcomes.count(False) != 1:
        message = (
            "PasswordCredentialStore.compare_and_replace_password atomicity invariant: two contenders must "
            "return exactly True and False"
        )
        raise AssertionError(message)
    password_after = await store.get_password_state(account.account_id)
    account_after = await store.get_by_id(account.account_id)
    if password_after is None or password_after.password_hash not in replacement_hashes:
        message = (
            "PasswordCredentialStore.compare_and_replace_password state invariant: stored password must be "
            "exactly one winner"
        )
        raise AssertionError(message)
    before_non_password = (password_state.security_epoch, password_state.active, password_state.verified)
    after_non_password = (password_after.security_epoch, password_after.active, password_after.verified)
    if account_after != account_before or after_non_password != before_non_password:
        message = (
            "PasswordCredentialStore.compare_and_replace_password state invariant: non-password account state "
            "must remain unchanged"
        )
        raise AssertionError(message)


async def _assert_password_epoch_bump(store: _ConformanceLocalAccountStore, account: LocalAccount[object]) -> None:
    password_state = await store.get_password_state(account.account_id)
    if password_state is None:  # pragma: no cover - preceding CAS guarantees it
        message = "PasswordCredentialStore.get_password_state invariant: password state must remain readable"
        raise AssertionError(message)
    replacement_hashes = ("conformance-epoch-a", "conformance-epoch-b")

    outcomes: list[PasswordChangeResult] = []

    async def bump_epoch(replacement_hash: str) -> None:
        outcomes.append(
            await store.replace_password_and_bump_epoch(
                account.account_id,
                replacement_hash,
                expected_epoch=password_state.security_epoch,
                event=_conformance_event("replace-password-and-bump-epoch"),
            )
        )

    async with create_task_group() as task_group:
        for replacement_hash in replacement_hashes:
            task_group.start_soon(bump_epoch, replacement_hash)
    statuses = tuple(result.status for result in outcomes)
    if statuses.count(PasswordChangeStatus.CHANGED) != 1 or statuses.count(PasswordChangeStatus.CONFLICT) != 1:
        message = (
            "PasswordCredentialStore.replace_password_and_bump_epoch epoch invariant: two contenders must "
            "return exactly CHANGED and CONFLICT"
        )
        raise AssertionError(message)
    current_epoch = await store.current_epoch(account.account_id)
    persisted = await store.get_password_state(account.account_id)
    if current_epoch != password_state.security_epoch + 1:
        message = (
            "PasswordCredentialStore.replace_password_and_bump_epoch epoch invariant: current epoch must "
            "advance by exactly one"
        )
        raise AssertionError(message)
    if (
        persisted is None
        or persisted.password_hash not in replacement_hashes
        or persisted.security_epoch != current_epoch
    ):
        message = (
            "PasswordCredentialStore.replace_password_and_bump_epoch state invariant: persisted password and "
            "password-state epoch must match the winning transition"
        )
        raise AssertionError(message)


async def _assert_verification_scenarios(
    store: _ConformanceLocalAccountStore, verification: PurposeTokenDelivery, account: LocalAccount[object]
) -> None:
    consumed = await store.consume_and_verify(
        verification.issue.token_id,
        verification.issue.digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("consume-and-verify"),
    )
    replay = await store.consume_and_verify(
        verification.issue.token_id,
        verification.issue.digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("consume-and-verify-replay"),
    )
    stored_account = await store.get_by_id(account.account_id)
    if (
        consumed.status is not ConsumeStatus.CONSUMED
        or consumed.account_id != account.account_id
        or consumed.security_epoch != account.security_epoch
        or stored_account is None
        or not stored_account.verified
        or stored_account.security_epoch != account.security_epoch
        or replay.status is ConsumeStatus.CONSUMED
    ):
        message = (
            "VerificationTokenStore.consume_and_verify replay invariant: a verification token must be consumed once"
        )
        raise AssertionError(message)
    await _assert_verification_expiry(store)
    await _assert_verification_attempt_exhaustion(store)


async def _assert_verification_expiry(store: _ConformanceLocalAccountStore) -> None:
    delivery = _conformance_verification_delivery(_DEFAULT_NOW, marker=4)
    account = await _conformance_register_account(store, "expired-verification@example.com", verification=delivery)
    result = await store.consume_and_verify(
        delivery.issue.token_id,
        delivery.issue.digest,
        now=delivery.issue.expires_at,
        event=_conformance_event("consume-expired-verification"),
    )
    stored = await store.get_by_id(account.account_id)
    if result.status is not ConsumeStatus.EXPIRED or stored is None or stored.verified:
        message = "VerificationTokenStore.consume_and_verify expiry invariant: expired tokens must not verify accounts"
        raise AssertionError(message)


async def _assert_verification_attempt_exhaustion(store: _ConformanceLocalAccountStore) -> None:
    delivery = _conformance_verification_delivery(_DEFAULT_NOW, marker=5, maximum_attempts=2)
    account = await _conformance_register_account(store, "burned-verification@example.com", verification=delivery)
    invalid_digest = _different_digest(delivery.issue.digest)
    invalid_results = tuple([
        await store.consume_and_verify(
            delivery.issue.token_id,
            invalid_digest,
            now=_DEFAULT_NOW,
            event=_conformance_event("burn-verification-attempt"),
        )
        for _attempt in range(delivery.issue.maximum_attempts)
    ])
    valid_after_burn = await store.consume_and_verify(
        delivery.issue.token_id,
        delivery.issue.digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("verification-after-burn"),
    )
    stored = await store.get_by_id(account.account_id)
    if (
        any(result.status is not ConsumeStatus.INVALID for result in invalid_results)
        or valid_after_burn.status is not ConsumeStatus.USED
        or stored is None
        or stored.verified
    ):
        message = (
            "VerificationTokenStore.consume_and_verify attempt invariant: maximum failures must burn the token "
            "and reject its valid proof"
        )
        raise AssertionError(message)


async def _assert_recovery_epoch(store: _ConformanceLocalAccountStore, account: LocalAccount[object]) -> None:
    delivery = _conformance_token_delivery(TokenPurpose.RECOVERY, marker=6)
    epoch = await store.current_epoch(account.account_id)
    if epoch is None:  # pragma: no cover - account was just registered
        message = "SecurityEpochStore.current_epoch invariant: a registered account must have an epoch"
        raise AssertionError(message)
    issue, notification = delivery.bind(account.account_id, security_epoch=epoch)
    await store.issue(issue, notification, event=_conformance_event("issue-recovery"))
    changed = await store.replace_password_and_bump_epoch(
        account.account_id,
        "conformance-password-recovery-change",
        expected_epoch=epoch,
        event=_conformance_event("change-before-recovery"),
    )
    changed_state = await store.get_password_state(account.account_id)
    reset = await store.consume_and_reset(
        issue.token_id,
        issue.digest,
        "conformance-password-reset",
        now=_DEFAULT_NOW,
        event=_conformance_event("consume-and-reset"),
    )
    state_after = await store.get_password_state(account.account_id)
    replay = await store.consume_and_reset(
        issue.token_id,
        issue.digest,
        "conformance-password-reset-replay",
        now=_DEFAULT_NOW,
        event=_conformance_event("consume-and-reset-replay"),
    )
    if (
        changed.status is not PasswordChangeStatus.CHANGED
        or changed_state is None
        or reset.status is not PasswordResetStatus.CONFLICT
        or replay.status is PasswordResetStatus.RESET
        or state_after != changed_state
    ):
        message = (
            "RecoveryTokenStore.consume_and_reset epoch invariant: a token issued before an epoch bump must be rejected"
        )
        raise AssertionError(message)


async def _assert_recovery_expiry(store: _ConformanceLocalAccountStore, account: LocalAccount[object]) -> None:
    delivery = _conformance_token_delivery(TokenPurpose.RECOVERY, marker=7)
    epoch = await store.current_epoch(account.account_id)
    state_before = await store.get_password_state(account.account_id)
    if epoch is None or state_before is None:  # pragma: no cover - account exists with a password
        message = "RecoveryTokenStore.consume_and_reset setup invariant: registered accounts require password state"
        raise AssertionError(message)
    issue, notification = delivery.bind(account.account_id, security_epoch=epoch)
    await store.issue(issue, notification, event=_conformance_event("issue-expired-recovery"))
    result = await store.consume_and_reset(
        issue.token_id,
        issue.digest,
        "expired-recovery-password",
        now=issue.expires_at,
        event=_conformance_event("consume-expired-recovery"),
    )
    if (
        result.status is not PasswordResetStatus.EXPIRED
        or await store.get_password_state(account.account_id) != state_before
    ):
        message = "RecoveryTokenStore.consume_and_reset expiry invariant: expired tokens must not change password state"
        raise AssertionError(message)


async def _assert_recovery_attempt_exhaustion(
    store: _ConformanceLocalAccountStore, account: LocalAccount[object]
) -> None:
    delivery = _conformance_token_delivery(TokenPurpose.RECOVERY, marker=8, maximum_attempts=2)
    epoch = await store.current_epoch(account.account_id)
    state_before = await store.get_password_state(account.account_id)
    if epoch is None or state_before is None:  # pragma: no cover - account exists with a password
        message = "RecoveryTokenStore.consume_and_reset setup invariant: registered accounts require password state"
        raise AssertionError(message)
    issue, notification = delivery.bind(account.account_id, security_epoch=epoch)
    await store.issue(issue, notification, event=_conformance_event("issue-burned-recovery"))
    invalid_digest = _different_digest(issue.digest)
    invalid_results: list[PasswordResetResult] = []
    for _attempt in range(issue.maximum_attempts):
        invalid_results.append(  # noqa: PERF401 - failed attempts must be sequential against one token
            await store.consume_and_reset(
                issue.token_id,
                invalid_digest,
                "invalid-recovery-password",
                now=_DEFAULT_NOW,
                event=_conformance_event("burn-recovery-attempt"),
            )
        )
    valid_after_burn = await store.consume_and_reset(
        issue.token_id,
        issue.digest,
        "valid-after-burn-password",
        now=_DEFAULT_NOW,
        event=_conformance_event("recovery-after-burn"),
    )
    if (
        any(result.status is not PasswordResetStatus.INVALID for result in invalid_results)
        or valid_after_burn.status is not PasswordResetStatus.USED
        or await store.get_password_state(account.account_id) != state_before
    ):
        message = (
            "RecoveryTokenStore.consume_and_reset attempt invariant: maximum failures must burn the token and "
            "reject its valid proof"
        )
        raise AssertionError(message)


async def _assert_final_login_method(store: _ConformanceLocalAccountStore, account: LocalAccount[object]) -> None:
    other_account = await _conformance_register_account(store, "login-method-owner@example.com")
    method = LoginMethod("conformance-password", "password", _DEFAULT_NOW)
    await store.register_login_method(account.account_id, method, event=_conformance_event("register-login-method"))
    cross_account = await store.revoke_login_method(
        other_account.account_id,
        method.method_id,
        require_remaining=True,
        event=_conformance_event("cross-account-login-method-revoke"),
    )
    final_method = await store.revoke_login_method(
        account.account_id,
        method.method_id,
        require_remaining=True,
        event=_conformance_event("revoke-final-login-method"),
    )
    absent = await store.revoke_login_method(
        account.account_id,
        "missing-login-method",
        require_remaining=True,
        event=_conformance_event("revoke-missing-login-method"),
    )
    if (
        cross_account.status is not RevokeLoginMethodStatus.NOT_FOUND
        or final_method.status is not RevokeLoginMethodStatus.FINAL_METHOD
        or absent.status is not RevokeLoginMethodStatus.NOT_FOUND
    ):
        message = (
            "LoginMethodStore.revoke_login_method final-method invariant: enforce ownership, preserve the final "
            "method, and report absent methods"
        )
        raise AssertionError(message)


async def assert_session_registry_conformance(  # noqa: C901, PLR0915 - one public scenario intentionally names each invariant
    factory: Callable[[], SessionRegistry], *, now: datetime = _DEFAULT_NOW
) -> None:
    """Assert session-registry state, atomic replacement, and ownership behavior.

    Args:
        factory: Isolated zero-argument session-registry factory initialized so
            ``get()`` evaluates expiry against ``now``.
        now: Time used for every created record and expiry assertion.

    Returns:
        None when every session-registry invariant holds.

    Raises:
        AssertionError: If session creation, expiry, replacement, or revocation
            violates its public contract.
    """
    store = factory()
    isolated = factory()
    if store is isolated:
        message = "SessionRegistry factory invariant: each call must return isolated state"
        raise AssertionError(message)
    command = _conformance_session_command(marker=1, account_id="conformance-session-owner", now=now)
    created = await store.create(command, event=_conformance_event("create-session"))
    expected = _conformance_session_record(command)
    if created != expected or await store.get(command.session_id) != expected:
        message = "SessionRegistry.create/get state invariant: created records must be exact"
        raise AssertionError(message)
    if await isolated.get(command.session_id) is not None:
        message = "SessionRegistry factory isolation invariant: created sessions must be factory-local"
        raise AssertionError(message)
    expired = _conformance_session_command(
        marker=2, account_id=command.account_id, now=now, created_at=now - timedelta(minutes=2), expires_at=now
    )
    await store.create(expired, event=_conformance_event("create-expired-session"))
    if await store.get(expired.session_id) is not None:
        message = "SessionRegistry.get expiry invariant: expired sessions must not be returned"
        raise AssertionError(message)

    replacements = tuple(
        _conformance_session_command(marker=marker, account_id=command.account_id, now=now) for marker in (3, 4)
    )

    results: list[tuple[CreateSessionCommand, SessionRecord | None]] = []

    def contender(replacement: CreateSessionCommand) -> Callable[[], Awaitable[bool]]:
        async def attempt() -> bool:
            result = await store.rebind(command.session_id, replacement, event=_conformance_event("rebind-session"))
            results.append((replacement, result))
            return _won_by_presence(result)

        return attempt

    winners = await _single_winner(tuple(contender(replacement) for replacement in replacements))
    if winners != 1:
        message = "SessionRegistry.rebind atomicity invariant: two contenders must produce one replacement"
        raise AssertionError(message)
    winner = next((candidate, result) for candidate, result in results if result is not None)
    winner_command, winner_record = winner
    if winner_record != _conformance_session_record(winner_command):
        message = "SessionRegistry.rebind state invariant: the winning replacement record must be exact"
        raise AssertionError(message)
    successor_records = [await store.get(replacement.session_id) for replacement in replacements]
    if await store.get(command.session_id) is not None or sum(record is not None for record in successor_records) != 1:
        message = (
            "SessionRegistry.rebind partial-write invariant: exactly one replacement must remain and the prior session "
            "must be gone"
        )
        raise AssertionError(message)

    other = _conformance_session_command(marker=5, account_id="conformance-session-other", now=now)
    await store.create(other, event=_conformance_event("create-other-session"))
    if await store.revoke_session_for_account(
        command.account_id, other.session_id, event=_conformance_event("cross-account-session-revoke")
    ) or await store.get(other.session_id) != _conformance_session_record(other):
        message = (
            "SessionRegistry.revoke_session_for_account ownership invariant: another account's session must remain"
        )
        raise AssertionError(message)
    current = next(record for record in successor_records if record is not None)
    extra = _conformance_session_command(marker=6, account_id=command.account_id, now=now)
    await store.create(extra, event=_conformance_event("create-extra-session"))
    await store.revoke_other_sessions(
        command.account_id, current.session_id, event=_conformance_event("revoke-other-sessions")
    )
    if (
        await store.get(current.session_id) != current
        or await store.get(extra.session_id) is not None
        or await store.get(other.session_id) != _conformance_session_record(other)
    ):
        message = "SessionRegistry.revoke_other_sessions keep-current invariant: retain only the named owner session"
        raise AssertionError(message)


class _ConformanceRefreshFamilyStore(RefreshTokenFamilyStore, RegistrationStore[object], Protocol):
    """Refresh-family port plus the account registration setup required by its epoch contract."""

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        """Return the password state used to force an epoch change after preparation."""
        ...  # pragma: no cover

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeResult:
        """Advance an account epoch so rotation must revalidate prepared context."""
        ...  # pragma: no cover


async def assert_refresh_family_store_conformance(factory: Callable[[], _ConformanceRefreshFamilyStore]) -> None:
    """Assert strict refresh-family creation, rotation, replay, and ownership behavior.

    Args:
        factory: Isolated zero-argument combined local-account and refresh-family
            store factory frozen at the conformance clock.

    Returns:
        None when every refresh-family invariant holds.

    Raises:
        AssertionError: If a refresh-family transition is not exact, atomic, or
            account-owned.
    """
    store = factory()
    isolated = factory()
    if store is isolated:
        message = "RefreshTokenFamilyStore factory invariant: each call must return isolated state"
        raise AssertionError(message)
    account = await _conformance_register_account(store, "refresh-owner@example.com")
    command = _conformance_refresh_family_command(account, marker=1)
    if not await store.create_family(command, event=_conformance_event("create-refresh-family")):
        message = "RefreshTokenFamilyStore.create_family state invariant: a current account epoch must create a family"
        raise AssertionError(message)
    context = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-refresh"),
    )
    expected_context = _conformance_refresh_context(command)
    if context != expected_context:
        message = "RefreshTokenFamilyStore.prepare_rotation state invariant: active family context must be exact"
        raise AssertionError(message)
    token_collision = replace(command, family_id=_conformance_identifier("rf_", 12))
    family_collision = replace(command, token_id=_conformance_identifier("rt_", 12), token_digest=bytes((12,)) * 32)
    if await store.create_family(
        token_collision, event=_conformance_event("create-refresh-token-collision")
    ) or await store.create_family(family_collision, event=_conformance_event("create-refresh-family-collision")):
        message = (
            "RefreshTokenFamilyStore.create_family collision invariant: "
            "duplicate token and family identifiers must each fail"
        )
        raise AssertionError(message)
    isolated_result = await isolated.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-isolated-refresh"),
    )
    if (
        not isinstance(isolated_result, PrepareRefreshResult)
        or isolated_result.status is not RefreshRotationStatus.INVALID
    ):
        message = "RefreshTokenFamilyStore factory isolation invariant: created families must be factory-local"
        raise AssertionError(message)

    expired = _conformance_refresh_family_command(account, marker=2, expires_at=_DEFAULT_NOW)
    if not await store.create_family(expired, event=_conformance_event("create-expired-refresh")):
        message = (
            "RefreshTokenFamilyStore.create_family expiry setup invariant: expired families must still be recorded"
        )
        raise AssertionError(message)
    expired_result = await store.prepare_rotation(
        RefreshTokenProof(expired.token_id, expired.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-expired-refresh"),
    )
    if (
        not isinstance(expired_result, PrepareRefreshResult)
        or expired_result.status is not RefreshRotationStatus.EXPIRED
    ):
        message = "RefreshTokenFamilyStore.prepare_rotation expiry invariant: expired tokens must be rejected"
        raise AssertionError(message)

    # A valid command requires token_expires_at <= family_expires_at, so an
    # independently expired family with a live token is unrepresentable. This
    # shared deadline covers the public state boundary; divergent internal
    # store state is outside the protocol contract.
    shared_expiry = _conformance_refresh_family_command(
        account, marker=15, token_expires_at=_DEFAULT_NOW, family_expires_at=_DEFAULT_NOW
    )
    if not await store.create_family(shared_expiry, event=_conformance_event("create-shared-expiry-refresh")):
        message = (
            "RefreshTokenFamilyStore.prepare_rotation expiry setup invariant: a shared-expiry family must be created"
        )
        raise AssertionError(message)
    shared_result = await store.prepare_rotation(
        RefreshTokenProof(shared_expiry.token_id, shared_expiry.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-shared-expiry-refresh"),
    )
    if not isinstance(shared_result, PrepareRefreshResult) or shared_result.status is not RefreshRotationStatus.EXPIRED:
        message = (
            "RefreshTokenFamilyStore.prepare_rotation shared-expiry invariant: "
            "the token/family deadline must bound rotation"
        )
        raise AssertionError(message)

    await _assert_refresh_rotation_atomicity(store, account)
    await _assert_refresh_rotation_commit(store, account)
    await _assert_refresh_replay_and_idempotency(store, account)
    await _assert_refresh_ownership(store, account)
    await _assert_refresh_late_rotation_rejection(store, account)


async def _assert_refresh_rotation_atomicity(
    store: _ConformanceRefreshFamilyStore, account: LocalAccount[object]
) -> None:
    command = _conformance_refresh_family_command(account, marker=3)
    if not await store.create_family(command, event=_conformance_event("create-atomic-refresh")):
        message = "RefreshTokenFamilyStore.rotate atomicity setup invariant: a fresh family must be created"
        raise AssertionError(message)
    context = _conformance_refresh_context(command)
    commands = tuple(_conformance_rotate_command(context, command, marker) for marker in (4, 5))
    results: list[tuple[RotateRefreshCommand, RotateRefreshResult]] = []

    async def rotate(candidate: RotateRefreshCommand) -> bool:
        result = await store.rotate(candidate, now=_DEFAULT_NOW, event=_conformance_event("rotate-refresh"))
        results.append((candidate, result))
        return _won_by_status(result.status, winning=RefreshRotationStatus.ROTATED)

    def contender(candidate: RotateRefreshCommand) -> Callable[[], Awaitable[bool]]:
        async def attempt() -> bool:
            return await rotate(candidate)

        return attempt

    winners = await _single_winner(tuple(contender(candidate) for candidate in commands))
    if winners != 1:
        message = "RefreshTokenFamilyStore.rotate atomicity invariant: two contenders must produce one rotation"
        raise AssertionError(message)
    winner, winner_result = next(
        (candidate, result) for candidate, result in results if result.status is RefreshRotationStatus.ROTATED
    )
    loser, loser_result = next((candidate, result) for candidate, result in results if candidate is not winner)
    winner_context = await store.prepare_rotation(
        RefreshTokenProof(winner.successor_id, winner.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-atomic-winner"),
    )
    loser_context = await store.prepare_rotation(
        RefreshTokenProof(loser.successor_id, loser.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-atomic-loser"),
    )
    if (
        winner_result.sealed_receipt != winner.sealed_receipt
        or loser_result.status is RefreshRotationStatus.ROTATED
        or loser_result.sealed_receipt is not None
        or winner_context != _conformance_successor_context(winner)
        or not isinstance(loser_context, PrepareRefreshResult)
        or loser_context.status is not RefreshRotationStatus.INVALID
    ):
        message = (
            "RefreshTokenFamilyStore.rotate durable-state invariant: one exact successor and receipt must persist, "
            "with no loser successor"
        )
        raise AssertionError(message)
    replay = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-atomic-replay"),
    )
    revoked_successor = await store.prepare_rotation(
        RefreshTokenProof(winner.successor_id, winner.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-atomic-revoked-successor"),
    )
    if (
        not isinstance(replay, PrepareRefreshResult)
        or replay.status is not RefreshRotationStatus.REPLAY_DETECTED
        or not replay.family_revoked
        or not isinstance(revoked_successor, PrepareRefreshResult)
        or revoked_successor.status is not RefreshRotationStatus.REVOKED
        or not revoked_successor.family_revoked
    ):
        message = (
            "RefreshTokenFamilyStore.prepare_rotation replay invariant: "
            "unkeyed consumed-token reuse must revoke the family"
        )
        raise AssertionError(message)


async def _assert_refresh_rotation_commit(store: _ConformanceRefreshFamilyStore, account: LocalAccount[object]) -> None:
    command = _conformance_refresh_family_command(account, marker=6)
    if not await store.create_family(command, event=_conformance_event("create-commit-refresh")):
        message = "RefreshTokenFamilyStore.rotate partial-write setup invariant: a fresh family must be created"
        raise AssertionError(message)
    context = _conformance_refresh_context(command)
    rotation = _conformance_rotate_command(context, command, marker=7)
    result = await store.rotate(rotation, now=_DEFAULT_NOW, event=_conformance_event("rotate-commit-refresh"))
    replay = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        rotation.idempotency_digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-commit-receipt"),
    )
    successor = await store.prepare_rotation(
        RefreshTokenProof(rotation.successor_id, rotation.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-commit-successor"),
    )
    if (
        result.status is not RefreshRotationStatus.ROTATED
        or result.sealed_receipt != rotation.sealed_receipt
        or not isinstance(replay, RefreshReceiptReplay)
        or replay.sealed_receipt != rotation.sealed_receipt
        or replay.context != context
        or successor != _conformance_successor_context(rotation)
    ):
        message = (
            "RefreshTokenFamilyStore.rotate partial-write invariant: "
            "consume, successor, and receipt must commit together"
        )
        raise AssertionError(message)


async def _assert_refresh_late_rotation_rejection(
    store: _ConformanceRefreshFamilyStore, account: LocalAccount[object]
) -> None:
    expiry_command = _conformance_refresh_family_command(account, marker=10)
    if not await store.create_family(expiry_command, event=_conformance_event("create-late-expiry-refresh")):
        message = "RefreshTokenFamilyStore.rotate late-expiry setup invariant: a fresh family must be created"
        raise AssertionError(message)
    expiry_context = await store.prepare_rotation(
        RefreshTokenProof(expiry_command.token_id, expiry_command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-late-expiry-refresh"),
    )
    if not isinstance(expiry_context, RefreshFamilyContext) or expiry_context != _conformance_refresh_context(
        expiry_command
    ):
        message = "RefreshTokenFamilyStore.rotate late-expiry setup invariant: an active context must be prepared"
        raise AssertionError(message)
    expired_rotation = _conformance_rotate_command(expiry_context, expiry_command, marker=16)
    expired_result = await store.rotate(
        expired_rotation, now=expiry_command.token_expires_at, event=_conformance_event("rotate-late-expiry-refresh")
    )
    expired_successor = await store.prepare_rotation(
        RefreshTokenProof(expired_rotation.successor_id, expired_rotation.successor_digest),
        None,
        now=expiry_command.token_expires_at,
        event=_conformance_event("prepare-late-expiry-successor"),
    )
    if (
        expired_result.status is RefreshRotationStatus.ROTATED
        or expired_result.sealed_receipt is not None
        or not isinstance(expired_successor, PrepareRefreshResult)
        or expired_successor.status is not RefreshRotationStatus.INVALID
    ):
        message = (
            "RefreshTokenFamilyStore.rotate late-expiry invariant: expired commit must leave no successor or receipt"
        )
        raise AssertionError(message)

    epoch_command = _conformance_refresh_family_command(account, marker=13)
    if not await store.create_family(epoch_command, event=_conformance_event("create-late-epoch-refresh")):
        message = "RefreshTokenFamilyStore.rotate epoch setup invariant: a fresh family must be created"
        raise AssertionError(message)
    epoch_context = await store.prepare_rotation(
        RefreshTokenProof(epoch_command.token_id, epoch_command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-late-epoch-refresh"),
    )
    password_state = await store.get_password_state(account.account_id)
    if (
        not isinstance(epoch_context, RefreshFamilyContext)
        or epoch_context != _conformance_refresh_context(epoch_command)
        or password_state is None
    ):
        message = "RefreshTokenFamilyStore.rotate epoch setup invariant: prepared families require password state"
        raise AssertionError(message)
    changed = await store.replace_password_and_bump_epoch(
        account.account_id,
        "conformance-refresh-epoch-bump",
        expected_epoch=epoch_context.security_epoch,
        event=_conformance_event("bump-refresh-epoch"),
    )
    epoch_rotation = _conformance_rotate_command(epoch_context, epoch_command, marker=14)
    epoch_result = await store.rotate(
        epoch_rotation, now=_DEFAULT_NOW, event=_conformance_event("rotate-late-epoch-refresh")
    )
    epoch_successor = await store.prepare_rotation(
        RefreshTokenProof(epoch_rotation.successor_id, epoch_rotation.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-late-epoch-successor"),
    )
    if (
        changed.status is not PasswordChangeStatus.CHANGED
        or epoch_result.status is RefreshRotationStatus.ROTATED
        or epoch_result.sealed_receipt is not None
        or not isinstance(epoch_successor, PrepareRefreshResult)
        or epoch_successor.status is not RefreshRotationStatus.INVALID
    ):
        message = (
            "RefreshTokenFamilyStore.rotate epoch invariant: stale prepared context must leave no successor or receipt"
        )
        raise AssertionError(message)


async def _assert_refresh_replay_and_idempotency(
    store: _ConformanceRefreshFamilyStore, account: LocalAccount[object]
) -> None:
    command = _conformance_refresh_family_command(account, marker=8)
    if not await store.create_family(command, event=_conformance_event("create-replay-refresh")):
        message = "RefreshTokenFamilyStore.prepare_rotation replay setup invariant: a fresh family must be created"
        raise AssertionError(message)
    context = _conformance_refresh_context(command)
    rotation = _conformance_rotate_command(context, command, marker=9)
    await store.rotate(rotation, now=_DEFAULT_NOW, event=_conformance_event("rotate-replay-refresh"))
    receipt = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        rotation.idempotency_digest,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-idempotent-refresh"),
    )
    if not isinstance(receipt, RefreshReceiptReplay) or receipt.sealed_receipt != rotation.sealed_receipt:
        message = (
            "RefreshTokenFamilyStore.prepare_rotation idempotency invariant: matching retries must recover one receipt"
        )
        raise AssertionError(message)
    replay = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        bytes((10,)) * 32,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-replayed-refresh"),
    )
    successor = await store.prepare_rotation(
        RefreshTokenProof(rotation.successor_id, rotation.successor_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-revoked-successor"),
    )
    if (
        not isinstance(replay, PrepareRefreshResult)
        or replay.status is not RefreshRotationStatus.REPLAY_DETECTED
        or not replay.family_revoked
        or not isinstance(successor, PrepareRefreshResult)
        or successor.status is not RefreshRotationStatus.REVOKED
        or not successor.family_revoked
    ):
        message = (
            "RefreshTokenFamilyStore.prepare_rotation replay invariant: consumed-token reuse must revoke its family"
        )
        raise AssertionError(message)


async def _assert_refresh_ownership(store: _ConformanceRefreshFamilyStore, account: LocalAccount[object]) -> None:
    command = _conformance_refresh_family_command(account, marker=11)
    if not await store.create_family(command, event=_conformance_event("create-owned-refresh")):
        message = (
            "RefreshTokenFamilyStore.revoke_token_for_account ownership setup invariant: a fresh family must be created"
        )
        raise AssertionError(message)
    other = await _conformance_register_account(store, "refresh-other@example.com")
    if await store.revoke_token_for_account(
        other.account_id,
        command.token_id,
        command.token_digest,
        event=_conformance_event("cross-account-refresh-revoke"),
    ):
        message = (
            "RefreshTokenFamilyStore.revoke_token_for_account ownership invariant: "
            "another account must not revoke a family"
        )
        raise AssertionError(message)
    result = await store.prepare_rotation(
        RefreshTokenProof(command.token_id, command.token_digest),
        None,
        now=_DEFAULT_NOW,
        event=_conformance_event("prepare-owned-refresh"),
    )
    if not isinstance(result, RefreshFamilyContext):
        message = (
            "RefreshTokenFamilyStore.revoke_token_for_account ownership invariant: "
            "rejected cross-account revocation must not mutate"
        )
        raise AssertionError(message)  # noqa: TRY004 - conformance failures are intentionally AssertionError


async def assert_mfa_store_conformance(factory: Callable[[], MFAStore]) -> None:
    """Assert atomic TOTP counter and recovery-code consumption.

    Args:
        factory: Isolated zero-argument MFA-store factory.

    Returns:
        None when every MFA-store invariant holds.

    Raises:
        AssertionError: If a counter update is non-atomic or a recovery code can be reused.
    """
    store = factory()
    enrollment = PendingTOTPEnrollment(
        enrollment_id="conformance-enrollment",
        method_id="conformance-totp",
        account_id="conformance-account",
        protected_secret=ProtectedSecret(ciphertext=b"secret", key_version="v1"),
        policy=TOTPPolicy(),
        created_at=_DEFAULT_NOW,
        expires_at=_DEFAULT_NOW + timedelta(minutes=5),
    )
    await store.create_totp_enrollment(enrollment)
    activated = await store.activate_totp(
        enrollment.account_id,
        enrollment.enrollment_id,
        accepted_counter=1,
        login_method=LoginMethod("conformance-totp", "totp", _DEFAULT_NOW),
        event=_conformance_event("activate-totp"),
        now=_DEFAULT_NOW,
    )
    if activated is None:
        raise AssertionError("MFAStore setup invariant: a fresh enrollment must activate")

    async def advance() -> bool:
        return await store.advance_totp_counter(activated.method_id, accepted_counter=2, now=_DEFAULT_NOW)

    if await _single_winner((advance, advance)) != 1:
        raise AssertionError("MFAStore.advance_totp_counter atomicity invariant: two contenders must have one winner")
    if await store.advance_totp_counter(activated.method_id, accepted_counter=2, now=_DEFAULT_NOW):
        raise AssertionError("MFAStore.advance_totp_counter monotonicity invariant: equal counters must be refused")
    if await store.advance_totp_counter(activated.method_id, accepted_counter=1, now=_DEFAULT_NOW):
        raise AssertionError("MFAStore.advance_totp_counter monotonicity invariant: lower counters must be refused")
    digest = b"r" * 32
    await store.replace_recovery_codes(
        enrollment.account_id, (RecoveryCodeDigest(enrollment.account_id, "v1", digest),), now=_DEFAULT_NOW
    )

    async def consume() -> bool:
        return await store.consume_recovery_code(enrollment.account_id, digest, now=_DEFAULT_NOW)

    if await _single_winner((consume, consume)) != 1:
        raise AssertionError("MFAStore.consume_recovery_code atomicity invariant: two contenders must have one winner")


async def assert_mfa_login_challenge_store_conformance(factory: Callable[[], MFALoginChallengeStore]) -> None:
    """Assert MFA-login challenges are bound, one-shot, and expiry-safe.

    Args:
        factory: Isolated zero-argument MFA login challenge-store factory.

    Returns:
        None when every MFA login challenge invariant holds.

    Raises:
        AssertionError: If a challenge can be replayed or survives a rejected binding or expiry.
    """
    store = factory()
    wrong_account = _conformance_mfa_login_challenge(b"m" * 32)
    await store.put(wrong_account)
    if (
        await store.consume(
            wrong_account.challenge_digest,
            account_id="other",
            security_epoch=wrong_account.security_epoch,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore binding invariant: wrong account must not consume successfully")
    if (
        await store.consume(
            wrong_account.challenge_digest,
            account_id=wrong_account.account_id,
            security_epoch=wrong_account.security_epoch,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore account-binding burn invariant: a rejected binding must burn")
    wrong_epoch = _conformance_mfa_login_challenge(b"n" * 32)
    await store.put(wrong_epoch)
    if (
        await store.consume(
            wrong_epoch.challenge_digest,
            account_id=wrong_epoch.account_id,
            security_epoch=wrong_epoch.security_epoch + 1,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore epoch invariant: wrong epoch must not consume successfully")
    if (
        await store.consume(
            wrong_epoch.challenge_digest,
            account_id=wrong_epoch.account_id,
            security_epoch=wrong_epoch.security_epoch,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore epoch-binding burn invariant: a rejected binding must burn")
    winner = _conformance_mfa_login_challenge(b"w" * 32)
    await store.put(winner)

    async def consume() -> MFALoginChallenge | None:
        return await store.consume(
            winner.challenge_digest,
            account_id=winner.account_id,
            security_epoch=winner.security_epoch,
            now=_DEFAULT_NOW,
        )

    if await _single_winner((lambda: _presence(consume()), lambda: _presence(consume()))) != 1:
        raise AssertionError("MFALoginChallengeStore atomicity invariant: two contenders must have one winner")
    expired = _conformance_mfa_login_challenge(b"x" * 32, expires_at=_DEFAULT_NOW + timedelta(seconds=1))
    await store.put(expired)
    if (
        await store.consume(
            expired.challenge_digest, account_id=expired.account_id, security_epoch=0, now=expired.expires_at
        )
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore expiry invariant: expired challenges must be rejected")
    if (
        await store.consume(expired.challenge_digest, account_id=expired.account_id, security_epoch=0, now=_DEFAULT_NOW)
        is not None
    ):
        raise AssertionError("MFALoginChallengeStore expiry burn invariant: expired challenges must be removed")


async def assert_webauthn_challenge_store_conformance(factory: Callable[[], WebAuthnChallengeStore]) -> None:
    """Assert WebAuthn challenges burn once and enforce every binding.

    Args:
        factory: Isolated zero-argument WebAuthn challenge-store factory.

    Returns:
        None when every WebAuthn challenge invariant holds.

    Raises:
        AssertionError: If consume-once, binding, purpose, or expiry behavior is violated.
    """
    store = factory()
    wrong_binding = _conformance_webauthn_challenge(b"b" * 32)
    await store.put(wrong_binding)
    if (
        await store.consume(
            wrong_binding.challenge_digest, binding_digest=b"z" * 32, purpose=wrong_binding.purpose, now=_DEFAULT_NOW
        )
        is not None
    ):
        raise AssertionError("WebAuthnChallengeStore binding invariant: wrong binding must return None")
    if (
        await store.consume(
            wrong_binding.challenge_digest,
            binding_digest=wrong_binding.binding_digest,
            purpose=wrong_binding.purpose,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("WebAuthnChallengeStore binding burn invariant: mismatched challenge must be removed")
    wrong_purpose = _conformance_webauthn_challenge(b"p" * 32)
    await store.put(wrong_purpose)
    if (
        await store.consume(
            wrong_purpose.challenge_digest,
            binding_digest=wrong_purpose.binding_digest,
            purpose="other",
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("WebAuthnChallengeStore purpose invariant: wrong purpose must return None")
    if (
        await store.consume(
            wrong_purpose.challenge_digest,
            binding_digest=wrong_purpose.binding_digest,
            purpose=wrong_purpose.purpose,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("WebAuthnChallengeStore purpose burn invariant: mismatched challenge must be removed")
    winner = _conformance_webauthn_challenge(b"w" * 32)
    await store.put(winner)

    async def consume() -> WebAuthnChallenge | None:
        return await store.consume(
            winner.challenge_digest, binding_digest=winner.binding_digest, purpose=winner.purpose, now=_DEFAULT_NOW
        )

    if await _single_winner((lambda: _presence(consume()), lambda: _presence(consume()))) != 1:
        raise AssertionError("WebAuthnChallengeStore atomicity invariant: two contenders must have one winner")
    expired = _conformance_webauthn_challenge(b"x" * 32, expires_at=_DEFAULT_NOW + timedelta(seconds=1))
    await store.put(expired)
    if (
        await store.consume(
            expired.challenge_digest,
            binding_digest=expired.binding_digest,
            purpose=expired.purpose,
            now=expired.expires_at,
        )
        is not None
    ):
        raise AssertionError("WebAuthnChallengeStore expiry invariant: expired challenges must be rejected")


async def assert_oauth_transaction_store_conformance(factory: Callable[[], OAuthTransactionStore]) -> None:
    """Assert OAuth transactions preserve matching, expiry, and one-shot consumption.

    Args:
        factory: Isolated zero-argument OAuth transaction-store factory.

    Returns:
        None when every OAuth transaction invariant holds.

    Raises:
        AssertionError: If callback state can be replayed or a mismatched callback is accepted.
    """
    store = factory()
    transaction = _conformance_oauth_transaction(b"s" * 32)
    await store.create(transaction)
    if (
        await store.consume(
            state_digest=transaction.state_digest,
            binding_digest=b"z" * 32,
            provider=transaction.provider,
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("OAuthTransactionStore binding invariant: wrong binding must return None")
    if (
        await store.consume(
            state_digest=transaction.state_digest,
            binding_digest=transaction.binding_digest,
            provider="other-provider",
            now=_DEFAULT_NOW,
        )
        is not None
    ):
        raise AssertionError("OAuthTransactionStore provider invariant: wrong provider must return None")
    winner = await store.consume(
        state_digest=transaction.state_digest,
        binding_digest=transaction.binding_digest,
        provider=transaction.provider,
        now=_DEFAULT_NOW,
    )
    if winner != transaction:
        raise AssertionError("OAuthTransactionStore matching invariant: an exact callback must return its transaction")
    replay = await store.consume(
        state_digest=transaction.state_digest,
        binding_digest=transaction.binding_digest,
        provider=transaction.provider,
        now=_DEFAULT_NOW,
    )
    if replay is not None:
        raise AssertionError("OAuthTransactionStore consume-once invariant: a consumed transaction must not replay")
    concurrent = _conformance_oauth_transaction(b"c" * 32)
    await store.create(concurrent)

    async def consume() -> OAuthTransaction | None:
        return await store.consume(
            state_digest=concurrent.state_digest,
            binding_digest=concurrent.binding_digest,
            provider=concurrent.provider,
            now=_DEFAULT_NOW,
        )

    if await _single_winner((lambda: _presence(consume()), lambda: _presence(consume()))) != 1:
        raise AssertionError("OAuthTransactionStore atomicity invariant: two contenders must have one winner")
    expired = _conformance_oauth_transaction(b"e" * 32, expires_at=_DEFAULT_NOW + timedelta(seconds=1))
    await store.create(expired)
    if (
        await store.consume(
            state_digest=expired.state_digest,
            binding_digest=expired.binding_digest,
            provider=expired.provider,
            now=expired.expires_at,
        )
        is not None
    ):
        raise AssertionError("OAuthTransactionStore expiry invariant: expired transactions must be rejected")


async def assert_websocket_connect_token_store_conformance(factory: Callable[[], WebSocketConnectTokenStore]) -> None:
    """Assert WebSocket connect tokens are exact, one-shot, and expiry-safe.

    Args:
        factory: Isolated zero-argument WebSocket connect-token store factory.

    Returns:
        None when every WebSocket connect-token invariant holds.

    Raises:
        AssertionError: If a wrong digest burns a token, or a token can be reused or outlive expiry.
    """
    store = factory()
    record = _conformance_connect_token_record("aWlpaWlpaWlpaWlpaWlpaQ", b"d" * 32)
    await store.create(record)
    if await store.consume(connect_token_id=record.connect_token_id, digest=b"z" * 32, now=_DEFAULT_NOW) is not None:
        raise AssertionError("WebSocketConnectTokenStore digest invariant: wrong digest must return None")
    if await store.consume(connect_token_id=record.connect_token_id, digest=record.digest, now=_DEFAULT_NOW) != record:
        raise AssertionError(
            "WebSocketConnectTokenStore digest preservation invariant: wrong digest must not consume the record"
        )
    winner = _conformance_connect_token_record("ampqampqampqampqampqag", b"w" * 32)
    await store.create(winner)

    async def consume() -> WebSocketConnectTokenRecord | None:
        return await store.consume(connect_token_id=winner.connect_token_id, digest=winner.digest, now=_DEFAULT_NOW)

    if await _single_winner((lambda: _presence(consume()), lambda: _presence(consume()))) != 1:
        raise AssertionError("WebSocketConnectTokenStore atomicity invariant: two contenders must have one winner")
    expired = _conformance_connect_token_record(
        "eXh4eXh4eXh4eXh4eXh4eA", b"e" * 32, expires_at=_DEFAULT_NOW + timedelta(seconds=1)
    )
    await store.create(expired)
    if (
        await store.consume(connect_token_id=expired.connect_token_id, digest=expired.digest, now=expired.expires_at)
        is not None
    ):
        raise AssertionError("WebSocketConnectTokenStore expiry invariant: expired records must be rejected")
    if (
        await store.consume(connect_token_id=expired.connect_token_id, digest=expired.digest, now=_DEFAULT_NOW)
        is not None
    ):
        raise AssertionError("WebSocketConnectTokenStore expiry deletion invariant: expired records must be removed")


async def assert_passkey_store_conformance(factory: Callable[[], PasskeyStore]) -> None:
    """Assert optimistic assertion recording and clone-risk results.

    Args:
        factory: Isolated zero-argument passkey-store factory.

    Returns:
        None when every passkey-store invariant holds.

    Raises:
        AssertionError: If only one optimistic writer is not recorded or clone risk is lost.
    """
    store = factory()
    credential = _conformance_passkey_credential(b"credential")
    if not await store.add_credential(
        credential,
        login_method=LoginMethod("passkey-method", "passkey", _DEFAULT_NOW),
        event=_conformance_event("add-passkey"),
    ):
        raise AssertionError("PasskeyStore setup invariant: a fresh credential must be added")

    async def record() -> AssertionRecordResult:
        return await store.record_assertion(
            credential.credential_id,
            expected_version=0,
            sign_count=2,
            backup_eligible=False,
            backup_state=False,
            clone_risk=False,
            now=_DEFAULT_NOW,
        )

    outcomes: list[AssertionRecordResult] = []
    async with create_task_group() as group:
        group.start_soon(_append_result, record, outcomes)
        group.start_soon(_append_result, record, outcomes)
    if outcomes.count(AssertionRecordResult.RECORDED) != 1 or outcomes.count(AssertionRecordResult.CONFLICT) != 1:
        raise AssertionError(
            "PasskeyStore.record_assertion atomicity invariant: contenders must return RECORDED and CONFLICT"
        )
    recorded = await store.get_credential(credential.credential_id)
    expected_sign_count = 2
    if recorded is None or recorded.version != 1 or recorded.sign_count != expected_sign_count or recorded.suspect:
        raise AssertionError(
            "PasskeyStore.record_assertion state invariant: winning assertion must persist exact state"
        )
    clone = _conformance_passkey_credential(b"clone")
    await store.add_credential(
        clone, login_method=LoginMethod("clone-method", "passkey", _DEFAULT_NOW), event=_conformance_event("add-clone")
    )
    if (
        await store.record_assertion(
            clone.credential_id,
            expected_version=0,
            sign_count=0,
            backup_eligible=False,
            backup_state=False,
            clone_risk=True,
            now=_DEFAULT_NOW,
        )
        is not AssertionRecordResult.CLONE_RISK
    ):
        raise AssertionError(
            "PasskeyStore.record_assertion clone-risk invariant: a clone-risk assertion must return CLONE_RISK"
        )
    cloned = await store.get_credential(clone.credential_id)
    if cloned is None or cloned.version != 1 or not cloned.suspect:
        raise AssertionError("PasskeyStore.record_assertion clone-state invariant: clone risk must persist suspicion")


async def assert_oauth_account_store_conformance(factory: Callable[[], OAuthAccountStore]) -> None:
    """Assert final-method protection and atomic OAuth identity unlinking.

    Args:
        factory: Isolated zero-argument OAuth account-store factory.

    Returns:
        None when every OAuth account-store invariant holds.

    Raises:
        AssertionError: If a final method can be removed or concurrent unlinking has two winners.
    """
    store = factory()
    identity = _conformance_provider_identity("first")
    first = await store.link_identity("conformance-account", identity, _conformance_provider_grant(), now=_DEFAULT_NOW)
    wrong_owner = await store.unlink_identity(
        "other-account", first.provider_account_id, require_remaining=True, now=_DEFAULT_NOW
    )
    if wrong_owner.status is not UnlinkStatus.NOT_FOUND:
        raise AssertionError("OAuthAccountStore ownership invariant: another account must receive NOT_FOUND")
    final = await store.unlink_identity(
        "conformance-account", first.provider_account_id, require_remaining=True, now=_DEFAULT_NOW
    )
    if final.status is not UnlinkStatus.FINAL_METHOD:
        raise AssertionError("OAuthAccountStore final-method invariant: the last identity must return FINAL_METHOD")
    preserved = await store.resolve_provider_account("conformance-account", first.provider)
    if preserved != first:
        raise AssertionError("OAuthAccountStore ownership preservation invariant: rejected unlink must not mutate")
    second = await store.link_identity(
        "conformance-account", _conformance_provider_identity("second"), _conformance_provider_grant(), now=_DEFAULT_NOW
    )

    async def unlink() -> UnlinkStatus:
        return (
            await store.unlink_identity(
                "conformance-account", second.provider_account_id, require_remaining=True, now=_DEFAULT_NOW
            )
        ).status

    statuses: list[UnlinkStatus] = []
    async with create_task_group() as group:
        group.start_soon(_append_result, unlink, statuses)
        group.start_soon(_append_result, unlink, statuses)
    if statuses.count(UnlinkStatus.UNLINKED) != 1 or statuses.count(UnlinkStatus.NOT_FOUND) != 1:
        raise AssertionError(
            "OAuthAccountStore.unlink_identity atomicity invariant: contenders must return UNLINKED and NOT_FOUND"
        )


async def assert_security_backend_conformance(factories: StoreConformanceFactories) -> None:
    """Run only the conformance scenarios whose factories were supplied.

    Args:
        factories: Explicit feature factories to exercise.

    Returns:
        None when every enabled feature passes.

    Raises:
        AssertionError: If any enabled feature violates its public protocol.
    """
    if factories.api_key_store is not None:
        await assert_api_key_store_conformance(factories.api_key_store)


def _conformance_api_key_record(key_id: str) -> APIKeyRecord:
    return APIKeyRecord(key_id=key_id, subject_id="conformance-subject", digest=b"d" * 32)


def _conformance_session_command(
    *,
    marker: int,
    account_id: str,
    now: datetime = _DEFAULT_NOW,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> CreateSessionCommand:
    """Build one deterministic session command with exact valid identifier material."""
    session_created_at = created_at if created_at is not None else now
    return CreateSessionCommand(
        session_id=_conformance_identifier(None, marker),
        binding_id=_conformance_identifier("sb_", marker),
        binding_digest=bytes((marker,)) * 32,
        account_id=account_id,
        security_epoch=1,
        created_at=session_created_at,
        authenticated_at=session_created_at,
        expires_at=expires_at if expires_at is not None else now + timedelta(minutes=5),
        display_metadata={"device": f"conformance-{marker}"},
    )


def _conformance_session_record(command: CreateSessionCommand) -> SessionRecord:
    """Return the exact stored projection required by one session creation command."""
    return SessionRecord(
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


def _conformance_refresh_family_command(
    account: LocalAccount[object],
    *,
    marker: int,
    expires_at: datetime | None = None,
    token_expires_at: datetime | None = None,
    family_expires_at: datetime | None = None,
) -> CreateRefreshFamilyCommand:
    """Build one deterministic family command bound to a registered account epoch."""
    expiration = token_expires_at if token_expires_at is not None else expires_at
    token_expiry = expiration if expiration is not None else _DEFAULT_NOW + timedelta(minutes=5)
    family_expiry = family_expires_at if family_expires_at is not None else _DEFAULT_NOW + timedelta(minutes=10)
    return CreateRefreshFamilyCommand(
        token_id=_conformance_identifier("rt_", marker),
        token_digest=bytes((marker,)) * 32,
        account_id=account.account_id,
        family_id=_conformance_identifier("rf_", marker),
        security_epoch=account.security_epoch,
        created_at=_DEFAULT_NOW - timedelta(minutes=1) if expiration is not None else _DEFAULT_NOW,
        token_expires_at=token_expiry,
        family_expires_at=family_expiry,
        scopes=frozenset({"conformance"}),
    )


def _conformance_refresh_context(command: CreateRefreshFamilyCommand) -> RefreshFamilyContext:
    """Return the exact active context for a newly created refresh family."""
    return RefreshFamilyContext(
        account_id=command.account_id,
        family_id=command.family_id,
        security_epoch=command.security_epoch,
        token_expires_at=command.token_expires_at,
        family_expires_at=command.family_expires_at,
        scopes=command.scopes,
    )


def _conformance_successor_context(command: RotateRefreshCommand) -> RefreshFamilyContext:
    """Return the exact active context committed for a rotated successor token."""
    return RefreshFamilyContext(
        account_id=command.account_id,
        family_id=command.family_id,
        security_epoch=command.security_epoch,
        token_expires_at=command.successor_expires_at,
        family_expires_at=command.family_expires_at,
        scopes=command.scopes,
    )


def _conformance_rotate_command(
    context: RefreshFamilyContext, command: CreateRefreshFamilyCommand, marker: int
) -> RotateRefreshCommand:
    """Build a deterministic one-time successor and receipt for one family context."""
    return RotateRefreshCommand(
        token_id=command.token_id,
        token_digest=command.token_digest,
        account_id=context.account_id,
        family_id=context.family_id,
        security_epoch=context.security_epoch,
        successor_id=_conformance_identifier("rt_", marker),
        successor_digest=bytes((marker,)) * 32,
        successor_expires_at=context.token_expires_at,
        family_expires_at=context.family_expires_at,
        sealed_receipt=bytes((marker,)),
        receipt_expires_at=context.token_expires_at,
        idempotency_digest=bytes((marker,)) * 32,
        scopes=context.scopes,
    )


def _conformance_identifier(prefix: str | None, marker: int) -> str:
    """Build an exact base64url lookup identifier without randomness."""
    length = 16 if prefix is not None else 32
    value = urlsafe_b64encode(bytes((marker,)) * length).rstrip(b"=").decode("ascii")
    return f"{prefix or ''}{value}"


async def _conformance_register_account(
    store: RegistrationStore[object], normalized_identifier: str, *, verification: PurposeTokenDelivery | None = None
) -> LocalAccount[object]:
    """Register one password account required by several local-account scenarios."""
    result = await store.register(
        _conformance_registration_command(normalized_identifier),
        "conformance-password-hash",
        invitation_digest=None,
        verification=verification,
        now=_DEFAULT_NOW,
        event=_conformance_event("register-setup"),
    )
    if result.status is not RegistrationStatus.CREATED or result.account is None:  # pragma: no cover - result invariant
        message = "RegistrationStore.register setup invariant: a fresh normalized identifier must create an account"
        raise AssertionError(message)
    return result.account


def _conformance_event(operation: str) -> SecurityEvent:
    return SecurityEvent(
        event_id=f"conformance-{operation}", occurred_at=_DEFAULT_NOW, operation=operation, outcome="conformance"
    )


def _conformance_registration_command(normalized_identifier: str) -> RegistrationCommand:
    return RegistrationCommand(normalized_identifier=normalized_identifier, display_name="Conformance")


def _conformance_verification_delivery(
    now: datetime, *, marker: int, maximum_attempts: int = 5
) -> PurposeTokenDelivery:
    return _conformance_token_delivery(
        TokenPurpose.VERIFICATION, now=now, marker=marker, maximum_attempts=maximum_attempts
    )


def _conformance_token_delivery(
    purpose: TokenPurpose, *, marker: int, now: datetime = _DEFAULT_NOW, maximum_attempts: int = 5
) -> PurposeTokenDelivery:
    marker_byte = bytes((marker,))
    return PurposeTokenCodec(pepper=bytes(32), entropy=lambda length: marker_byte * length).issue(
        purpose,
        now=now,
        lifetime=timedelta(minutes=5),
        template=purpose.value,
        destination=f"{purpose.value}@example.com",
        maximum_attempts=maximum_attempts,
    )


def _different_digest(digest: bytes) -> bytes:
    return bytes((digest[0] ^ 1,)) + digest[1:]


def _conformance_mfa_login_challenge(digest: bytes, *, expires_at: datetime | None = None) -> MFALoginChallenge:
    """Build a fixed valid MFA-login challenge."""
    return MFALoginChallenge(
        challenge_digest=digest,
        account_id="conformance-account",
        security_epoch=0,
        client_key="conformance-client",
        issued_at=_DEFAULT_NOW,
        expires_at=expires_at if expires_at is not None else _DEFAULT_NOW + timedelta(minutes=5),
    )


def _conformance_webauthn_challenge(digest: bytes, *, expires_at: datetime | None = None) -> WebAuthnChallenge:
    """Build a fixed valid WebAuthn challenge."""
    return WebAuthnChallenge(
        challenge_digest=digest,
        binding_digest=b"b" * 32,
        purpose="authentication",
        account_id="conformance-account",
        rp_id="example.test",
        origins=("https://app.example",),
        user_verification=UserVerification.REQUIRED,
        algorithms=(-7,),
        expires_at=expires_at if expires_at is not None else _DEFAULT_NOW + timedelta(minutes=5),
    )


def _conformance_oauth_transaction(digest: bytes, *, expires_at: datetime | None = None) -> OAuthTransaction:
    """Build one fixed OAuth login transaction."""
    return OAuthTransaction(
        state_digest=digest,
        binding_digest=b"b" * 32,
        operation=OAuthOperation.LOGIN,
        provider="conformance-provider",
        expected_issuer="https://issuer.example",
        redirect_uri="https://app.example/callback",
        return_to="/",
        requested_scopes=frozenset({"profile"}),
        pkce_verifier=SecretStr("v" * 43),
        expires_at=expires_at if expires_at is not None else _DEFAULT_NOW + timedelta(minutes=5),
    )


def _conformance_connect_token_record(
    connect_token_id: str, digest: bytes, *, expires_at: datetime | None = None
) -> WebSocketConnectTokenRecord:
    """Build one fixed valid WebSocket connect-token record."""
    return WebSocketConnectTokenRecord(
        connect_token_id=connect_token_id,
        digest=digest,
        subject_id="conformance-subject",
        route_name="conformance-route",
        origin="https://app.example",
        restrictions=CredentialRestrictions(),
        policy_fingerprint="f" * 64,
        issued_at=_DEFAULT_NOW,
        expires_at=expires_at if expires_at is not None else _DEFAULT_NOW + timedelta(seconds=30),
    )


def _conformance_passkey_credential(credential_id: bytes) -> PasskeyCredential:
    """Build one fixed verified passkey credential."""
    return PasskeyCredential(
        credential_id=credential_id,
        account_id="conformance-account",
        public_key=b"public-key",
        sign_count=1,
        backup_eligible=False,
        backup_state=False,
        user_verified=True,
        aaguid="aaguid",
        attestation_format="none",
        created_at=_DEFAULT_NOW,
    )


def _conformance_provider_identity(subject: str) -> ProviderIdentity:
    """Build one distinct OAuth provider identity."""
    return ProviderIdentity(
        provider="conformance-provider",
        issuer="https://issuer.example",
        subject=subject,
        display_name="Conformance",
        email=f"{subject}@example.com",
        email_verified=True,
        raw_claims={"sub": subject},
    )


def _conformance_provider_grant() -> ProviderGrant:
    """Build one fixed OAuth provider grant."""
    return ProviderGrant(scopes=frozenset({"profile"}), expires_at=_DEFAULT_NOW + timedelta(hours=1))


async def _presence(operation: Awaitable[object | None]) -> bool:
    """Project an optional async result to the shared winner boolean shape."""
    return _won_by_presence(await operation)


async def _append_result(operation: Callable[[], Awaitable[ResultT]], results: list[ResultT]) -> None:
    """Run one contender and retain its exact status result."""
    results.append(await operation())


async def _single_winner(contenders: tuple[Callable[[], Awaitable[bool]], ...]) -> int:
    """Run every contender concurrently and count the ones that won."""
    outcomes: list[bool] = []
    async with create_task_group() as task_group:
        for attempt in contenders:
            task_group.start_soon(_record, attempt, outcomes)
    return outcomes.count(True)


async def _record(attempt: Callable[[], Awaitable[bool]], outcomes: list[bool]) -> None:
    outcomes.append(_won_by_status(await attempt(), winning=True))


def _won_by_return(result: object) -> bool:
    """Return whether a boolean-result contender won."""
    return result is True


def _won_by_presence(result: object | None) -> bool:
    """Return whether an optional-result contender produced a record."""
    return _won_by_return(result is not None)


def _won_by_status(result: object, *, winning: object) -> bool:
    """Return whether a status-result contender produced its winning status."""
    return _won_by_presence(result if result == winning else None)


async def _won_unless_raised(operation: Callable[[], Awaitable[object]]) -> bool:
    """Return whether a contender completed without an implementation conflict."""
    try:
        await operation()
    except Exception:  # noqa: BLE001 - conformance accepts implementation-specific conflict exceptions
        return False
    return True


@dataclass(frozen=True, slots=True)
class _DeterministicProtector:
    active_key_version: str = "test-v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        prefix = sha256(associated_data).digest()
        return ProtectedOAuthSecret(ciphertext=prefix + secret[::-1], key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        prefix = sha256(associated_data).digest()
        if not protected.ciphertext.startswith(prefix):  # pragma: no cover - only corrupted private store state
            message = "Protected test secret has different associated data"
            raise ValueError(message)
        return protected.ciphertext[len(prefix) :][::-1]


class InMemoryMFAStore:
    """Atomic in-memory implementation of the MFA store contract."""

    __slots__ = ("_lock", "enrollments", "events", "login_methods", "methods", "recovery_codes")

    def __init__(self) -> None:
        """Initialize isolated mutable state."""
        self._lock = Lock()
        self.enrollments: dict[str, PendingTOTPEnrollment] = {}
        self.events: list[SecurityEvent] = []
        self.login_methods: dict[str, LoginMethod] = {}
        self.methods: dict[str, TOTPMethod] = {}
        self.recovery_codes: dict[str, tuple[RecoveryCodeDigest, ...]] = {}

    async def create_totp_enrollment(self, enrollment: PendingTOTPEnrollment) -> None:
        """Store one enrollment.

        Args:
            enrollment: Protected pending enrollment.
        """
        async with self._lock:
            self.enrollments[enrollment.enrollment_id] = enrollment

    async def get_totp_enrollment(self, enrollment_id: str) -> PendingTOTPEnrollment | None:
        """Load one enrollment.

        Args:
            enrollment_id: Enrollment identifier.

        Returns:
            The pending enrollment, if present.
        """
        return self.enrollments.get(enrollment_id)

    async def activate_totp(  # noqa: PLR0913 - mirrors the atomic public protocol
        self,
        account_id: str,
        enrollment_id: str,
        *,
        accepted_counter: int,
        login_method: LoginMethod,
        event: SecurityEvent,
        now: datetime,
    ) -> TOTPMethod | None:
        """Atomically consume and activate one enrollment.

        Args:
            account_id: Expected owner.
            enrollment_id: Enrollment to consume.
            accepted_counter: Verified initial counter.
            login_method: Viable method committed with activation.
            event: Durable creation event.
            now: Commit timestamp.

        Returns:
            The active method only for the winning call.
        """
        async with self._lock:
            enrollment = self.enrollments.pop(enrollment_id, None)
            if enrollment is None or enrollment.account_id != account_id or enrollment.expires_at <= now:
                return None
            method = TOTPMethod(
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

    async def activate_totp_with_recovery_codes(  # noqa: PLR0913 - mirrors the atomic public protocol
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
        """Atomically activate one enrollment and replace recovery codes."""
        async with self._lock:
            enrollment = self.enrollments.get(enrollment_id)
            if enrollment is None or enrollment.account_id != account_id or enrollment.expires_at <= now:
                return None
            method = TOTPMethod(
                method_id=enrollment.method_id,
                account_id=account_id,
                protected_secret=enrollment.protected_secret,
                policy=enrollment.policy,
                last_accepted_counter=accepted_counter,
                created_at=now,
            )
            del self.enrollments[enrollment_id]
            self.methods[method.method_id] = method
            self.recovery_codes[account_id] = tuple(codes)
            self.login_methods[login_method.method_id] = login_method
            self.events.append(event)
            return method

    async def get_totp_method(self, account_id: str, method_id: str) -> TOTPMethod | None:
        """Load an owner-checked active method.

        Args:
            account_id: Expected owner.
            method_id: Method identifier.

        Returns:
            The active method only for its owner.
        """
        method = self.methods.get(method_id)
        return method if method is not None and method.account_id == account_id else None

    async def advance_totp_counter(self, method_id: str, *, accepted_counter: int, now: datetime) -> bool:
        """Atomically advance a strictly monotonic TOTP counter.

        Args:
            method_id: Method identifier.
            accepted_counter: Verified counter.
            now: Commit timestamp.

        Returns:
            Whether this call won the monotonic update.
        """
        async with self._lock:
            method = self.methods.get(method_id)
            if method is None or accepted_counter <= method.last_accepted_counter:
                return False
            self.methods[method_id] = replace(method, last_accepted_counter=accepted_counter, last_used_at=now)
            return True

    async def replace_recovery_codes(
        self, account_id: str, codes: tuple[RecoveryCodeDigest, ...], *, now: datetime
    ) -> None:
        """Atomically replace an account's complete digest set.

        Args:
            account_id: Owning account.
            codes: Complete replacement set.
            now: Commit timestamp, accepted for protocol parity.
        """
        del now
        async with self._lock:
            self.recovery_codes[account_id] = tuple(code for code in codes if code.account_id == account_id)

    async def consume_recovery_code(self, account_id: str, digest: bytes, *, now: datetime) -> bool:
        """Atomically compare and consume one recovery digest.

        Args:
            account_id: Expected owner.
            digest: Presented HMAC digest.
            now: Commit timestamp, accepted for protocol parity.

        Returns:
            Whether this call consumed one matching digest.
        """
        del now
        async with self._lock:
            codes = self.recovery_codes.get(account_id, ())
            match = next((code for code in codes if compare_digest(code.digest, digest)), None)
            if match is None:
                return False
            self.recovery_codes[account_id] = tuple(code for code in codes if code is not match)
            return True


class InMemoryWebAuthnChallengeStore:
    """Atomic in-memory digest-only WebAuthn challenge store."""

    __slots__ = ("_lock", "challenges")

    def __init__(self) -> None:
        """Initialize isolated mutable state."""
        self._lock = Lock()
        self.challenges: dict[bytes, WebAuthnChallenge] = {}

    async def put(self, challenge: WebAuthnChallenge) -> None:
        """Store one digest-only challenge.

        Args:
            challenge: Bound challenge state.
        """
        async with self._lock:
            self.challenges[challenge.challenge_digest] = challenge

    async def consume(
        self, challenge_digest: bytes, *, binding_digest: bytes, purpose: str, now: datetime
    ) -> WebAuthnChallenge | None:
        """Atomically burn and return one exact challenge.

        Args:
            challenge_digest: Presented challenge digest.
            binding_digest: Current transport binding digest.
            purpose: Expected ceremony.
            now: Consumption time.

        Returns:
            The record only for the winning exact match.
        """
        async with self._lock:
            challenge = self.challenges.pop(challenge_digest, None)
            if (
                challenge is None
                or not compare_digest(challenge.binding_digest, binding_digest)
                or challenge.purpose != purpose
                or challenge.expires_at <= now
            ):
                return None
            return challenge


class InMemoryPasskeyStore:
    """Atomic in-memory passkey credential store."""

    __slots__ = ("_lock", "credentials", "events", "login_methods")

    def __init__(self) -> None:
        """Initialize isolated mutable state."""
        self._lock = Lock()
        self.credentials: dict[bytes, PasskeyCredential] = {}
        self.events: list[SecurityEvent] = []
        self.login_methods: dict[str, LoginMethod] = {}

    async def add_credential(
        self, credential: PasskeyCredential, *, login_method: LoginMethod, event: SecurityEvent
    ) -> bool:
        """Atomically register a credential, login method, and event.

        Args:
            credential: Verified credential.
            login_method: Viable method committed with the credential.
            event: Durable creation event.

        Returns:
            Whether it was absent and added.
        """
        async with self._lock:
            if credential.credential_id in self.credentials:
                return False
            self.credentials[credential.credential_id] = credential
            self.login_methods[login_method.method_id] = login_method
            self.events.append(event)
            return True

    async def get_credential(self, credential_id: bytes) -> PasskeyCredential | None:
        """Load one credential.

        Args:
            credential_id: Binary credential identifier.

        Returns:
            The credential, if present.
        """
        return self.credentials.get(credential_id)

    async def record_assertion(  # noqa: PLR0913 - mirrors the explicit atomic public protocol
        self,
        credential_id: bytes,
        *,
        expected_version: int,
        sign_count: int,
        backup_eligible: bool,
        backup_state: bool,
        clone_risk: bool,
        now: datetime,
    ) -> AssertionRecordResult:
        """Atomically record one verified assertion.

        Args:
            credential_id: Credential to update.
            expected_version: Optimistic version.
            sign_count: Verified new signature counter.
            backup_eligible: Immutable BE flag.
            backup_state: Current BS flag.
            clone_risk: Whether the counter signaled possible cloning.
            now: Commit timestamp.

        Returns:
            Structured record, conflict, or clone-risk status.
        """
        async with self._lock:
            credential = self.credentials.get(credential_id)
            if (
                credential is None
                or credential.version != expected_version
                or credential.backup_eligible != backup_eligible
            ):
                return AssertionRecordResult.CONFLICT
            self.credentials[credential_id] = replace(
                credential,
                sign_count=sign_count,
                backup_state=backup_state,
                suspect=credential.suspect or clone_risk,
                last_used_at=now,
                version=credential.version + 1,
            )
            return AssertionRecordResult.CLONE_RISK if clone_risk else AssertionRecordResult.RECORDED

    async def list_credentials(self, account_id: str) -> tuple[PasskeyCredential, ...]:
        """List an account's credentials.

        Args:
            account_id: Owning account.

        Returns:
            Stable credential snapshot.
        """
        return tuple(value for value in self.credentials.values() if value.account_id == account_id)

    async def rename_credential(
        self, account_id: str, credential_id: bytes, display_name: str
    ) -> PasskeyCredential | None:
        """Atomically rename one owner-checked credential.

        Args:
            account_id: Expected owner.
            credential_id: Credential identifier.
            display_name: Replacement metadata.

        Returns:
            Updated credential, or ``None``.
        """
        async with self._lock:
            credential = self.credentials.get(credential_id)
            if credential is None or credential.account_id != account_id:
                return None
            updated = replace(credential, display_name=display_name, version=credential.version + 1)
            self.credentials[credential_id] = updated
            return updated


class InMemoryMFALoginChallengeStore:
    """Atomic in-memory digest-only MFA login challenge store."""

    __slots__ = ("_lock", "challenges")

    def __init__(self) -> None:
        """Initialize isolated mutable state."""
        self._lock = Lock()
        self.challenges: dict[bytes, MFALoginChallenge] = {}

    async def put(self, challenge: MFALoginChallenge) -> None:
        """Store one pending digest-only challenge.

        Args:
            challenge: Pending second-factor state.
        """
        async with self._lock:
            self.challenges[challenge.challenge_digest] = challenge

    async def consume(
        self, challenge_digest: bytes, *, account_id: str, security_epoch: int, now: datetime
    ) -> MFALoginChallenge | None:
        """Atomically burn and return one exact, current challenge.

        Args:
            challenge_digest: Presented challenge digest.
            account_id: Expected local account.
            security_epoch: Expected current account epoch.
            now: Consumption time.

        Returns:
            The record only for the winning exact, unexpired match.
        """
        async with self._lock:
            challenge = self.challenges.pop(challenge_digest, None)
            if (
                challenge is None
                or challenge.account_id != account_id
                or challenge.security_epoch != security_epoch
                or challenge.expires_at <= now
            ):
                return None
            return challenge


class InMemoryStepUpStore:
    """Atomic in-memory digest-only step-up store."""

    __slots__ = ("_lock", "grants")

    def __init__(self) -> None:
        """Initialize isolated mutable state."""
        self._lock = Lock()
        self.grants: dict[bytes, StepUpRecord] = {}

    async def put(self, record: StepUpRecord) -> None:
        """Store one grant record.

        Args:
            record: Digest-only grant.
        """
        async with self._lock:
            self.grants[record.grant_digest] = record

    async def consume(  # noqa: PLR0913 - mirrors the exact atomic public protocol
        self,
        grant_digest: bytes,
        *,
        principal_id: str,
        security_epoch: int,
        purpose: str,
        transport_digest: bytes,
        now: datetime,
    ) -> StepUpRecord | None:
        """Atomically burn and return one exact current grant.

        Args:
            grant_digest: Presented grant digest.
            principal_id: Expected principal.
            security_epoch: Expected current epoch.
            purpose: Expected protected action.
            transport_digest: Expected transport binding digest.
            now: Consumption time.

        Returns:
            The record only for the winning exact match.
        """
        async with self._lock:
            record = self.grants.pop(grant_digest, None)
            if (
                record is None
                or record.principal_id != principal_id
                or record.security_epoch != security_epoch
                or record.purpose != purpose
                or not compare_digest(record.transport_digest, transport_digest)
                or record.expires_at <= now
            ):
                return None
            return record
