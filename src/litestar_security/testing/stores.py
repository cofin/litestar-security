"""In-memory security store doubles and reference backend implementations."""

import heapq
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
from hmac import compare_digest
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from anyio import Lock

from litestar_security.accounts import (
    CreateRefreshFamilyCommand,
    CreateSessionCommand,
    LocalAccountState,
    LoginMethod,
    NotificationCommand,
    PasswordChangeOutcome,
    PasswordChangeStatus,
    PasswordCredentialState,
    PasswordResetOutcome,
    PasswordResetStatus,
    PurposeTokenDelivery,
    RefreshFamilyContext,
    RefreshPreflightOutcome,
    RefreshReceiptReplay,
    RefreshRotationOutcome,
    RefreshRotationStatus,
    RefreshTokenProof,
    RegistrationCommand,
    RegistrationOutcome,
    RegistrationStatus,
    RevokeLoginMethodOutcome,
    RevokeLoginMethodStatus,
    RotateRefreshCommand,
    SecurityEvent,
    TokenIssue,
    TokenPurpose,
    UserAuthSession,
    VerificationOutcome,
    VerificationStatus,
)

if TYPE_CHECKING:
    from litestar_security.accounts import (
        MFALoginChallenge,
        PasskeyAssertionStatus,
        PasskeyCredential,
        PendingTOTPEnrollment,
        RecoveryCodeDigest,
        StepUpGrantState,
        TOTPMethod,
        WebAuthnChallenge,
    )
from litestar_security.providers.api_key import APIKeyState
from litestar_security.providers.oauth import (
    MemoryOAuthAccountStore,
    MemoryOAuthTransactionStore,
    OAuthTransactionProtector,
    OIDCLogoutIdentity,
    ProtectedOAuthSecret,
)
from litestar_security.testing.fakes import BackendBarrier, BackendEvent
from litestar_security.websocket import InMemoryWebSocketConnectTokenStore

__all__ = (
    "InMemoryAPIKeyStore",
    "InMemoryLocalAccountStore",
    "InMemoryMFALoginChallengeStore",
    "InMemoryMFAStore",
    "InMemoryOIDCSessionLogoutStore",
    "InMemoryPasskeyStore",
    "InMemorySecurityBackend",
    "InMemoryStepUpStore",
    "InMemoryWebAuthnChallengeStore",
    "InMemoryWebSocketConnectTokenStore",
    "MemoryOAuthAccountStore",
    "MemoryOAuthTransactionStore",
    "TTLEvictionManager",
)

_DEFAULT_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_DEFAULT_CREDENTIAL_HASH = "$litestar-security$deterministic-test-hash"


def _default_identifier(namespace: str, sequence: int) -> str:
    """Format a deterministic identifier from namespace and sequence."""
    return f"{namespace}-{sequence:04d}"


class TTLEvictionManager:
    """Min-heap priority queue tracking expirations for active and lazy eviction."""

    __slots__ = ("_heap",)

    def __init__(self) -> None:
        """Initialize an empty min-heap eviction queue."""
        self._heap: list[tuple[float, str, str]] = []

    def schedule(self, kind: str, item_id: str, expires_at: datetime) -> None:
        """Register an item for future eviction.

        Args:
            kind: Category of the item ('session', 'purpose', 'refresh').
            item_id: Unique identifier of the item.
            expires_at: Expiration datetime.
        """
        heapq.heappush(self._heap, (expires_at.timestamp(), kind, item_id))

    def evict_due(self, now: datetime) -> list[tuple[str, str]]:
        """Pop all entries whose expiration timestamp is less than or equal to now.

        Args:
            now: Current datetime.

        Returns:
            List of (kind, item_id) tuples ready for eviction.
        """
        now_ts = now.timestamp()
        due: list[tuple[str, str]] = []
        while self._heap and self._heap[0][0] <= now_ts:
            _, kind, item_id = heapq.heappop(self._heap)
            due.append((kind, item_id))
        return due


class InMemoryAPIKeyStore:
    """Atomic digest-only API-key store for tests and examples."""

    __slots__ = ("_lock", "_observe", "_records")

    def __init__(self, observe: Callable[[str, Mapping[str, str]], Awaitable[None]]) -> None:
        """Initialize isolated records and an aggregate diagnostic callback.

        Args:
            observe: Async operation callback owned by the aggregate backend.
        """
        self._records: dict[str, APIKeyState] = {}
        self._lock = Lock()
        self._observe = observe

    @property
    def records(self) -> tuple[APIKeyState, ...]:
        """Return a stable immutable record snapshot."""
        return tuple(self._records[key_id] for key_id in sorted(self._records))

    async def get(self, key_id: str) -> APIKeyState | None:
        """Return one digest-only record."""
        await self._observe("api_key.get", {"key_id": key_id})
        async with self._lock:
            return self._records.get(key_id)

    async def create(self, record: APIKeyState) -> None:
        """Atomically create one unique digest-only record."""
        await self._observe("api_key.create", {"key_id": record.key_id})
        async with self._lock:
            if record.key_id in self._records:
                message = "API-key ID already exists"
                raise ValueError(message)
            self._records[record.key_id] = record

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyState, overlap_until: datetime | None, now: datetime
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
    """Atomic in-memory local-account, session, and refresh reference store.

    Features domain-level lock striping, O(1) secondary index dictionaries,
    and priority queue TTL expiration to eliminate linear scans and memory leaks.
    """

    __slots__ = (
        "_account_lock",
        "_accounts",
        "_accounts_by_identifier",
        "_clock",
        "_entropy",
        "_eviction_manager",
        "_identifiers",
        "_lock",
        "_login_methods",
        "_observe",
        "_password_hashes",
        "_purpose_attempts",
        "_purpose_lock",
        "_purpose_tokens",
        "_refresh_by_family",
        "_refresh_lock",
        "_refresh_tokens",
        "_session_lock",
        "_sessions",
        "_sessions_by_account",
        "_used_purpose_tokens",
    )

    def __init__(
        self,
        observe: Callable[[str, Mapping[str, str]], Awaitable[None]],
        *,
        clock: Callable[[], datetime],
        identifiers: Callable[[str], str],
        entropy: Callable[[int], bytes],
    ) -> None:
        """Initialize isolated state with domain lock striping and secondary indexes."""
        self._accounts: dict[str, LocalAccountState[object]] = {}
        self._accounts_by_identifier: dict[str, str] = {}
        self._password_hashes: dict[str, str] = {}
        self._login_methods: dict[str, dict[str, LoginMethod]] = {}
        self._purpose_attempts: dict[str, int] = {}
        self._purpose_tokens: dict[str, TokenIssue] = {}
        self._used_purpose_tokens: set[str] = set()
        self._sessions: dict[str, UserAuthSession] = {}
        self._sessions_by_account: dict[str, set[str]] = {}
        self._refresh_tokens: dict[str, _InMemoryRefreshState] = {}
        self._refresh_by_family: dict[str, set[str]] = {}
        self._clock = clock
        self._identifiers = identifiers
        self._entropy = entropy
        self._eviction_manager = TTLEvictionManager()
        self._lock = Lock()
        self._account_lock = Lock()
        self._session_lock = Lock()
        self._refresh_lock = Lock()
        self._purpose_lock = Lock()
        self._observe = observe

    def evict_expired(self, now: datetime | None = None) -> int:
        """Actively evict expired sessions and purpose tokens based on current time."""
        current_time = self._clock() if now is None else now
        due_items = self._eviction_manager.evict_due(current_time)
        evicted_count = 0
        for kind, item_id in due_items:
            if kind == "session":
                session = self._sessions.pop(item_id, None)
                if session is not None:
                    account_sessions = self._sessions_by_account.get(session.account_id)
                    if account_sessions is not None:
                        account_sessions.discard(item_id)
                        if not account_sessions:
                            self._sessions_by_account.pop(session.account_id, None)
                    evicted_count += 1
            elif kind == "purpose":
                if item_id in self._purpose_tokens:
                    del self._purpose_tokens[item_id]
                    self._purpose_attempts.pop(item_id, None)
                    evicted_count += 1
        return evicted_count

    async def find_for_login(self, normalized_identifier: str) -> LocalAccountState[object] | None:
        """Find one account through its normalized identifier in O(1) time."""
        async with self._lock:
            account_id = self._accounts_by_identifier.get(normalized_identifier)
            if account_id is None:
                return None
            return self._accounts.get(account_id)

    async def get_by_id(self, account_id: str) -> LocalAccountState[object] | None:
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
    ) -> PasswordChangeOutcome:
        """Replace a password and advance its exact security epoch."""
        del event
        await self._observe("accounts.replace_password_and_bump_epoch", {"account_id": account_id})
        async with self._lock:
            account = self._accounts.get(account_id)
            if account is None:
                return PasswordChangeOutcome(PasswordChangeStatus.NOT_FOUND)
            if account.security_epoch != expected_epoch:
                return PasswordChangeOutcome(PasswordChangeStatus.CONFLICT)
            self._password_hashes[account_id] = password_hash
            self._accounts[account_id] = replace(account, security_epoch=expected_epoch + 1)
            return PasswordChangeOutcome(PasswordChangeStatus.CHANGED, expected_epoch + 1)

    async def list_methods(self, account_id: str) -> tuple[LoginMethod, ...]:
        """Return every login method recorded for an account."""
        await self._observe("accounts.list_methods", {"account_id": account_id})
        async with self._lock:
            return tuple(self._login_methods.get(account_id, {}).values())

    async def register_login_method(self, account_id: str, method: LoginMethod, *, event: SecurityEvent) -> None:
        """Record a login method for an existing account."""
        del event
        await self._observe("accounts.register_login_method", {"account_id": account_id, "method_id": method.method_id})
        async with self._lock:
            self._login_methods.setdefault(account_id, {})[method.method_id] = method

    async def revoke_login_method(
        self, account_id: str, method_id: str, *, require_remaining: bool = True, event: SecurityEvent
    ) -> RevokeLoginMethodOutcome:
        """Revoke one login method while preserving the requested invariant."""
        del event
        await self._observe("accounts.revoke_login_method", {"account_id": account_id, "method_id": method_id})
        async with self._lock:
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
        """Create one account and optional verification issue atomically."""
        del event
        await self._observe("accounts.register", {"normalized_identifier": command.normalized_identifier})
        async with self._lock:
            if command.normalized_identifier in self._accounts_by_identifier:
                return RegistrationOutcome(RegistrationStatus.DUPLICATE)
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
                return RegistrationOutcome(RegistrationStatus.INVALID_INVITATION)
            if verification is not None and self._purpose_token_id_exists_locked(verification.issue.token_id):
                message = "In-memory purpose-token identifier collision"
                raise ValueError(message)
            account_id = self._identifiers("account")
            if account_id in self._accounts:
                message = "In-memory account identifier collision"
                raise ValueError(message)
            account = LocalAccountState(
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
                self._eviction_manager.schedule("purpose", issue.token_id, issue.expires_at)
            self._accounts[account_id] = account
            self._accounts_by_identifier[command.normalized_identifier] = account_id
            self._password_hashes[account_id] = password_hash
            if invitation is not None:
                del self._purpose_tokens[invitation.token_id]
                self._used_purpose_tokens.add(invitation.token_id)
            return RegistrationOutcome(RegistrationStatus.CREATED, account)

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        """Store one purpose-token issue without retaining its delivery secret."""
        del notification, event
        await self._observe("accounts.issue", {"account_id": issue.account_id, "token_id": issue.token_id})
        async with self._lock:
            if self._purpose_token_id_exists_locked(issue.token_id):
                message = "In-memory purpose-token identifier collision"
                raise ValueError(message)
            self._purpose_tokens[issue.token_id] = issue
            self._eviction_manager.schedule("purpose", issue.token_id, issue.expires_at)

    async def issue_absent(self) -> None:
        """Perform the deterministic no-op used for absent accounts."""
        await self._observe("accounts.issue_absent", {})
        async with self._lock:
            return

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: datetime, event: SecurityEvent
    ) -> VerificationOutcome:
        """Consume one verification token and mark its account verified."""
        del event
        await self._observe("accounts.consume_and_verify", {"token_id": token_id})
        async with self._lock:
            issue = self._purpose_tokens.get(token_id)
            if issue is None or issue.purpose is not TokenPurpose.VERIFICATION:
                status = (
                    VerificationStatus.USED if token_id in self._used_purpose_tokens else VerificationStatus.INVALID
                )
                return VerificationOutcome(status)
            if not compare_digest(issue.digest, digest):
                self._record_failed_purpose_proof_locked(issue)
                return VerificationOutcome(VerificationStatus.INVALID)
            if issue.expires_at <= now:
                return VerificationOutcome(VerificationStatus.EXPIRED)
            account = self._accounts.get(issue.account_id)
            if account is None:
                return VerificationOutcome(VerificationStatus.INVALID)
            del self._purpose_tokens[token_id]
            self._purpose_attempts.pop(token_id, None)
            self._used_purpose_tokens.add(token_id)
            self._accounts[account.account_id] = replace(account, verified=True)
            return VerificationOutcome(VerificationStatus.CONSUMED, account.account_id, account.security_epoch)

    async def consume_and_reset(
        self, token_id: str, digest: bytes, new_password_hash: str, *, now: datetime, event: SecurityEvent
    ) -> PasswordResetOutcome:
        """Consume one recovery token and reset its account password atomically."""
        del event
        await self._observe("accounts.consume_and_reset", {"token_id": token_id})
        async with self._lock:
            issue = self._purpose_tokens.get(token_id)
            if issue is None or issue.purpose is not TokenPurpose.RECOVERY:
                status = (
                    PasswordResetStatus.USED if token_id in self._used_purpose_tokens else PasswordResetStatus.INVALID
                )
                return PasswordResetOutcome(status)
            if not compare_digest(issue.digest, digest):
                self._record_failed_purpose_proof_locked(issue)
                return PasswordResetOutcome(PasswordResetStatus.INVALID)
            if issue.expires_at <= now:
                return PasswordResetOutcome(PasswordResetStatus.EXPIRED)
            account = self._accounts.get(issue.account_id)
            if account is None or issue.issued_security_epoch != account.security_epoch:
                return PasswordResetOutcome(PasswordResetStatus.CONFLICT)
            next_epoch = account.security_epoch + 1
            del self._purpose_tokens[token_id]
            self._purpose_attempts.pop(token_id, None)
            self._used_purpose_tokens.add(token_id)
            self._password_hashes[account.account_id] = new_password_hash
            self._accounts[account.account_id] = replace(account, security_epoch=next_epoch)
            return PasswordResetOutcome(PasswordResetStatus.RESET, account.account_id, next_epoch)

    async def create(self, command: CreateSessionCommand, *, event: SecurityEvent) -> UserAuthSession:
        """Create one native session record."""
        del event
        await self._observe(
            "accounts.create_session", {"account_id": command.account_id, "session_id": command.session_id}
        )
        async with self._lock:
            if command.session_id in self._sessions:
                message = "In-memory session identifier collision"
                raise ValueError(message)
            record = UserAuthSession(
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
            self._sessions_by_account.setdefault(command.account_id, set()).add(command.session_id)
            self._eviction_manager.schedule("session", command.session_id, command.expires_at)
            return record

    async def get(self, session_id: str) -> UserAuthSession | None:
        """Return one currently stored native session."""
        async with self._lock:
            record = self._sessions.get(session_id)
            return record if record is not None and record.expires_at > self._clock() else None

    async def list_for_account(self, account_id: str) -> tuple[UserAuthSession, ...]:
        """Return the account's current native-session records using the secondary index."""
        async with self._lock:
            current = self._clock()
            session_ids = self._sessions_by_account.get(account_id, set())
            return tuple(
                self._sessions[session_id]
                for session_id in session_ids
                if session_id in self._sessions and self._sessions[session_id].expires_at > current
            )

    async def touch(self, session_id: str, *, now: datetime) -> UserAuthSession | None:
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
            account_sessions = self._sessions_by_account.get(account_id)
            if account_sessions is not None:
                account_sessions.discard(session_id)
                if not account_sessions:
                    self._sessions_by_account.pop(account_id, None)
            return True

    async def revoke_sessions_for_account(self, account_id: str, *, event: SecurityEvent) -> int:
        """Revoke every native session owned by one account."""
        del event
        await self._observe("accounts.revoke_sessions", {"account_id": account_id})
        async with self._lock:
            session_ids = tuple(self._sessions_by_account.pop(account_id, set()))
            for session_id in session_ids:
                self._sessions.pop(session_id, None)
            return len(session_ids)

    async def revoke_other_sessions(self, account_id: str, session_id: str, *, event: SecurityEvent) -> int:
        """Revoke all native sessions except the named current one."""
        del event
        await self._observe("accounts.revoke_other_sessions", {"account_id": account_id, "session_id": session_id})
        async with self._lock:
            account_sessions = self._sessions_by_account.get(account_id, set())
            other_session_ids = tuple(sid for sid in account_sessions if sid != session_id)
            for other_id in other_session_ids:
                self._sessions.pop(other_id, None)
                account_sessions.discard(other_id)
            return len(other_session_ids)

    async def rebind(
        self, prior_session_id: str, command: CreateSessionCommand, *, event: SecurityEvent
    ) -> UserAuthSession | None:
        """Replace one existing session with a successor atomically."""
        del event
        await self._observe(
            "accounts.rebind_session", {"prior_session_id": prior_session_id, "session_id": command.session_id}
        )
        async with self._lock:
            prior_record = self._sessions.get(prior_session_id)
            if prior_record is None:
                return None
            if command.session_id in self._sessions:
                message = "In-memory session identifier collision"
                raise ValueError(message)
            del self._sessions[prior_session_id]
            prior_account_sessions = self._sessions_by_account.get(prior_record.account_id)
            if prior_account_sessions is not None:
                prior_account_sessions.discard(prior_session_id)

            record = UserAuthSession(
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
            self._sessions_by_account.setdefault(command.account_id, set()).add(command.session_id)
            self._eviction_manager.schedule("session", command.session_id, command.expires_at)
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
                or command.family_id in self._refresh_by_family
            ):
                return False
            refresh_state = _InMemoryRefreshState(
                token_id=command.token_id,
                token_digest=command.token_digest,
                account_id=command.account_id,
                family_id=command.family_id,
                security_epoch=command.security_epoch,
                token_expires_at=command.token_expires_at,
                family_expires_at=command.family_expires_at,
                scopes=command.scopes,
            )
            self._refresh_tokens[command.token_id] = refresh_state
            self._refresh_by_family.setdefault(command.family_id, set()).add(command.token_id)
            return True

    async def prepare_rotation(
        self, proof: RefreshTokenProof, idempotency_digest: bytes | None, *, now: datetime, event: SecurityEvent
    ) -> RefreshFamilyContext | RefreshReceiptReplay | RefreshPreflightOutcome:
        """Resolve one exact refresh token for a later atomic rotation."""
        del event
        await self._observe("accounts.prepare_refresh_rotation", {"token_id": proof.token_id})
        async with self._lock:
            state = self._refresh_tokens.get(proof.token_id)
            if state is None or state.token_digest != proof.digest:
                return RefreshPreflightOutcome(RefreshRotationStatus.INVALID)
            if state.revoked:
                return RefreshPreflightOutcome(RefreshRotationStatus.REVOKED, family_revoked=True)
            if state.consumed:
                if state.idempotency_digest == idempotency_digest and state.sealed_receipt is not None:
                    return RefreshReceiptReplay(self._refresh_context(state), state.sealed_receipt)
                self._revoke_family_locked(state.family_id)
                return RefreshPreflightOutcome(RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True)
            if state.token_expires_at <= now or state.family_expires_at <= now:
                return RefreshPreflightOutcome(RefreshRotationStatus.EXPIRED)
            account = self._accounts.get(state.account_id)
            if account is None or account.security_epoch != state.security_epoch:
                return RefreshPreflightOutcome(RefreshRotationStatus.EPOCH_MISMATCH)
            return self._refresh_context(state)

    async def rotate(
        self, command: RotateRefreshCommand, *, now: datetime, event: SecurityEvent
    ) -> RefreshRotationOutcome:
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
                return RefreshRotationOutcome(RefreshRotationStatus.INVALID)
            if state.token_expires_at <= now or state.family_expires_at <= now:
                return RefreshRotationOutcome(RefreshRotationStatus.EXPIRED)
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
            self._refresh_by_family.setdefault(command.family_id, set()).add(command.successor_id)
            return RefreshRotationOutcome(RefreshRotationStatus.ROTATED, command.sealed_receipt)

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


class _DeterministicProtector:
    """Deterministic token protector for test OAuth transactions."""

    active_key_version: str = "test-v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        """Protect a secret deterministically for tests."""
        prefix = sha256(associated_data).digest()
        return ProtectedOAuthSecret(ciphertext=prefix + secret[::-1], key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        """Unprotect a test secret deterministically."""
        prefix = sha256(associated_data).digest()
        if not protected.ciphertext.startswith(prefix):
            message = "Protected test secret has different associated data"
            raise ValueError(message)
        return protected.ciphertext[len(prefix) :][::-1]


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
        "oauth_transactions",
        "oidc_session_logout",
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
        self.oidc_session_logout = InMemoryOIDCSessionLogoutStore(
            session_mappings=(), frontchannel_bindings={}, clock=self.clock
        )
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
        if type(length) is not int or length < 1:
            message = "In-memory backend entropy length must be positive"
            raise ValueError(message)
        if self._entropy is None:
            start = self._entropy_offset
            value = bytes((start + offset) % 256 for offset in range(length))
            self._entropy_offset += length
        else:
            value = self._entropy(length)
        if type(value) is not bytes or len(value) != length:
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


class InMemoryOIDCSessionLogoutStore:
    """Lock-protected OIDC mapped-session logout reference for deterministic tests."""

    _clock: Callable[[], datetime]

    __slots__ = (
        "_clock",
        "_consumed_frontchannel_mappings",
        "_consumed_token_ids",
        "_frontchannel_bindings",
        "_lock",
        "_revoked_mappings",
        "_session_mappings",
    )

    def __init__(
        self,
        *,
        session_mappings: tuple[tuple[str, str, str | None, str | None], ...],
        frontchannel_bindings: Mapping[tuple[str, str, str], str],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize fixed secret-free mappings and browser bindings.

        Args:
            session_mappings: (provider, issuer, subject, session_id) rows, one per local session.
            frontchannel_bindings: Browser binding by exact provider, issuer, and provider-session tuple.
            clock: Time source used to reject expired logout identities.
        """
        self._lock = Lock()
        self._clock = (lambda: _DEFAULT_NOW) if clock is None else clock
        self._session_mappings = session_mappings
        self._frontchannel_bindings = dict(frontchannel_bindings)
        self._consumed_token_ids: set[str] = set()
        self._consumed_frontchannel_mappings: set[tuple[str, str, str]] = set()
        self._revoked_mappings: set[int] = set()

    async def consume_backchannel(self, identity: OIDCLogoutIdentity, *, now: datetime) -> int | None:
        """Consume one token id and revoke every active exact identity mapping."""
        if identity.expires_at <= max(now, self._clock()):
            return None
        async with self._lock:
            if identity.token_id in self._consumed_token_ids:
                return None
            self._consumed_token_ids.add(identity.token_id)
            revoked = 0
            for index, (provider, issuer, subject, session_id) in enumerate(self._session_mappings):
                if (
                    index in self._revoked_mappings
                    or provider != identity.provider
                    or issuer != identity.issuer
                    or (identity.subject is not None and subject != identity.subject)
                    or (identity.session_id is not None and session_id != identity.session_id)
                ):
                    continue
                self._revoked_mappings.add(index)
                revoked += 1
            return revoked

    async def revoke_frontchannel(
        self, provider: str, issuer: str, session_id: str, *, binding: str, now: datetime
    ) -> int | None:
        """Consume one exact browser-bound mapping and revoke its active local sessions."""
        del now
        key = (provider, issuer, session_id)
        async with self._lock:
            if key in self._consumed_frontchannel_mappings or self._frontchannel_bindings.get(key) != binding:
                return None
            matching_indexes = tuple(
                index
                for index, mapping in enumerate(self._session_mappings)
                if mapping[0] == provider and mapping[1] == issuer and mapping[3] == session_id
            )
            if not matching_indexes:
                return None
            self._consumed_frontchannel_mappings.add(key)
            revoked = 0
            for index in matching_indexes:
                if index not in self._revoked_mappings:
                    self._revoked_mappings.add(index)
                    revoked += 1
            return revoked


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

    async def create_totp_enrollment(self, enrollment: "PendingTOTPEnrollment") -> None:
        """Store one enrollment."""
        async with self._lock:
            self.enrollments[enrollment.enrollment_id] = enrollment

    async def get_totp_enrollment(self, enrollment_id: str) -> "PendingTOTPEnrollment | None":
        """Load one enrollment."""
        return self.enrollments.get(enrollment_id)

    async def activate_totp(
        self,
        account_id: str,
        enrollment_id: str,
        *,
        accepted_counter: int,
        login_method: LoginMethod,
        event: SecurityEvent,
        now: datetime,
    ) -> "TOTPMethod | None":
        """Atomically consume and activate one enrollment."""
        async with self._lock:
            from litestar_security.accounts._mfa import TOTPMethod

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

    async def activate_totp_with_recovery_codes(
        self,
        account_id: str,
        enrollment_id: str,
        *,
        accepted_counter: int,
        codes: "tuple[RecoveryCodeDigest, ...]",
        login_method: LoginMethod,
        event: SecurityEvent,
        now: datetime,
    ) -> "TOTPMethod | None":
        """Atomically activate one enrollment and replace recovery codes."""
        async with self._lock:
            from litestar_security.accounts._mfa import TOTPMethod

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

    async def get_totp_method(self, account_id: str, method_id: str) -> "TOTPMethod | None":
        """Load an owner-checked active method."""
        method = self.methods.get(method_id)
        return method if method is not None and method.account_id == account_id else None

    async def advance_totp_counter(self, method_id: str, *, accepted_counter: int, now: datetime) -> bool:
        """Atomically advance a strictly monotonic TOTP counter."""
        async with self._lock:
            method = self.methods.get(method_id)
            if method is None or accepted_counter <= method.last_accepted_counter:
                return False
            self.methods[method_id] = replace(method, last_accepted_counter=accepted_counter, last_used_at=now)
            return True

    async def replace_recovery_codes(
        self, account_id: str, codes: "tuple[RecoveryCodeDigest, ...]", *, now: datetime
    ) -> None:
        """Atomically replace an account's complete digest set."""
        del now
        async with self._lock:
            self.recovery_codes[account_id] = tuple(code for code in codes if code.account_id == account_id)

    async def consume_recovery_code(self, account_id: str, digest: bytes, *, now: datetime) -> bool:
        """Atomically compare and consume one recovery digest."""
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

    async def put(self, challenge: "WebAuthnChallenge") -> None:
        """Store one digest-only challenge."""
        async with self._lock:
            self.challenges[challenge.challenge_digest] = challenge

    async def consume(
        self, challenge_digest: bytes, *, binding_digest: bytes, purpose: str, now: datetime
    ) -> "WebAuthnChallenge | None":
        """Atomically burn and return one exact challenge."""
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
        self, credential: "PasskeyCredential", *, login_method: LoginMethod, event: SecurityEvent
    ) -> bool:
        """Atomically register a credential, login method, and event."""
        async with self._lock:
            if credential.credential_id in self.credentials:
                return False
            self.credentials[credential.credential_id] = credential
            self.login_methods[login_method.method_id] = login_method
            self.events.append(event)
            return True

    async def get_credential(self, credential_id: bytes) -> "PasskeyCredential | None":
        """Load one credential."""
        return self.credentials.get(credential_id)

    async def record_assertion(
        self,
        credential_id: bytes,
        *,
        expected_version: int,
        sign_count: int,
        backup_eligible: bool,
        backup_state: bool,
        clone_risk: bool,
        now: datetime,
    ) -> "PasskeyAssertionStatus":
        """Atomically record one verified assertion."""
        async with self._lock:
            from litestar_security.accounts._passkeys import PasskeyAssertionStatus

            credential = self.credentials.get(credential_id)
            if (
                credential is None
                or credential.version != expected_version
                or credential.backup_eligible != backup_eligible
            ):
                return PasskeyAssertionStatus.CONFLICT
            self.credentials[credential_id] = replace(
                credential,
                sign_count=sign_count,
                backup_state=backup_state,
                suspect=credential.suspect or clone_risk,
                last_used_at=now,
                version=credential.version + 1,
            )
            return PasskeyAssertionStatus.CLONE_RISK if clone_risk else PasskeyAssertionStatus.RECORDED

    async def list_credentials(self, account_id: str) -> "tuple[PasskeyCredential, ...]":
        """List an account's credentials."""
        return tuple(value for value in self.credentials.values() if value.account_id == account_id)

    async def rename_credential(
        self, account_id: str, credential_id: bytes, display_name: str
    ) -> "PasskeyCredential | None":
        """Atomically rename one owner-checked credential."""
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

    async def put(self, challenge: "MFALoginChallenge") -> None:
        """Store one pending digest-only challenge."""
        async with self._lock:
            self.challenges[challenge.challenge_digest] = challenge

    async def consume(
        self, challenge_digest: bytes, *, account_id: str, security_epoch: int, now: datetime
    ) -> "MFALoginChallenge | None":
        """Atomically burn and return one exact, current challenge."""
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
        self.grants: dict[bytes, StepUpGrantState] = {}

    async def put(self, record: "StepUpGrantState") -> None:
        """Store one grant record."""
        async with self._lock:
            self.grants[record.grant_digest] = record

    async def consume(
        self,
        grant_digest: bytes,
        *,
        principal_id: str,
        security_epoch: int,
        purpose: str,
        transport_digest: bytes,
        now: datetime,
    ) -> "StepUpGrantState | None":
        """Atomically burn and return one exact current grant."""
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
