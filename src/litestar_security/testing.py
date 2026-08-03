"""Deterministic conformance helpers for security integration test suites."""

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from hmac import compare_digest
from types import MappingProxyType
from typing import cast
from urllib.parse import parse_qsl

import httpx
from anyio import Event, Lock, create_task_group

from litestar_security.accounts import (
    AssertionRecordResult,
    LoginMethod,
    PasskeyCredential,
    PendingTOTPEnrollment,
    RecoveryCodeDigest,
    SecurityEvent,
    StepUpRecord,
    TOTPMethod,
    WebAuthnChallenge,
)
from litestar_security.providers.api_key import APIKeyRecord, APIKeyStore
from litestar_security.providers.oauth import (
    MemoryOAuthAccountStore,
    MemoryOAuthTransactionStore,
    MemoryTokenVault,
    OAuthTransaction,
    OAuthTransactionProtector,
    OAuthTransactionStart,
    ProtectedOAuthSecret,
    ProviderIdentity,
    ProviderTokenSet,
    SecretStr,
)
from litestar_security.websocket import InMemoryWebSocketConnectTokenStore

__all__ = (
    "BackendBarrier",
    "BackendEvent",
    "FakeClock",
    "FakeOAuthHTTPTransport",
    "FakeOAuthProvider",
    "InMemoryAPIKeyStore",
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
    "assert_security_backend_conformance",
)

_DEFAULT_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_DEFAULT_CREDENTIAL_HASH = "$litestar-security$deterministic-test-hash"


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
        "api_keys",
        "challenges",
        "mfa",
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
        self.challenges = InMemoryWebAuthnChallengeStore()
        self.passkeys = InMemoryPasskeyStore()
        self.step_up = InMemoryStepUpStore()
        self.oauth_accounts = MemoryOAuthAccountStore()
        self.oauth_transactions = MemoryOAuthTransactionStore(protector=selected_protector)
        self.oauth_tokens = MemoryTokenVault(provider="test", client_id="test-client", protector=selected_protector)
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


async def assert_api_key_store_conformance(  # noqa: C901 - one scenario keeps each API-key invariant in order
    factory: Callable[[], APIKeyStore],
) -> None:
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
    outcomes: list[bool] = []

    async def rotate(replacement: APIKeyRecord) -> None:
        try:
            await store.rotate(
                current_key_id=current.key_id,
                replacement=replacement,
                overlap_until=_DEFAULT_NOW + timedelta(seconds=30),
                now=_DEFAULT_NOW,
            )
        except Exception:  # noqa: BLE001 - conformance accepts implementation-specific conflict exceptions
            outcomes.append(False)
        else:
            outcomes.append(True)

    async with create_task_group() as task_group:
        for replacement in replacements:
            task_group.start_soon(rotate, replacement)
    if outcomes.count(True) != 1:
        message = (
            "APIKeyStore.rotate atomicity invariant: two contenders must produce one atomic winner "
            f"(observed {outcomes.count(True)})"
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
