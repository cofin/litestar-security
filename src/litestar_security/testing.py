"""Deterministic conformance helpers for security integration test suites."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hmac import compare_digest

from anyio import Lock

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

__all__ = (
    "FakeClock",
    "InMemoryMFAStore",
    "InMemoryPasskeyStore",
    "InMemoryStepUpStore",
    "InMemoryWebAuthnChallengeStore",
)


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
