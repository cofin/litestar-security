"""MFA assurance, TOTP, recovery, and step-up contracts."""

from base64 import b32decode, urlsafe_b64encode
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha1, sha256, sha512
from hmac import compare_digest
from hmac import new as new_hmac
from secrets import token_bytes, token_urlsafe
from typing import Literal, Protocol, cast, runtime_checkable

import pyotp
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import (
    aware_utc_time,
    new_event_id,
    strict_context_text,
    utc_now,
    valid_security_epoch,
)
from litestar_security.accounts._operations import (
    MFA_RECOVERY_CONSUME,
    MFA_RECOVERY_REPLACE,
    MFA_TOTP_ENROLL,
    MFA_TOTP_REMOVE,
    MFA_TOTP_VERIFY,
    OUTCOME_CREATED,
    OUTCOME_REVOKED,
    OUTCOME_UPDATED,
    OUTCOME_VERIFIED,
)
from litestar_security.accounts._records import (
    LoginMethod,
    NoOpSecurityEventSink,
    RevokeLoginMethodResult,
    SecurityEvent,
    SecurityEventSink,
)
from litestar_security.accounts._stores import LoginMethodStore
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence

__all__ = (
    "MFAService",
    "MFAStore",
    "PendingTOTPEnrollment",
    "ProtectedSecret",
    "RecoveryCodeDigest",
    "RecoveryCodePepper",
    "RecoveryCodes",
    "SecretProtector",
    "StepUpGrant",
    "StepUpRecord",
    "StepUpService",
    "StepUpStore",
    "TOTPEnrollment",
    "TOTPMethod",
    "TOTPPolicy",
)

_MINIMUM_SECRET_BITS = 160
_MAXIMUM_DRIFT_STEPS = 10
_MAXIMUM_PERIOD_SECONDS = 300
_MAXIMUM_ENROLLMENT_TTL = timedelta(hours=1)
_DEFAULT_STEP_UP_TTL = timedelta(minutes=5)
_MAXIMUM_STEP_UP_TTL = timedelta(minutes=15)
_RECOVERY_CODE_BYTES = 16
_STEP_UP_TOKEN_BYTES = 32
_RECOVERY_CODE_COUNT = 10
_MAXIMUM_RECOVERY_CODE_COUNT = 100
_MINIMUM_PEPPER_BYTES = 32
_MAXIMUM_PEPPER_VERSION_LENGTH = 16
_RECOVERY_CODE_PARTS = 3
_ALGORITHMS = {"SHA1": sha1, "SHA256": sha256, "SHA512": sha512}


@dataclass(frozen=True, slots=True)
class TOTPPolicy:
    """Validated interoperable TOTP profile."""

    digits: Literal[6, 8] = 6
    period_seconds: int = 30
    algorithm: Literal["SHA1", "SHA256", "SHA512"] = "SHA1"
    allowed_drift_steps: int = 1
    enrollment_ttl: timedelta = timedelta(minutes=10)

    def __post_init__(self) -> None:
        """Reject ambiguous or resource-unbounded profiles."""
        digits = cast("object", self.digits)
        period_seconds = cast("object", self.period_seconds)
        allowed_drift_steps = cast("object", self.allowed_drift_steps)
        if digits.__class__ is not int or digits not in {6, 8}:
            message = "TOTP digits must be 6 or 8"
            raise ImproperlyConfiguredException(detail=message)
        if (
            period_seconds.__class__ is not int
            or not 1
            <= cast("int", period_seconds)  # type: ignore[redundant-cast]  # pyright does not narrow from __class__
            <= _MAXIMUM_PERIOD_SECONDS
        ):
            message = "TOTP period must be a positive bounded integer"
            raise ImproperlyConfiguredException(detail=message)
        if self.algorithm not in _ALGORITHMS:
            message = "TOTP algorithm must be SHA1, SHA256, or SHA512"
            raise ImproperlyConfiguredException(detail=message)
        if (
            allowed_drift_steps.__class__ is not int
            or not 0
            <= cast("int", allowed_drift_steps)  # type: ignore[redundant-cast]  # pyright does not narrow from __class__
            <= _MAXIMUM_DRIFT_STEPS
        ):
            message = "TOTP drift must be a bounded non-negative integer"
            raise ImproperlyConfiguredException(detail=message)
        if not timedelta() < self.enrollment_ttl <= _MAXIMUM_ENROLLMENT_TTL:
            message = "TOTP enrollment lifetime must be positive and at most one hour"
            raise ImproperlyConfiguredException(detail=message)


@dataclass(frozen=True, slots=True)
class ProtectedSecret:
    """Opaque application-protected secret envelope."""

    ciphertext: bytes = field(repr=False)
    key_version: str

    def __post_init__(self) -> None:
        """Require non-empty ciphertext and a stable key version."""
        ciphertext = cast("object", self.ciphertext)
        if not isinstance(ciphertext, bytes) or not ciphertext or not strict_context_text(self.key_version):
            message = "Protected secret requires ciphertext and a key version"
            raise ValueError(message)


@runtime_checkable
class SecretProtector(Protocol):
    """Protect MFA secrets with application-owned versioned key material."""

    @property
    def active_key_version(self) -> str:
        """Return the stable version used by the next protection operation."""
        ...  # pragma: no cover

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedSecret:
        """Protect a secret under exact associated data.

        Args:
            secret: The plaintext secret to protect.
            associated_data: Account, method, purpose, and key-version binding.

        Returns:
            An opaque ciphertext envelope carrying the selected key version.
        """
        ...  # pragma: no cover

    async def unprotect(self, protected: ProtectedSecret, *, associated_data: bytes) -> bytes:
        """Recover a secret only under the original associated data.

        Args:
            protected: The stored opaque envelope.
            associated_data: Account, method, purpose, and key-version binding.

        Returns:
            The recovered plaintext for immediate verification only.
        """
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class PendingTOTPEnrollment:
    """Stored one-time enrollment containing no recoverable plaintext."""

    enrollment_id: str
    method_id: str
    account_id: str
    protected_secret: ProtectedSecret = field(repr=False)
    policy: TOTPPolicy
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        """Validate enrollment identity and bounded UTC lifetime."""
        created_at = aware_utc_time(self.created_at)
        expires_at = aware_utc_time(self.expires_at)
        if (
            not strict_context_text(self.enrollment_id)
            or not strict_context_text(self.method_id)
            or not strict_context_text(self.account_id)
            or expires_at <= created_at
            or expires_at - created_at > _MAXIMUM_ENROLLMENT_TTL
        ):
            message = "Pending TOTP enrollment requires stable identity and lifetime"
            raise ValueError(message)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "expires_at", expires_at)


@dataclass(frozen=True, slots=True)
class TOTPMethod:
    """Active TOTP method with a monotonic accepted counter."""

    method_id: str
    account_id: str
    protected_secret: ProtectedSecret = field(repr=False)
    policy: TOTPPolicy
    last_accepted_counter: int
    created_at: datetime
    last_used_at: datetime | None = None

    def __post_init__(self) -> None:
        """Validate identity, counter, and UTC timestamps."""
        created_at = aware_utc_time(self.created_at)
        last_used_at = aware_utc_time(self.last_used_at) if self.last_used_at is not None else None
        if (
            not strict_context_text(self.method_id)
            or not strict_context_text(self.account_id)
            or self.last_accepted_counter.__class__ is not int
            or self.last_accepted_counter < 0
        ):
            message = "TOTP method requires stable identity and a non-negative counter"
            raise ValueError(message)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "last_used_at", last_used_at)


@dataclass(frozen=True, slots=True)
class TOTPEnrollment:
    """Reveal-once enrollment URI response."""

    enrollment_id: str
    method_id: str
    provisioning_uri: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RecoveryCodePepper:
    """Versioned HMAC key for non-recoverable recovery-code digests."""

    key_version: str
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Require a stable version and at least 256 bits of key material."""
        key = cast("object", self.key)
        if (
            not strict_context_text(self.key_version)
            or "_" in self.key_version
            or len(self.key_version) > _MAXIMUM_PEPPER_VERSION_LENGTH
            or not isinstance(key, bytes)
            or len(key) < _MINIMUM_PEPPER_BYTES
        ):
            message = "Recovery-code pepper requires a short version and at least 32 key bytes"
            raise ImproperlyConfiguredException(detail=message)


@dataclass(frozen=True, slots=True)
class RecoveryCodeDigest:
    """Stored recovery-code digest carrying no recoverable credential."""

    account_id: str
    pepper_version: str
    digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Require exact HMAC-SHA-256 output and stable bindings."""
        digest = cast("object", self.digest)
        if (
            not strict_context_text(self.account_id)
            or not strict_context_text(self.pepper_version)
            or not isinstance(digest, bytes)
            or len(digest) != sha256().digest_size
        ):
            message = "Recovery-code digest requires account, version, and SHA-256 output"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class RecoveryCodes:
    """Reveal-once recovery-code response."""

    codes: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class StepUpGrant:
    """Reveal-once transport-bound step-up credential."""

    token: str = field(repr=False)
    purpose: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class StepUpRecord:
    """Digest-only one-time step-up state."""

    grant_digest: bytes = field(repr=False)
    transport_digest: bytes = field(repr=False)
    principal_id: str
    security_epoch: int
    purpose: str
    methods: frozenset[str]
    traits: frozenset[str]
    authenticated_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        """Validate exact bindings and a bounded UTC lifetime."""
        authenticated_at = aware_utc_time(self.authenticated_at)
        expires_at = aware_utc_time(self.expires_at)
        if (
            not strict_context_text(self.principal_id)
            or not valid_security_epoch(self.security_epoch)
            or not strict_context_text(self.purpose)
            or len(self.grant_digest) != sha256().digest_size
            or len(self.transport_digest) != sha256().digest_size
            or expires_at <= authenticated_at
            or expires_at - authenticated_at > _MAXIMUM_STEP_UP_TTL
        ):
            message = "Step-up record requires exact identity, transport, purpose, epoch, and lifetime bindings"
            raise ValueError(message)
        object.__setattr__(self, "authenticated_at", authenticated_at)
        object.__setattr__(self, "expires_at", expires_at)


@runtime_checkable
class StepUpStore(Protocol):
    """Persist and atomically consume digest-only step-up grants."""

    async def put(self, record: StepUpRecord) -> None:
        """Persist one unconsumed grant.

        Args:
            record: The complete digest-only grant state.
        """
        ...  # pragma: no cover

    async def consume(  # noqa: PLR0913 - every exact grant binding is an independent store predicate
        self,
        grant_digest: bytes,
        *,
        principal_id: str,
        security_epoch: int,
        purpose: str,
        transport_digest: bytes,
        now: datetime,
    ) -> StepUpRecord | None:
        """Atomically consume only an exact, current binding match.

        Args:
            grant_digest: Digest of the reveal-once credential.
            principal_id: Current authenticated principal.
            security_epoch: Current authoritative account epoch.
            purpose: Exact protected action.
            transport_digest: Digest of the current session or token transport.
            now: UTC consumption time.

        Returns:
            The consumed record only for the single winning exact match.
        """
        ...  # pragma: no cover


@runtime_checkable
class MFAStore(Protocol):
    """Persist TOTP lifecycle through atomic replay boundaries."""

    async def create_totp_enrollment(self, enrollment: PendingTOTPEnrollment) -> None:
        """Store one pending enrollment.

        Args:
            enrollment: Secret-protected enrollment to store.
        """
        ...  # pragma: no cover

    async def get_totp_enrollment(self, enrollment_id: str) -> PendingTOTPEnrollment | None:
        """Load one pending enrollment by its opaque identifier.

        Args:
            enrollment_id: The enrollment identifier.

        Returns:
            The pending enrollment, or ``None``.
        """
        ...  # pragma: no cover

    async def activate_totp(  # noqa: PLR0913 - one atomic port carries every committed factor record
        self,
        account_id: str,
        enrollment_id: str,
        *,
        accepted_counter: int,
        login_method: LoginMethod,
        event: SecurityEvent,
        now: datetime,
    ) -> TOTPMethod | None:
        """Atomically consume an enrollment and register its active login method.

        Args:
            account_id: The owning account.
            enrollment_id: The pending enrollment to consume.
            accepted_counter: The counter verified during activation.
            login_method: The viable method to register in the shared account inventory.
            event: The durable creation event to commit with both records.
            now: The commit timestamp.

        Returns:
            The active method only for the single winning consumption.
        """
        ...  # pragma: no cover

    async def activate_totp_with_recovery_codes(  # noqa: PLR0913 - one atomic port carries every committed factor record
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
        """Atomically activate TOTP and replace the complete recovery-code set.

        Implementations must consume the enrollment, create the active method,
        replace recovery codes, register the viable login method, and commit
        the event in one transaction or perform none of them.

        Args:
            account_id: The owning account.
            enrollment_id: The pending enrollment to consume.
            accepted_counter: The counter verified during activation.
            codes: The complete recovery-code replacement set.
            login_method: The viable method to register in the shared account inventory.
            event: The durable creation event to commit with every record.
            now: The commit timestamp.

        Returns:
            The active method only for the single winning atomic commit.
        """
        ...  # pragma: no cover

    async def get_totp_method(self, account_id: str, method_id: str) -> TOTPMethod | None:
        """Load an active method only for its owner.

        Args:
            account_id: The expected owner.
            method_id: The method identifier.

        Returns:
            The method, or ``None``.
        """
        ...  # pragma: no cover

    async def advance_totp_counter(self, method_id: str, *, accepted_counter: int, now: datetime) -> bool:
        """Atomically advance only to a strictly greater accepted counter.

        Args:
            method_id: The active method.
            accepted_counter: The verified counter.
            now: The commit timestamp.

        Returns:
            ``True`` for the single accepted advance.
        """
        ...  # pragma: no cover

    async def replace_recovery_codes(
        self, account_id: str, codes: tuple[RecoveryCodeDigest, ...], *, now: datetime
    ) -> None:
        """Atomically replace every recovery code for an account.

        Args:
            account_id: The owning account.
            codes: The complete replacement set of HMAC digests.
            now: The commit timestamp.
        """
        ...  # pragma: no cover

    async def consume_recovery_code(self, account_id: str, digest: bytes, *, now: datetime) -> bool:
        """Atomically compare in constant time and consume one digest.

        Implementations must compare the supplied digest in constant time and
        remove exactly one matching unused record in the same transaction.

        Args:
            account_id: The expected owner.
            digest: The HMAC digest to compare.
            now: The commit timestamp.

        Returns:
            ``True`` only for the single winning consumption.
        """
        ...  # pragma: no cover


@dataclass(slots=True)
class MFAService:
    """Orchestrate protected TOTP enrollment and replay-safe verification."""

    store: MFAStore
    secret_protector: SecretProtector
    policy: TOTPPolicy = field(default_factory=TOTPPolicy)
    issuer: str = "Litestar Security"
    clock: Callable[[], datetime] = field(default=utc_now, repr=False, compare=False)
    secret_generator: Callable[[], str] = field(
        default=lambda: pyotp.random_base32(length=32), repr=False, compare=False
    )
    identifiers: Callable[[], str] = field(default=lambda: token_urlsafe(18), repr=False, compare=False)
    login_methods: LoginMethodStore | None = field(default=None, repr=False, compare=False)
    recovery_peppers: tuple[RecoveryCodePepper, ...] = field(default=(), repr=False)
    recovery_code_count: int = _RECOVERY_CODE_COUNT
    recovery_entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)
    events: SecurityEventSink = field(default_factory=NoOpSecurityEventSink, repr=False, compare=False)
    event_ids: Callable[[], str] = field(default=new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate structural capabilities and stable issuer configuration."""
        store = cast("object", self.store)
        secret_protector = cast("object", self.secret_protector)
        if not isinstance(store, MFAStore):
            message = "MFA service store must implement MFAStore"
            raise ImproperlyConfiguredException(detail=message)
        if not isinstance(secret_protector, SecretProtector):
            message = "MFA secret protector must implement SecretProtector"
            raise ImproperlyConfiguredException(detail=message)
        if not strict_context_text(self.issuer):
            message = "MFA issuer must be non-blank text"
            raise ImproperlyConfiguredException(detail=message)
        self.recovery_peppers = tuple(self.recovery_peppers)

    async def begin_totp_enrollment(self, account_id: str, *, label: str) -> TOTPEnrollment | VerificationUnavailable:
        """Create and persist one reveal-once TOTP enrollment.

        Args:
            account_id: The account gaining the method.
            label: The account label shown by an authenticator.

        Returns:
            A reveal-once provisioning URI or sanitized operational failure.
        """
        try:
            now = aware_utc_time(self.clock())
            enrollment_id = self.identifiers()
            method_id = self.identifiers()
            secret = self.secret_generator()
            _validate_secret(secret)
            key_version = self.secret_protector.active_key_version
            associated_data = _totp_associated_data(account_id, method_id, key_version)
            protected = await self.secret_protector.protect(secret.encode("ascii"), associated_data=associated_data)
            if protected.key_version != key_version:
                return VerificationUnavailable()
            pending = PendingTOTPEnrollment(
                enrollment_id=enrollment_id,
                method_id=method_id,
                account_id=account_id,
                protected_secret=protected,
                policy=self.policy,
                created_at=now,
                expires_at=now + self.policy.enrollment_ttl,
            )
            totp = _totp(secret, self.policy)
            provisioning_uri = cast(
                "Callable[[str | None, str | None], str]",
                totp.provisioning_uri,  # pyright: ignore[reportUnknownMemberType] - PyOTP exposes untyped kwargs
            )
            uri = provisioning_uri(label, self.issuer)
            await self.store.create_totp_enrollment(pending)
        except Exception:  # noqa: BLE001 - sanitize application protector/store and entropy failures
            return VerificationUnavailable()
        await self._emit_event(
            operation=MFA_TOTP_ENROLL, outcome=OUTCOME_CREATED, account_id=account_id, occurred_at=now
        )
        return TOTPEnrollment(
            enrollment_id=enrollment_id, method_id=method_id, provisioning_uri=uri, expires_at=pending.expires_at
        )

    async def activate_totp(
        self, account_id: str, enrollment_id: str, code: str
    ) -> TOTPMethod | InvalidCredentials | VerificationUnavailable:
        """Verify and atomically consume a pending enrollment.

        Args:
            account_id: The expected enrollment owner.
            enrollment_id: The pending enrollment.
            code: The presented TOTP value.

        Returns:
            The active method, generic invalid credentials, or operational failure.
        """
        try:
            now = aware_utc_time(self.clock())
            enrollment = await self.store.get_totp_enrollment(enrollment_id)
            if enrollment is None or enrollment.account_id != account_id or enrollment.expires_at <= now:
                return InvalidCredentials()
            secret = await self._recover_secret(account_id, enrollment.method_id, enrollment.protected_secret)
            counter = _accepted_counter(secret, code, now, enrollment.policy)
            if counter is None:
                return InvalidCredentials()
            login_method = LoginMethod(method_id=enrollment.method_id, kind="totp", created_at=now)
            method = await self.store.activate_totp(
                account_id,
                enrollment_id,
                accepted_counter=counter,
                login_method=login_method,
                event=SecurityEvent(
                    event_id=self.event_ids(),
                    occurred_at=now,
                    operation=MFA_TOTP_VERIFY,
                    outcome=OUTCOME_VERIFIED,
                    account_id=account_id,
                ),
                now=now,
            )
        except Exception:  # noqa: BLE001 - sanitize application protector/store failures
            return VerificationUnavailable()
        if method is None:
            return InvalidCredentials()
        return method

    async def activate_totp_with_recovery_codes(
        self, account_id: str, enrollment_id: str, code: str
    ) -> RecoveryCodes | InvalidCredentials | VerificationUnavailable:
        """Activate one enrollment and replace recovery codes in one atomic commit.

        Args:
            account_id: The expected enrollment owner.
            enrollment_id: The pending enrollment.
            code: The presented TOTP value.

        Returns:
            Reveal-once recovery codes, generic invalid credentials, or an
            operational failure.
        """
        try:
            now = aware_utc_time(self.clock())
            enrollment = await self.store.get_totp_enrollment(enrollment_id)
            if enrollment is None or enrollment.account_id != account_id or enrollment.expires_at <= now:
                return InvalidCredentials()
            secret = await self._recover_secret(account_id, enrollment.method_id, enrollment.protected_secret)
            counter = _accepted_counter(secret, code, now, enrollment.policy)
            if counter is None:
                return InvalidCredentials()
            peppers = _validate_recovery_configuration(self.recovery_peppers, self.recovery_code_count)
            active = peppers[0]
            codes = _generate_recovery_codes(active.key_version, self.recovery_code_count, self.recovery_entropy)
            digests = tuple(
                RecoveryCodeDigest(
                    account_id=account_id,
                    pepper_version=active.key_version,
                    digest=_recovery_digest(active, recovery_code),
                )
                for recovery_code in codes
            )
            method = await self.store.activate_totp_with_recovery_codes(
                account_id,
                enrollment_id,
                accepted_counter=counter,
                codes=digests,
                login_method=LoginMethod(method_id=enrollment.method_id, kind="totp", created_at=now),
                event=SecurityEvent(
                    event_id=self.event_ids(),
                    occurred_at=now,
                    operation=MFA_TOTP_VERIFY,
                    outcome=OUTCOME_VERIFIED,
                    account_id=account_id,
                ),
                now=now,
            )
        except Exception:  # noqa: BLE001 - sanitize application protector, entropy, and store failures
            return VerificationUnavailable()
        if method is None:
            return InvalidCredentials()
        await self._emit_event(
            operation=MFA_TOTP_VERIFY, outcome=OUTCOME_VERIFIED, account_id=account_id, occurred_at=now
        )
        await self._emit_event(
            operation=MFA_RECOVERY_REPLACE, outcome=OUTCOME_CREATED, account_id=account_id, occurred_at=now
        )
        return RecoveryCodes(codes=codes)

    async def verify_totp(
        self, account_id: str, method_id: str, code: str
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        """Verify a TOTP and atomically prevent counter replay.

        Args:
            account_id: The expected method owner.
            method_id: The active method.
            code: The presented TOTP value.

        Returns:
            Fresh TOTP evidence, generic invalid credentials, or operational failure.
        """
        try:
            now = aware_utc_time(self.clock())
            method = await self.store.get_totp_method(account_id, method_id)
            if method is None:
                return InvalidCredentials()
            secret = await self._recover_secret(account_id, method_id, method.protected_secret)
            counter = _accepted_counter(secret, code, now, method.policy)
            if counter is None or counter <= method.last_accepted_counter:
                return InvalidCredentials()
            if not await self.store.advance_totp_counter(method_id, accepted_counter=counter, now=now):
                return InvalidCredentials()
        except Exception:  # noqa: BLE001 - sanitize application protector/store failures
            return VerificationUnavailable()
        await self._emit_event(
            operation=MFA_TOTP_VERIFY, outcome=OUTCOME_VERIFIED, account_id=account_id, occurred_at=now
        )
        return AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=now, methods=frozenset({"totp"}))

    async def generate_recovery_codes(self, account_id: str) -> RecoveryCodes | VerificationUnavailable:
        """Atomically replace and reveal one set of recovery codes.

        Args:
            account_id: The account receiving the replacement set.

        Returns:
            Reveal-once codes or a sanitized operational failure.
        """
        try:
            now = aware_utc_time(self.clock())
            peppers = _validate_recovery_configuration(self.recovery_peppers, self.recovery_code_count)
            active = peppers[0]
            codes = _generate_recovery_codes(active.key_version, self.recovery_code_count, self.recovery_entropy)
            digests = tuple(
                RecoveryCodeDigest(
                    account_id=account_id, pepper_version=active.key_version, digest=_recovery_digest(active, code)
                )
                for code in codes
            )
            await self.store.replace_recovery_codes(account_id, digests, now=now)
        except Exception:  # noqa: BLE001 - sanitize application store, clock, and entropy failures
            return VerificationUnavailable()
        await self._emit_event(
            operation=MFA_RECOVERY_REPLACE, outcome=OUTCOME_UPDATED, account_id=account_id, occurred_at=now
        )
        return RecoveryCodes(codes=codes)

    async def consume_recovery_code(
        self, account_id: str, code: str
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        """Verify and atomically consume one recovery code.

        Args:
            account_id: The expected code owner.
            code: The reveal-once recovery credential.

        Returns:
            Recovery evidence, generic invalid credentials, or operational failure.
        """
        try:
            now = aware_utc_time(self.clock())
            version = _recovery_code_version(code)
            pepper = next((candidate for candidate in self.recovery_peppers if candidate.key_version == version), None)
            if pepper is None:
                return InvalidCredentials()
            digest = _recovery_digest(pepper, code)
            if not await self.store.consume_recovery_code(account_id, digest, now=now):
                return InvalidCredentials()
        except (TypeError, ValueError):
            return InvalidCredentials()
        except Exception:  # noqa: BLE001 - sanitize application store and clock failures
            return VerificationUnavailable()
        await self._emit_event(
            operation=MFA_RECOVERY_CONSUME, outcome=OUTCOME_VERIFIED, account_id=account_id, occurred_at=now
        )
        return AuthenticationEvidence(
            mechanism="recovery-code", slot="mfa", authenticated_at=now, methods=frozenset({"recovery-code"})
        )

    async def remove_totp_method(
        self, account_id: str, method_id: str
    ) -> RevokeLoginMethodResult | VerificationUnavailable:
        """Remove a TOTP method through the shared final-method-safe operation.

        Args:
            account_id: The owning account.
            method_id: The TOTP method to remove.

        Returns:
            The atomic revocation result or sanitized operational failure.
        """
        login_methods = self.login_methods
        if login_methods is None:
            return VerificationUnavailable()
        try:
            now = aware_utc_time(self.clock())
            event = SecurityEvent(
                event_id=self.event_ids(),
                occurred_at=now,
                operation=MFA_TOTP_REMOVE,
                outcome=OUTCOME_REVOKED,
                account_id=account_id,
            )
            return await login_methods.revoke_login_method(account_id, method_id, require_remaining=True, event=event)
        except Exception:  # noqa: BLE001 - sanitize application login-method store failures
            return VerificationUnavailable()

    async def _recover_secret(self, account_id: str, method_id: str, protected: ProtectedSecret) -> str:
        associated_data = _totp_associated_data(account_id, method_id, protected.key_version)
        plaintext = await self.secret_protector.unprotect(protected, associated_data=associated_data)
        secret = plaintext.decode("ascii")
        _validate_secret(secret)
        return secret

    async def _emit_event(self, *, operation: str, outcome: str, account_id: str, occurred_at: datetime) -> None:
        try:
            await self.events.emit(
                SecurityEvent(
                    event_id=self.event_ids(),
                    occurred_at=occurred_at,
                    operation=operation,
                    outcome=outcome,
                    account_id=account_id,
                )
            )
        except Exception:  # noqa: BLE001 - observational audit failure cannot change a settled decision
            return


@dataclass(slots=True)
class StepUpService:
    """Issue and consume opaque grants bound to one authenticated transport."""

    store: StepUpStore
    ttl: timedelta = _DEFAULT_STEP_UP_TTL
    clock: Callable[[], datetime] = field(default=utc_now, repr=False, compare=False)
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate the atomic store and bounded grant lifetime."""
        if not isinstance(cast("object", self.store), StepUpStore):
            message = "Step-up service store must implement StepUpStore"
            raise ImproperlyConfiguredException(detail=message)
        if not timedelta() < self.ttl <= _MAXIMUM_STEP_UP_TTL:
            message = "Step-up grant lifetime must be positive and at most fifteen minutes"
            raise ImproperlyConfiguredException(detail=message)

    async def issue(
        self,
        *,
        principal_id: str,
        security_epoch: int,
        purpose: str,
        transport_binding: bytes,
        evidence: AuthenticationEvidence,
    ) -> StepUpGrant | InvalidCredentials | VerificationUnavailable:
        """Issue one opaque grant from freshly verified factor evidence.

        Args:
            principal_id: Current authenticated principal.
            security_epoch: Current authoritative account epoch.
            purpose: Exact action the grant may authorize.
            transport_binding: Current session or token proof bytes.
            evidence: Factor evidence verified by an MFA or passkey service.

        Returns:
            A reveal-once grant or a sanitized rejection.
        """
        try:
            now = aware_utc_time(self.clock())
            if (
                not strict_context_text(principal_id)
                or not valid_security_epoch(security_epoch)
                or not strict_context_text(purpose)
                or not transport_binding
                or evidence.authenticated_at > now
                or now - evidence.authenticated_at > self.ttl
            ):
                return InvalidCredentials()
            raw_value = cast("object", self.entropy(_STEP_UP_TOKEN_BYTES))
            if not isinstance(raw_value, bytes) or len(raw_value) != _STEP_UP_TOKEN_BYTES:
                return VerificationUnavailable()
            raw = raw_value
            token = urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
            expires_at = now + self.ttl
            await self.store.put(
                StepUpRecord(
                    grant_digest=sha256(token.encode("ascii")).digest(),
                    transport_digest=sha256(transport_binding).digest(),
                    principal_id=principal_id,
                    security_epoch=security_epoch,
                    purpose=purpose,
                    methods=evidence.methods,
                    traits=evidence.traits,
                    authenticated_at=now,
                    expires_at=expires_at,
                )
            )
        except Exception:  # noqa: BLE001 - sanitize application stores, clocks, and entropy failures
            return VerificationUnavailable()
        return StepUpGrant(token=token, purpose=purpose, expires_at=expires_at)

    async def consume(
        self, token: str, *, principal_id: str, security_epoch: int, purpose: str, transport_binding: bytes
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        """Consume one exact principal, epoch, purpose, and transport binding.

        Args:
            token: Reveal-once opaque grant.
            principal_id: Current authenticated principal.
            security_epoch: Current authoritative account epoch.
            purpose: Exact protected action.
            transport_binding: Current session or token proof bytes.

        Returns:
            Purpose evidence only for the one winning atomic consumption.
        """
        try:
            now = aware_utc_time(self.clock())
            if (
                not strict_context_text(token)
                or not strict_context_text(principal_id)
                or not valid_security_epoch(security_epoch)
                or not strict_context_text(purpose)
                or not transport_binding
            ):
                return InvalidCredentials()
            record = await self.store.consume(
                sha256(token.encode("ascii")).digest(),
                principal_id=principal_id,
                security_epoch=security_epoch,
                purpose=purpose,
                transport_digest=sha256(transport_binding).digest(),
                now=now,
            )
        except Exception:  # noqa: BLE001 - sanitize application store and clock failures
            return VerificationUnavailable()
        if record is None:
            return InvalidCredentials()
        return AuthenticationEvidence(
            mechanism="step-up",
            slot="mfa",
            authenticated_at=record.authenticated_at,
            expires_at=record.expires_at,
            methods=record.methods,
            traits=record.traits | frozenset({f"purpose:{purpose}"}),
        )


def _validate_secret(secret: str) -> None:
    secret_value = cast("object", secret)
    if not isinstance(secret_value, str) or secret_value.__class__ is not str:
        raise ValueError
    try:
        decoded = b32decode(secret, casefold=False)
    except (UnicodeEncodeError, ValueError):
        raise ValueError from None
    if len(decoded) * 8 < _MINIMUM_SECRET_BITS:
        raise ValueError


def _totp(secret: str, policy: TOTPPolicy) -> pyotp.TOTP:
    return pyotp.TOTP(
        secret, digits=policy.digits, digest=_ALGORITHMS[policy.algorithm], interval=policy.period_seconds
    )


def _accepted_counter(secret: str, code: str, now: datetime, policy: TOTPPolicy) -> int | None:
    code_value = cast("object", code)
    if (
        not isinstance(code_value, str)
        or code_value.__class__ is not str
        or len(code_value) != policy.digits
        or not code_value.isascii()
    ):
        return None
    if not code.isdigit():
        return None
    current = int(now.timestamp()) // policy.period_seconds
    generator = _totp(secret, policy)
    accepted: int | None = None
    for offset in range(-policy.allowed_drift_steps, policy.allowed_drift_steps + 1):
        counter = current + offset
        if counter >= 0 and compare_digest(generator.generate_otp(counter), code):
            accepted = counter
    return accepted


def _totp_associated_data(account_id: str, method_id: str, key_version: str) -> bytes:
    values = (account_id, method_id, "totp", key_version)
    if not all(strict_context_text(value) and "\x00" not in value for value in values):
        raise ValueError
    return b"\x00".join(value.encode("utf-8") for value in values)


def _validate_recovery_configuration(
    peppers: tuple[RecoveryCodePepper, ...], count: int
) -> tuple[RecoveryCodePepper, ...]:
    if (
        not peppers
        or len({pepper.key_version for pepper in peppers}) != len(peppers)
        or count.__class__ is not int
        or not 1 <= count <= _MAXIMUM_RECOVERY_CODE_COUNT
    ):
        raise ValueError
    return peppers


def _generate_recovery_codes(key_version: str, count: int, entropy: Callable[[int], bytes]) -> tuple[str, ...]:
    codes: list[str] = []
    attempts = 0
    while len(codes) < count and attempts < count * 4:
        attempts += 1
        value = entropy(_RECOVERY_CODE_BYTES)
        value_object = cast("object", value)
        if not isinstance(value_object, bytes) or len(value_object) != _RECOVERY_CODE_BYTES:
            raise ValueError
        code = f"rc_{key_version}_{value.hex().upper()}"
        if code not in codes:
            codes.append(code)
    if len(codes) != count:
        raise ValueError
    return tuple(codes)


def _recovery_code_version(code: str) -> str:
    code_value = cast("object", code)
    if not isinstance(code_value, str) or code_value.__class__ is not str:
        raise TypeError
    parts = code_value.split("_")
    if (
        len(parts) != _RECOVERY_CODE_PARTS
        or parts[0] != "rc"
        or not strict_context_text(parts[1])
        or len(parts[2]) != _RECOVERY_CODE_BYTES * 2
        or parts[2] != parts[2].upper()
        or any(character not in "0123456789ABCDEF" for character in parts[2])
    ):
        raise ValueError
    return parts[1]


def _recovery_digest(pepper: RecoveryCodePepper, code: str) -> bytes:
    _recovery_code_version(code)
    payload = b"litestar-security:recovery-code:v1\x00" + code.encode("ascii")
    return new_hmac(pepper.key, payload, sha256).digest()
