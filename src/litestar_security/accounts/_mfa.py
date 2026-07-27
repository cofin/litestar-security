"""MFA assurance, TOTP, recovery, and step-up contracts."""

from base64 import b32decode
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha1, sha256, sha512
from hmac import compare_digest
from secrets import token_urlsafe
from typing import Literal, Protocol, cast, runtime_checkable

import pyotp
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import aware_utc_time, strict_context_text, utc_now
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence

__all__ = (
    "MFAService",
    "MFAStore",
    "PendingTOTPEnrollment",
    "ProtectedSecret",
    "SecretProtector",
    "TOTPEnrollment",
    "TOTPMethod",
    "TOTPPolicy",
)

_MINIMUM_SECRET_BITS = 160
_MAXIMUM_DRIFT_STEPS = 10
_MAXIMUM_PERIOD_SECONDS = 300
_MAXIMUM_ENROLLMENT_TTL = timedelta(hours=1)
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

    async def activate_totp(
        self, account_id: str, enrollment_id: str, *, accepted_counter: int, now: datetime
    ) -> TOTPMethod | None:
        """Atomically consume an enrollment and create its active method.

        Args:
            account_id: The owning account.
            enrollment_id: The pending enrollment to consume.
            accepted_counter: The counter verified during activation.
            now: The commit timestamp.

        Returns:
            The active method only for the single winning consumption.
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
            method = await self.store.activate_totp(account_id, enrollment_id, accepted_counter=counter, now=now)
        except Exception:  # noqa: BLE001 - sanitize application protector/store failures
            return VerificationUnavailable()
        return method if method is not None else InvalidCredentials()

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
        return AuthenticationEvidence(mechanism="totp", slot="mfa", authenticated_at=now, methods=frozenset({"totp"}))

    async def _recover_secret(self, account_id: str, method_id: str, protected: ProtectedSecret) -> str:
        associated_data = _totp_associated_data(account_id, method_id, protected.key_version)
        plaintext = await self.secret_protector.unprotect(protected, associated_data=associated_data)
        secret = plaintext.decode("ascii")
        _validate_secret(secret)
        return secret


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
