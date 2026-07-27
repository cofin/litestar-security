"""Backend-agnostic local-account contracts and explicit transport profiles."""

from collections.abc import Mapping  # noqa: TC003 - Litestar resolves public annotations at runtime
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import partial
from hmac import compare_digest
from logging import getLogger
from time import perf_counter
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic, Protocol, TypeVar, runtime_checkable
from unicodedata import normalize
from uuid import uuid4

from anyio import to_thread
from argon2 import PasswordHasher as _Argon2Engine
from argon2 import extract_parameters
from argon2.exceptions import Argon2Error, InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type as Argon2Type
from litestar.config.csrf import CSRFConfig
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts.sessions import RefreshTokenFamilyStore, SessionBindingConfig, SessionRegistry
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.config import ExternalCSRF, WorkerLimits
from litestar_security.context import AuthenticationEvidence
from litestar_security.providers.jwt import LocalKeyRing

if TYPE_CHECKING:
    from collections.abc import Callable

    from argon2 import Parameters

__all__ = (
    "AccountLookup",
    "Argon2PasswordHasher",
    "ConsumeResult",
    "ConsumeStatus",
    "LocalAccount",
    "LocalAccountCapabilities",
    "LocalAuth",
    "LocalAuthConfig",
    "LocalAuthMode",
    "LoginMethod",
    "LoginMethodStore",
    "NoOpSecurityEventSink",
    "NotificationCommand",
    "PasswordChangeResult",
    "PasswordChangeStatus",
    "PasswordCredentialStore",
    "PasswordHasher",
    "PasswordHashingUnavailableError",
    "PasswordPolicy",
    "PasswordPolicyResult",
    "PasswordPolicyViolation",
    "PasswordReauthenticationService",
    "PasswordResetResult",
    "PasswordResetStatus",
    "PasswordVerificationResult",
    "PasswordVerificationStatus",
    "RecoveryTokenStore",
    "RegistrationCommand",
    "RegistrationMode",
    "RegistrationPolicy",
    "RegistrationResult",
    "RegistrationStatus",
    "RegistrationStore",
    "RevokeLoginMethodResult",
    "RevokeLoginMethodStatus",
    "SecurityEpochStore",
    "SecurityEvent",
    "SecurityEventSink",
    "TokenIssue",
    "VerificationTokenStore",
    "normalize_identifier",
)

UserT = TypeVar("UserT")
_EMPTY_CORRELATION: "Mapping[str, str]" = MappingProxyType({})
_ASCII_CONTROL_LIMIT = 32
_MAXIMUM_PASSWORD_BYTES = 1_024
_DEFAULT_REAUTHENTICATION_TTL = timedelta(minutes=5)
_DUMMY_PASSWORD = b"litestar-security constant-work password"
_DEFAULT_DUMMY_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$1jpw6PiEXNroO450O0ENlg$k5iQe1zKB0ogyhtm3Mlb9jKlwlPcJ5YeD5GJQ9faW+E"
)
_MAXIMUM_ARGON2_MEMORY_COST = 262_144
_MAXIMUM_ARGON2_TIME_COST = 10
_MAXIMUM_ARGON2_PARALLELISM = 8
_MAXIMUM_ARGON2_SALT_LENGTH = 64
_MAXIMUM_ARGON2_HASH_LENGTH = 64
_MAXIMUM_ENCODED_PASSWORD_HASH_BYTES = 1_024
_MAXIMUM_ARGON2_WORKER_MEMORY_KIB = 1_048_576
_ARGON2_VERSION = 19
_LOGGER = getLogger(__name__)


class LocalAuthMode(str, Enum):
    """Visible local-authentication transport selection."""

    SESSION = "session"
    TOKENS = "tokens"
    HYBRID = "hybrid"


class RegistrationMode(str, Enum):
    """Supported self-service registration policies."""

    DISABLED = "disabled"
    PUBLIC = "public"
    INVITE_ONLY = "invite_only"


class PasswordChangeStatus(str, Enum):
    """Atomic password-change outcomes."""

    CHANGED = "changed"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"


class PasswordPolicyViolation(str, Enum):
    """Secret-free reasons a candidate password does not satisfy policy."""

    TOO_SHORT = "too_short"
    TOO_LONG = "too_long"
    TOO_MANY_BYTES = "too_many_bytes"
    INVALID_TEXT = "invalid_text"
    MATCHES_IDENTIFIER = "matches_identifier"
    COMPROMISED = "compromised"


class PasswordVerificationStatus(str, Enum):
    """Sanitized outcomes from one constant-work password verification."""

    VERIFIED = "verified"
    INVALID = "invalid"
    MALFORMED = "malformed"
    TOO_LONG = "too_long"


class RevokeLoginMethodStatus(str, Enum):
    """Atomic login-method revocation outcomes."""

    REVOKED = "revoked"
    NOT_FOUND = "not_found"
    FINAL_METHOD = "final_method"


class RegistrationStatus(str, Enum):
    """Atomic registration outcomes."""

    CREATED = "created"
    DUPLICATE = "duplicate"
    INVALID_INVITATION = "invalid_invitation"


class ConsumeStatus(str, Enum):
    """Atomic purpose-token consumption outcomes."""

    CONSUMED = "consumed"
    INVALID = "invalid"
    EXPIRED = "expired"
    USED = "used"


class PasswordResetStatus(str, Enum):
    """Atomic recovery-token/password-reset outcomes."""

    RESET = "reset"
    INVALID = "invalid"
    EXPIRED = "expired"
    USED = "used"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class LocalAccount(Generic[UserT]):
    """Application-owned account projection needed by local authentication."""

    account_id: str
    normalized_identifier: str
    display_name: str | None
    active: bool
    verified: bool
    security_epoch: int
    user: UserT | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class LoginMethod:
    """One application-owned viable login method."""

    method_id: str
    kind: str
    created_at: "datetime"
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Secret-free event committed with a security decision or mutation."""

    event_id: str
    occurred_at: "datetime"
    operation: str
    outcome: str
    account_id: str | None = None
    principal_id: str | None = None
    mechanism: str | None = None
    session_id: str | None = None
    family_id: str | None = None
    correlation: "Mapping[str, str]" = field(default=_EMPTY_CORRELATION)

    def __post_init__(self) -> None:
        """Freeze caller-supplied correlation fields."""
        object.__setattr__(self, "correlation", MappingProxyType(dict(self.correlation)))


@runtime_checkable
class SecurityEventSink(Protocol):
    """Application-owned sink for secret-free, non-transactional decisions."""

    async def emit(self, event: SecurityEvent) -> None:
        """Record one sanitized security decision."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class NoOpSecurityEventSink:
    """Accept security events when an application has not configured a sink."""

    async def emit(self, event: SecurityEvent) -> None:
        """Discard one already-sanitized observational event."""
        del event


@dataclass(frozen=True, slots=True)
class TokenIssue:
    """Hashed, purpose-bound token material accepted by an atomic store."""

    token_id: str
    digest: bytes = field(repr=False)
    purpose: str
    account_id: str
    expires_at: "datetime"
    maximum_attempts: int


@dataclass(frozen=True, slots=True)
class NotificationCommand:
    """Delivery-neutral notification data with a one-time opaque token."""

    template: str
    destination: str = field(repr=False)
    token: str = field(repr=False)
    expires_at: "datetime"
    return_url: str | None = None


@dataclass(frozen=True, slots=True)
class RegistrationCommand:
    """Application-neutral local registration input."""

    normalized_identifier: str = field(repr=False)
    display_name: str | None = None


def normalize_identifier(value: str) -> str:
    """Apply the default compatibility, whitespace, and case normalization."""
    if value.__class__ is not str:
        msg = "Identifier normalization requires text"
        raise ValueError(msg)
    return normalize("NFKC", value).strip().casefold()


def _password_shape_violations(password: str, policy: "PasswordPolicy") -> set[PasswordPolicyViolation]:
    violations: set[PasswordPolicyViolation] = set()
    if len(password) < policy.minimum_length:
        violations.add(PasswordPolicyViolation.TOO_SHORT)
    if len(password) > policy.maximum_length:
        violations.add(PasswordPolicyViolation.TOO_LONG)
    try:
        password_bytes = password.encode("utf-8")
    except UnicodeEncodeError:
        violations.add(PasswordPolicyViolation.INVALID_TEXT)
    else:
        if len(password_bytes) > policy.maximum_bytes:
            violations.add(PasswordPolicyViolation.TOO_MANY_BYTES)
    return violations


def _password_matches_identifier(password: str, normalized_identifier: str, normalizer: "Callable[[str], str]") -> bool:
    candidate = normalizer(password).encode("utf-8")
    expected = normalizer(normalized_identifier).encode("utf-8")
    return compare_digest(candidate, expected)


@dataclass(frozen=True, slots=True)
class PasswordPolicyResult:
    """Secret-free immutable password-policy decision."""

    violations: frozenset[PasswordPolicyViolation] = frozenset()

    @property
    def accepted(self) -> bool:
        """Return whether no policy violation was found."""
        return not self.violations


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """Length-first password policy without composition or rotation rules."""

    minimum_length: int = 15
    maximum_length: int = 128
    maximum_bytes: int = _MAXIMUM_PASSWORD_BYTES
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    compromised: "Callable[[str], bool] | None" = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Reject contradictory bounds and invalid customization hooks."""
        normalizer_value: object = object.__getattribute__(self, "normalizer")
        compromised_value: object = object.__getattribute__(self, "compromised")
        if (
            self.minimum_length.__class__ is not int
            or self.maximum_length.__class__ is not int
            or self.maximum_bytes.__class__ is not int
            or self.minimum_length < 1
            or self.maximum_length < self.minimum_length
            or not 1 <= self.maximum_bytes <= _MAXIMUM_PASSWORD_BYTES
        ):
            msg = "Password policy lengths must be positive, ordered, and bounded"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(normalizer_value):
            msg = "Password policy normalizer must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        if compromised_value is not None and not callable(compromised_value):
            msg = "Password policy compromised-password predicate must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    def check(self, password: str, *, normalized_identifier: str | None = None) -> PasswordPolicyResult:
        """Evaluate one candidate without retaining or rendering it."""
        if password.__class__ is not str:
            return PasswordPolicyResult(frozenset({PasswordPolicyViolation.INVALID_TEXT}))
        violations = _password_shape_violations(password, self)
        if normalized_identifier is not None:
            try:
                matches_identifier = _password_matches_identifier(password, normalized_identifier, self.normalizer)
            except (TypeError, UnicodeError, ValueError):
                violations.add(PasswordPolicyViolation.INVALID_TEXT)
            else:
                if matches_identifier:
                    violations.add(PasswordPolicyViolation.MATCHES_IDENTIFIER)
        if not violations and self.compromised is not None:
            compromised_value: object = self.compromised(password)
            if compromised_value.__class__ is not bool:
                msg = "Password policy compromised-password predicate must return bool"
                raise ImproperlyConfiguredException(detail=msg)
            if compromised_value:
                violations.add(PasswordPolicyViolation.COMPROMISED)
        return PasswordPolicyResult(frozenset(violations))


@dataclass(frozen=True, slots=True)
class PasswordVerificationResult:
    """Sanitized verification decision with an optional secret rehash value."""

    status: PasswordVerificationStatus
    replacement_hash: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Allow a replacement hash only after successful verification."""
        if self.replacement_hash is not None and self.status is not PasswordVerificationStatus.VERIFIED:
            msg = "Only verified passwords may carry a replacement hash"
            raise ValueError(msg)

    @property
    def verified(self) -> bool:
        """Return whether the password matched the stored hash."""
        return self.status is PasswordVerificationStatus.VERIFIED


class PasswordHashingUnavailableError(RuntimeError):
    """Indicate that bounded password hashing could not complete."""

    def __init__(self) -> None:
        """Initialize the stable secret-free error."""
        super().__init__("Password hashing unavailable")


@runtime_checkable
class PasswordHasher(Protocol):
    """Async password hashing boundary suitable for custom implementations."""

    async def hash(self, password: str) -> str:
        """Return one encoded password hash."""
        ...  # pragma: no cover

    async def verify(self, encoded_hash: str | None, password: str) -> PasswordVerificationResult:
        """Verify one password with constant work for absent credentials."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class Argon2PasswordHasher:
    """Argon2id password hasher using one bounded crypto-worker budget."""

    memory_cost: int = 19_456
    time_cost: int = 2
    parallelism: int = 1
    salt_len: int = 16
    hash_len: int = 32
    worker_limits: WorkerLimits = field(default_factory=WorkerLimits, repr=False, compare=False)
    dummy_hash: str = field(default=_DEFAULT_DUMMY_HASH, repr=False, compare=False)
    _engine: _Argon2Engine = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate bounded parameters and one policy-matched precomputed dummy."""
        _validate_argon2_configuration(
            memory_cost=self.memory_cost,
            time_cost=self.time_cost,
            parallelism=self.parallelism,
            salt_len=self.salt_len,
            hash_len=self.hash_len,
            worker_limits=self.worker_limits,
        )
        dummy_parameters = _safe_argon2_parameters(self.dummy_hash, self.worker_limits)
        if dummy_parameters is None or not _parameters_match_hasher(dummy_parameters, self):
            msg = "Argon2 dummy hash must exactly match the configured policy"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "_engine", _build_argon2_engine(self))

    @classmethod
    async def create(  # noqa: PLR0913
        cls,
        *,
        memory_cost: int = 19_456,
        time_cost: int = 2,
        parallelism: int = 1,
        salt_len: int = 16,
        hash_len: int = 32,
        worker_limits: WorkerLimits | None = None,
    ) -> "Argon2PasswordHasher":
        """Create a strengthened policy while generating its dummy in a worker."""
        workers = WorkerLimits() if worker_limits is None else worker_limits
        _validate_argon2_configuration(
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            salt_len=salt_len,
            hash_len=hash_len,
            worker_limits=workers,
        )
        engine = _Argon2Engine(
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            salt_len=salt_len,
            hash_len=hash_len,
            type=Argon2Type.ID,
        )
        try:
            dummy_hash = await _run_password_worker(partial(engine.hash, _DUMMY_PASSWORD), workers)
        except Exception:  # noqa: BLE001
            raise PasswordHashingUnavailableError from None
        return cls(
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            salt_len=salt_len,
            hash_len=hash_len,
            worker_limits=workers,
            dummy_hash=dummy_hash,
        )

    async def hash(self, password: str) -> str:
        """Hash one bounded UTF-8 password in the dedicated crypto worker."""
        password_bytes = _password_bytes(password)
        return await self._hash_bytes(password_bytes)

    async def verify(self, encoded_hash: str | None, password: str) -> PasswordVerificationResult:
        """Verify with equal Argon2 work for absent, mismatched, and malformed hashes."""
        password_input = _password_verification_input(password)
        if isinstance(password_input, PasswordVerificationResult):
            return password_input
        password_bytes = password_input
        candidate_hash = self.dummy_hash if encoded_hash is None else encoded_hash
        parameters = _safe_argon2_parameters(candidate_hash, self.worker_limits)
        if parameters is None:
            await self._verify_dummy(password_bytes)
            return PasswordVerificationResult(PasswordVerificationStatus.MALFORMED)
        matched = await self._match_candidate(candidate_hash, password_bytes)
        if isinstance(matched, PasswordVerificationResult):
            return matched
        if encoded_hash is None or not matched:
            return PasswordVerificationResult(PasswordVerificationStatus.INVALID)
        needs_rehash = not _parameters_match_hasher(parameters, self)
        replacement = await self._hash_bytes(password_bytes) if needs_rehash else None
        return PasswordVerificationResult(PasswordVerificationStatus.VERIFIED, replacement_hash=replacement)

    async def _hash_bytes(self, password: bytes) -> str:
        try:
            return await _run_password_worker(partial(self._engine.hash, password), self.worker_limits)
        except Exception:  # noqa: BLE001
            raise PasswordHashingUnavailableError from None

    async def _match_candidate(self, candidate_hash: str, password: bytes) -> bool | PasswordVerificationResult:
        try:
            return await self._verify_once(candidate_hash, password)
        except VerifyMismatchError:
            return False
        except (InvalidHashError, VerificationError):
            if candidate_hash == self.dummy_hash:
                raise PasswordHashingUnavailableError from None
            await self._verify_dummy(password)
            return PasswordVerificationResult(PasswordVerificationStatus.MALFORMED)
        except Exception:  # noqa: BLE001
            raise PasswordHashingUnavailableError from None

    async def _verify_once(self, encoded_hash: str, password: bytes) -> bool:
        return await _run_password_worker(partial(self._engine.verify, encoded_hash, password), self.worker_limits)

    async def _verify_dummy(self, password: bytes) -> None:
        try:
            await self._verify_once(self.dummy_hash, password)
        except VerifyMismatchError:
            pass
        except Exception:  # noqa: BLE001
            raise PasswordHashingUnavailableError from None


class _PasswordTooLongError(ValueError):
    pass


def _password_bytes(password: str) -> bytes:
    if password.__class__ is not str:
        msg = "Password must be text"
        raise ValueError(msg)
    try:
        value = password.encode("utf-8")
    except UnicodeEncodeError:
        msg = "Password must contain valid UTF-8 text"
        raise ValueError(msg) from None
    if len(value) > _MAXIMUM_PASSWORD_BYTES:
        msg = "Password must not exceed 1,024 UTF-8 bytes"
        raise _PasswordTooLongError(msg)
    return value


def _password_verification_input(password: str) -> bytes | PasswordVerificationResult:
    try:
        return _password_bytes(password)
    except _PasswordTooLongError:
        return PasswordVerificationResult(PasswordVerificationStatus.TOO_LONG)
    except ValueError:
        return PasswordVerificationResult(PasswordVerificationStatus.INVALID)


async def _run_password_worker(operation: "Callable[[], UserT]", workers: WorkerLimits) -> UserT:
    started = perf_counter()
    result = await to_thread.run_sync(operation, abandon_on_cancel=False, limiter=workers.crypto_limiter)
    if perf_counter() - started > workers.timeout:
        raise TimeoutError
    return result


def _validate_argon2_configuration(  # noqa: PLR0913
    *, memory_cost: int, time_cost: int, parallelism: int, salt_len: int, hash_len: int, worker_limits: WorkerLimits
) -> None:
    values = (
        (memory_cost, 19_456, _MAXIMUM_ARGON2_MEMORY_COST),
        (time_cost, 2, _MAXIMUM_ARGON2_TIME_COST),
        (parallelism, 1, _MAXIMUM_ARGON2_PARALLELISM),
        (salt_len, 16, _MAXIMUM_ARGON2_SALT_LENGTH),
        (hash_len, 32, _MAXIMUM_ARGON2_HASH_LENGTH),
    )
    if any(value.__class__ is not int or not minimum <= value <= maximum for value, minimum, maximum in values):
        msg = "Argon2 password parameters must be strengthened within safe bounds"
        raise ImproperlyConfiguredException(detail=msg)
    if worker_limits.__class__ is not WorkerLimits:
        msg = "Argon2 password worker limits must be WorkerLimits"
        raise ImproperlyConfiguredException(detail=msg)
    if memory_cost * worker_limits.crypto_tokens > _MAXIMUM_ARGON2_WORKER_MEMORY_KIB:
        msg = "Argon2 password memory cost and crypto workers must not exceed 1 GiB"
        raise ImproperlyConfiguredException(detail=msg)


def _build_argon2_engine(hasher: Argon2PasswordHasher) -> _Argon2Engine:
    try:
        return _Argon2Engine(
            memory_cost=hasher.memory_cost,
            time_cost=hasher.time_cost,
            parallelism=hasher.parallelism,
            salt_len=hasher.salt_len,
            hash_len=hasher.hash_len,
            type=Argon2Type.ID,
        )
    except (Argon2Error, TypeError, ValueError):
        msg = "Invalid Argon2 password parameters"
        raise ImproperlyConfiguredException(detail=msg) from None


def _safe_argon2_parameters(encoded_hash: object, worker_limits: WorkerLimits) -> "Parameters | None":
    if not isinstance(encoded_hash, str):
        return None
    try:
        encoded_bytes = encoded_hash.encode("ascii")
        if len(encoded_bytes) > _MAXIMUM_ENCODED_PASSWORD_HASH_BYTES:
            return None
        parameters = extract_parameters(encoded_hash)
    except (InvalidHashError, UnicodeError, ValueError):
        return None
    if (
        parameters.type is not Argon2Type.ID
        or parameters.version != _ARGON2_VERSION
        or not 1 <= parameters.memory_cost <= _MAXIMUM_ARGON2_MEMORY_COST
        or not 1 <= parameters.time_cost <= _MAXIMUM_ARGON2_TIME_COST
        or not 1 <= parameters.parallelism <= _MAXIMUM_ARGON2_PARALLELISM
        or not 1 <= parameters.salt_len <= _MAXIMUM_ARGON2_SALT_LENGTH
        or not 1 <= parameters.hash_len <= _MAXIMUM_ARGON2_HASH_LENGTH
        or parameters.memory_cost * worker_limits.crypto_tokens > _MAXIMUM_ARGON2_WORKER_MEMORY_KIB
    ):
        return None
    return parameters


def _parameters_match_hasher(parameters: "Parameters", hasher: Argon2PasswordHasher) -> bool:
    return (
        parameters.memory_cost,
        parameters.time_cost,
        parameters.parallelism,
        parameters.salt_len,
        parameters.hash_len,
    ) == (hasher.memory_cost, hasher.time_cost, hasher.parallelism, hasher.salt_len, hasher.hash_len)


@dataclass(frozen=True, slots=True)
class PasswordChangeResult:
    """Atomic password replacement and security-epoch outcome."""

    status: PasswordChangeStatus
    security_epoch: int | None = None

    def __post_init__(self) -> None:
        """Require an epoch only for a successful atomic replacement."""
        changed = self.status is PasswordChangeStatus.CHANGED
        if changed != (self.security_epoch is not None):
            msg = "Changed password results require exactly one security epoch"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RevokeLoginMethodResult:
    """Atomic login-method revocation outcome."""

    status: RevokeLoginMethodStatus


@dataclass(frozen=True, slots=True)
class RegistrationResult(Generic[UserT]):
    """Atomic registration outcome."""

    status: RegistrationStatus
    account: LocalAccount[UserT] | None = None

    def __post_init__(self) -> None:
        """Require an account projection only for a created registration."""
        if (self.status is RegistrationStatus.CREATED) != (self.account is not None):
            msg = "Created registration results require exactly one account"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ConsumeResult:
    """Atomic verification-token consumption outcome."""

    status: ConsumeStatus
    account_id: str | None = None
    security_epoch: int | None = None

    def __post_init__(self) -> None:
        """Require account and epoch payload only for successful consumption."""
        consumed = self.status is ConsumeStatus.CONSUMED
        has_payload = self.account_id is not None and self.security_epoch is not None
        if consumed != has_payload or (
            not consumed and (self.account_id is not None or self.security_epoch is not None)
        ):
            msg = "Consumed verification results require exactly one account and security epoch"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class PasswordResetResult:
    """Atomic recovery-token consumption and password-reset outcome."""

    status: PasswordResetStatus
    account_id: str | None = None
    security_epoch: int | None = None

    def __post_init__(self) -> None:
        """Require account and epoch payload only for a completed reset."""
        reset = self.status is PasswordResetStatus.RESET
        has_payload = self.account_id is not None and self.security_epoch is not None
        if reset != has_payload or (not reset and (self.account_id is not None or self.security_epoch is not None)):
            msg = "Reset password results require exactly one account and security epoch"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RegistrationPolicy:
    """Explicit self-service registration policy."""

    mode: RegistrationMode
    require_verification: bool = True

    @classmethod
    def disabled(cls) -> "RegistrationPolicy":
        """Disable self-service registration."""
        return cls(mode=RegistrationMode.DISABLED)

    @classmethod
    def public(cls, *, require_verification: bool = True) -> "RegistrationPolicy":
        """Enable public self-service registration."""
        return cls(mode=RegistrationMode.PUBLIC, require_verification=require_verification)

    @classmethod
    def invite_only(cls, *, require_verification: bool = True) -> "RegistrationPolicy":
        """Require an atomic invitation consume during registration."""
        return cls(mode=RegistrationMode.INVITE_ONLY, require_verification=require_verification)


@runtime_checkable
class AccountLookup(Protocol[UserT]):
    """Resolve the minimal application account projection."""

    async def find_for_login(self, normalized_identifier: str) -> "LocalAccount[UserT] | None":
        """Find an account through an already-normalized identifier."""
        ...  # pragma: no cover

    async def get_by_id(self, account_id: str) -> "LocalAccount[UserT] | None":
        """Resolve an account by its stable security identifier."""
        ...  # pragma: no cover


@runtime_checkable
class PasswordCredentialStore(Protocol):
    """Store password credentials through atomic security operations."""

    async def get_password_hash(self, account_id: str) -> str | None:
        """Load the current encoded password hash."""
        ...  # pragma: no cover

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, *, event: SecurityEvent
    ) -> bool:
        """Atomically replace a hash only when its expected value is current."""
        ...  # pragma: no cover

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, event: SecurityEvent
    ) -> PasswordChangeResult:
        """Atomically replace a password and increment the security epoch."""
        ...  # pragma: no cover


@runtime_checkable
class LoginMethodStore(Protocol):
    """Maintain viable login methods through guarded atomic operations."""

    async def register_login_method(self, account_id: str, method: LoginMethod, *, event: SecurityEvent) -> None:
        """Register one login method and its durable event."""
        ...  # pragma: no cover

    async def revoke_login_method(
        self, account_id: str, method_id: str, *, require_remaining: bool = True, event: SecurityEvent
    ) -> RevokeLoginMethodResult:
        """Revoke a method without removing the final viable method by default."""
        ...  # pragma: no cover


@runtime_checkable
class RegistrationStore(Protocol[UserT]):
    """Create an account and consume any invitation atomically."""

    async def register(  # noqa: PLR0913
        self,
        command: RegistrationCommand,
        password_hash: str,
        *,
        invitation_digest: bytes | None,
        verification: TokenIssue,
        notification: NotificationCommand,
        event: SecurityEvent,
    ) -> RegistrationResult[UserT]:
        """Commit registration, invitation, verification, notification, and event."""
        ...  # pragma: no cover


@runtime_checkable
class VerificationTokenStore(Protocol):
    """Issue and atomically consume account-verification tokens."""

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        """Commit a verification issue, notification, and durable event."""
        ...  # pragma: no cover

    async def consume_and_verify(
        self, token_id: str, digest: bytes, *, now: "datetime", event: SecurityEvent
    ) -> ConsumeResult:
        """Consume a verification token and verify its account atomically."""
        ...  # pragma: no cover


@runtime_checkable
class RecoveryTokenStore(Protocol):
    """Issue and atomically consume password-recovery tokens."""

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, *, event: SecurityEvent) -> None:
        """Commit a recovery issue, notification, and durable event."""
        ...  # pragma: no cover

    async def consume_and_reset(
        self, token_id: str, digest: bytes, new_password_hash: str, *, now: "datetime", event: SecurityEvent
    ) -> PasswordResetResult:
        """Consume a recovery token and reset password/epoch atomically."""
        ...  # pragma: no cover


@runtime_checkable
class SecurityEpochStore(Protocol):
    """Resolve the exact current account security epoch."""

    async def current_epoch(self, account_id: str) -> int | None:
        """Return the current epoch or ``None`` for an absent account."""
        ...  # pragma: no cover


@runtime_checkable
class LocalAccountCapabilities(
    AccountLookup[UserT],
    PasswordCredentialStore,
    LoginMethodStore,
    VerificationTokenStore,
    RecoveryTokenStore,
    SecurityEpochStore,
    Protocol[UserT],
):
    """Structural account capabilities required by every local-auth profile."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_event_id() -> str:
    return uuid4().hex


def _aware_utc_time(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class PasswordReauthenticationService:
    """Verify a current password and emit short-lived password evidence."""

    accounts: PasswordCredentialStore = field(repr=False)
    hasher: PasswordHasher = field(repr=False)
    evidence_ttl: timedelta = _DEFAULT_REAUTHENTICATION_TTL
    clock: "Callable[[], datetime]" = field(default=_utc_now, repr=False, compare=False)
    events: SecurityEventSink = field(default_factory=NoOpSecurityEventSink, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=_new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate structural ports and the bounded evidence lifetime."""
        accounts_value: object = object.__getattribute__(self, "accounts")
        hasher_value: object = object.__getattribute__(self, "hasher")
        evidence_ttl_value: object = object.__getattribute__(self, "evidence_ttl")
        clock_value: object = object.__getattribute__(self, "clock")
        events_value: object = object.__getattribute__(self, "events")
        event_ids_value: object = object.__getattribute__(self, "event_ids")
        if not isinstance(accounts_value, PasswordCredentialStore):
            msg = "Password reauthentication accounts must implement PasswordCredentialStore"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(hasher_value, PasswordHasher):
            msg = "Password reauthentication hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if (
            not isinstance(evidence_ttl_value, timedelta)
            or evidence_ttl_value <= timedelta(0)
            or evidence_ttl_value > _DEFAULT_REAUTHENTICATION_TTL
        ):
            msg = "Password reauthentication evidence lifetime must be positive and at most five minutes"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(clock_value):
            msg = "Password reauthentication clock must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(events_value, SecurityEventSink):
            msg = "Password reauthentication events must implement SecurityEventSink"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(event_ids_value):
            msg = "Password reauthentication event id factory must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    async def verify(
        self, account_id: str, password: str, *, now: datetime | None = None
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        """Return fresh password evidence or one sanitized domain outcome."""
        account_value: object = account_id
        if account_value.__class__ is not str or not (normalized_account_id := account_id.strip()):
            return InvalidCredentials()
        try:
            authenticated_at = _aware_utc_time(self.clock() if now is None else now)
            encoded_hash = await self.accounts.get_password_hash(normalized_account_id)
            result = await self.hasher.verify(encoded_hash, password)
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if not result.verified or encoded_hash is None:
            if result.status is PasswordVerificationStatus.MALFORMED:
                await self._emit_malformed(normalized_account_id, authenticated_at)
            return InvalidCredentials()
        if result.replacement_hash is not None and not await self._rehash(
            normalized_account_id, encoded_hash, result.replacement_hash, authenticated_at
        ):
            return VerificationUnavailable()
        return AuthenticationEvidence(
            mechanism="password",
            slot="password",
            authenticated_at=authenticated_at,
            expires_at=authenticated_at + self.evidence_ttl,
            methods=frozenset({"password"}),
            amr=("pwd",),
        )

    async def _rehash(self, account_id: str, expected_hash: str, replacement_hash: str, occurred_at: datetime) -> bool:
        try:
            event = self._event(account_id, occurred_at, operation="local.password.rehash", outcome="updated")
            replaced: object = await self.accounts.compare_and_replace_password(
                account_id, expected_hash, replacement_hash, event=event
            )
        except Exception:  # noqa: BLE001
            return False
        return replaced.__class__ is bool

    def _event(self, account_id: str, occurred_at: datetime, *, operation: str, outcome: str) -> SecurityEvent:
        event_id = self.event_ids().strip()
        if not event_id:
            raise ValueError
        return SecurityEvent(
            event_id=event_id,
            occurred_at=occurred_at,
            operation=operation,
            outcome=outcome,
            account_id=account_id,
            mechanism="password",
        )

    async def _emit_malformed(self, account_id: str, occurred_at: datetime) -> None:
        try:
            await self.events.emit(
                self._event(account_id, occurred_at, operation="local.password.verify", outcome="malformed_hash")
            )
        except Exception:  # noqa: BLE001
            _LOGGER.error("Security event sink failed")  # noqa: TRY400 - omit untrusted exception details


@dataclass(frozen=True, slots=True)
class LocalAuthConfig(Generic[UserT]):
    """Explicit local-authentication transport and capability selection."""

    mode: LocalAuthMode
    accounts: LocalAccountCapabilities[UserT] = field(repr=False)
    registration: RegistrationPolicy
    route_prefix: str
    csrf: CSRFConfig | ExternalCSRF | None = field(default=None, repr=False)
    binding: SessionBindingConfig | None = field(default=None, repr=False)
    key_ring: LocalKeyRing | None = field(default=None, repr=False)
    token_audience: str | None = None

    def __post_init__(self) -> None:
        """Validate transport-specific values and structural capabilities."""
        if self.mode.__class__ is not LocalAuthMode:
            msg = "Local authentication mode must be a LocalAuthMode"
            raise ImproperlyConfiguredException(detail=msg)
        if self.registration.__class__ is not RegistrationPolicy:
            msg = "Local authentication registration must be a RegistrationPolicy"
            raise ImproperlyConfiguredException(detail=msg)
        if self.route_prefix.__class__ is not str:
            msg = "Local authentication route prefix must be an absolute non-root path"
            raise ImproperlyConfiguredException(detail=msg)
        route_prefix = self.route_prefix.rstrip("/")
        if (
            not route_prefix.startswith("/")
            or route_prefix == ""
            or "//" in route_prefix
            or any(value in route_prefix for value in ("\\", "{", "}", "?", "#"))
            or any(segment in {".", ".."} for segment in route_prefix.split("/"))
            or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in route_prefix)
        ):
            msg = "Local authentication route prefix must be an absolute non-root path"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "route_prefix", route_prefix)
        if self.mode in {LocalAuthMode.SESSION, LocalAuthMode.HYBRID} and (
            not isinstance(self.csrf, (CSRFConfig, ExternalCSRF)) or not isinstance(self.binding, SessionBindingConfig)
        ):
            msg = "Session local authentication requires explicit CSRF and binding configuration"
            raise ImproperlyConfiguredException(detail=msg)
        if self.mode in {LocalAuthMode.TOKENS, LocalAuthMode.HYBRID}:
            audience = self.token_audience.strip() if isinstance(self.token_audience, str) else ""
            if not isinstance(self.key_ring, LocalKeyRing) or not audience:
                msg = "Token local authentication requires an explicit key ring and audience"
                raise ImproperlyConfiguredException(detail=msg)
            object.__setattr__(self, "token_audience", audience)
        self._validate_capabilities()

    def _validate_capabilities(self) -> None:
        required: list[type[Any]] = [
            AccountLookup,
            PasswordCredentialStore,
            LoginMethodStore,
            VerificationTokenStore,
            RecoveryTokenStore,
            SecurityEpochStore,
        ]
        if self.registration.mode is not RegistrationMode.DISABLED:
            required.append(RegistrationStore)
        if self.mode in {LocalAuthMode.SESSION, LocalAuthMode.HYBRID}:
            required.append(SessionRegistry)
        if self.mode in {LocalAuthMode.TOKENS, LocalAuthMode.HYBRID}:
            required.append(RefreshTokenFamilyStore)
        missing = tuple(protocol.__name__ for protocol in required if not isinstance(self.accounts, protocol))
        if missing:
            msg = f"Local authentication account capabilities missing for {self.mode.value}: {', '.join(missing)}"
            raise ImproperlyConfiguredException(detail=msg)


_DISABLED_REGISTRATION = RegistrationPolicy.disabled()


class LocalAuth:
    """Construct explicit session, token, or hybrid local-auth profiles."""

    @classmethod
    def session(
        cls,
        *,
        accounts: LocalAccountCapabilities[UserT],
        csrf: CSRFConfig | ExternalCSRF,
        binding: SessionBindingConfig,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
    ) -> "LocalAuthConfig[UserT]":
        """Select native-session local authentication."""
        return LocalAuthConfig(
            mode=LocalAuthMode.SESSION,
            accounts=accounts,
            csrf=csrf,
            binding=binding,
            registration=registration,
            route_prefix=route_prefix,
        )

    @classmethod
    def tokens(
        cls,
        *,
        accounts: LocalAccountCapabilities[UserT],
        key_ring: LocalKeyRing,
        token_audience: str,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
    ) -> "LocalAuthConfig[UserT]":
        """Select bearer access/refresh-token local authentication."""
        return LocalAuthConfig(
            mode=LocalAuthMode.TOKENS,
            accounts=accounts,
            key_ring=key_ring,
            token_audience=token_audience,
            registration=registration,
            route_prefix=route_prefix,
        )

    @classmethod
    def hybrid(  # noqa: PLR0913
        cls,
        *,
        accounts: LocalAccountCapabilities[UserT],
        csrf: CSRFConfig | ExternalCSRF,
        binding: SessionBindingConfig,
        key_ring: LocalKeyRing,
        token_audience: str,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
    ) -> "LocalAuthConfig[UserT]":
        """Select distinct native-session and bearer-token local transports."""
        return LocalAuthConfig(
            mode=LocalAuthMode.HYBRID,
            accounts=accounts,
            csrf=csrf,
            binding=binding,
            key_ring=key_ring,
            token_audience=token_audience,
            registration=registration,
            route_prefix=route_prefix,
        )
