"""Backend-agnostic local-account contracts and explicit transport profiles."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Mapping  # noqa: TC003 - Litestar resolves public annotations at runtime
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import partial
from hmac import compare_digest
from hmac import digest as hmac_digest
from logging import getLogger
from secrets import token_bytes
from time import perf_counter
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic, Protocol, TypeVar, cast, runtime_checkable
from unicodedata import normalize
from urllib.parse import urlsplit
from uuid import uuid4

from anyio import CancelScope, to_thread
from argon2 import PasswordHasher as _Argon2Engine
from argon2 import extract_parameters
from argon2.exceptions import Argon2Error, InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type as Argon2Type
from litestar.config.csrf import CSRFConfig
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts.sessions import (
    CreateSessionCommand,
    NativeSessionAuth,
    NativeSessionStore,
    RefreshTokenFamilyStore,
    SessionBindingConfig,
    SessionRegistry,
)
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.config import ExternalCSRF, WorkerLimits
from litestar_security.providers.jwt import LocalKeyRing

if TYPE_CHECKING:
    from collections.abc import Callable

    from argon2 import Parameters

__all__ = (
    "AccountLookup",
    "Argon2PasswordHasher",
    "ConsumeResult",
    "ConsumeStatus",
    "InvalidInvitation",
    "InvalidLifecycleRequest",
    "LifecycleAccepted",
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
    "PasswordChangeService",
    "PasswordChangeStatus",
    "PasswordCredentialState",
    "PasswordCredentialStore",
    "PasswordHasher",
    "PasswordHashingUnavailableError",
    "PasswordPolicy",
    "PasswordPolicyResult",
    "PasswordPolicyViolation",
    "PasswordReauthenticationProof",
    "PasswordReauthenticationService",
    "PasswordResetResult",
    "PasswordResetStatus",
    "PasswordVerificationResult",
    "PasswordVerificationStatus",
    "PendingTokenIssue",
    "PurposeTokenCodec",
    "PurposeTokenDelivery",
    "PurposeTokenGenerationError",
    "PurposeTokenProof",
    "RecoveryTokenService",
    "RecoveryTokenStore",
    "RegistrationCommand",
    "RegistrationMode",
    "RegistrationPolicy",
    "RegistrationResult",
    "RegistrationService",
    "RegistrationStatus",
    "RegistrationStore",
    "RevokeLoginMethodResult",
    "RevokeLoginMethodStatus",
    "SecurityEpochStore",
    "SecurityEpochValidator",
    "SecurityEvent",
    "SecurityEventSink",
    "TokenIssue",
    "TokenPurpose",
    "VerificationTokenService",
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
_MINIMUM_TOKEN_PEPPER_BYTES = 32
_TOKEN_LOOKUP_BYTES = 16
_TOKEN_SECRET_BYTES = 32
_TOKEN_DIGEST_BYTES = 32
_TOKEN_LOOKUP_CHARACTERS = 22
_TOKEN_SECRET_CHARACTERS = 43
_DEFAULT_TOKEN_ATTEMPTS = 5
_MAXIMUM_TOKEN_ATTEMPTS = 100
_MAXIMUM_SECURITY_EPOCH = 9_223_372_036_854_775_807
_VERIFICATION_TOKEN_LIFETIME = timedelta(hours=24)
_RECOVERY_TOKEN_LIFETIME = timedelta(minutes=30)
_DUMMY_TOKEN_LOOKUP = b"\x00" * _TOKEN_LOOKUP_BYTES
_DUMMY_TOKEN_SECRET = b"\x00" * _TOKEN_SECRET_BYTES
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


class TokenPurpose(str, Enum):
    """Closed namespaces for one-time local-account tokens."""

    INVITATION = "invitation"
    VERIFICATION = "verification"
    RECOVERY = "recovery"


class PasswordChangeStatus(str, Enum):
    """Atomic password-change outcomes."""

    CHANGED = "changed"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"
    EPOCH_EXHAUSTED = "epoch_exhausted"


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
    EPOCH_EXHAUSTED = "epoch_exhausted"


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

    def __post_init__(self) -> None:
        """Validate the stable account and strict epoch projection."""
        if (
            not _strict_text(self.account_id)
            or not _strict_text(self.normalized_identifier)
            or not _valid_security_epoch(self.security_epoch)
        ):
            msg = "Local account requires stable identifiers and a valid security epoch"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class LoginMethod:
    """One application-owned viable login method."""

    method_id: str
    kind: str
    created_at: "datetime"
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class PasswordCredentialState:
    """Atomic password hash and epoch snapshot used for reauthentication."""

    password_hash: str = field(repr=False)
    security_epoch: int

    def __post_init__(self) -> None:
        """Require one encoded hash bound to a strict current epoch."""
        if not _strict_text(self.password_hash) or not _valid_security_epoch(self.security_epoch):
            msg = "Password credential state requires a hash and valid security epoch"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class PasswordReauthenticationProof:
    """Account- and epoch-bound recent password proof for sensitive mutation."""

    account_id: str
    security_epoch: int
    authenticated_at: "datetime"
    expires_at: "datetime"

    def __post_init__(self) -> None:
        """Require a strict identity, epoch, and forward-moving proof window."""
        try:
            authenticated_at = _aware_utc_time(self.authenticated_at)
            expires_at = _aware_utc_time(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Password reauthentication proof timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not _strict_text(self.account_id)
            or not _valid_security_epoch(self.security_epoch)
            or expires_at <= authenticated_at
            or expires_at - authenticated_at > _DEFAULT_REAUTHENTICATION_TTL
        ):
            msg = "Password reauthentication proof requires an account, epoch, and valid lifetime"
            raise ValueError(msg)
        object.__setattr__(self, "authenticated_at", authenticated_at)
        object.__setattr__(self, "expires_at", expires_at)


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
class PendingTokenIssue:
    """Account-unbound hashed token material for one atomic registration."""

    token_id: str
    digest: bytes = field(repr=False)
    purpose: TokenPurpose
    expires_at: "datetime"
    maximum_attempts: int

    def __post_init__(self) -> None:
        """Validate secret-safe storage material and bounded attempt policy."""
        _validate_pending_token_issue(self)

    def bind(self, account_id: str, *, security_epoch: int | None = None) -> "TokenIssue":
        """Bind this material to an application-allocated account ID."""
        return TokenIssue(
            token_id=self.token_id,
            digest=self.digest,
            purpose=self.purpose,
            account_id=account_id,
            expires_at=self.expires_at,
            maximum_attempts=self.maximum_attempts,
            issued_security_epoch=security_epoch,
        )


@dataclass(frozen=True, slots=True)
class TokenIssue:
    """Hashed, purpose-bound token material accepted by an atomic store."""

    token_id: str
    digest: bytes = field(repr=False)
    purpose: TokenPurpose
    expires_at: "datetime"
    maximum_attempts: int
    account_id: str
    issued_security_epoch: int | None = None

    def __post_init__(self) -> None:
        """Require a stable account binding in addition to valid token material."""
        _validate_pending_token_issue(self)
        recovery_epoch_valid = self.purpose is not TokenPurpose.RECOVERY or _valid_security_epoch(
            self.issued_security_epoch
        )
        non_recovery_epoch_valid = self.purpose is TokenPurpose.RECOVERY or self.issued_security_epoch is None
        if not _strict_text(self.account_id) or not recovery_epoch_valid or not non_recovery_epoch_valid:
            msg = "Purpose token account binding or issuance epoch is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class NotificationCommand:
    """Delivery-neutral notification data with a one-time opaque token."""

    template: str
    destination: str = field(repr=False)
    token: str = field(repr=False)
    expires_at: "datetime"
    return_url: str | None = None

    def __post_init__(self) -> None:
        """Reject incomplete delivery commands and unapproved callback shapes."""
        if not _strict_text(self.template) or not _strict_text(self.destination) or not _strict_text(self.token):
            msg = "Notification template, destination, and token must not be blank"
            raise ValueError(msg)
        try:
            _aware_utc_time(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Notification expiry must be timezone-aware"
            raise ValueError(msg) from None
        if self.return_url is not None and not _approved_return_url(self.return_url):
            msg = "Notification return URL must be an absolute HTTP(S) URL without credentials or fragments"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RegistrationCommand:
    """Application-neutral local registration input."""

    normalized_identifier: str = field(repr=False)
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class PurposeTokenProof:
    """Secret-free parsed lookup and HMAC proof passed to an atomic store."""

    token_id: str
    digest: bytes = field(repr=False)
    purpose: TokenPurpose

    def __post_init__(self) -> None:
        """Validate the exact storage-facing proof shape."""
        if (
            self.purpose.__class__ is not TokenPurpose
            or not _valid_token_id(self.token_id, self.purpose)
            or len(self.digest) != _TOKEN_DIGEST_BYTES
        ):
            msg = "Invalid purpose token proof"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True, init=False)
class PurposeTokenDelivery:
    """Codec-created storage issue and durable notification outbox plan."""

    issue: PendingTokenIssue
    notification: NotificationCommand

    def __init__(self) -> None:
        """Prevent callers from bypassing codec-owned digest binding."""
        message = "PurposeTokenDelivery must be created by PurposeTokenCodec"
        raise TypeError(message)

    def bind(self, account_id: str, *, security_epoch: int | None = None) -> tuple[TokenIssue, NotificationCommand]:
        """Bind the storage material while preserving the codec-created notification."""
        return self.issue.bind(account_id, security_epoch=security_epoch), self.notification


@dataclass(frozen=True, slots=True)
class LifecycleAccepted:
    """Shared enumeration-resistant response body for lifecycle requests."""

    detail: str = field(default="If eligible, the request will be processed.", init=False)


@dataclass(frozen=True, slots=True)
class InvalidInvitation:
    """Generic invalid-invitation response without expiry or replay details."""

    detail: str = "Invitation is invalid or unavailable."


@dataclass(frozen=True, slots=True)
class InvalidLifecycleRequest:
    """Generic malformed lifecycle request response."""

    detail: str = "The request is invalid."


def normalize_identifier(value: str) -> str:
    """Apply the default compatibility, whitespace, and case normalization."""
    if value.__class__ is not str:
        msg = "Identifier normalization requires text"
        raise ValueError(msg)
    return normalize("NFKC", value).strip().casefold()


class PurposeTokenGenerationError(RuntimeError):
    """Indicate that one-time token material could not be generated safely."""

    def __init__(self) -> None:
        """Initialize a stable secret-free error."""
        super().__init__("Purpose token generation unavailable")


@dataclass(frozen=True, slots=True)
class PurposeTokenCodec:
    """Generate and verify strict purpose-bound opaque one-time tokens."""

    pepper: bytes = field(repr=False)
    entropy: "Callable[[int], bytes]" = field(default=token_bytes, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Require an explicit strong HMAC pepper and callable entropy source."""
        pepper_value: object = object.__getattribute__(self, "pepper")
        entropy_value: object = object.__getattribute__(self, "entropy")
        if pepper_value.__class__ is not bytes or len(self.pepper) < _MINIMUM_TOKEN_PEPPER_BYTES:
            msg = "Purpose token pepper must contain at least 32 bytes"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(entropy_value):
            msg = "Purpose token entropy must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    def issue(  # noqa: PLR0913
        self,
        purpose: TokenPurpose,
        *,
        now: datetime,
        lifetime: timedelta,
        template: str,
        destination: str,
        return_url: str | None = None,
        maximum_attempts: int = _DEFAULT_TOKEN_ATTEMPTS,
    ) -> PurposeTokenDelivery:
        """Create one digest-bound issue whose raw token exists only in its notification."""
        if purpose.__class__ is not TokenPurpose:
            msg = "Purpose token namespace must be a TokenPurpose"
            raise ValueError(msg)
        issued_at = _aware_utc_time(now)
        if lifetime.__class__ is not timedelta or lifetime <= timedelta(0):
            msg = "Purpose token lifetime must be positive"
            raise ValueError(msg)
        if maximum_attempts.__class__ is not int or not 1 <= maximum_attempts <= _MAXIMUM_TOKEN_ATTEMPTS:
            msg = "Purpose token attempts must be a positive bounded integer"
            raise ValueError(msg)
        lookup = self._entropy(_TOKEN_LOOKUP_BYTES)
        secret = self._entropy(_TOKEN_SECRET_BYTES)
        lookup_segment = _encode_token_segment(lookup)
        secret_segment = _encode_token_segment(secret)
        token_id = f"{purpose.value}_{lookup_segment}"
        token = f"{token_id}.{secret_segment}"
        issue = PendingTokenIssue(
            token_id=token_id,
            digest=_purpose_token_digest(self.pepper, purpose, lookup, secret),
            purpose=purpose,
            expires_at=issued_at + lifetime,
            maximum_attempts=maximum_attempts,
        )
        notification = NotificationCommand(
            template=template, destination=destination, token=token, expires_at=issue.expires_at, return_url=return_url
        )
        delivery = object.__new__(PurposeTokenDelivery)
        object.__setattr__(delivery, "issue", issue)
        object.__setattr__(delivery, "notification", notification)
        return delivery

    def proof(self, token: object, *, expected_purpose: TokenPurpose) -> PurposeTokenProof | None:
        """Return a storage proof after one HMAC work class, or generic invalid."""
        if expected_purpose.__class__ is not TokenPurpose:
            msg = "Expected purpose token namespace must be a TokenPurpose"
            raise ValueError(msg)
        lookup = _DUMMY_TOKEN_LOOKUP
        secret = _DUMMY_TOKEN_SECRET
        token_id = ""
        valid = False
        if isinstance(token, str) and token.__class__ is str:
            expected_prefix = f"{expected_purpose.value}_"
            left, separator, secret_segment = token.partition(".")
            purpose_prefix, purpose_separator, lookup_segment = left.partition("_")
            decoded_lookup = _decode_token_segment(lookup_segment, _TOKEN_LOOKUP_BYTES)
            decoded_secret = _decode_token_segment(secret_segment, _TOKEN_SECRET_BYTES)
            valid = (
                separator == "."
                and "." not in secret_segment
                and purpose_separator == "_"
                and compare_digest(purpose_prefix, expected_purpose.value)
                and left.startswith(expected_prefix)
                and decoded_lookup is not None
                and decoded_secret is not None
            )
            if decoded_lookup is not None:
                lookup = decoded_lookup
            if decoded_secret is not None:
                secret = decoded_secret
            if valid:
                token_id = left
        digest = _purpose_token_digest(self.pepper, expected_purpose, lookup, secret)
        if not valid:
            return None
        return PurposeTokenProof(token_id=token_id, digest=digest, purpose=expected_purpose)

    def _entropy(self, length: int) -> bytes:
        try:
            value = self.entropy(length)
        except Exception:  # noqa: BLE001
            raise PurposeTokenGenerationError from None
        if value.__class__ is not bytes or len(value) != length:
            raise PurposeTokenGenerationError
        return value


def _strict_text(value: object) -> bool:
    return isinstance(value, str) and value.__class__ is str and bool(value.strip())


def _valid_security_epoch(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAXIMUM_SECURITY_EPOCH


def _validate_pending_token_issue(issue: "PendingTokenIssue | TokenIssue") -> None:
    if (
        issue.purpose.__class__ is not TokenPurpose
        or not _valid_token_id(issue.token_id, issue.purpose)
        or issue.digest.__class__ is not bytes
        or len(issue.digest) != _TOKEN_DIGEST_BYTES
        or issue.maximum_attempts.__class__ is not int
        or not 1 <= issue.maximum_attempts <= _MAXIMUM_TOKEN_ATTEMPTS
    ):
        msg = "Invalid pending purpose token issue"
        raise ValueError(msg)
    try:
        _aware_utc_time(issue.expires_at)
    except (AttributeError, ValueError):
        msg = "Pending purpose token expiry must be timezone-aware"
        raise ValueError(msg) from None


def _valid_token_id(token_id: object, purpose: TokenPurpose) -> bool:
    if not isinstance(token_id, str) or token_id.__class__ is not str:
        return False
    prefix = f"{purpose.value}_"
    if not token_id.startswith(prefix):
        return False
    segment = token_id[len(prefix) :]
    return _decode_token_segment(segment, _TOKEN_LOOKUP_BYTES) is not None


def _purpose_token_digest(pepper: bytes, purpose: TokenPurpose, lookup: bytes, secret: bytes) -> bytes:
    return hmac_digest(pepper, purpose.value.encode("ascii") + lookup + secret, "sha256")


def _encode_token_segment(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_token_segment(value: object, expected_bytes: int) -> bytes | None:
    expected_characters = (
        _TOKEN_LOOKUP_CHARACTERS if expected_bytes == _TOKEN_LOOKUP_BYTES else _TOKEN_SECRET_CHARACTERS
    )
    if not isinstance(value, str) or value.__class__ is not str or len(value) != expected_characters:
        return None
    try:
        encoded = value.encode("ascii")
        decoded = urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    except (UnicodeError, ValueError):
        return None
    if len(decoded) != expected_bytes or _encode_token_segment(decoded) != value:
        return None
    return decoded


def _approved_return_url(value: object) -> bool:
    if (
        not isinstance(value, str)
        or value.__class__ is not str
        or not value.strip()
        or any(ord(character) < _ASCII_CONTROL_LIMIT for character in value)
    ):
        return False
    parsed = urlsplit(value)
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
    )


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
        if (
            self.status.__class__ is not PasswordChangeStatus
            or changed != (self.security_epoch is not None)
            or (changed and not _valid_security_epoch(self.security_epoch))
        ):
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
        if (
            self.status.__class__ is not PasswordResetStatus
            or reset != has_payload
            or (not reset and (self.account_id is not None or self.security_epoch is not None))
            or (reset and (not _strict_text(self.account_id) or not _valid_security_epoch(self.security_epoch)))
        ):
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

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        """Load one atomic encoded-password and security-epoch snapshot."""
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
        verification: PurposeTokenDelivery | None,
        now: "datetime",
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
        """Consume only at its issued epoch, then reset password and advance epoch atomically."""
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


@dataclass(frozen=True, slots=True)
class SecurityEpochValidator:
    """Validate one presented epoch against authoritative application state."""

    store: SecurityEpochStore = field(repr=False)

    def __post_init__(self) -> None:
        """Require the exact epoch lookup capability."""
        if not isinstance(object.__getattribute__(self, "store"), SecurityEpochStore):
            msg = "Security epoch validator store must implement SecurityEpochStore"
            raise ImproperlyConfiguredException(detail=msg)

    async def validate(
        self, account_id: str, presented_epoch: int
    ) -> InvalidCredentials | VerificationUnavailable | None:
        """Return ``None`` only when the exact current epoch matches."""
        if not _strict_text(account_id) or not _valid_security_epoch(presented_epoch):
            return InvalidCredentials()
        try:
            current_epoch = await self.store.current_epoch(account_id)
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if not _valid_security_epoch(current_epoch) or current_epoch != presented_epoch:
            return InvalidCredentials()
        return None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_event_id() -> str:
    return uuid4().hex


def _aware_utc_time(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    return value.astimezone(timezone.utc)


def _lifecycle_event(
    event_ids: "Callable[[], str]",
    occurred_at: datetime,
    *,
    operation: str,
    outcome: str,
    account_id: str | None = None,
) -> SecurityEvent:
    event_id = event_ids()
    if not _strict_text(event_id):
        raise ValueError
    return SecurityEvent(
        event_id=event_id.strip(),
        occurred_at=occurred_at,
        operation=operation,
        outcome=outcome,
        account_id=account_id,
        mechanism="password",
    )


@dataclass(frozen=True, slots=True)
class RegistrationService(Generic[UserT]):
    """Apply policy and commit one atomic enumeration-resistant registration."""

    accounts: RegistrationStore[UserT] = field(repr=False)
    hasher: PasswordHasher = field(repr=False)
    tokens: PurposeTokenCodec = field(repr=False)
    registration: RegistrationPolicy
    password_policy: PasswordPolicy = field(default_factory=PasswordPolicy)
    verification_lifetime: timedelta = _VERIFICATION_TOKEN_LIFETIME
    verification_attempts: int = _DEFAULT_TOKEN_ATTEMPTS
    verification_return_url: str | None = None
    clock: "Callable[[], datetime]" = field(default=_utc_now, repr=False, compare=False)
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=_new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate the selected registration policy and injected boundaries."""
        accounts_value: object = object.__getattribute__(self, "accounts")
        hasher_value: object = object.__getattribute__(self, "hasher")
        tokens_value: object = object.__getattribute__(self, "tokens")
        if not isinstance(accounts_value, RegistrationStore):
            msg = "Registration service accounts must implement RegistrationStore"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(hasher_value, PasswordHasher):
            msg = "Registration service hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if tokens_value.__class__ is not PurposeTokenCodec:
            msg = "Registration service tokens must be PurposeTokenCodec"
            raise ImproperlyConfiguredException(detail=msg)
        if self.registration.__class__ is not RegistrationPolicy or self.registration.mode is RegistrationMode.DISABLED:
            msg = "Registration service requires an enabled RegistrationPolicy"
            raise ImproperlyConfiguredException(detail=msg)
        _validate_lifecycle_configuration(
            lifetime=self.verification_lifetime,
            attempts=self.verification_attempts,
            return_url=self.verification_return_url,
            clock=self.clock,
            normalizer=self.normalizer,
            event_ids=self.event_ids,
            name="Registration service",
        )

    async def register(  # noqa: PLR0911
        self,
        identifier: str,
        password: str,
        *,
        display_name: str | None = None,
        invitation_token: str | None = None,
        now: datetime | None = None,
    ) -> (
        LifecycleAccepted | InvalidInvitation | InvalidLifecycleRequest | PasswordPolicyResult | VerificationUnavailable
    ):
        """Hash and pass one complete candidate registration to the atomic store."""
        try:
            occurred_at = _aware_utc_time(self.clock() if now is None else now)
            normalized_identifier = self.normalizer(identifier)
        except (TypeError, UnicodeError, ValueError):
            return InvalidLifecycleRequest()
        if not _strict_text(normalized_identifier):
            return InvalidLifecycleRequest()
        try:
            password_result = self.password_policy.check(password, normalized_identifier=normalized_identifier)
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if not password_result.accepted:
            return password_result
        invitation_digest: bytes | None = None
        if self.registration.mode is RegistrationMode.INVITE_ONLY:
            invitation = self.tokens.proof(invitation_token, expected_purpose=TokenPurpose.INVITATION)
            if invitation is None:
                return InvalidInvitation()
            invitation_digest = invitation.digest
        try:
            password_hash = await self.hasher.hash(password)
            verification = self._verification_plan(normalized_identifier, occurred_at)
            event = _lifecycle_event(self.event_ids, occurred_at, operation="local.registration", outcome="created")
            result = await self.accounts.register(
                RegistrationCommand(normalized_identifier=normalized_identifier, display_name=display_name),
                password_hash,
                invitation_digest=invitation_digest,
                verification=verification,
                now=occurred_at,
                event=event,
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if result.status is RegistrationStatus.INVALID_INVITATION:
            return InvalidInvitation()
        return LifecycleAccepted()

    def _verification_plan(self, destination: str, occurred_at: datetime) -> PurposeTokenDelivery | None:
        if not self.registration.require_verification:
            return None
        return self.tokens.issue(
            TokenPurpose.VERIFICATION,
            now=occurred_at,
            lifetime=self.verification_lifetime,
            template="local.verify",
            destination=destination,
            return_url=self.verification_return_url,
            maximum_attempts=self.verification_attempts,
        )


@dataclass(frozen=True, slots=True)
class VerificationTokenService(Generic[UserT]):
    """Issue generic verification resends and atomically consume confirmations."""

    accounts: AccountLookup[UserT] = field(repr=False)
    store: VerificationTokenStore = field(repr=False)
    tokens: PurposeTokenCodec = field(repr=False)
    lifetime: timedelta = _VERIFICATION_TOKEN_LIFETIME
    maximum_attempts: int = _DEFAULT_TOKEN_ATTEMPTS
    return_url: str | None = None
    clock: "Callable[[], datetime]" = field(default=_utc_now, repr=False, compare=False)
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=_new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate lookup, atomic token store, and deterministic hooks."""
        if not isinstance(object.__getattribute__(self, "accounts"), AccountLookup):
            msg = "Verification token accounts must implement AccountLookup"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(object.__getattribute__(self, "store"), VerificationTokenStore):
            msg = "Verification token store must implement VerificationTokenStore"
            raise ImproperlyConfiguredException(detail=msg)
        if object.__getattribute__(self, "tokens").__class__ is not PurposeTokenCodec:
            msg = "Verification token codec must be PurposeTokenCodec"
            raise ImproperlyConfiguredException(detail=msg)
        _validate_lifecycle_configuration(
            lifetime=self.lifetime,
            attempts=self.maximum_attempts,
            return_url=self.return_url,
            clock=self.clock,
            normalizer=self.normalizer,
            event_ids=self.event_ids,
            name="Verification token service",
        )

    async def resend(self, identifier: str, *, now: datetime | None = None) -> LifecycleAccepted:
        """Always return the shared response after one token-HMAC work class."""
        try:
            occurred_at = _aware_utc_time(self.clock() if now is None else now)
            normalized_identifier = self.normalizer(identifier)
            issued = self.tokens.issue(
                TokenPurpose.VERIFICATION,
                now=occurred_at,
                lifetime=self.lifetime,
                template="local.verify",
                destination=normalized_identifier,
                return_url=self.return_url,
                maximum_attempts=self.maximum_attempts,
            )
            account = await self.accounts.find_for_login(normalized_identifier) if normalized_identifier else None
            if account is not None and account.active and not account.verified:
                issue, notification = issued.bind(account.account_id)
                await self.store.issue(
                    issue,
                    notification,
                    event=_lifecycle_event(
                        self.event_ids,
                        occurred_at,
                        operation="local.verification.issue",
                        outcome="issued",
                        account_id=account.account_id,
                    ),
                )
        except Exception:  # noqa: BLE001
            _LOGGER.error("Verification token request failed")  # noqa: TRY400 - omit untrusted exception details
        return LifecycleAccepted()

    async def consume(self, token: object, *, now: datetime | None = None) -> ConsumeResult | VerificationUnavailable:
        """Verify purpose locally and delegate single-use mutation atomically."""
        proof = self.tokens.proof(token, expected_purpose=TokenPurpose.VERIFICATION)
        if proof is None:
            return ConsumeResult(ConsumeStatus.INVALID)
        try:
            occurred_at = _aware_utc_time(self.clock() if now is None else now)
            return await self.store.consume_and_verify(
                proof.token_id,
                proof.digest,
                now=occurred_at,
                event=_lifecycle_event(
                    self.event_ids, occurred_at, operation="local.verification.consume", outcome="verified"
                ),
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()


@dataclass(frozen=True, slots=True)
class PasswordChangeService:
    """Apply authenticated or administrative password changes and epoch invalidation."""

    accounts: PasswordCredentialStore = field(repr=False)
    hasher: PasswordHasher = field(repr=False)
    password_policy: PasswordPolicy = field(default_factory=PasswordPolicy, repr=False)
    sessions: SessionRegistry | None = field(default=None, repr=False)
    refresh_tokens: RefreshTokenFamilyStore | None = field(default=None, repr=False)
    evidence_ttl: timedelta = _DEFAULT_REAUTHENTICATION_TTL
    clock: "Callable[[], datetime]" = field(default=_utc_now, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=_new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate atomic mutation, hashing, and optional transport cleanup ports."""
        if not isinstance(object.__getattribute__(self, "accounts"), PasswordCredentialStore):
            msg = "Password change accounts must implement PasswordCredentialStore"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(object.__getattribute__(self, "hasher"), PasswordHasher):
            msg = "Password change hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if object.__getattribute__(self, "password_policy").__class__ is not PasswordPolicy:
            msg = "Password change policy must be PasswordPolicy"
            raise ImproperlyConfiguredException(detail=msg)
        if self.sessions is not None and not isinstance(object.__getattribute__(self, "sessions"), SessionRegistry):
            msg = "Password change sessions must implement SessionRegistry"
            raise ImproperlyConfiguredException(detail=msg)
        if self.refresh_tokens is not None and not isinstance(
            object.__getattribute__(self, "refresh_tokens"), RefreshTokenFamilyStore
        ):
            msg = "Password change refresh tokens must implement RefreshTokenFamilyStore"
            raise ImproperlyConfiguredException(detail=msg)
        if (
            self.evidence_ttl.__class__ is not timedelta
            or self.evidence_ttl <= timedelta(0)
            or self.evidence_ttl > _DEFAULT_REAUTHENTICATION_TTL
            or not callable(self.clock)
            or not callable(self.event_ids)
        ):
            msg = "Password change evidence lifetime and hooks must be valid"
            raise ImproperlyConfiguredException(detail=msg)

    async def change(  # noqa: PLR0913
        self,
        account_id: str,
        password: str,
        *,
        proof: PasswordReauthenticationProof,
        normalized_identifier: str | None = None,
        current_session_id: str | None = None,
        replacement_session: CreateSessionCommand | None = None,
        compromise: bool = False,
        now: datetime | None = None,
    ) -> (
        PasswordChangeResult
        | PasswordPolicyResult
        | InvalidCredentials
        | InvalidLifecycleRequest
        | VerificationUnavailable
    ):
        """Change a password after recent proof and preserve only an explicitly rebound session."""
        try:
            occurred_at = _aware_utc_time(self.clock() if now is None else now)
        except (AttributeError, TypeError, ValueError):
            return InvalidLifecycleRequest()
        if not self._recent_password_proof(account_id, proof, occurred_at):
            return InvalidCredentials()
        return await self._replace(
            account_id,
            password,
            expected_epoch=proof.security_epoch,
            normalized_identifier=normalized_identifier,
            current_session_id=current_session_id,
            replacement_session=replacement_session,
            compromise=compromise,
            occurred_at=occurred_at,
            operation="local.password.change",
        )

    async def force_reset(
        self,
        account_id: str,
        password: str,
        *,
        expected_epoch: int,
        normalized_identifier: str | None = None,
        now: datetime | None = None,
    ) -> PasswordChangeResult | PasswordPolicyResult | InvalidLifecycleRequest | VerificationUnavailable:
        """Perform an application-authorized reset without registering an admin route."""
        try:
            occurred_at = _aware_utc_time(self.clock() if now is None else now)
        except (AttributeError, TypeError, ValueError):
            return InvalidLifecycleRequest()
        return await self._replace(
            account_id,
            password,
            expected_epoch=expected_epoch,
            normalized_identifier=normalized_identifier,
            current_session_id=None,
            replacement_session=None,
            compromise=True,
            occurred_at=occurred_at,
            operation="local.password.force_reset",
        )

    async def _replace(  # noqa: PLR0911, PLR0913
        self,
        account_id: str,
        password: str,
        *,
        expected_epoch: int,
        normalized_identifier: str | None,
        current_session_id: str | None,
        replacement_session: CreateSessionCommand | None,
        compromise: bool,
        occurred_at: datetime,
        operation: str,
    ) -> PasswordChangeResult | PasswordPolicyResult | InvalidLifecycleRequest | VerificationUnavailable:
        if (
            not _strict_text(account_id)
            or not _valid_security_epoch(expected_epoch)
            or not self._valid_rebind(
                account_id,
                occurred_at,
                current_session_id=current_session_id,
                replacement_session=replacement_session,
                compromise=compromise,
            )
        ):
            return InvalidLifecycleRequest()
        if expected_epoch == _MAXIMUM_SECURITY_EPOCH:
            return PasswordChangeResult(PasswordChangeStatus.EPOCH_EXHAUSTED)
        try:
            policy_result = self.password_policy.check(password, normalized_identifier=normalized_identifier)
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if not policy_result.accepted:
            return policy_result
        try:
            password_hash = await self.hasher.hash(password)
            result = await self.accounts.replace_password_and_bump_epoch(
                account_id,
                password_hash,
                expected_epoch=expected_epoch,
                event=_lifecycle_event(
                    self.event_ids, occurred_at, operation=operation, outcome="changed", account_id=account_id
                ),
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if result.status is not PasswordChangeStatus.CHANGED:
            return result
        new_epoch = result.security_epoch
        if new_epoch is None or new_epoch != expected_epoch + 1:
            return VerificationUnavailable()
        with CancelScope(shield=True):
            await self._cleanup_after_change(
                account_id,
                new_epoch,
                occurred_at,
                current_session_id=current_session_id,
                replacement_session=replacement_session,
                compromise=compromise,
            )
        return result

    def _valid_rebind(
        self,
        account_id: str,
        occurred_at: datetime,
        *,
        current_session_id: str | None,
        replacement_session: CreateSessionCommand | None,
        compromise: bool,
    ) -> bool:
        if compromise and (current_session_id is not None or replacement_session is not None):
            return False
        if (current_session_id is None) != (replacement_session is None):
            return False
        if current_session_id is None:
            return True
        if self.sessions is None or not _strict_text(current_session_id) or replacement_session is None:
            return False
        try:
            expires_at = _aware_utc_time(replacement_session.expires_at)
        except (AttributeError, ValueError):
            return False
        return (
            replacement_session.__class__ is CreateSessionCommand
            and replacement_session.account_id == account_id
            and _strict_text(replacement_session.session_id)
            and replacement_session.session_id != current_session_id
            and expires_at > occurred_at
        )

    def _recent_password_proof(self, account_id: str, proof: object, occurred_at: datetime) -> bool:
        if (
            not isinstance(proof, PasswordReauthenticationProof)
            or proof.__class__ is not PasswordReauthenticationProof
            or not _strict_text(account_id)
        ):
            return False
        return (
            compare_digest(proof.account_id.encode("utf-8"), account_id.encode("utf-8"))
            and proof.authenticated_at <= occurred_at
            and occurred_at - proof.authenticated_at <= self.evidence_ttl
            and occurred_at <= proof.expires_at
        )

    async def _cleanup_after_change(  # noqa: PLR0913
        self,
        account_id: str,
        security_epoch: int,
        occurred_at: datetime,
        *,
        current_session_id: str | None,
        replacement_session: CreateSessionCommand | None,
        compromise: bool,
    ) -> None:
        if self.refresh_tokens is not None:
            try:
                await self.refresh_tokens.revoke_for_account(
                    account_id,
                    event=_lifecycle_event(
                        self.event_ids,
                        occurred_at,
                        operation="local.password.refresh_revoke",
                        outcome="revoked",
                        account_id=account_id,
                    ),
                )
            except Exception:  # noqa: BLE001
                _LOGGER.error("Password refresh cleanup failed")  # noqa: TRY400
        if self.sessions is None:
            return
        if compromise or current_session_id is None or replacement_session is None:
            await _revoke_all_sessions(self.sessions, account_id, occurred_at, self.event_ids)
            return
        try:
            await self.sessions.revoke_other_sessions(
                account_id,
                current_session_id,
                event=_lifecycle_event(
                    self.event_ids,
                    occurred_at,
                    operation="local.password.session_revoke_others",
                    outcome="revoked",
                    account_id=account_id,
                ),
            )
        except Exception:  # noqa: BLE001
            _LOGGER.error("Password session cleanup failed")  # noqa: TRY400
        try:
            await self.sessions.rebind(
                current_session_id,
                replace(
                    replacement_session, account_id=account_id, security_epoch=security_epoch, created_at=occurred_at
                ),
                event=_lifecycle_event(
                    self.event_ids,
                    occurred_at,
                    operation="local.password.session_rebind",
                    outcome="rebound",
                    account_id=account_id,
                ),
            )
        except Exception:  # noqa: BLE001
            _LOGGER.error("Password session rebind failed")  # noqa: TRY400


@dataclass(frozen=True, slots=True)
class RecoveryTokenService(Generic[UserT]):
    """Issue enumeration-resistant password-recovery notification commands."""

    accounts: AccountLookup[UserT] = field(repr=False)
    store: RecoveryTokenStore = field(repr=False)
    tokens: PurposeTokenCodec = field(repr=False)
    hasher: PasswordHasher = field(repr=False)
    password_policy: PasswordPolicy = field(default_factory=PasswordPolicy, repr=False)
    sessions: SessionRegistry | None = field(default=None, repr=False)
    refresh_tokens: RefreshTokenFamilyStore | None = field(default=None, repr=False)
    lifetime: timedelta = _RECOVERY_TOKEN_LIFETIME
    maximum_attempts: int = _DEFAULT_TOKEN_ATTEMPTS
    return_url: str | None = None
    clock: "Callable[[], datetime]" = field(default=_utc_now, repr=False, compare=False)
    normalizer: "Callable[[str], str]" = field(default=normalize_identifier, repr=False, compare=False)
    event_ids: "Callable[[], str]" = field(default=_new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate lookup, atomic recovery store, and deterministic hooks."""
        if not isinstance(object.__getattribute__(self, "accounts"), AccountLookup):
            msg = "Recovery token accounts must implement AccountLookup"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(object.__getattribute__(self, "store"), RecoveryTokenStore):
            msg = "Recovery token store must implement RecoveryTokenStore"
            raise ImproperlyConfiguredException(detail=msg)
        if object.__getattribute__(self, "tokens").__class__ is not PurposeTokenCodec:
            msg = "Recovery token codec must be PurposeTokenCodec"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(object.__getattribute__(self, "hasher"), PasswordHasher):
            msg = "Recovery token hasher must implement PasswordHasher"
            raise ImproperlyConfiguredException(detail=msg)
        if object.__getattribute__(self, "password_policy").__class__ is not PasswordPolicy:
            msg = "Recovery token password policy must be PasswordPolicy"
            raise ImproperlyConfiguredException(detail=msg)
        if self.sessions is not None and not isinstance(object.__getattribute__(self, "sessions"), SessionRegistry):
            msg = "Recovery token sessions must implement SessionRegistry"
            raise ImproperlyConfiguredException(detail=msg)
        if self.refresh_tokens is not None and not isinstance(
            object.__getattribute__(self, "refresh_tokens"), RefreshTokenFamilyStore
        ):
            msg = "Recovery token refresh tokens must implement RefreshTokenFamilyStore"
            raise ImproperlyConfiguredException(detail=msg)
        _validate_lifecycle_configuration(
            lifetime=self.lifetime,
            attempts=self.maximum_attempts,
            return_url=self.return_url,
            clock=self.clock,
            normalizer=self.normalizer,
            event_ids=self.event_ids,
            name="Recovery token service",
        )

    async def request(self, identifier: str, *, now: datetime | None = None) -> LifecycleAccepted:
        """Always return the shared response after one token-HMAC work class."""
        try:
            occurred_at = _aware_utc_time(self.clock() if now is None else now)
            normalized_identifier = self.normalizer(identifier)
            issued = self.tokens.issue(
                TokenPurpose.RECOVERY,
                now=occurred_at,
                lifetime=self.lifetime,
                template="local.recovery",
                destination=normalized_identifier,
                return_url=self.return_url,
                maximum_attempts=self.maximum_attempts,
            )
            account = await self.accounts.find_for_login(normalized_identifier) if normalized_identifier else None
            if account is not None and account.active:
                issue, notification = issued.bind(account.account_id, security_epoch=account.security_epoch)
                await self.store.issue(
                    issue,
                    notification,
                    event=_lifecycle_event(
                        self.event_ids,
                        occurred_at,
                        operation="local.recovery.issue",
                        outcome="issued",
                        account_id=account.account_id,
                    ),
                )
        except Exception:  # noqa: BLE001
            _LOGGER.error("Recovery token request failed")  # noqa: TRY400 - omit untrusted exception details
        return LifecycleAccepted()

    async def reset(
        self, token: object, password: str, *, now: datetime | None = None
    ) -> PasswordResetResult | PasswordPolicyResult | VerificationUnavailable:
        """Apply policy and delegate token consumption and password replacement atomically."""
        proof = self.tokens.proof(token, expected_purpose=TokenPurpose.RECOVERY)
        if proof is None:
            return PasswordResetResult(PasswordResetStatus.INVALID)
        try:
            policy_result = self.password_policy.check(password)
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if not policy_result.accepted:
            return policy_result
        try:
            occurred_at = _aware_utc_time(self.clock() if now is None else now)
            password_hash = await self.hasher.hash(password)
            result = await self.store.consume_and_reset(
                proof.token_id,
                proof.digest,
                password_hash,
                now=occurred_at,
                event=_lifecycle_event(
                    self.event_ids, occurred_at, operation="local.recovery.consume", outcome="reset"
                ),
            )
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if result.status is PasswordResetStatus.RESET and result.account_id is not None:
            with CancelScope(shield=True):
                await _revoke_all_credentials(
                    account_id=result.account_id,
                    sessions=self.sessions,
                    refresh_tokens=self.refresh_tokens,
                    occurred_at=occurred_at,
                    event_ids=self.event_ids,
                    operation="local.recovery",
                )
        return result


async def _revoke_all_sessions(
    sessions: SessionRegistry,
    account_id: str,
    occurred_at: datetime,
    event_ids: "Callable[[], str]",
    *,
    operation: str = "local.password.session_revoke_all",
) -> None:
    try:
        await sessions.revoke_sessions_for_account(
            account_id,
            event=_lifecycle_event(
                event_ids, occurred_at, operation=operation, outcome="revoked", account_id=account_id
            ),
        )
    except Exception:  # noqa: BLE001
        _LOGGER.error("Password session cleanup failed")  # noqa: TRY400


async def _revoke_all_credentials(  # noqa: PLR0913
    *,
    account_id: str,
    sessions: SessionRegistry | None,
    refresh_tokens: RefreshTokenFamilyStore | None,
    occurred_at: datetime,
    event_ids: "Callable[[], str]",
    operation: str,
) -> None:
    if sessions is not None:
        await _revoke_all_sessions(
            sessions, account_id, occurred_at, event_ids, operation=f"{operation}.session_revoke_all"
        )
    if refresh_tokens is not None:
        try:
            await refresh_tokens.revoke_for_account(
                account_id,
                event=_lifecycle_event(
                    event_ids,
                    occurred_at,
                    operation=f"{operation}.refresh_revoke",
                    outcome="revoked",
                    account_id=account_id,
                ),
            )
        except Exception:  # noqa: BLE001
            _LOGGER.error("Password refresh cleanup failed")  # noqa: TRY400


def _validate_lifecycle_configuration(  # noqa: PLR0913
    *,
    lifetime: timedelta,
    attempts: int,
    return_url: str | None,
    clock: object,
    normalizer: object,
    event_ids: object,
    name: str,
) -> None:
    if lifetime.__class__ is not timedelta or lifetime <= timedelta(0):
        msg = f"{name} lifetime must be positive"
        raise ImproperlyConfiguredException(detail=msg)
    if attempts.__class__ is not int or not 1 <= attempts <= _MAXIMUM_TOKEN_ATTEMPTS:
        msg = f"{name} attempts must be a positive bounded integer"
        raise ImproperlyConfiguredException(detail=msg)
    if return_url is not None and not _approved_return_url(return_url):
        msg = f"{name} return URL must be an approved absolute HTTP(S) URL"
        raise ImproperlyConfiguredException(detail=msg)
    if not callable(clock) or not callable(normalizer) or not callable(event_ids):
        msg = f"{name} hooks must be callable"
        raise ImproperlyConfiguredException(detail=msg)


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
    ) -> PasswordReauthenticationProof | InvalidCredentials | VerificationUnavailable:
        """Return an account- and epoch-bound proof or one sanitized domain outcome."""
        account_value: object = account_id
        if account_value.__class__ is not str or not (normalized_account_id := account_id.strip()):
            return InvalidCredentials()
        try:
            authenticated_at = _aware_utc_time(self.clock() if now is None else now)
            state = await self.accounts.get_password_state(normalized_account_id)
            encoded_hash = state.password_hash if state is not None else None
            result = await self.hasher.verify(encoded_hash, password)
        except Exception:  # noqa: BLE001
            return VerificationUnavailable()
        if not result.verified or encoded_hash is None or state is None:
            if result.status is PasswordVerificationStatus.MALFORMED:
                await self._emit_malformed(normalized_account_id, authenticated_at)
            return InvalidCredentials()
        if result.replacement_hash is not None and not await self._rehash(
            normalized_account_id, encoded_hash, result.replacement_hash, authenticated_at
        ):
            return VerificationUnavailable()
        return PasswordReauthenticationProof(
            account_id=normalized_account_id,
            security_epoch=state.security_epoch,
            authenticated_at=authenticated_at,
            expires_at=authenticated_at + self.evidence_ttl,
        )

    async def _rehash(self, account_id: str, expected_hash: str, replacement_hash: str, occurred_at: datetime) -> bool:
        try:
            event = self._event(account_id, occurred_at, operation="local.password.rehash", outcome="updated")
            replaced: object = await self.accounts.compare_and_replace_password(
                account_id, expected_hash, replacement_hash, event=event
            )
        except Exception:  # noqa: BLE001
            return False
        return replaced is True

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
    session_auth: NativeSessionAuth[UserT] | None = field(default=None, repr=False, compare=False)

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
        self._configure_session_auth()

    def _configure_session_auth(self) -> None:
        if self.mode not in {LocalAuthMode.SESSION, LocalAuthMode.HYBRID}:
            if self.session_auth is not None:
                msg = "Token-only local authentication cannot configure native session authentication"
                raise ImproperlyConfiguredException(detail=msg)
            return
        binding = self.binding
        if not isinstance(binding, SessionBindingConfig):  # pragma: no cover - guarded above
            return
        session_auth = self.session_auth
        if session_auth is None:
            object.__setattr__(
                self,
                "session_auth",
                NativeSessionAuth[UserT](accounts=cast("NativeSessionStore[UserT]", self.accounts), binding=binding),
            )
        elif id(session_auth.accounts) != id(self.accounts) or session_auth.binding is not binding:
            msg = "Custom native session authentication must share the configured accounts and binding"
            raise ImproperlyConfiguredException(detail=msg)

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
    def session(  # noqa: PLR0913
        cls,
        *,
        accounts: LocalAccountCapabilities[UserT],
        csrf: CSRFConfig | ExternalCSRF,
        binding: SessionBindingConfig,
        session_auth: NativeSessionAuth[UserT] | None = None,
        registration: RegistrationPolicy = _DISABLED_REGISTRATION,
        route_prefix: str = "/auth",
    ) -> "LocalAuthConfig[UserT]":
        """Select native-session local authentication."""
        return LocalAuthConfig(
            mode=LocalAuthMode.SESSION,
            accounts=accounts,
            csrf=csrf,
            binding=binding,
            session_auth=session_auth,
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
        session_auth: NativeSessionAuth[UserT] | None = None,
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
            session_auth=session_auth,
            registration=registration,
            route_prefix=route_prefix,
        )
