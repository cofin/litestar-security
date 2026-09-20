"""Unified token generation, encoding, decoding, validation, and refresh rotation."""

import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import Error as BinasciiError
from collections.abc import Callable, Mapping
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
from hmac import compare_digest
from hmac import digest as hmac_digest
from secrets import token_bytes
from types import MappingProxyType
from typing import Any, ClassVar, Generic, Literal, Protocol, TypeVar, cast, runtime_checkable
from unicodedata import normalize
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import (
    DIGEST_BYTES,
    LOOKUP_BYTES,
    MINIMUM_PEPPER_BYTES,
    SECRET_BYTES,
    SECRET_CHARACTERS,
    aware_utc_time,
    decode_random,
    decode_random_unbounded,
    encode_random,
    new_event_id,
    strict_context_text,
    strict_text,
    utc_now,
    valid_identifier,
    valid_security_epoch,
)
from litestar_security.accounts._operations import (
    OUTCOME_ATTEMPTED,
    OUTCOME_CREATED,
    OUTCOME_REVOKED,
    REFRESH_CREATE,
    REFRESH_PREPARE,
    REFRESH_RECEIPT,
    REFRESH_REVOKE,
    REFRESH_ROTATE,
)
from litestar_security.accounts._rate_limits import RateLimited, RateLimitGuard, validate_rate_limits
from litestar_security.accounts.models import LocalAccountState, SecurityEvent, TokenPurpose
from litestar_security.accounts.protocols import AccountLookup, SecurityEpochStore, SecurityEpochValidator
from litestar_security.authentication import (
    Authenticated,
    AuthenticationOutcome,
    InvalidCredentials,
    VerificationUnavailable,
)
from litestar_security.context import AuthenticationEvidence, AuthorizationSnapshot, Principal
from litestar_security.providers.jwt import (
    JWTClaims,
    JWTValidationConfig,
    JWTVerifier,
    TokenSigner,
    build_access_token_claims,
)
from litestar_security.schema import WireStruct

__all__ = (
    "REFRESH_RESPONSE_HEADERS",
    "CreateRefreshFamilyCommand",
    "LocalAccessToken",
    "LocalAccessTokenIssuer",
    "LocalAccessVerifier",
    "LocalBearerIdentityResolver",
    "NotificationCommand",
    "PendingTokenIssue",
    "PurposeTokenCodec",
    "PurposeTokenDelivery",
    "PurposeTokenGenerationError",
    "PurposeTokenProof",
    "RefreshFamilyContext",
    "RefreshPreflightOutcome",
    "RefreshReceiptContext",
    "RefreshReceiptKey",
    "RefreshReceiptReplay",
    "RefreshReceiptSealer",
    "RefreshRotationOutcome",
    "RefreshRotationStatus",
    "RefreshTokenCodec",
    "RefreshTokenFamilyStore",
    "RefreshTokenIssue",
    "RefreshTokenProof",
    "RefreshTokenService",
    "RegistrationCommand",
    "RotateRefreshCommand",
    "TokenIssue",
    "TokenPair",
    "approved_return_url",
    "b64url_decode",
    "b64url_encode",
    "hmac_digest",
    "normalize_refresh_scopes",
    "secure_compare_digest",
    "valid_refresh_scope",
    "validate_access_token_lifetime",
)

UserT = TypeVar("UserT")

_ASCII_CONTROL_LIMIT = 32
_DEFAULT_ACCESS_TOKEN_LIFETIME = timedelta(minutes=10)
_MINIMUM_ACCESS_TOKEN_LIFETIME = timedelta(seconds=30)
_MAXIMUM_ACCESS_TOKEN_LIFETIME = timedelta(hours=1)
_DEFAULT_LOCAL_CLIENT_ID = "local"
_MAXIMUM_ACCESS_TOKEN_BYTES = 16_384
_COMPACT_JWT_SEGMENTS = 3

_MINIMUM_TOKEN_PEPPER_BYTES = 32
_TOKEN_LOOKUP_BYTES = 16
_TOKEN_SECRET_BYTES = 32
_TOKEN_DIGEST_BYTES = 32
_TOKEN_LOOKUP_CHARACTERS = 22
_TOKEN_SECRET_CHARACTERS = 43
_DEFAULT_TOKEN_ATTEMPTS = 5
_MAXIMUM_TOKEN_ATTEMPTS = 100
_DUMMY_TOKEN_LOOKUP = b"\x00" * _TOKEN_LOOKUP_BYTES
_DUMMY_TOKEN_SECRET = b"\x00" * _TOKEN_SECRET_BYTES

_REFRESH_TOKEN_PREFIX = "rt_"
_REFRESH_FAMILY_PREFIX = "rf_"
_REFRESH_TOKEN_DOMAIN = b"refresh-token\x00"
_REFRESH_IDEMPOTENCY_DOMAIN = b"refresh-idempotency\x00"
_MINIMUM_IDEMPOTENCY_CHARACTERS = 22
_MAXIMUM_IDEMPOTENCY_CHARACTERS = 128
_MINIMUM_ACCESS_TOKEN_SECONDS = 30
_MAXIMUM_ACCESS_TOKEN_SECONDS = 3_600

_REFRESH_RECEIPT_VERSION = "rr1"
_RECEIPT_NONCE_BYTES = 12
_MAXIMUM_RECEIPT_BYTES = 32_768
_AES_256_KEY_BYTES = 32

_DEFAULT_REFRESH_IDLE_LIFETIME = timedelta(days=7)
_DEFAULT_REFRESH_ABSOLUTE_LIFETIME = timedelta(days=30)
_DEFAULT_REFRESH_RECEIPT_WINDOW = timedelta(seconds=30)
_MAXIMUM_REFRESH_RECEIPT_WINDOW = timedelta(seconds=30)

REFRESH_RESPONSE_HEADERS: Mapping[str, str] = MappingProxyType({"Cache-Control": "no-store", "Pragma": "no-cache"})


def b64url_encode(value: bytes) -> str:
    """Encode bytes into an unpadded URL-safe base64 string."""
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Decode an unpadded or padded URL-safe base64 string to bytes."""
    encoded = value.encode("ascii")
    padding = b"=" * (-len(encoded) % 4)
    return urlsafe_b64decode(encoded + padding)


def secure_compare_digest(a: bytes | str, b: bytes | str) -> bool:
    """Compare two digests in constant time to prevent timing attacks."""
    if isinstance(a, str) and isinstance(b, str):
        return compare_digest(a, b)
    if isinstance(a, bytes) and isinstance(b, bytes):
        return compare_digest(a, b)
    return False


def _purpose_token_digest(pepper: bytes, purpose: TokenPurpose, lookup: bytes, secret: bytes) -> bytes:
    return hmac_digest(pepper, purpose.value.encode("ascii") + lookup + secret, "sha256")


def _encode_token_segment(value: bytes) -> str:
    return b64url_encode(value)


def _decode_token_segment(value: object, expected_bytes: int) -> bytes | None:
    expected_characters = (
        _TOKEN_LOOKUP_CHARACTERS if expected_bytes == _TOKEN_LOOKUP_BYTES else _TOKEN_SECRET_CHARACTERS
    )
    if not isinstance(value, str) or type(value) is not str or len(value) != expected_characters:
        return None
    try:
        decoded = b64url_decode(value)
    except (UnicodeError, ValueError):
        return None
    if len(decoded) != expected_bytes or _encode_token_segment(decoded) != value:
        return None
    return decoded


def approved_return_url(value: object) -> bool:
    """Validate return URL security requirements."""
    if (
        not isinstance(value, str)
        or type(value) is not str
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


def _validate_pending_token_issue(issue: "PendingTokenIssue | TokenIssue") -> None:
    if (
        type(issue.purpose) is not TokenPurpose
        or not _valid_token_id(issue.token_id, issue.purpose)
        or type(issue.digest) is not bytes
        or len(issue.digest) != _TOKEN_DIGEST_BYTES
        or type(issue.maximum_attempts) is not int
        or not 1 <= issue.maximum_attempts <= _MAXIMUM_TOKEN_ATTEMPTS
    ):
        msg = "Invalid pending purpose token issue"
        raise ValueError(msg)
    try:
        aware_utc_time(issue.expires_at)
    except (AttributeError, ValueError):
        msg = "Pending purpose token expiry must be timezone-aware"
        raise ValueError(msg) from None


def _valid_token_id(token_id: object, purpose: TokenPurpose) -> bool:
    if not isinstance(token_id, str) or type(token_id) is not str:
        return False
    prefix = f"{purpose.value}_"
    if not token_id.startswith(prefix):
        return False
    segment = token_id[len(prefix) :]
    return _decode_token_segment(segment, _TOKEN_LOOKUP_BYTES) is not None


@dataclass(frozen=True, slots=True)
class PendingTokenIssue:
    """Account-unbound hashed token material for one atomic registration."""

    token_id: str
    digest: bytes = field(repr=False)
    purpose: TokenPurpose
    expires_at: datetime
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
    expires_at: datetime
    maximum_attempts: int
    account_id: str
    issued_security_epoch: int | None = None

    def __post_init__(self) -> None:
        """Require a stable account binding in addition to valid token material."""
        _validate_pending_token_issue(self)
        recovery_epoch_valid = self.purpose is not TokenPurpose.RECOVERY or valid_security_epoch(
            self.issued_security_epoch
        )
        non_recovery_epoch_valid = self.purpose is TokenPurpose.RECOVERY or self.issued_security_epoch is None
        if not strict_text(self.account_id) or not recovery_epoch_valid or not non_recovery_epoch_valid:
            msg = "Purpose token account binding or issuance epoch is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class NotificationCommand:
    """Delivery-neutral notification data with a one-time opaque token."""

    template: str
    destination: str = field(repr=False)
    token: str = field(repr=False)
    expires_at: datetime
    return_url: str | None = None

    def __post_init__(self) -> None:
        """Reject incomplete delivery commands and unapproved callback shapes."""
        if not strict_text(self.template) or not strict_text(self.token):
            msg = "Notification template and token must not be blank"
            raise ValueError(msg)
        if not strict_context_text(self.destination):
            msg = "Notification destination must be bounded text without control characters"
            raise ValueError(msg)
        try:
            aware_utc_time(self.expires_at)
        except (AttributeError, ValueError):
            msg = "Notification expiry must be timezone-aware"
            raise ValueError(msg) from None
        if self.return_url is not None and not approved_return_url(self.return_url):
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
            type(self.purpose) is not TokenPurpose
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


class PurposeTokenGenerationError(RuntimeError):
    """Indicate that one-time token material could not be generated safely."""

    def __init__(self) -> None:
        """Initialize a stable secret-free error."""
        super().__init__("Purpose token generation unavailable")


@dataclass(frozen=True, slots=True)
class PurposeTokenCodec:
    """Generate and verify strict purpose-bound opaque one-time tokens."""

    pepper: bytes = field(repr=False)
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Require an explicit strong HMAC pepper and callable entropy source."""
        pepper_value: object = object.__getattribute__(self, "pepper")
        entropy_value: object = object.__getattribute__(self, "entropy")
        if type(pepper_value) is not bytes or len(self.pepper) < _MINIMUM_TOKEN_PEPPER_BYTES:
            msg = "Purpose token pepper must contain at least 32 bytes"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(entropy_value):
            msg = "Purpose token entropy must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    def issue(
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
        if type(purpose) is not TokenPurpose:
            msg = "Purpose token namespace must be a TokenPurpose"
            raise ValueError(msg)
        issued_at = aware_utc_time(now)
        if type(lifetime) is not timedelta or lifetime <= timedelta(0):
            msg = "Purpose token lifetime must be positive"
            raise ValueError(msg)
        if type(maximum_attempts) is not int or not 1 <= maximum_attempts <= _MAXIMUM_TOKEN_ATTEMPTS:
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
        if type(expected_purpose) is not TokenPurpose:
            msg = "Expected purpose token namespace must be a TokenPurpose"
            raise ValueError(msg)
        lookup = _DUMMY_TOKEN_LOOKUP
        secret = _DUMMY_TOKEN_SECRET
        token_id = ""
        valid = False
        if isinstance(token, str) and type(token) is str:
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
        except Exception:
            raise PurposeTokenGenerationError from None
        if type(value) is not bytes or len(value) != length:
            raise PurposeTokenGenerationError
        return value


def validate_access_token_lifetime(value: object) -> None:
    """Validate access-token lifetime parameters."""
    if not isinstance(value, timedelta):
        msg = "Local access-token lifetime must be a timedelta"
        raise ImproperlyConfiguredException(detail=msg)
    if value < _MINIMUM_ACCESS_TOKEN_LIFETIME:
        msg = "Local access-token lifetime must be at least 30 seconds"
        raise ImproperlyConfiguredException(detail=msg)
    if value > _MAXIMUM_ACCESS_TOKEN_LIFETIME:
        msg = "Local access-token lifetime must be at most one hour"
        raise ImproperlyConfiguredException(detail=msg)
    if value.microseconds:
        msg = "Local access-token lifetime must use whole seconds"
        raise ImproperlyConfiguredException(detail=msg)


def _strict_claim_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and type(value) is str
        and bool(value)
        and value == value.strip()
        and normalize("NFC", value) == value
        and all(not character.isspace() and ord(character) >= _ASCII_CONTROL_LIMIT for character in value)
    )


def _valid_compact_access_token(value: object) -> bool:
    if not isinstance(value, str) or type(value) is not str:
        return False
    segments = value.split(".")
    structurally_valid = (
        strict_text(value)
        and len(value.encode("ascii", errors="ignore")) == len(value)
        and len(value) <= _MAXIMUM_ACCESS_TOKEN_BYTES
        and len(segments) == _COMPACT_JWT_SEGMENTS
        and all(segments)
    )
    if not structurally_valid:
        return False
    try:
        return all(b64url_encode(b64url_decode(segment)) == segment for segment in segments)
    except (BinasciiError, UnicodeEncodeError, ValueError):
        return False


def _claim_set(value: object) -> frozenset[str] | None:
    if value is None:
        return frozenset()
    if not isinstance(value, (list, tuple)):
        return None
    values = cast("list[object] | tuple[object, ...]", value)
    if any(not _strict_claim_text(item) for item in values):
        return None
    normalized = frozenset(cast("list[str] | tuple[str, ...]", values))
    return normalized if len(normalized) == len(values) else None


def _claim_authentication_time(value: object, *, fallback: datetime) -> datetime | None:
    if value is None:
        return fallback
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    try:
        return datetime.fromtimestamp(value, tz=fallback.tzinfo)
    except (OverflowError, OSError, ValueError):
        return None


@dataclass(frozen=True, slots=True)
class LocalAccessToken:
    """Secret-safe response from one local access-token issuance."""

    access_token: str = field(repr=False)
    expires_in: int
    token_type: Literal["Bearer"] = field(default="Bearer", init=False)

    def __post_init__(self) -> None:
        """Require one compact credential and a bounded whole-second lifetime."""
        token_value: object = self.access_token
        if (
            not _valid_compact_access_token(token_value)
            or type(self.expires_in) is not int
            or not int(_MINIMUM_ACCESS_TOKEN_LIFETIME.total_seconds())
            <= self.expires_in
            <= int(_MAXIMUM_ACCESS_TOKEN_LIFETIME.total_seconds())
        ):
            msg = "Local access token requires a compact credential and bounded expiry"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class LocalAccessTokenIssuer(Generic[UserT]):
    """Issue local access tokens by signing a minimal server-owned claim set."""

    signer: TokenSigner = field(repr=False)
    issuer: str
    audience: str
    client_id: str = _DEFAULT_LOCAL_CLIENT_ID
    lifetime: timedelta = _DEFAULT_ACCESS_TOKEN_LIFETIME
    clock: Callable[[], datetime] = field(default=utc_now, repr=False, compare=False)
    token_ids: Callable[[], str] = field(default=new_event_id, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate server-owned claims and the configured access-token lifetime."""
        signer_value: object = object.__getattribute__(self, "signer")
        clock_value: object = object.__getattribute__(self, "clock")
        token_ids_value: object = object.__getattribute__(self, "token_ids")
        if not isinstance(signer_value, TokenSigner):
            msg = "Local access-token issuer signer must implement TokenSigner"
            raise ImproperlyConfiguredException(detail=msg)
        for value, name in ((self.issuer, "issuer"), (self.audience, "audience"), (self.client_id, "client id")):
            if not _strict_claim_text(value):
                msg = f"Local access-token {name} must be non-empty normalized text"
                raise ImproperlyConfiguredException(detail=msg)
        validate_access_token_lifetime(self.lifetime)
        if not callable(clock_value) or not callable(token_ids_value):
            msg = "Local access-token clock and token id factory must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    async def issue(
        self,
        account: LocalAccountState[UserT],
        *,
        scopes: AbstractSet[str] = frozenset(),
        evidence: AuthenticationEvidence | None = None,
        now: datetime | None = None,
    ) -> LocalAccessToken | InvalidCredentials | VerificationUnavailable:
        """Issue one short-lived epoch-bound token without serializing application data."""
        if type(account) is not LocalAccountState or not account.active or not account.verified:
            return InvalidCredentials()
        try:
            issued_at = aware_utc_time(self.clock() if now is None else now)
            token_id = self.token_ids()
        except Exception:
            return VerificationUnavailable()
        try:
            claims = build_access_token_claims(
                issuer=self.issuer,
                audience=self.audience,
                subject=account.account_id,
                client_id=self.client_id,
                security_epoch=account.security_epoch,
                now=issued_at,
                lifetime=self.lifetime,
                scopes=scopes,
                methods=evidence.methods if evidence is not None else frozenset(),
                traits=evidence.traits if evidence is not None else frozenset(),
                amr=evidence.amr if evidence is not None else (),
                authenticated_at=evidence.authenticated_at if evidence is not None else None,
                jti=token_id,
            )
        except (TypeError, ValueError):
            return InvalidCredentials()
        try:
            token = await self.signer.sign(claims, now=issued_at)
            return LocalAccessToken(access_token=token, expires_in=int(self.lifetime.total_seconds()))
        except Exception:
            return VerificationUnavailable()


@dataclass(slots=True)
class LocalAccessVerifier:
    """Promote only application-issued local scopes into authorization grants."""

    config: JWTValidationConfig
    verifier: JWTVerifier[JWTClaims] = field(repr=False)

    async def verify(self, token: str, *, now: datetime) -> AuthenticationOutcome[JWTClaims]:
        """Verify token against configuration."""
        outcome = await self.verifier.verify(token, now=now)
        if not isinstance(outcome, Authenticated):
            return outcome
        methods = _claim_set(outcome.claims.raw.get("amr"))
        traits = _claim_set(outcome.claims.raw.get("security_traits"))
        authenticated_at = _claim_authentication_time(
            outcome.claims.raw.get("auth_time"), fallback=outcome.claims.issued_at
        )
        if methods is None or traits is None or authenticated_at is None:
            return InvalidCredentials()
        return replace(
            outcome,
            evidence=replace(
                outcome.evidence,
                authenticated_at=authenticated_at,
                methods=methods,
                traits=traits,
                amr=tuple(sorted(methods)),
            ),
            grants=AuthorizationSnapshot(scopes=outcome.claims.scopes),
        )


@dataclass(frozen=True, slots=True)
class LocalBearerIdentityResolver(Generic[UserT]):
    """Resolve verified local JWT claims through exact account and epoch state."""

    accounts: AccountLookup[UserT] = field(repr=False)
    _epochs: SecurityEpochValidator = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Require account and authoritative security-epoch lookup capabilities."""
        accounts_value: object = object.__getattribute__(self, "accounts")
        if not isinstance(accounts_value, AccountLookup) or not isinstance(accounts_value, SecurityEpochStore):
            msg = "Local bearer resolver accounts must implement AccountLookup and SecurityEpochStore"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "_epochs", SecurityEpochValidator(store=cast("SecurityEpochStore", accounts_value)))

    async def resolve(self, claims: JWTClaims) -> Principal[UserT] | InvalidCredentials | VerificationUnavailable:
        """Return a principal only for an active account at the exact current epoch."""
        epoch = claims.raw.get("se")
        if claims.subject is None or not valid_security_epoch(epoch):
            return InvalidCredentials()
        try:
            account = await self.accounts.get_by_id(claims.subject)
        except Exception:
            return VerificationUnavailable()
        if (
            account is None
            or account.account_id != claims.subject
            or not account.active
            or not account.verified
            or account.security_epoch != epoch
        ):
            return InvalidCredentials()
        epoch_result = await self._epochs.validate(claims.subject, cast("int", epoch))
        if epoch_result is not None:
            return epoch_result
        return Principal(id=account.account_id, display_name=account.display_name, user=account.user)


class RefreshRotationStatus(str, Enum):
    """Atomic refresh-token rotation outcomes."""

    ROTATED = "rotated"
    IDEMPOTENT_REPLAY = "idempotent_replay"
    REPLAY_DETECTED = "replay_detected"
    EXPIRED = "expired"
    REVOKED = "revoked"
    EPOCH_MISMATCH = "epoch_mismatch"
    INVALID = "invalid"


def valid_refresh_scope(value: object) -> bool:
    """Validate whether a value conforms to the refresh token scope syntax."""
    return (
        isinstance(value, str)
        and bool(value)
        and all(character == "!" or "#" <= character <= "[" or "]" <= character <= "~" for character in value)
    )


def normalize_refresh_scopes(scopes: object) -> frozenset[str] | None:
    """Normalize and validate an abstract set of refresh scopes."""
    if not isinstance(scopes, AbstractSet):
        return None
    try:
        normalized = frozenset(cast("AbstractSet[object]", scopes))
    except TypeError:
        return None
    return cast("frozenset[str]", normalized) if all(valid_refresh_scope(scope) for scope in normalized) else None


@dataclass(frozen=True, slots=True)
class RefreshTokenProof:
    """Parsed refresh-token lookup and fixed-size domain-separated digest."""

    token_id: str
    digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Validate identifier syntax and digest length."""
        if (
            not valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or self.digest.__class__ is not bytes
            or len(self.digest) != DIGEST_BYTES
        ):
            msg = "Refresh token proof is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RefreshTokenIssue:
    """Generated refresh token paired with its storage-bound identifier and digest."""

    refresh_token: str = field(repr=False)
    token_id: str
    digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Validate token structure, identifier, and digest length."""
        if (
            _parse_refresh_token(self.refresh_token) is None
            or not valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or not self.refresh_token.startswith(f"{self.token_id}.")
            or self.digest.__class__ is not bytes
            or len(self.digest) != DIGEST_BYTES
        ):
            msg = "Refresh token issue is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RefreshTokenCodec:
    """Issue and verify opaque refresh tokens while storing only HMAC digests."""

    pepper: bytes = field(repr=False)
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate pepper and entropy configuration."""
        entropy_value: object = self.entropy
        if self.pepper.__class__ is not bytes or len(self.pepper) < MINIMUM_PEPPER_BYTES:
            msg = "Refresh token pepper must contain at least 32 bytes"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(entropy_value):
            msg = "Refresh token entropy source must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    def issue(self) -> RefreshTokenIssue:
        """Create one lookup/secret pair and its storage-safe digest."""
        lookup = self.entropy(LOOKUP_BYTES)
        secret = self.entropy(SECRET_BYTES)
        if (
            lookup.__class__ is not bytes
            or len(lookup) != LOOKUP_BYTES
            or secret.__class__ is not bytes
            or len(secret) != SECRET_BYTES
        ):
            msg = "Refresh token entropy source returned invalid material"
            raise RuntimeError(msg)
        token_id = f"{_REFRESH_TOKEN_PREFIX}{encode_random(lookup)}"
        refresh_token = f"{token_id}.{encode_random(secret)}"
        return RefreshTokenIssue(refresh_token=refresh_token, token_id=token_id, digest=self._digest(token_id, secret))

    def verify(self, refresh_token: str) -> RefreshTokenProof | InvalidCredentials:
        """Parse one canonical token while keeping malformed work in the HMAC class."""
        parsed = _parse_refresh_token(refresh_token)
        token_id, secret = (
            parsed
            if parsed is not None
            else (f"{_REFRESH_TOKEN_PREFIX}{encode_random(bytes(LOOKUP_BYTES))}", bytes(SECRET_BYTES))
        )
        digest = self._digest(token_id, secret)
        return RefreshTokenProof(token_id=token_id, digest=digest) if parsed is not None else InvalidCredentials()

    def digest_idempotency_key(self, token_id: str, value: str) -> bytes | InvalidCredentials:
        """Hash one canonical key carrying at least 128 bits of caller entropy."""
        if (
            not valid_identifier(token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or value.__class__ is not str
            or not _MINIMUM_IDEMPOTENCY_CHARACTERS <= len(value) <= _MAXIMUM_IDEMPOTENCY_CHARACTERS
        ):
            return InvalidCredentials()
        try:
            decoded = decode_random_unbounded(value)
        except (BinasciiError, UnicodeEncodeError, ValueError):
            return InvalidCredentials()
        return hmac_digest(
            self.pepper, _REFRESH_IDEMPOTENCY_DOMAIN + token_id.encode("ascii") + b"\x00" + decoded, sha256
        )

    def _digest(self, token_id: str, secret: bytes) -> bytes:
        return hmac_digest(self.pepper, _REFRESH_TOKEN_DOMAIN + token_id.encode("ascii") + b"\x00" + secret, sha256)


class TokenPair(WireStruct, frozen=True):
    """Secret-safe token response recovered from a sealed rotation receipt."""

    __wire_casing__: ClassVar[bool] = False

    access_token: str
    refresh_token: str
    expires_in: int
    token_type: Literal["Bearer"] = "Bearer"

    def __repr__(self) -> str:
        """Redact both issued credentials."""
        return (
            f"{type(self).__name__}(access_token=<redacted>, refresh_token=<redacted>, "
            f"expires_in={self.expires_in!r}, token_type={self.token_type!r})"
        )

    def __post_init__(self) -> None:
        """Validate exact bearer response fields without exposing credentials."""
        if (
            not _valid_compact_jwt(self.access_token)
            or _parse_refresh_token(self.refresh_token) is None
            or self.expires_in.__class__ is not int
            or self.expires_in < _MINIMUM_ACCESS_TOKEN_SECONDS
            or self.expires_in > _MAXIMUM_ACCESS_TOKEN_SECONDS
        ):
            msg = "Refresh token response is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RefreshFamilyContext:
    """Secret-free preflight state revalidated by the atomic rotation call."""

    account_id: str
    family_id: str
    security_epoch: int
    token_expires_at: datetime
    family_expires_at: datetime
    scopes: frozenset[str] = frozenset()
    evidence: AuthenticationEvidence | None = None

    def __post_init__(self) -> None:
        """Validate proof-checked preflight metadata and preserved scopes."""
        try:
            token_expires_at = aware_utc_time(self.token_expires_at)
            family_expires_at = aware_utc_time(self.family_expires_at)
        except (AttributeError, ValueError):
            msg = "Refresh family expiry must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not strict_context_text(self.account_id)
            or not valid_identifier(self.family_id, prefix=_REFRESH_FAMILY_PREFIX)
            or not valid_security_epoch(self.security_epoch)
            or token_expires_at > family_expires_at
            or any(not valid_refresh_scope(scope) for scope in self.scopes)
            or (self.evidence is not None and type(self.evidence) is not AuthenticationEvidence)
        ):
            msg = "Refresh family context is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "token_expires_at", token_expires_at)
        object.__setattr__(self, "family_expires_at", family_expires_at)
        object.__setattr__(self, "scopes", frozenset(self.scopes))


def _parse_refresh_token(value: object) -> tuple[str, bytes] | None:
    if not isinstance(value, str) or value.__class__ is not str:
        return None
    token_id, separator, encoded_secret = value.partition(".")
    if (
        separator != "."
        or "." in encoded_secret
        or not valid_identifier(token_id, prefix=_REFRESH_TOKEN_PREFIX)
        or len(encoded_secret) != SECRET_CHARACTERS
    ):
        return None
    secret = decode_random(encoded_secret, SECRET_BYTES)
    return (token_id, secret) if secret is not None else None


def _valid_compact_jwt(value: object) -> bool:
    if not isinstance(value, str) or value.__class__ is not str or len(value) > _MAXIMUM_ACCESS_TOKEN_BYTES:
        return False
    segments = value.split(".")
    if len(segments) != _COMPACT_JWT_SEGMENTS or any(not segment for segment in segments):
        return False
    try:
        return all(bool(decode_random_unbounded(segment)) for segment in segments)
    except (BinasciiError, UnicodeEncodeError, ValueError):
        return False


@dataclass(frozen=True, slots=True)
class RefreshReceiptKey:
    """One AES-256-GCM receipt key selected by a non-secret key ID."""

    key_id: str
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Require one safe lookup ID and exact AES-256 key."""
        if (
            not strict_context_text(self.key_id)
            or any(
                not (character.isascii() and (character.isalnum() or character in "_-")) for character in self.key_id
            )
            or type(self.key) is not bytes
            or len(self.key) != _AES_256_KEY_BYTES
        ):
            msg = "Refresh receipt key requires a safe ID and 32-byte key"
            raise ImproperlyConfiguredException(detail=msg)


@dataclass(frozen=True, slots=True)
class RefreshReceiptContext:
    """Public receipt binding values; no raw credential material is retained."""

    token_id: str
    family_id: str
    account_id: str
    security_epoch: int
    idempotency_digest: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Validate every authenticated receipt binding value."""
        if (
            not valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or not valid_identifier(self.family_id, prefix=_REFRESH_FAMILY_PREFIX)
            or not strict_context_text(self.account_id)
            or not valid_security_epoch(self.security_epoch)
            or (
                self.idempotency_digest is not None
                and (type(self.idempotency_digest) is not bytes or len(self.idempotency_digest) != DIGEST_BYTES)
            )
        ):
            msg = "Refresh receipt context is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RefreshReceiptSealer:
    """Seal exact refresh responses with rotating AES-GCM keys and bound AAD."""

    active_key: RefreshReceiptKey = field(repr=False)
    retained_keys: tuple[RefreshReceiptKey, ...] = field(default=(), repr=False)
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)
    _keys: Mapping[str, RefreshReceiptKey] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Compile active and retained receipt keys by unique ID."""
        active_key_value: object = self.active_key
        retained_values: tuple[object, ...] = tuple(self.retained_keys)
        entropy_value: object = self.entropy
        keys = (_require_receipt_key(active_key_value), *(_require_receipt_key(key) for key in retained_values))
        if len({key.key_id for key in keys}) != len(keys):
            msg = "Refresh receipt key IDs must be unique"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(entropy_value):
            msg = "Refresh receipt entropy source must be callable"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "retained_keys", tuple(self.retained_keys))
        object.__setattr__(self, "_keys", MappingProxyType({key.key_id: key for key in keys}))

    def seal(self, response: TokenPair, context: RefreshReceiptContext, *, expires_at: datetime) -> bytes:
        """Seal one exact response and authenticate all replay decision fields."""
        expiry = _receipt_expiry(expires_at)
        nonce = self.entropy(_RECEIPT_NONCE_BYTES)
        if type(nonce) is not bytes or len(nonce) != _RECEIPT_NONCE_BYTES:
            msg = "Refresh receipt entropy source returned an invalid nonce"
            raise RuntimeError(msg)
        plaintext = json.dumps(
            {
                "access_token": response.access_token,
                "expires_in": response.expires_in,
                "refresh_token": response.refresh_token,
                "token_type": response.token_type,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        ciphertext = AESGCM(self.active_key.key).encrypt(
            nonce, plaintext, _receipt_aad(context, expiry, self.active_key.key_id)
        )
        return ".".join((
            _REFRESH_RECEIPT_VERSION,
            self.active_key.key_id,
            str(expiry),
            encode_random(nonce),
            encode_random(ciphertext),
        )).encode("ascii")

    def unseal(
        self, sealed_receipt: bytes, context: RefreshReceiptContext, *, now: datetime
    ) -> TokenPair | InvalidCredentials:
        """Recover one response only while its bound receipt and key remain valid."""
        try:
            current = aware_utc_time(now)
        except (AttributeError, ValueError):
            return InvalidCredentials()
        parsed = _parse_receipt_envelope(sealed_receipt)
        if parsed is None:
            return InvalidCredentials()
        key_id, expiry, nonce, ciphertext = parsed
        key = self._keys.get(key_id)
        if key is None or _timestamp_microseconds(current) >= expiry:
            return InvalidCredentials()
        try:
            plaintext = AESGCM(key.key).decrypt(nonce, ciphertext, _receipt_aad(context, expiry, key_id))
            payload_value: object = json.loads(plaintext)
            if not isinstance(payload_value, dict):
                return InvalidCredentials()
            payload = cast("Mapping[str, object]", payload_value)
            if frozenset(payload) != frozenset({"access_token", "expires_in", "refresh_token", "token_type"}):
                return InvalidCredentials()
            access_token = payload.get("access_token")
            refresh_token = payload.get("refresh_token")
            expires_in = payload.get("expires_in")
            if (
                payload.get("token_type") != "Bearer"
                or not isinstance(access_token, str)
                or not isinstance(refresh_token, str)
                or not isinstance(expires_in, int)
                or isinstance(expires_in, bool)
            ):
                return InvalidCredentials()
            return TokenPair(access_token=access_token, refresh_token=refresh_token, expires_in=expires_in)
        except (InvalidTag, KeyError, TypeError, UnicodeDecodeError, ValueError):
            return InvalidCredentials()


@dataclass(frozen=True, slots=True)
class RefreshReceiptReplay:
    """Proof-checked same-key replay recoverable without speculative crypto."""

    context: RefreshFamilyContext
    sealed_receipt: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Validate bounded ciphertext and exact replay context."""
        if (
            type(self.context) is not RefreshFamilyContext
            or type(self.sealed_receipt) is not bytes
            or not self.sealed_receipt
            or len(self.sealed_receipt) > _MAXIMUM_RECEIPT_BYTES
        ):
            msg = "Refresh receipt replay is invalid"
            raise ValueError(msg)


def _require_receipt_key(value: object) -> RefreshReceiptKey:
    if type(value) is not RefreshReceiptKey:
        msg = "Refresh receipt keys must be RefreshReceiptKey values"
        raise ImproperlyConfiguredException(detail=msg)
    return value


def _receipt_expiry(value: datetime) -> int:
    try:
        normalized = aware_utc_time(value)
    except (AttributeError, ValueError):
        msg = "Refresh receipt expiry must be timezone-aware"
        raise ValueError(msg) from None
    expiry = _timestamp_microseconds(normalized)
    if expiry < 1:
        msg = "Refresh receipt expiry is invalid"
        raise ValueError(msg)
    return expiry


def _timestamp_microseconds(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def _receipt_aad(context: RefreshReceiptContext, expiry: int, key_id: str) -> bytes:
    return json.dumps(
        {
            "account_id": context.account_id,
            "expiry": expiry,
            "family_id": context.family_id,
            "idempotency": (None if context.idempotency_digest is None else context.idempotency_digest.hex()),
            "key_id": key_id,
            "security_epoch": context.security_epoch,
            "token_id": context.token_id,
            "version": _REFRESH_RECEIPT_VERSION,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _parse_receipt_envelope(value: object) -> tuple[str, int, bytes, bytes] | None:
    if not isinstance(value, bytes):
        return None
    receipt = value
    if not receipt or len(receipt) > _MAXIMUM_RECEIPT_BYTES:
        return None
    try:
        version, key_id, expiry_text, nonce_text, ciphertext_text = receipt.decode("ascii").split(".")
        if (
            version != _REFRESH_RECEIPT_VERSION
            or not strict_context_text(key_id)
            or any(not (character.isascii() and (character.isalnum() or character in "_-")) for character in key_id)
            or not expiry_text.isascii()
            or not expiry_text.isdecimal()
            or str(expiry := int(expiry_text)) != expiry_text
        ):
            return None
        nonce = decode_random(nonce_text, _RECEIPT_NONCE_BYTES)
        ciphertext = decode_random_unbounded(ciphertext_text)
    except (BinasciiError, UnicodeDecodeError, UnicodeEncodeError, ValueError):
        return None
    if nonce is None or not ciphertext:
        return None
    return key_id, expiry, nonce, ciphertext


@dataclass(frozen=True, slots=True)
class CreateRefreshFamilyCommand:
    """Initial opaque refresh token committed atomically with its family."""

    token_id: str
    token_digest: bytes = field(repr=False)
    account_id: str
    family_id: str
    security_epoch: int
    created_at: datetime
    token_expires_at: datetime
    family_expires_at: datetime
    scopes: frozenset[str] = frozenset()
    evidence: AuthenticationEvidence | None = None

    def __post_init__(self) -> None:
        """Validate one complete atomic family creation candidate."""
        try:
            created_at = aware_utc_time(self.created_at)
            token_expires_at = aware_utc_time(self.token_expires_at)
            family_expires_at = aware_utc_time(self.family_expires_at)
        except (AttributeError, ValueError):
            msg = "Refresh family timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or type(self.token_digest) is not bytes
            or len(self.token_digest) != DIGEST_BYTES
            or not strict_context_text(self.account_id)
            or not valid_identifier(self.family_id, prefix=_REFRESH_FAMILY_PREFIX)
            or not valid_security_epoch(self.security_epoch)
            or not created_at < token_expires_at <= family_expires_at
            or any(not valid_refresh_scope(scope) for scope in self.scopes)
            or (self.evidence is not None and type(self.evidence) is not AuthenticationEvidence)
        ):
            msg = "Refresh family creation command is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "token_expires_at", token_expires_at)
        object.__setattr__(self, "family_expires_at", family_expires_at)
        object.__setattr__(self, "scopes", frozenset(self.scopes))


@dataclass(frozen=True, slots=True)
class RotateRefreshCommand:
    """Candidate one-time refresh rotation passed to an atomic store."""

    token_id: str
    token_digest: bytes = field(repr=False)
    account_id: str
    family_id: str
    security_epoch: int
    successor_id: str
    successor_digest: bytes = field(repr=False)
    successor_expires_at: datetime
    family_expires_at: datetime
    sealed_receipt: bytes = field(repr=False)
    receipt_expires_at: datetime
    idempotency_digest: bytes | None = field(default=None, repr=False)
    scopes: frozenset[str] = frozenset()
    evidence: AuthenticationEvidence | None = None

    def __post_init__(self) -> None:
        """Reject malformed storage material and contradictory deadlines."""
        try:
            successor_expires_at = aware_utc_time(self.successor_expires_at)
            family_expires_at = aware_utc_time(self.family_expires_at)
            receipt_expires_at = aware_utc_time(self.receipt_expires_at)
        except (AttributeError, ValueError):
            msg = "Refresh rotation timestamps must be timezone-aware"
            raise ValueError(msg) from None
        if (
            not valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or type(self.token_digest) is not bytes
            or len(self.token_digest) != DIGEST_BYTES
            or not strict_context_text(self.account_id)
            or not valid_identifier(self.family_id, prefix=_REFRESH_FAMILY_PREFIX)
            or not valid_security_epoch(self.security_epoch)
            or not valid_identifier(self.successor_id, prefix=_REFRESH_TOKEN_PREFIX)
            or self.successor_id == self.token_id
            or type(self.successor_digest) is not bytes
            or len(self.successor_digest) != DIGEST_BYTES
            or not successor_expires_at <= family_expires_at
            or receipt_expires_at > family_expires_at
            or type(self.sealed_receipt) is not bytes
            or not self.sealed_receipt
            or len(self.sealed_receipt) > _MAXIMUM_RECEIPT_BYTES
            or (
                self.idempotency_digest is not None
                and (type(self.idempotency_digest) is not bytes or len(self.idempotency_digest) != DIGEST_BYTES)
            )
            or any(not valid_refresh_scope(scope) for scope in self.scopes)
            or (self.evidence is not None and type(self.evidence) is not AuthenticationEvidence)
        ):
            msg = "Refresh rotation command or security epoch is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "successor_expires_at", successor_expires_at)
        object.__setattr__(self, "family_expires_at", family_expires_at)
        object.__setattr__(self, "receipt_expires_at", receipt_expires_at)
        object.__setattr__(self, "scopes", frozenset(self.scopes))


@dataclass(frozen=True, slots=True)
class RefreshRotationOutcome:
    """Atomic strict rotation, idempotent receipt, or replay outcome."""

    status: RefreshRotationStatus
    sealed_receipt: bytes | None = field(default=None, repr=False)
    family_revoked: bool = False

    def __post_init__(self) -> None:
        """Reject contradictory receipt and revocation outcomes."""
        if type(self.status) is not RefreshRotationStatus or type(self.family_revoked) is not bool:
            msg = "Refresh rotation outcome is invalid"
            raise ValueError(msg)
        receipt_status = self.status in {RefreshRotationStatus.ROTATED, RefreshRotationStatus.IDEMPOTENT_REPLAY}
        if (
            receipt_status != (self.sealed_receipt is not None)
            or (receipt_status and self.family_revoked)
            or (
                self.sealed_receipt is not None
                and (
                    type(self.sealed_receipt) is not bytes
                    or not self.sealed_receipt
                    or len(self.sealed_receipt) > _MAXIMUM_RECEIPT_BYTES
                )
            )
        ):
            msg = "Successful refresh rotation outcomes require exactly one sealed receipt"
            raise ValueError(msg)
        revoked_status = self.status in {RefreshRotationStatus.REPLAY_DETECTED, RefreshRotationStatus.REVOKED}
        if revoked_status != self.family_revoked:
            msg = "Replay or revoked refresh outcomes must report family revocation"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RefreshPreflightOutcome:
    """Proof-checked negative preflight outcome with exact revocation evidence."""

    status: RefreshRotationStatus
    family_revoked: bool = False

    def __post_init__(self) -> None:
        """Reject success statuses and unproven revocation claims."""
        allowed = {
            RefreshRotationStatus.REPLAY_DETECTED,
            RefreshRotationStatus.EXPIRED,
            RefreshRotationStatus.REVOKED,
            RefreshRotationStatus.EPOCH_MISMATCH,
            RefreshRotationStatus.INVALID,
        }
        if type(self.status) is not RefreshRotationStatus or self.status not in allowed:
            msg = "Refresh preflight outcome requires a negative status"
            raise ValueError(msg)
        revoked_status = self.status in {RefreshRotationStatus.REPLAY_DETECTED, RefreshRotationStatus.REVOKED}
        if type(self.family_revoked) is not bool or revoked_status != self.family_revoked:
            msg = "Refresh preflight revocation status is invalid"
            raise ValueError(msg)


@runtime_checkable
class RefreshTokenFamilyStore(Protocol):
    """Atomic strict refresh-family rotation and revocation boundary."""

    async def create_family(self, command: CreateRefreshFamilyCommand, *, event: SecurityEvent) -> bool:
        """Create one family only if its account epoch is still current, atomically."""
        ...

    async def prepare_rotation(
        self, proof: RefreshTokenProof, idempotency_digest: bytes | None, *, now: datetime, event: SecurityEvent
    ) -> RefreshFamilyContext | RefreshReceiptReplay | RefreshPreflightOutcome:
        """Atomically return active state, recover a receipt, or revoke and record consumed reuse."""
        ...

    async def rotate(
        self, command: RotateRefreshCommand, *, now: datetime, event: SecurityEvent
    ) -> RefreshRotationOutcome:
        """Atomically revalidate context/current epoch and rotate or revoke."""
        ...

    async def revoke_family(self, family_id: str, *, event: SecurityEvent) -> bool:
        """Revoke one refresh-token family."""
        ...

    async def revoke_token(self, token_id: str, token_digest: bytes, *, event: SecurityEvent) -> bool:
        """Revoke the family owning one exact presented token."""
        ...

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, *, event: SecurityEvent
    ) -> bool:
        """Revoke one exact token only when its family belongs to the caller account."""
        ...

    async def revoke_for_account(self, account_id: str, *, event: SecurityEvent) -> int:
        """Revoke every refresh family for an account."""
        ...


def _new_refresh_family_id() -> str:
    return f"{_REFRESH_FAMILY_PREFIX}{encode_random(token_bytes(LOOKUP_BYTES))}"


def _new_refresh_event_id() -> str:
    return f"event_{encode_random(token_bytes(LOOKUP_BYTES))}"


@dataclass(slots=True)
class RefreshTokenService(Generic[UserT]):
    """Issue, strictly rotate, and revoke opaque local refresh families."""

    accounts: object = field(repr=False)
    store: RefreshTokenFamilyStore = field(repr=False)
    codec: RefreshTokenCodec = field(repr=False)
    receipts: RefreshReceiptSealer = field(repr=False)
    access_tokens: LocalAccessTokenIssuer[UserT] = field(repr=False)
    idle_lifetime: timedelta = _DEFAULT_REFRESH_IDLE_LIFETIME
    absolute_lifetime: timedelta = _DEFAULT_REFRESH_ABSOLUTE_LIFETIME
    receipt_window: timedelta = _DEFAULT_REFRESH_RECEIPT_WINDOW
    clock: Callable[[], datetime] = field(default=utc_now, repr=False, compare=False)
    family_ids: Callable[[], str] = field(default=_new_refresh_family_id, repr=False, compare=False)
    event_ids: Callable[[], str] = field(default=_new_refresh_event_id, repr=False, compare=False)
    rate_limits: RateLimitGuard | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate structural ports, lifetimes, and customization hooks."""
        validate_rate_limits(self.rate_limits, name="Refresh token service")
        accounts_value = object.__getattribute__(self, "accounts")
        access_tokens_value = object.__getattribute__(self, "access_tokens")
        if not callable(getattr(accounts_value, "get_by_id", None)) or not callable(
            getattr(accounts_value, "current_epoch", None)
        ):
            msg = "Refresh token accounts must provide account and epoch lookup"
            raise ImproperlyConfiguredException(detail=msg)
        if not isinstance(object.__getattribute__(self, "store"), RefreshTokenFamilyStore):
            msg = "Refresh token store must implement RefreshTokenFamilyStore"
            raise ImproperlyConfiguredException(detail=msg)
        if type(self.codec) is not RefreshTokenCodec:
            msg = "Refresh token codec must be RefreshTokenCodec"
            raise ImproperlyConfiguredException(detail=msg)
        if type(self.receipts) is not RefreshReceiptSealer:
            msg = "Refresh token receipts must be RefreshReceiptSealer"
            raise ImproperlyConfiguredException(detail=msg)
        if not callable(getattr(access_tokens_value, "issue", None)):
            msg = "Refresh access-token issuer must provide issue()"
            raise ImproperlyConfiguredException(detail=msg)
        if (
            type(self.idle_lifetime) is not timedelta
            or type(self.absolute_lifetime) is not timedelta
            or type(self.receipt_window) is not timedelta
            or self.idle_lifetime <= timedelta(0)
            or self.absolute_lifetime < self.idle_lifetime
            or not timedelta(0) < self.receipt_window <= _MAXIMUM_REFRESH_RECEIPT_WINDOW
        ):
            msg = "Refresh token lifetimes are invalid"
            raise ImproperlyConfiguredException(detail=msg)
        if not all(callable(value) for value in (self.clock, self.family_ids, self.event_ids)):
            msg = "Refresh token clock and ID factories must be callable"
            raise ImproperlyConfiguredException(detail=msg)

    async def issue(
        self,
        account: LocalAccountState[UserT],
        *,
        scopes: AbstractSet[str] = frozenset(),
        evidence: AuthenticationEvidence | None = None,
        now: datetime | None = None,
    ) -> TokenPair | InvalidCredentials | VerificationUnavailable:
        """Create the initial family before revealing either credential."""
        if type(account) is not LocalAccountState or not account.active or not account.verified:
            return InvalidCredentials()
        try:
            issued_at = aware_utc_time(self.clock() if now is None else now)
            current_epoch = await cast("Any", self.accounts).current_epoch(account.account_id)
        except Exception:
            return VerificationUnavailable()
        if not valid_security_epoch(current_epoch) or current_epoch != account.security_epoch:
            return InvalidCredentials()
        normalized_scopes = normalize_refresh_scopes(scopes)
        if normalized_scopes is None:
            return InvalidCredentials()
        try:
            access_value: object = await self.access_tokens.issue(
                account, scopes=normalized_scopes, evidence=evidence, now=issued_at
            )
        except Exception:
            return VerificationUnavailable()
        if isinstance(access_value, InvalidCredentials | VerificationUnavailable):
            return access_value
        if access_value.__class__ is not LocalAccessToken:
            return VerificationUnavailable()
        access = access_value
        try:
            refresh = self.codec.issue()
        except Exception:
            return VerificationUnavailable()
        family_id = self.family_ids()
        if not valid_identifier(family_id, prefix=_REFRESH_FAMILY_PREFIX):
            return VerificationUnavailable()
        family_expires_at = issued_at + self.absolute_lifetime
        token_expires_at = min(issued_at + self.idle_lifetime, family_expires_at)
        command = CreateRefreshFamilyCommand(
            token_id=refresh.token_id,
            token_digest=refresh.digest,
            account_id=account.account_id,
            family_id=family_id,
            security_epoch=account.security_epoch,
            created_at=issued_at,
            token_expires_at=token_expires_at,
            family_expires_at=family_expires_at,
            scopes=normalized_scopes,
            evidence=evidence,
        )
        try:
            created = await self.store.create_family(
                command,
                event=self._event(
                    issued_at,
                    operation=REFRESH_CREATE,
                    outcome=OUTCOME_CREATED,
                    account_id=account.account_id,
                    family_id=family_id,
                ),
            )
        except Exception:
            return VerificationUnavailable()
        if created is not True:
            return VerificationUnavailable()
        return TokenPair(
            access_token=access.access_token, refresh_token=refresh.refresh_token, expires_in=access.expires_in
        )

    async def rotate(
        self,
        refresh_token: str,
        *,
        idempotency_key: str | None = None,
        now: datetime | None = None,
        client_key: str | None = None,
    ) -> TokenPair | RateLimited | InvalidCredentials | VerificationUnavailable:
        """Return exactly the store-accepted sealed response or one safe failure."""
        if self.rate_limits is not None:
            limited = await self.rate_limits.check(REFRESH_ROTATE, client_key=client_key)
            if limited is not None:
                return limited
        proof = self.codec.verify(refresh_token)
        if not isinstance(proof, RefreshTokenProof):
            return proof
        idempotency_digest: bytes | None = None
        invalid_idempotency = False
        if idempotency_key is not None:
            digest_result = self.codec.digest_idempotency_key(proof.token_id, idempotency_key)
            if isinstance(digest_result, InvalidCredentials):
                invalid_idempotency = True
            else:
                idempotency_digest = digest_result
        try:
            rotated_at = aware_utc_time(self.clock() if now is None else now)
            prepared: object = await self.store.prepare_rotation(
                proof,
                idempotency_digest,
                now=rotated_at,
                event=self._event(
                    rotated_at, operation=REFRESH_PREPARE, outcome=OUTCOME_ATTEMPTED, account_id=None, family_id=None
                ),
            )
        except Exception:
            return VerificationUnavailable()
        if isinstance(prepared, RefreshReceiptReplay):
            account_result = await self._resolve_account(prepared.context)
            if not isinstance(account_result, LocalAccountState):
                return account_result
            return await self._recover_receipt(
                prepared.context,
                prepared.sealed_receipt,
                token_id=proof.token_id,
                idempotency_digest=idempotency_digest,
                occurred_at=rotated_at,
            )
        if isinstance(prepared, RefreshPreflightOutcome):
            return InvalidCredentials()
        if type(prepared) is not RefreshFamilyContext:
            return VerificationUnavailable()
        if invalid_idempotency:
            return InvalidCredentials()
        if prepared.token_expires_at <= rotated_at or prepared.family_expires_at <= rotated_at:
            return InvalidCredentials()
        account_result = await self._resolve_account(prepared)
        if not isinstance(account_result, LocalAccountState):
            return account_result
        account = account_result
        try:
            successor = self.codec.issue()
            successor_expires_at = min(rotated_at + self.idle_lifetime, prepared.family_expires_at)
            receipt_expires_at = min(rotated_at + self.receipt_window, prepared.family_expires_at)
            access_value: object = await self.access_tokens.issue(
                account, scopes=prepared.scopes, evidence=prepared.evidence, now=rotated_at
            )
            if isinstance(access_value, InvalidCredentials | VerificationUnavailable):
                return access_value
            if access_value.__class__ is not LocalAccessToken:
                return VerificationUnavailable()
            access = access_value
            tokens = TokenPair(
                access_token=access.access_token, refresh_token=successor.refresh_token, expires_in=access.expires_in
            )
            command_token_id = proof.token_id
            context = RefreshReceiptContext(
                token_id=command_token_id,
                family_id=prepared.family_id,
                account_id=prepared.account_id,
                security_epoch=prepared.security_epoch,
                idempotency_digest=idempotency_digest,
            )
            sealed_receipt = self.receipts.seal(tokens, context, expires_at=receipt_expires_at)
            command = RotateRefreshCommand(
                token_id=command_token_id,
                token_digest=proof.digest,
                account_id=prepared.account_id,
                family_id=prepared.family_id,
                security_epoch=prepared.security_epoch,
                successor_id=successor.token_id,
                successor_digest=successor.digest,
                successor_expires_at=successor_expires_at,
                family_expires_at=prepared.family_expires_at,
                sealed_receipt=sealed_receipt,
                receipt_expires_at=receipt_expires_at,
                idempotency_digest=idempotency_digest,
                scopes=prepared.scopes,
                evidence=prepared.evidence,
            )
            result_value: object = await self.store.rotate(
                command,
                now=rotated_at,
                event=self._event(
                    rotated_at,
                    operation=REFRESH_ROTATE,
                    outcome=OUTCOME_ATTEMPTED,
                    account_id=prepared.account_id,
                    family_id=prepared.family_id,
                ),
            )
        except Exception:
            return VerificationUnavailable()
        if type(result_value) is not RefreshRotationOutcome:
            return VerificationUnavailable()
        result = result_value
        if result.status not in {RefreshRotationStatus.ROTATED, RefreshRotationStatus.IDEMPOTENT_REPLAY}:
            return InvalidCredentials()
        if result.sealed_receipt is None or type(result.sealed_receipt) is not bytes:
            return InvalidCredentials()
        return await self._recover_receipt(
            prepared,
            result.sealed_receipt,
            token_id=proof.token_id,
            idempotency_digest=idempotency_digest,
            occurred_at=rotated_at,
        )

    async def revoke(
        self, refresh_token: str, *, now: datetime | None = None
    ) -> bool | InvalidCredentials | VerificationUnavailable:
        """Revoke the family owning one exact presented opaque token."""
        proof = self.codec.verify(refresh_token)
        if not isinstance(proof, RefreshTokenProof):
            return proof
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            revoked = await self.store.revoke_token(
                proof.token_id,
                proof.digest,
                event=self._event(
                    occurred_at, operation=REFRESH_REVOKE, outcome=OUTCOME_REVOKED, account_id=None, family_id=None
                ),
            )
        except Exception:
            return VerificationUnavailable()
        return revoked if type(revoked) is bool else VerificationUnavailable()

    async def revoke_for_account(
        self, account_id: str, refresh_token: str, *, now: datetime | None = None
    ) -> bool | InvalidCredentials | VerificationUnavailable:
        """Revoke one caller-owned refresh family without exposing cross-account state."""
        proof = self.codec.verify(refresh_token)
        if not strict_context_text(account_id) or not isinstance(proof, RefreshTokenProof):
            return InvalidCredentials()
        try:
            occurred_at = aware_utc_time(self.clock() if now is None else now)
            revoked = await self.store.revoke_token_for_account(
                account_id,
                proof.token_id,
                proof.digest,
                event=self._event(
                    occurred_at,
                    operation=REFRESH_REVOKE,
                    outcome=OUTCOME_REVOKED,
                    account_id=account_id,
                    family_id=None,
                ),
            )
        except Exception:
            return VerificationUnavailable()
        return revoked if type(revoked) is bool else VerificationUnavailable()

    async def _resolve_account(
        self, context: RefreshFamilyContext
    ) -> LocalAccountState[UserT] | InvalidCredentials | VerificationUnavailable:
        try:
            account = await cast("Any", self.accounts).get_by_id(context.account_id)
            current_epoch = await cast("Any", self.accounts).current_epoch(context.account_id)
        except Exception:
            return VerificationUnavailable()
        if (
            not isinstance(account, LocalAccountState)
            or account.account_id != context.account_id
            or not account.active
            or not account.verified
            or account.security_epoch != context.security_epoch
            or not valid_security_epoch(current_epoch)
            or current_epoch != context.security_epoch
        ):
            return InvalidCredentials()
        return cast("LocalAccountState[UserT]", account)

    async def _fail_closed_receipt(
        self, context: RefreshFamilyContext, occurred_at: datetime
    ) -> InvalidCredentials | VerificationUnavailable:
        try:
            revoked = await self.store.revoke_family(
                context.family_id,
                event=self._event(
                    occurred_at,
                    operation=REFRESH_RECEIPT,
                    outcome=OUTCOME_REVOKED,
                    account_id=context.account_id,
                    family_id=context.family_id,
                ),
            )
        except Exception:
            return VerificationUnavailable()
        return InvalidCredentials() if revoked is True else VerificationUnavailable()

    async def _recover_receipt(
        self,
        context: RefreshFamilyContext,
        sealed_receipt: bytes,
        *,
        token_id: str,
        idempotency_digest: bytes | None,
        occurred_at: datetime,
    ) -> TokenPair | InvalidCredentials | VerificationUnavailable:
        receipt_context = RefreshReceiptContext(
            token_id=token_id,
            family_id=context.family_id,
            account_id=context.account_id,
            security_epoch=context.security_epoch,
            idempotency_digest=idempotency_digest,
        )
        accepted = self.receipts.unseal(sealed_receipt, receipt_context, now=occurred_at)
        return accepted if isinstance(accepted, TokenPair) else await self._fail_closed_receipt(context, occurred_at)

    def _event(
        self, occurred_at: datetime, *, operation: str, outcome: str, account_id: str | None, family_id: str | None
    ) -> SecurityEvent:
        event_id = self.event_ids()
        if not strict_context_text(event_id):
            raise ValueError
        return SecurityEvent(
            event_id=event_id,
            occurred_at=occurred_at,
            operation=operation,
            outcome=outcome,
            account_id=account_id,
            family_id=family_id,
            mechanism="refresh",
        )
