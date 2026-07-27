"""Purpose-bound one-time token issuing, delivery, and verification."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hmac import compare_digest
from hmac import digest as hmac_digest
from secrets import token_bytes
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._internal import aware_utc_time, strict_text, valid_security_epoch
from litestar_security.accounts._records import TokenPurpose

if TYPE_CHECKING:
    from collections.abc import Callable


__all__ = (
    "NotificationCommand",
    "PendingTokenIssue",
    "PurposeTokenCodec",
    "PurposeTokenDelivery",
    "PurposeTokenGenerationError",
    "PurposeTokenProof",
    "RegistrationCommand",
    "TokenIssue",
)


_ASCII_CONTROL_LIMIT = 32


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
    expires_at: "datetime"
    return_url: str | None = None

    def __post_init__(self) -> None:
        """Reject incomplete delivery commands and unapproved callback shapes."""
        if not strict_text(self.template) or not strict_text(self.destination) or not strict_text(self.token):
            msg = "Notification template, destination, and token must not be blank"
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

    def issue(  # noqa: PLR0913 - explicit configuration surface; every input is named
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
        issued_at = aware_utc_time(now)
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
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            raise PurposeTokenGenerationError from None
        if value.__class__ is not bytes or len(value) != length:
            raise PurposeTokenGenerationError
        return value


def approved_return_url(value: object) -> bool:
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
        aware_utc_time(issue.expires_at)
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
