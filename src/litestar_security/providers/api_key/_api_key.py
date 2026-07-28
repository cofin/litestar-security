"""Opaque API-key value objects, codec, and application-owned store ports."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import Error as BinasciiError
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from hmac import compare_digest
from hmac import new as hmac_new
from secrets import token_bytes
from typing import TYPE_CHECKING, Protocol, TypeVar, cast, runtime_checkable

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.context import CredentialRestrictions

if TYPE_CHECKING:
    from litestar_security.authentication import AuthenticationMechanism, CredentialSlot, IdentityResolver
    from litestar_security.config import SecurityMetrics
    from litestar_security.providers.api_key._runtime import APIKeyClaims, APIKeyService

from litestar_security.config import NoOpSecurityMetrics

UserT = TypeVar("UserT")

__all__ = (
    "APIKeyCodec",
    "APIKeyConfig",
    "APIKeyGenerationError",
    "APIKeyProof",
    "APIKeyRecord",
    "APIKeyStore",
    "APIKeyUsageSink",
    "IssuedAPIKey",
)


_KEY_ID_BYTES = 12
_KEY_ID_CHARACTERS = 16
_SECRET_BYTES = 32
_SECRET_CHARACTERS = 43
_DIGEST_BYTES = 32
_MINIMUM_PEPPER_BYTES = 32
_MAXIMUM_PREFIX_CHARACTERS = 32
_MAXIMUM_USAGE_BUFFER_CAPACITY = 1_000_000
_KEY_COMPONENTS = 3
_ASCII_CONTROL_LIMIT = 32
_DOMAIN = b"litestar-security:api-key:v1\x00"
_BASE64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_PREFIX_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class APIKeyRecord:
    """Storage-safe API-key state containing only a keyed digest.

    The application store must persist this record without adding the raw key
    or its secret component.
    """

    key_id: str
    subject_id: str
    digest: bytes = field(repr=False, metadata={"sensitive": True})
    restrictions: CredentialRestrictions = field(default_factory=CredentialRestrictions)
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    overlap_until: datetime | None = None

    def __post_init__(self) -> None:
        """Validate canonical lookup, digest, timestamps, and rotation bounds."""
        try:
            expires_at = _optional_utc(self.expires_at)
            revoked_at = _optional_utc(self.revoked_at)
            overlap_until = _optional_utc(self.overlap_until)
        except (AttributeError, ValueError):
            message = "API-key record timestamps must be timezone-aware"
            raise ValueError(message) from None
        restrictions = cast("object", self.restrictions)
        valid_overlap = overlap_until is None or (
            revoked_at is not None
            and overlap_until >= revoked_at
            and (expires_at is None or overlap_until <= expires_at)
        )
        if (
            _decode_segment(self.key_id, expected_bytes=_KEY_ID_BYTES, expected_characters=_KEY_ID_CHARACTERS) is None
            or not _strict_text(self.subject_id)
            or self.digest.__class__ is not bytes
            or len(self.digest) != _DIGEST_BYTES
            or not isinstance(restrictions, CredentialRestrictions)
            or not valid_overlap
        ):
            message = "API-key record contains invalid storage state"
            raise ValueError(message)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "revoked_at", revoked_at)
        object.__setattr__(self, "overlap_until", overlap_until)

    def is_valid_at(self, now: datetime) -> bool:
        """Return whether expiry and revocation permit use at one instant.

        Args:
            now: The timezone-aware instant to evaluate.

        Returns:
            ``True`` while the record is active or inside its explicit overlap.

        Raises:
            ValueError: If ``now`` is not timezone-aware.
        """
        current = _utc(now)
        if self.expires_at is not None and current >= self.expires_at:
            return False
        if self.revoked_at is None or current < self.revoked_at:
            return True
        return self.overlap_until is not None and current <= self.overlap_until

    def as_dict(self) -> dict[str, object]:
        """Return a secret-redacted representation for explicit serialization.

        Returns:
            A dictionary containing public metadata and a redacted digest.
        """
        return {
            "key_id": self.key_id,
            "subject_id": self.subject_id,
            "digest": "<redacted>",
            "restrictions": self.restrictions,
            "expires_at": self.expires_at,
            "revoked_at": self.revoked_at,
            "overlap_until": self.overlap_until,
        }


@dataclass(frozen=True, slots=True, repr=False)
class IssuedAPIKey:
    """Reveal-once raw API key returned only to the issuing caller."""

    key_id: str
    value: str = field(repr=False, metadata={"sensitive": True})

    def __post_init__(self) -> None:
        """Require the public lookup to match one canonical encoded key."""
        parts = self.value.split("_") if self.value.__class__ is str else []
        if (
            len(parts) != _KEY_COMPONENTS
            or not _valid_prefix(parts[0])
            or parts[1] != self.key_id
            or _decode_segment(parts[1], expected_bytes=_KEY_ID_BYTES, expected_characters=_KEY_ID_CHARACTERS) is None
            or _decode_segment(parts[2], expected_bytes=_SECRET_BYTES, expected_characters=_SECRET_CHARACTERS) is None
        ):
            message = "Issued API key is not canonical"
            raise ValueError(message)

    def __repr__(self) -> str:
        """Return a stable representation that never reveals the raw key."""
        return f"IssuedAPIKey(key_id={self.key_id!r}, value='<redacted>')"

    __str__ = __repr__

    def as_dict(self) -> dict[str, str]:
        """Return a secret-redacted representation for explicit serialization.

        Returns:
            A dictionary containing the lookup ID and a redaction marker.
        """
        return {"key_id": self.key_id, "value": "<redacted>"}


@dataclass(frozen=True, slots=True)
class APIKeyProof:
    """Canonical public lookup and digest passed toward storage verification."""

    key_id: str
    digest: bytes = field(repr=False, metadata={"sensitive": True})

    def __post_init__(self) -> None:
        """Validate the exact storage-facing proof shape."""
        if (
            _decode_segment(self.key_id, expected_bytes=_KEY_ID_BYTES, expected_characters=_KEY_ID_CHARACTERS) is None
            or self.digest.__class__ is not bytes
            or len(self.digest) != _DIGEST_BYTES
        ):
            message = "API-key proof is invalid"
            raise ValueError(message)


@runtime_checkable
class APIKeyStore(Protocol):
    """Application-owned atomic persistence port for digest-only API keys.

    Implementations must reject duplicate IDs. ``rotate()`` must create the
    replacement and transition the current record in one atomic operation,
    bounding overlap by the current record's original expiry. No method may
    accept or persist a raw key or secret component.
    """

    async def get(self, key_id: str) -> APIKeyRecord | None:
        """Return one record by its indexed public lookup.

        Args:
            key_id: The canonical 16-character public lookup.

        Returns:
            The digest-only record, or ``None`` when it does not exist.
        """
        ...  # pragma: no cover

    async def create(self, record: APIKeyRecord) -> None:
        """Persist one new record and reject a duplicate ID atomically.

        Args:
            record: The digest-only record to create.

        Raises:
            Exception: When the ID exists or persistence cannot commit.
        """
        ...  # pragma: no cover

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyRecord, overlap_until: datetime | None, now: datetime
    ) -> None:
        """Atomically create a successor and revoke the current record.

        Implementations must set the current record's revocation to ``now``.
        When overlap is requested, they must cap it at the current record's
        original expiry; ``None`` means the current key stops immediately.

        Args:
            current_key_id: The public lookup being replaced.
            replacement: The digest-only successor record.
            overlap_until: The requested inclusive end of old-key overlap.
            now: The transition timestamp.

        Raises:
            Exception: When either transition cannot commit as one unit.
        """
        ...  # pragma: no cover

    async def revoke(self, *, key_id: str, now: datetime) -> None:
        """Atomically revoke one key with no remaining overlap.

        Args:
            key_id: The public lookup to revoke.
            now: The revocation timestamp.

        Raises:
            Exception: When revocation cannot commit.
        """
        ...  # pragma: no cover


@runtime_checkable
class APIKeyUsageSink(Protocol):
    """Application-owned sink for coalesced, secret-free API-key usage."""

    async def record(self, *, key_id: str, used_at: datetime) -> None:
        """Persist one coalesced usage observation.

        Args:
            key_id: The public lookup only, never raw key material.
            used_at: The timezone-aware observation time.
        """
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class APIKeyConfig:
    """API-key persistence, digest, usage, and namespace configuration."""

    store: APIKeyStore
    pepper: bytes = field(repr=False, metadata={"sensitive": True})
    identity_resolver: object | None = field(default=None, repr=False, compare=False)
    usage_sink: APIKeyUsageSink | None = None
    usage_write_interval: timedelta = timedelta(minutes=5)
    usage_buffer_capacity: int = 1024
    prefix: str = "lsk"
    header_name: str = "X-API-Key"

    def __post_init__(self) -> None:
        """Reject weak peppers, malformed namespaces, and invalid ports."""
        store = cast("object", self.store)
        usage_sink = cast("object", self.usage_sink)
        if (
            not isinstance(store, APIKeyStore)
            or self.pepper.__class__ is not bytes
            or len(self.pepper) < _MINIMUM_PEPPER_BYTES
            or (self.identity_resolver is not None and not callable(getattr(self.identity_resolver, "resolve", None)))
            or (usage_sink is not None and not isinstance(usage_sink, APIKeyUsageSink))
            or self.usage_write_interval.__class__ is not timedelta
            or self.usage_write_interval <= timedelta(0)
            or self.usage_buffer_capacity.__class__ is not int
            or not 1 <= self.usage_buffer_capacity <= _MAXIMUM_USAGE_BUFFER_CAPACITY
            or not _valid_prefix(self.prefix)
            or not _valid_header_name(self.header_name)
        ):
            raise ImproperlyConfiguredException(detail="API-key configuration is invalid")

    def as_dict(self) -> dict[str, object]:
        """Return a secret-redacted representation for explicit serialization.

        Returns:
            Public configuration values with the pepper redacted.
        """
        return {
            "pepper": "<redacted>",
            "usage_write_interval": self.usage_write_interval,
            "usage_buffer_capacity": self.usage_buffer_capacity,
            "prefix": self.prefix,
            "header_name": self.header_name,
        }

    def build(
        self,
        resolver: "IdentityResolver[APIKeyClaims, UserT] | None" = None,
        *,
        clock: "Callable[[], datetime]" = _utc_now,
        entropy: "Callable[[int], bytes]" = token_bytes,
        metrics: "SecurityMetrics | None" = None,
        participates_by_default: bool = True,
    ) -> "tuple[CredentialSlot[str], AuthenticationMechanism[str, APIKeyClaims, UserT], APIKeyService]":
        """Build one physical slot, mechanism, and lifecycle service.

        Args:
            resolver: Application identity resolver for verified API-key claims.
            clock: Time source for authentication and mutations.
            entropy: Random-byte source used only for issuance.
            metrics: Optional vendor-neutral usage metrics.
            participates_by_default: Include API keys in implicit protection.

        Returns:
            The slot, authentication mechanism, and lifecycle service.
        """
        from litestar_security.providers.api_key._runtime import (  # noqa: PLC0415 - breaks config/runtime cycle
            build_api_key_runtime,
        )

        if not callable(clock) or not callable(entropy) or participates_by_default.__class__ is not bool:
            raise ImproperlyConfiguredException(detail="API-key runtime configuration is invalid")
        selected_resolver = self.identity_resolver if resolver is None else resolver
        if not callable(getattr(selected_resolver, "resolve", None)):
            raise ImproperlyConfiguredException(detail="API-key identity resolver is required")
        return build_api_key_runtime(
            self,
            cast("IdentityResolver[APIKeyClaims, UserT]", selected_resolver),
            clock=clock,
            entropy=entropy,
            metrics=NoOpSecurityMetrics() if metrics is None else metrics,
            participates_by_default=participates_by_default,
        )


class APIKeyGenerationError(RuntimeError):
    """Indicate that a configured entropy source failed closed."""

    def __init__(self) -> None:
        """Initialize a stable error without exposing entropy-source detail."""
        super().__init__("API-key generation unavailable")


@dataclass(frozen=True, slots=True)
class APIKeyCodec:
    """Issue and parse strict opaque API keys without persistence access."""

    pepper: bytes = field(repr=False, metadata={"sensitive": True})
    prefix: str = "lsk"
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)
    comparator: Callable[[bytes, bytes], bool] = field(default=compare_digest, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Require a strong pepper, safe prefix, entropy, and comparator."""
        if (
            self.pepper.__class__ is not bytes
            or len(self.pepper) < _MINIMUM_PEPPER_BYTES
            or not _valid_prefix(self.prefix)
            or not callable(self.entropy)
            or not callable(self.comparator)
        ):
            raise ImproperlyConfiguredException(detail="API-key codec configuration is invalid")

    def issue(
        self, *, subject_id: str, restrictions: CredentialRestrictions | None = None, expires_at: datetime | None = None
    ) -> tuple[IssuedAPIKey, APIKeyRecord]:
        """Create reveal-once key material paired with a digest-only record.

        Args:
            subject_id: The application identity this key authenticates.
            restrictions: Optional authorization bounds carried by the key.
            expires_at: Optional exclusive expiry timestamp.

        Returns:
            The reveal-once value and the storage-safe record.

        Raises:
            APIKeyGenerationError: If the entropy source raises or returns an
                invalid value.
            ValueError: If record metadata is invalid.
        """
        key_id = _encode_segment(self._entropy(_KEY_ID_BYTES))
        secret = _encode_segment(self._entropy(_SECRET_BYTES))
        value = f"{self.prefix}_{key_id}_{secret}"
        issued = IssuedAPIKey(key_id=key_id, value=value)
        record = APIKeyRecord(
            key_id=key_id,
            subject_id=subject_id,
            digest=_digest(self.pepper, key_id, secret),
            restrictions=restrictions if restrictions is not None else CredentialRestrictions(),
            expires_at=expires_at,
        )
        return issued, record

    def proof(self, value: object) -> APIKeyProof | None:
        """Parse a canonical key into storage-safe lookup and digest material.

        Args:
            value: The presented API-key value of any runtime type.

        Returns:
            A digest-only proof, or ``None`` when parsing fails.
        """
        if not isinstance(value, str) or value.__class__ is not str:
            return None
        parts = value.split("_")
        if len(parts) != _KEY_COMPONENTS:
            return None
        prefix, key_id, secret = parts
        if (
            prefix != self.prefix
            or _decode_segment(key_id, expected_bytes=_KEY_ID_BYTES, expected_characters=_KEY_ID_CHARACTERS) is None
            or _decode_segment(secret, expected_bytes=_SECRET_BYTES, expected_characters=_SECRET_CHARACTERS) is None
        ):
            return None
        return APIKeyProof(key_id=key_id, digest=_digest(self.pepper, key_id, secret))

    def matches(self, proof: APIKeyProof, record: APIKeyRecord) -> bool:
        """Compare one computed digest with a record through the configured comparator.

        Args:
            proof: The storage-safe proof derived from a presented key.
            record: The looked-up digest-only record.

        Returns:
            ``True`` only when both public lookup and digest match.
        """
        return proof.key_id == record.key_id and self.comparator(proof.digest, record.digest)

    def _entropy(self, length: int) -> bytes:
        try:
            value = self.entropy(length)
        except Exception:  # noqa: BLE001 - application entropy may raise anything; fail closed
            raise APIKeyGenerationError from None
        if value.__class__ is not bytes or len(value) != length:
            raise APIKeyGenerationError
        return value


def _strict_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.__class__ is str
        and value == value.strip()
        and bool(value)
        and all(ord(character) >= _ASCII_CONTROL_LIMIT for character in value)
    )


def _valid_prefix(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.__class__ is str
        and 1 <= len(value) <= _MAXIMUM_PREFIX_CHARACTERS
        and all(character in _PREFIX_ALPHABET for character in value)
    )


def _valid_header_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.__class__ is str
        and bool(value)
        and all(character.isascii() and (character.isalnum() or character == "-") for character in value)
    )


def _encode_segment(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_segment(value: object, *, expected_bytes: int, expected_characters: int) -> bytes | None:
    if (
        not isinstance(value, str)
        or value.__class__ is not str
        or len(value) != expected_characters
        or any(character not in _BASE64URL_ALPHABET for character in value)
    ):
        return None
    try:
        encoded = value.encode("ascii")
        decoded = urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    except (BinasciiError, UnicodeError, ValueError):  # pragma: no cover - strict alphabet guards decoding
        return None
    return decoded if len(decoded) == expected_bytes and _encode_segment(decoded) == value else None


def _digest(pepper: bytes, key_id: str, secret: str) -> bytes:
    return hmac_new(pepper, _DOMAIN + key_id.encode("ascii") + b"\x00" + secret.encode("ascii"), sha256).digest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        message = "API-key timestamp must be timezone-aware"
        raise ValueError(message)
    return value.astimezone(timezone.utc)


def _optional_utc(value: datetime | None) -> datetime | None:
    return None if value is None else _utc(value)
