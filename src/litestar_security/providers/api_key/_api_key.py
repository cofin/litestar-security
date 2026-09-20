"""Opaque API-key value objects, codec, and application-owned store ports."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import Error as BinasciiError
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from hmac import compare_digest
from hmac import new as hmac_new
from inspect import iscoroutinefunction
from secrets import token_bytes
from typing import Any, Protocol, TypeVar, cast, runtime_checkable

from litestar.connection import ASGIConnection
from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi.spec import SecurityScheme

from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationOutcome,
    CredentialExtraction,
    CredentialSlot,
    IdentityResolver,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
)
from litestar_security.context import AuthenticationEvidence, CredentialRestrictions
from litestar_security.providers._internal import safe_increment
from litestar_security.workers import BlockingCallRunner, BlockingIntegration, NoOpSecurityMetrics, SecurityMetrics

UserT = TypeVar("UserT")

__all__ = (
    "APIKeyClaims",
    "APIKeyCodec",
    "APIKeyConfig",
    "APIKeyGenerationError",
    "APIKeyProof",
    "APIKeyService",
    "APIKeyState",
    "APIKeyStore",
    "APIKeyUsageSink",
    "BufferedAPIKeyUsage",
    "IssuedAPIKey",
    "build_api_key_runtime",
)


_KEY_ID_BYTES = 12
_KEY_ID_CHARACTERS = 16
_SECRET_BYTES = 32
_SECRET_CHARACTERS = 43
_DIGEST_BYTES = 32
_MINIMUM_PEPPER_BYTES = 32
_MAXIMUM_PREFIX_CHARACTERS = 32
_MAXIMUM_USAGE_BUFFER_CAPACITY = 1_000_000
_API_KEY_STORE_METHODS = ("get", "create", "rotate", "revoke")
_ASCII_CONTROL_LIMIT = 32
_DOMAIN = b"litestar-security:api-key:v1\x00"
_BASE64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_PREFIX_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
_ASCII_DELETE = 127
_MECHANISM_NAME = "api-key"
_SLOT_NAME = "api-key"


@dataclass(frozen=True, slots=True)
class APIKeyClaims:
    """Verified digest-free identity carried from authentication to resolution."""

    key_id: str
    subject_id: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class APIKeyState:
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
        parts = _parse_key_value(self.value)
        if (
            parts is None
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
    bounding overlap by the current record's original expiry and rejecting an
    already-revoked current record so concurrent rotations have one winner. No
    method may accept or persist a raw key or secret component.
    """

    async def get(self, key_id: str) -> APIKeyState | None:
        """Return one record by its indexed public lookup.

        Args:
            key_id: The canonical 16-character public lookup.

        Returns:
            The digest-only record, or ``None`` when it does not exist.
        """
        ...  # pragma: no cover

    async def create(self, record: APIKeyState) -> None:
        """Persist one new record and reject a duplicate ID atomically.

        Args:
            record: The digest-only record to create.

        Raises:
            Exception: When the ID exists or persistence cannot commit.
        """
        ...  # pragma: no cover

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyState, overlap_until: datetime | None, now: datetime
    ) -> None:
        """Atomically create a successor and revoke the current record.

        Implementations must reject a missing or already-revoked current record
        and set a live current record's revocation to ``now``. When overlap is
        requested, they must cap it at the current record's original expiry;
        ``None`` means the current key stops immediately.

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

        Returns:
            ``None`` after accepting the best-effort observation.

        Raises:
            Exception: When the sink cannot persist the observation.

        Notes:
            ``BufferedAPIKeyUsage.flush()`` catches every sink exception,
            increments ``security.api_key.usage_failure``, drops the pending
            observation, and never changes authentication or API-key validity.
        """
        ...  # pragma: no cover


class _SyncAPIKeyStore(Protocol):
    def get(self, key_id: str) -> APIKeyState | None: ...  # pragma: no cover

    def create(self, record: APIKeyState) -> None: ...  # pragma: no cover

    def rotate(
        self, *, current_key_id: str, replacement: APIKeyState, overlap_until: datetime | None, now: datetime
    ) -> None: ...  # pragma: no cover

    def revoke(self, *, key_id: str, now: datetime) -> None: ...  # pragma: no cover


@dataclass(slots=True)
class _BlockingAPIKeyStore:
    implementation: "_SyncAPIKeyStore" = field(repr=False)
    runner: BlockingCallRunner = field(default_factory=BlockingCallRunner, repr=False)

    async def get(self, key_id: str) -> APIKeyState | None:
        method = cast("Callable[[str], APIKeyState | None]", self.implementation.get)
        return await self.runner.run(method, key_id)

    async def create(self, record: APIKeyState) -> None:
        method = cast("Callable[[APIKeyState], None]", self.implementation.create)
        await self.runner.run(method, record)

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyState, overlap_until: datetime | None, now: datetime
    ) -> None:
        method = cast("Callable[..., None]", self.implementation.rotate)
        await self.runner.run(
            method, current_key_id=current_key_id, replacement=replacement, overlap_until=overlap_until, now=now
        )

    async def revoke(self, *, key_id: str, now: datetime) -> None:
        method = cast("Callable[..., None]", self.implementation.revoke)
        await self.runner.run(method, key_id=key_id, now=now)


@dataclass(frozen=True, slots=True)
class APIKeyConfig:
    """API-key persistence, digest, usage, and namespace configuration."""

    store: APIKeyStore | BlockingIntegration[_SyncAPIKeyStore]
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
        implementation = (
            cast("BlockingIntegration[object]", store).implementation
            if isinstance(store, BlockingIntegration)
            else store
        )
        usage_sink = cast("object", self.usage_sink)
        missing_store_methods = tuple(
            method for method in _API_KEY_STORE_METHODS if not callable(getattr(implementation, method, None))
        )
        if missing_store_methods:
            missing = ", ".join(missing_store_methods)
            raise ImproperlyConfiguredException(
                detail=f"API-key store {type(implementation).__name__} is missing capabilities: {missing}"
            )
        if isinstance(store, BlockingIntegration) and any(
            iscoroutinefunction(getattr(implementation, method)) for method in _API_KEY_STORE_METHODS
        ):
            raise ImproperlyConfiguredException(
                detail=(
                    f"API-key store {type(implementation).__name__} wrapped by BlockingIntegration must be synchronous"
                )
            )
        if (
            (not isinstance(store, BlockingIntegration) and not isinstance(store, APIKeyStore))
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
        if not callable(clock) or not callable(entropy) or participates_by_default.__class__ is not bool:
            raise ImproperlyConfiguredException(detail="API-key runtime configuration is invalid")
        selected_resolver = self.identity_resolver if resolver is None else resolver
        if not callable(getattr(selected_resolver, "resolve", None)):
            raise ImproperlyConfiguredException(detail="API-key identity resolver is required")
        normalized = (
            replace(self, store=_BlockingAPIKeyStore(self.store.implementation))
            if isinstance(self.store, BlockingIntegration)
            else self
        )
        return build_api_key_runtime(
            normalized,
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
    """Issue and parse strict opaque API keys without persistence access.

    Args:
        pepper: Secret mixed into every stored digest; at least 32 bytes.
        prefix: Version-carrying key prefix accepted and issued by this codec.
        entropy: Source of key-id and secret bytes.
        comparator: Digest equality used by :meth:`matches`. A supplied
            comparator **must** compare in constant time over equal-length
            digests, as the default :func:`hmac.compare_digest` does; a
            variable-time comparator reintroduces a timing side channel on the
            stored digest. This contract is documented rather than
            runtime-enforceable, so construction only verifies callability.
    """

    pepper: bytes = field(repr=False, metadata={"sensitive": True})
    prefix: str = "lsk"
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)
    comparator: Callable[[bytes, bytes], bool] = field(default=compare_digest, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Require a strong pepper, safe prefix, entropy, and comparator.

        Callability is the only property of the comparator that can be checked
        here; its constant-time contract rests with the implementer.
        """
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
    ) -> tuple[IssuedAPIKey, APIKeyState]:
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
        record = APIKeyState(
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
        parts = _parse_key_value(value)
        if parts is None:
            return None
        prefix, key_id, secret = parts
        if (
            prefix != self.prefix
            or _decode_segment(key_id, expected_bytes=_KEY_ID_BYTES, expected_characters=_KEY_ID_CHARACTERS) is None
            or _decode_segment(secret, expected_bytes=_SECRET_BYTES, expected_characters=_SECRET_CHARACTERS) is None
        ):
            return None
        return APIKeyProof(key_id=key_id, digest=_digest(self.pepper, key_id, secret))

    def matches(self, proof: APIKeyProof, record: APIKeyState) -> bool:
        """Compare one computed digest with a record through the configured comparator.

        The comparator receives two equal-length digests and must compare them
        in constant time; see :class:`APIKeyCodec` for the contract an override
        honors.

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
        except Exception:
            raise APIKeyGenerationError from None
        if value.__class__ is not bytes or len(value) != length:
            raise APIKeyGenerationError
        return value


def _parse_key_value(value: object) -> tuple[str, str, str] | None:
    if not isinstance(value, str) or value.__class__ is not str:
        return None
    prefix, separator, encoded = value.partition("_")
    if (
        not separator
        or len(encoded) != _KEY_ID_CHARACTERS + 1 + _SECRET_CHARACTERS
        or encoded[_KEY_ID_CHARACTERS] != "_"
    ):
        return None
    return prefix, encoded[:_KEY_ID_CHARACTERS], encoded[_KEY_ID_CHARACTERS + 1 :]


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


@dataclass(slots=True)
class BufferedAPIKeyUsage:
    """Bound and coalesce best-effort usage observations away from requests."""

    sink: object
    interval: timedelta
    capacity: int = 1024
    metrics: SecurityMetrics = field(default_factory=NoOpSecurityMetrics)
    _pending: dict[str, datetime] = field(default_factory=dict[str, datetime], init=False, repr=False)
    _last_written: dict[str, datetime] = field(default_factory=dict[str, datetime], init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate a structural sink and positive finite buffer policy."""
        sink = self.sink
        metrics = cast("object", self.metrics)
        if not hasattr(sink, "record") or not callable(getattr(sink, "record", None)):
            message = "API-key usage sink must define record"
            raise ValueError(message)
        if self.interval.__class__ is not timedelta or self.interval <= timedelta(0):
            message = "API-key usage interval must be positive"
            raise ValueError(message)
        if self.capacity.__class__ is not int:
            message = "API-key usage capacity must be an integer"
            raise TypeError(message)
        if not 1 <= self.capacity <= _MAXIMUM_USAGE_BUFFER_CAPACITY:
            message = "API-key usage capacity must be positive and bounded"
            raise ValueError(message)
        if not isinstance(metrics, SecurityMetrics):
            message = "API-key usage metrics must implement SecurityMetrics"
            raise TypeError(message)

    def observe(self, key_id: str, used_at: datetime) -> None:
        """Retain one latest secret-free observation without performing I/O.

        Args:
            key_id: The public key lookup.
            used_at: The timezone-aware usage timestamp.
        """
        normalized = _utc(used_at)
        if key_id in self._pending:
            self._pending[key_id] = max(self._pending[key_id], normalized)
            safe_increment(self.metrics, "security.api_key.usage_coalesced")
            return
        if len(self._pending) >= self.capacity:
            safe_increment(self.metrics, "security.api_key.usage_dropped")
            return
        self._pending[key_id] = normalized

    async def flush(self, *, force: bool = False) -> None:
        """Write eligible coalesced observations without raising sink failures.

        Args:
            force: Ignore the interval during shutdown.
        """
        for key_id, used_at in tuple(self._pending.items()):
            last_written = self._last_written.get(key_id)
            if not force and last_written is not None and used_at - last_written < self.interval:
                continue
            try:
                await cast("Any", self.sink).record(key_id=key_id, used_at=used_at)
            except Exception:
                safe_increment(self.metrics, "security.api_key.usage_failure")
            else:
                self._last_written[key_id] = used_at
            self._pending.pop(key_id, None)

    async def close(self) -> None:
        """Flush every pending observation during shutdown."""
        await self.flush(force=True)


@dataclass(slots=True)
class APIKeyService:
    """Issue, rotate, revoke, and flush API keys through atomic application ports."""

    config: APIKeyConfig
    codec: APIKeyCodec
    clock: Callable[[], datetime] = field(repr=False)
    usage: BufferedAPIKeyUsage | None = field(default=None, repr=False)

    async def issue(
        self, *, subject_id: str, restrictions: CredentialRestrictions | None = None, expires_at: datetime | None = None
    ) -> IssuedAPIKey:
        """Issue one reveal-once key and persist only its digest record.

        Args:
            subject_id: The application identity the key authenticates.
            restrictions: Optional credential authorization bounds.
            expires_at: Optional exclusive expiry.

        Returns:
            The reveal-once key.
        """
        issued, record = self.codec.issue(subject_id=subject_id, restrictions=restrictions, expires_at=expires_at)
        await _runtime_store(self.config).create(record)
        return issued

    async def rotate(
        self,
        *,
        current_key_id: str,
        subject_id: str,
        restrictions: CredentialRestrictions | None = None,
        expires_at: datetime | None = None,
        overlap: timedelta = timedelta(0),
    ) -> IssuedAPIKey:
        """Atomically replace one key with an optional bounded overlap.

        Args:
            current_key_id: The public lookup being replaced.
            subject_id: The replacement identity binding.
            restrictions: Replacement authorization bounds.
            expires_at: Replacement exclusive expiry.
            overlap: How long the current key may remain valid.

        Returns:
            The reveal-once replacement.

        Raises:
            ValueError: If overlap is negative.
        """
        if overlap.__class__ is not timedelta or overlap < timedelta(0):
            message = "API-key rotation overlap must not be negative"
            raise ValueError(message)
        now = _utc(self.clock())
        issued, replacement = self.codec.issue(subject_id=subject_id, restrictions=restrictions, expires_at=expires_at)
        await _runtime_store(self.config).rotate(
            current_key_id=current_key_id,
            replacement=replacement,
            overlap_until=now + overlap if overlap else None,
            now=now,
        )
        return issued

    async def revoke(self, key_id: str) -> None:
        """Revoke one key immediately through the atomic store operation.

        Args:
            key_id: The public lookup to revoke.
        """
        await _runtime_store(self.config).revoke(key_id=key_id, now=_utc(self.clock()))

    async def flush_usage(self) -> None:
        """Flush eligible buffered usage observations."""
        if self.usage is not None:
            await self.usage.flush()

    async def close(self) -> None:
        """Flush all pending usage observations during application shutdown."""
        if self.usage is not None:
            await self.usage.close()


@dataclass(slots=True)
class _APIKeyCredentialSlot:
    header_name: str
    maximum_value_bytes: int
    name: str = field(default=_SLOT_NAME, init=False)

    def extract(self, connection: ASGIConnection[Any, Any, Any, Any]) -> CredentialExtraction[str]:
        values = tuple(
            value
            for name, value in connection.scope["headers"]
            if name.lower() == self.header_name.lower().encode("ascii")
        )
        if not values:
            return NoCredentials()
        if len(values) != 1 or not values[0] or len(values[0]) > self.maximum_value_bytes:
            return InvalidCredentials()
        try:
            value = values[0].decode("ascii")
        except (AttributeError, UnicodeDecodeError):
            return InvalidCredentials()
        if any(
            ord(character) < _ASCII_CONTROL_LIMIT or ord(character) == _ASCII_DELETE or character.isspace()
            for character in value
        ):
            return InvalidCredentials()
        return PresentedCredential(value)


@dataclass(slots=True)
class _APIKeyAuthenticator:
    config: APIKeyConfig
    codec: APIKeyCodec
    clock: Callable[[], datetime] = field(repr=False)
    usage: BufferedAPIKeyUsage | None = field(default=None, repr=False)
    participates_by_default: bool = True
    name: str = field(default=_MECHANISM_NAME, init=False)
    slot: str = field(default=_SLOT_NAME, init=False)

    async def authenticate(
        self, credential: str, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> AuthenticationOutcome[APIKeyClaims]:
        del connection
        proof = self.codec.proof(credential)
        if proof is None:
            return InvalidCredentials()
        try:
            record = await _runtime_store(self.config).get(proof.key_id)
        except Exception:
            return VerificationUnavailable()
        if record is None or not self.codec.matches(proof, record):
            return InvalidCredentials()
        now = _utc(self.clock())
        if not record.is_valid_at(now):
            return InvalidCredentials()
        if self.usage is not None:
            self.usage.observe(record.key_id, now)
        claims = APIKeyClaims(key_id=record.key_id, subject_id=record.subject_id)
        return Authenticated(
            claims=claims,
            evidence=AuthenticationEvidence(
                mechanism=self.name,
                slot=self.slot,
                authenticated_at=now,
                expires_at=record.expires_at,
                methods=frozenset({_MECHANISM_NAME}),
            ),
            restrictions=record.restrictions,
        )


def build_api_key_runtime(
    config: APIKeyConfig,
    resolver: IdentityResolver[APIKeyClaims, UserT],
    *,
    clock: Callable[[], datetime],
    entropy: Callable[[int], bytes],
    metrics: SecurityMetrics,
    participates_by_default: bool,
) -> tuple[CredentialSlot[str], AuthenticationMechanism[str, APIKeyClaims, UserT], APIKeyService]:
    codec = APIKeyCodec(pepper=config.pepper, prefix=config.prefix, entropy=entropy)
    usage = (
        BufferedAPIKeyUsage(
            sink=config.usage_sink,
            interval=config.usage_write_interval,
            capacity=config.usage_buffer_capacity,
            metrics=metrics,
        )
        if config.usage_sink is not None
        else None
    )
    slot = _APIKeyCredentialSlot(
        header_name=config.header_name, maximum_value_bytes=len(config.prefix) + 1 + 16 + 1 + 43
    )
    authenticator = _APIKeyAuthenticator(
        config=config, codec=codec, clock=clock, usage=usage, participates_by_default=participates_by_default
    )
    mechanism = AuthenticationMechanism(
        authenticator=authenticator,
        resolver=resolver,
        scheme_name="APIKey",
        security_scheme=SecurityScheme(type="apiKey", name=config.header_name, security_scheme_in="header"),
    )
    api_key_service = APIKeyService(config=config, codec=codec, clock=clock, usage=usage)
    return slot, mechanism, api_key_service


def _runtime_store(config: APIKeyConfig) -> APIKeyStore:
    return cast("APIKeyStore", config.store)
