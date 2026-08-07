"""Opaque refresh-token value types, their codec, and family identity.

These are inert values with no store or clock dependency. Both the receipt sealer
and the rotation service build on them, so keeping them free of service imports is
what lets those two modules depend on each other in only one direction.
"""

from binascii import Error as BinasciiError
from collections.abc import Callable
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from hmac import digest as hmac_digest
from secrets import token_bytes
from typing import TYPE_CHECKING, ClassVar, Literal, TypeVar, cast

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
    strict_context_text,
    valid_identifier,
    valid_security_epoch,
)
from litestar_security.authentication import InvalidCredentials
from litestar_security.context import AuthenticationEvidence
from litestar_security.schema import WireStruct

if TYPE_CHECKING:
    from datetime import datetime

__all__ = (
    "RefreshFamilyContext",
    "RefreshRotationStatus",
    "RefreshTokenCodec",
    "RefreshTokenIssue",
    "RefreshTokenProof",
    "TokenPair",
)


UserT = TypeVar("UserT")


_REFRESH_TOKEN_PREFIX = "rt_"  # noqa: S105 - public token namespace, not a credential


_REFRESH_FAMILY_PREFIX = "rf_"


_REFRESH_TOKEN_DOMAIN = b"refresh-token\x00"


_REFRESH_IDEMPOTENCY_DOMAIN = b"refresh-idempotency\x00"


_MINIMUM_IDEMPOTENCY_CHARACTERS = 22


_MAXIMUM_IDEMPOTENCY_CHARACTERS = 128


_MAXIMUM_ACCESS_TOKEN_BYTES = 16_384


_COMPACT_JWT_SEGMENTS = 3


_MINIMUM_ACCESS_TOKEN_SECONDS = 30


_MAXIMUM_ACCESS_TOKEN_SECONDS = 3_600


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
    return (
        isinstance(value, str)
        and bool(value)
        and all(character == "!" or "#" <= character <= "[" or "]" <= character <= "~" for character in value)
    )


def normalize_refresh_scopes(scopes: object) -> frozenset[str] | None:
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
        """Validate canonical lookup and digest material."""
        if (
            not valid_identifier(self.token_id, prefix=_REFRESH_TOKEN_PREFIX)
            or self.digest.__class__ is not bytes
            or len(self.digest) != DIGEST_BYTES
        ):
            msg = "Refresh token proof is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RefreshTokenIssue:
    """Reveal-once opaque refresh token plus storage-safe material."""

    refresh_token: str = field(repr=False)
    token_id: str
    digest: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Validate reveal-once and storage-safe material agree."""
        parsed = _parse_refresh_token(self.refresh_token)
        if (
            parsed is None
            or parsed[0] != self.token_id
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
        """Create one lookup/secret pair and its storage-safe digest.

        Returns:
            The reveal-once token alongside the digest to store. The secret half
            is never recoverable from what is stored.
        """
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
        """Parse one canonical token while keeping malformed work in the HMAC class.

        Args:
            refresh_token: The presented opaque token.

        Returns:
            The parsed lookup and digest, or ``InvalidCredentials``. Every
            rejection costs the same work.
        """
        parsed = _parse_refresh_token(refresh_token)
        token_id, secret = (
            parsed
            if parsed is not None
            else (f"{_REFRESH_TOKEN_PREFIX}{encode_random(bytes(LOOKUP_BYTES))}", bytes(SECRET_BYTES))
        )
        digest = self._digest(token_id, secret)
        return RefreshTokenProof(token_id=token_id, digest=digest) if parsed is not None else InvalidCredentials()

    def digest_idempotency_key(self, token_id: str, value: str) -> bytes | InvalidCredentials:
        """Hash one canonical key carrying at least 128 bits of caller entropy.

        Args:
            token_id: The token the key is scoped to, so a key cannot be reused
                across tokens.
            value: The caller's ``Idempotency-Key`` header.

        Returns:
            The digest to compare against the stored one, or ``InvalidCredentials``
            when the key carries too little entropy to be safe.
        """
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
    """RFC 6749 section 5.1 names every member below, so no policy may rename them."""

    access_token: str
    refresh_token: str
    expires_in: int
    # RFC 6749 section 5.1 member names, so none of these may be renamed.
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105 - the public RFC 6749 token type, not a credential

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
    token_expires_at: "datetime"
    family_expires_at: "datetime"
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
            or (
                self.evidence is not None
                and not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime store boundary
                    self.evidence, AuthenticationEvidence
                )
            )
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
