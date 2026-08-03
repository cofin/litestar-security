"""One-time credentials that authorize a single WebSocket connection.

A connect token is issued to an already-authenticated caller, bound to one
route, origin, and policy, and consumed atomically at handshake.
"""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import Error as BinasciiError
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from hmac import compare_digest
from secrets import token_bytes
from typing import Any, Protocol, cast, runtime_checkable

from anyio import Lock
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.context import CredentialRestrictions, Principal, SecurityContext
from litestar_security.websocket._internal import _canonical_origin, _strict_text, _utc

__all__ = (
    "InMemoryWebSocketConnectTokenStore",
    "IssuedWebSocketConnectToken",
    "WebSocketConnectTokenRecord",
    "WebSocketConnectTokenService",
    "WebSocketConnectTokenStore",
    "WebSocketConnectTokenUnavailableError",
    "issue_websocket_connect_token",
)

_MAXIMUM_CONNECT_TOKEN_TTL = timedelta(minutes=2)
_CONNECT_TOKEN_ID_BYTES = 16
_CONNECT_TOKEN_SECRET_BYTES = 32
_CONNECT_TOKEN_ID_CHARACTERS = 22
_CONNECT_TOKEN_SECRET_CHARACTERS = 43
_CONNECT_TOKEN_PREFIX = "wsct"  # noqa: S105 - a credential format prefix, not a secret
_CONNECT_TOKEN_DOMAIN = b"litestar-security/websocket-connect-token/v1\x00"
_CONNECT_TOKEN_COMPONENTS = 3
_BASE64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_DIGEST_BYTES = sha256().digest_size


@dataclass(frozen=True, slots=True)
class WebSocketConnectTokenRecord:
    """Storage-safe one-time connect token binding containing no recoverable value."""

    connect_token_id: str
    digest: bytes = field(repr=False, metadata={"sensitive": True})
    subject_id: str
    route_name: str
    origin: str
    restrictions: CredentialRestrictions
    policy_fingerprint: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        """Validate the immutable connect token binding and exclusive expiry."""
        issued_at = _utc(self.issued_at)
        expires_at = _utc(self.expires_at)
        if (
            _decode_connect_token_segment(
                self.connect_token_id,
                expected_bytes=_CONNECT_TOKEN_ID_BYTES,
                expected_characters=_CONNECT_TOKEN_ID_CHARACTERS,
            )
            is None
            or self.digest.__class__ is not bytes
            or len(self.digest) != _DIGEST_BYTES
            or not _strict_text(self.subject_id)
            or not _strict_text(self.route_name)
            or _canonical_origin(self.origin, configuration=True) != self.origin
            or self.restrictions.__class__ is not CredentialRestrictions
            or not _strict_text(self.policy_fingerprint)
            or expires_at <= issued_at
            or expires_at - issued_at > _MAXIMUM_CONNECT_TOKEN_TTL
        ):
            message = "WebSocket connect token record is invalid"
            raise ValueError(message)
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)


@dataclass(frozen=True, slots=True, repr=False)
class IssuedWebSocketConnectToken:
    """Reveal-once WebSocket connect token value."""

    value: str = field(repr=False, metadata={"sensitive": True})
    expires_at: datetime

    def __post_init__(self) -> None:
        """Require canonical connect token material and a timezone-aware expiry."""
        if _connect_token_proof(self.value) is None:
            message = "Issued WebSocket connect token is invalid"
            raise ValueError(message)
        object.__setattr__(self, "expires_at", _utc(self.expires_at))

    def __repr__(self) -> str:
        """Return a secret-free representation."""
        return f"IssuedWebSocketConnectToken(value='<redacted>', expires_at={self.expires_at!r})"


@runtime_checkable
class WebSocketConnectTokenStore(Protocol):
    """Application-owned atomic persistence port for one-time connect tokens."""

    async def create(self, record: WebSocketConnectTokenRecord) -> None:
        """Persist one new digest-only record, rejecting duplicate IDs."""
        ...  # pragma: no cover

    async def consume(
        self, *, connect_token_id: str, digest: bytes, now: datetime
    ) -> WebSocketConnectTokenRecord | None:
        """Atomically return and delete one matching unexpired record."""
        ...  # pragma: no cover


class WebSocketConnectTokenUnavailableError(RuntimeError):
    """Raised when the application connect token store cannot verify a connect token."""


@dataclass(slots=True)
class InMemoryWebSocketConnectTokenStore:
    """Deterministic concurrency-safe connect token store for tests and examples."""

    _records: dict[str, WebSocketConnectTokenRecord] = field(
        default_factory=dict[str, WebSocketConnectTokenRecord], init=False, repr=False
    )
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    @property
    def records(self) -> tuple[WebSocketConnectTokenRecord, ...]:
        """Return a stable snapshot of digest-only records."""
        return tuple(self._records.values())

    async def create(self, record: WebSocketConnectTokenRecord) -> None:
        """Persist one record while rejecting duplicate public IDs."""
        async with self._lock:
            if record.connect_token_id in self._records:
                message = "WebSocket connect token ID already exists"
                raise ValueError(message)
            self._records[record.connect_token_id] = record

    async def consume(
        self, *, connect_token_id: str, digest: bytes, now: datetime
    ) -> WebSocketConnectTokenRecord | None:
        """Atomically return and delete one matching unexpired record."""
        current = _utc(now)
        async with self._lock:
            record = self._records.get(connect_token_id)
            if record is None:
                return None
            if record.expires_at <= current:
                self._records.pop(connect_token_id, None)
                return None
            if not compare_digest(digest, record.digest):
                return None
            return self._records.pop(connect_token_id)


@dataclass(frozen=True, slots=True)
class WebSocketConnectTokenService:
    """Issue and atomically consume exact one-handshake connect token bindings."""

    store: WebSocketConnectTokenStore
    ttl: timedelta = timedelta(seconds=30)
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc), repr=False, compare=False)
    entropy: Callable[[int], bytes] = field(default=token_bytes, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate the structural store and bounded connect token lifetime."""
        store = cast("object", self.store)
        if (
            not isinstance(store, WebSocketConnectTokenStore)
            or self.ttl.__class__ is not timedelta
            or not timedelta(0) < self.ttl <= _MAXIMUM_CONNECT_TOKEN_TTL
            or not callable(self.clock)
            or not callable(self.entropy)
        ):
            message = "WebSocket connect token service configuration is invalid"
            raise ImproperlyConfiguredException(detail=message)

    async def issue(  # noqa: PLR0913 - every security binding remains an explicit keyword
        self,
        *,
        principal: Principal[Any],
        context: SecurityContext,
        route_name: str,
        origin: str,
        policy_fingerprint: str,
        restrictions: CredentialRestrictions | None = None,
    ) -> IssuedWebSocketConnectToken:
        """Issue one digest-only, exact-route connect token for an authenticated context."""
        if not principal.is_authenticated or context.__class__ is not SecurityContext:
            message = "WebSocket connect tokens require an authenticated security context"
            raise ValueError(message)
        now = _utc(self.clock())
        connect_token_id = _encode_connect_token_segment(self._entropy(_CONNECT_TOKEN_ID_BYTES))
        secret = _encode_connect_token_segment(self._entropy(_CONNECT_TOKEN_SECRET_BYTES))
        selected_restrictions = restrictions if restrictions is not None else CredentialRestrictions()
        record = WebSocketConnectTokenRecord(
            connect_token_id=connect_token_id,
            digest=_connect_token_digest(connect_token_id, secret),
            subject_id=cast("str", principal.id),
            route_name=route_name,
            origin=origin,
            restrictions=selected_restrictions,
            policy_fingerprint=policy_fingerprint,
            issued_at=now,
            expires_at=now + self.ttl,
        )
        await self.store.create(record)
        return IssuedWebSocketConnectToken(
            value=f"{_CONNECT_TOKEN_PREFIX}.{connect_token_id}.{secret}", expires_at=record.expires_at
        )

    async def consume(
        self, value: object, *, route_name: str, origin: str, policy_fingerprint: str
    ) -> WebSocketConnectTokenRecord | None:
        """Atomically consume a connect token before validating later route bindings."""
        proof = _connect_token_proof(value)
        if proof is None:
            return None
        connect_token_id, digest = proof
        try:
            record = await self.store.consume(connect_token_id=connect_token_id, digest=digest, now=_utc(self.clock()))
        except Exception:  # noqa: BLE001 - application store failures fail closed at the connect token boundary
            raise WebSocketConnectTokenUnavailableError from None
        if (
            record is None
            or record.route_name != route_name
            or record.origin != origin
            or record.policy_fingerprint != policy_fingerprint
        ):
            return None
        return record

    def _entropy(self, length: int) -> bytes:
        try:
            value = self.entropy(length)
        except Exception:  # noqa: BLE001 - entropy failures become one stable issuance error
            message = "WebSocket connect token entropy is unavailable"
            raise ValueError(message) from None
        if value.__class__ is not bytes or len(value) != length:
            message = "WebSocket connect token entropy is unavailable"
            raise ValueError(message)
        return value


async def issue_websocket_connect_token(  # noqa: PLR0913 - the helper makes every connect token binding explicit
    *,
    principal: Principal[Any],
    context: SecurityContext,
    route_name: str,
    origin: str,
    policy_fingerprint: str,
    restrictions: CredentialRestrictions,
    store: WebSocketConnectTokenStore,
    clock: Callable[[], datetime],
    ttl: timedelta = timedelta(seconds=30),
) -> IssuedWebSocketConnectToken:
    """Issue one reveal-once WebSocket connect token through an application store.

    Args:
        principal: The authenticated principal the connect token speaks for.
        context: The security context the connect token is bound to.
        route_name: The single route the connect token authorizes; it is valid nowhere else.
        origin: The exact origin the handshake must present.
        policy_fingerprint: The compiled policy binding the handshake revalidates.
        restrictions: The credential restrictions carried into the connection.
        store: The application store that persists the digest-only record.
        clock: The timezone-aware clock used for issuance and expiry.
        ttl: How long the connect token stays valid, bounded by the two-minute maximum.

    Returns:
        The issued connect token, whose reveal-once value is not recoverable from the
        stored record.

    Raises:
        ValueError: If the principal is unauthenticated, the context is not a
            ``SecurityContext``, or any binding fails validation.
    """
    return await WebSocketConnectTokenService(store=store, ttl=ttl, clock=clock).issue(
        principal=principal,
        context=context,
        route_name=route_name,
        origin=origin,
        policy_fingerprint=policy_fingerprint,
        restrictions=restrictions,
    )


def _encode_connect_token_segment(value: bytes) -> str:
    if value.__class__ is not bytes:
        message = "WebSocket connect token entropy is unavailable"
        raise ValueError(message)
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_connect_token_segment(value: object, *, expected_bytes: int, expected_characters: int) -> bytes | None:
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
    return decoded if len(decoded) == expected_bytes and _encode_connect_token_segment(decoded) == value else None


def _connect_token_digest(connect_token_id: str, secret: str) -> bytes:
    return sha256(_CONNECT_TOKEN_DOMAIN + connect_token_id.encode("ascii") + b"\x00" + secret.encode("ascii")).digest()


def _connect_token_proof(value: object) -> tuple[str, bytes] | None:
    if not isinstance(value, str) or value.__class__ is not str:
        return None
    parts = value.split(".")
    if len(parts) != _CONNECT_TOKEN_COMPONENTS:
        return None
    prefix, connect_token_id, secret = parts
    if (
        prefix != _CONNECT_TOKEN_PREFIX
        or _decode_connect_token_segment(
            connect_token_id, expected_bytes=_CONNECT_TOKEN_ID_BYTES, expected_characters=_CONNECT_TOKEN_ID_CHARACTERS
        )
        is None
        or _decode_connect_token_segment(
            secret, expected_bytes=_CONNECT_TOKEN_SECRET_BYTES, expected_characters=_CONNECT_TOKEN_SECRET_CHARACTERS
        )
        is None
    ):
        return None
    return connect_token_id, _connect_token_digest(connect_token_id, secret)
