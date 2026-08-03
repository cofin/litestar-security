"""WebSocket-specific transport policy.

Content Security Policy ``connect-src`` is complementary browser hardening. It
does not replace exact server-side Origin validation or credential policy.
"""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import Error as BinasciiError
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from hmac import compare_digest
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from secrets import token_bytes
from string import hexdigits
from typing import TYPE_CHECKING, Any, Literal, NoReturn, Protocol, TypeVar, cast, runtime_checkable
from urllib.parse import parse_qsl, urlsplit

from anyio import Lock, create_task_group, sleep
from litestar.exceptions import (
    ImproperlyConfiguredException,
    NotAuthorizedException,
    PermissionDeniedException,
    ServiceUnavailableException,
    WebSocketException,
)

from litestar_security.context import AuthorizationSnapshot, CredentialRestrictions, Principal, SecurityContext

if TYPE_CHECKING:
    from collections.abc import Iterable

    from litestar.connection import ASGIConnection
    from litestar.types import Message, Send

__all__ = (
    "AuthorizationSnapshotRefresher",
    "InMemoryWebSocketConnectTokenStore",
    "IssuedWebSocketConnectToken",
    "WebSocketBinding",
    "WebSocketCloseCodes",
    "WebSocketConnectTokenRecord",
    "WebSocketConnectTokenService",
    "WebSocketConnectTokenStore",
    "WebSocketHandshake",
    "WebSocketRevocationSource",
    "WebSocketSecurityConfig",
    "extract_websocket_handshake",
    "issue_websocket_connect_token",
    "websocket_policy_fingerprint",
)

_DEFAULT_UNAUTHENTICATED_CLOSE = 4401
_DEFAULT_UNAUTHORIZED_CLOSE = 4403
_DEFAULT_UNAVAILABLE_CLOSE = 1013
_MAXIMUM_CONNECT_TOKEN_TTL = timedelta(minutes=2)
_RESERVED_QUERY_PARAMETERS = frozenset({"access_token", "authorization", "bearer", "jwt", "token"})
_HTTP_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAXIMUM_HOST_LENGTH = 253
_MAXIMUM_HOST_LABEL_LENGTH = 63
_PRIVATE_CLOSE_CODE_MINIMUM = 4000
_PRIVATE_CLOSE_CODE_MAXIMUM = 4999
_CONNECT_TOKEN_ID_BYTES = 16
_CONNECT_TOKEN_SECRET_BYTES = 32
_CONNECT_TOKEN_ID_CHARACTERS = 22
_CONNECT_TOKEN_SECRET_CHARACTERS = 43
_CONNECT_TOKEN_PREFIX = "wsct"  # noqa: S105 - a credential format prefix, not a secret
_CONNECT_TOKEN_DOMAIN = b"litestar-security/websocket-connect-token/v1\x00"
_CONNECT_TOKEN_COMPONENTS = 3
_BASE64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_DIGEST_BYTES = sha256().digest_size
_ASCII_CONTROL_LIMIT = 32
UserT = TypeVar("UserT")


@dataclass(frozen=True, slots=True)
class WebSocketCloseCodes:
    """Map stable security outcomes to WebSocket close codes."""

    unauthenticated: int = _DEFAULT_UNAUTHENTICATED_CLOSE
    unauthorized: int = _DEFAULT_UNAUTHORIZED_CLOSE
    verification_unavailable: int = _DEFAULT_UNAVAILABLE_CLOSE


@dataclass(frozen=True, slots=True)
class WebSocketSecurityConfig:
    """Configure WebSocket transport validation and optional lifetime hooks."""

    allowed_origins: frozenset[str] = frozenset()
    connect_token_store: "WebSocketConnectTokenStore | None" = field(default=None, repr=False)
    connect_token_ttl: timedelta = timedelta(seconds=30)
    maximum_connect_token_ttl: timedelta = _MAXIMUM_CONNECT_TOKEN_TTL
    connect_token_query_parameter: str = "connect_token"  # noqa: S105 - a query parameter name, not a secret
    refresh_interval: timedelta | None = None
    snapshot_refresher: "AuthorizationSnapshotRefresher[Any] | None" = field(default=None, repr=False)
    revocation_source: "WebSocketRevocationSource | None" = field(default=None, repr=False)
    close_codes: WebSocketCloseCodes = WebSocketCloseCodes()
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc), repr=False, compare=False)
    sleeper: Callable[[float], Awaitable[None]] = field(default=sleep, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate and freeze security-sensitive transport settings."""
        object.__setattr__(self, "allowed_origins", _normalize_allowed_origins(self.allowed_origins))
        _validate_connect_token_settings(self)
        _validate_refresh_settings(self)
        _validate_close_codes(self.close_codes)
        if not callable(self.clock) or not callable(self.sleeper):
            _configuration_error("WebSocket clock and sleeper must be callable")


@dataclass(frozen=True, slots=True)
class WebSocketHandshake:
    """Describe credential transports presented by one WebSocket handshake."""

    origin: str | None
    uses_cookie_credentials: bool
    uses_authorization_header: bool
    connect_token: str | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class WebSocketBinding:
    """Secret-free identity and route binding supplied to revocation hooks."""

    connection_id: str
    subject_id: str
    credential_ids: frozenset[str]
    session_id: str | None
    route_name: str

    def __post_init__(self) -> None:
        """Normalize stable binding identifiers."""
        if (
            not _strict_text(self.connection_id)
            or not _strict_text(self.subject_id)
            or not _strict_text(self.route_name)
            or any(not _strict_text(value) for value in self.credential_ids)
            or (self.session_id is not None and not _strict_text(self.session_id))
        ):
            message = "WebSocket revocation binding is invalid"
            raise ValueError(message)
        object.__setattr__(self, "credential_ids", frozenset(self.credential_ids))


@runtime_checkable
class WebSocketRevocationSource(Protocol):
    """Event-driven application hook that returns when a binding is revoked."""

    async def wait(self, binding: WebSocketBinding) -> None:
        """Wait without polling until the supplied connection binding is revoked."""
        ...  # pragma: no cover


@runtime_checkable
class AuthorizationSnapshotRefresher(Protocol[UserT]):
    """Application hook returning one detached immutable authorization snapshot."""

    async def refresh(
        self, *, principal: Principal[UserT], previous: AuthorizationSnapshot, route_name: str
    ) -> AuthorizationSnapshot:
        """Resolve and return the next detached snapshot."""
        ...  # pragma: no cover


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


# ai: these files are a mess of config, services, errors, etc.  we need to
# consider all of this when refactoring and recording.
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


def websocket_policy_fingerprint(plan: object) -> str:
    """Return a stable process-independent fingerprint for one compiled plan.

    Args:
        plan: The frozen compiled security plan.

    Returns:
        A hexadecimal SHA-256 fingerprint.
    """
    authenticate = bool(getattr(plan, "authenticate", False))
    required = bool(getattr(plan, "required", False))
    allow_anonymous = bool(getattr(plan, "allow_anonymous", False))
    participant_names = sorted(cast("frozenset[str] | None", getattr(plan, "participant_names", None)) or ())
    alternatives = cast("tuple[tuple[object, ...], ...]", getattr(plan, "alternatives", ()))
    serialized_alternatives = tuple(
        tuple(
            (
                cast("str", getattr(requirement, "name", "")),
                tuple(cast("tuple[str, ...]", getattr(requirement, "scopes", ()))),
            )
            for requirement in alternative
        )
        for alternative in alternatives
    )
    payload = repr((authenticate, required, allow_anonymous, participant_names, serialized_alternatives)).encode()
    return sha256(b"litestar-security/websocket-policy/v1\x00" + payload).hexdigest()


async def close_websocket(send: "Send", *, code: int, reason: str) -> None:
    """Send one sanitized WebSocket close event.

    Args:
        send: The routed WebSocket send callable.
        code: A validated WebSocket close code.
        reason: A stable machine-readable reason.

    Returns:
        None.
    """
    await send({"type": "websocket.close", "code": code, "reason": reason})


@dataclass(slots=True)
class WebSocketCloseCoordinator:
    """Serialize accepted and terminal ASGI events for one WebSocket."""

    send_callable: "Send" = field(repr=False)
    state: Literal["pending", "accepted", "closing", "closed"] = field(default="pending", init=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    async def send(self, message: "Message") -> None:
        """Forward one event unless a terminal close already won."""
        async with self._lock:
            if self.state == "closed":
                return
            if message["type"] == "websocket.accept":
                if self.state != "pending":
                    return
                self.state = "accepted"
            elif message["type"] == "websocket.close":
                self.state = "closing"
                await self.send_callable(message)
                self.state = "closed"
                return
            await self.send_callable(message)

    async def close(self, *, code: int, reason: str) -> bool:
        """Send the sole close event and report whether this call won."""
        async with self._lock:
            if self.state in {"closing", "closed"}:
                return False
            self.state = "closing"
            await self.send_callable({"type": "websocket.close", "code": code, "reason": reason})
            self.state = "closed"
            return True


async def supervise_websocket_lifetime(  # noqa: C901, PLR0913 - explicit race branches and injectable scheduler inputs
    handler: Callable[[], Awaitable[None]],
    *,
    expires_at: datetime | None,
    coordinator: WebSocketCloseCoordinator,
    unauthenticated_close_code: int,
    unauthorized_close_code: int = _DEFAULT_UNAUTHORIZED_CLOSE,
    unavailable_close_code: int = _DEFAULT_UNAVAILABLE_CLOSE,
    revocation_wait: Callable[[], Awaitable[None]] | None = None,
    refresh: Callable[[], Awaitable[None]] | None = None,
    refresh_interval: timedelta | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    sleeper: Callable[[float], Awaitable[None]] = sleep,
) -> None:
    """Run a handler with at most one non-polling credential-expiry task."""
    if expires_at is None and revocation_wait is None and refresh is None:
        await handler()
        return
    delay = (_utc(expires_at) - _utc(clock())).total_seconds() if expires_at is not None else None
    if delay is not None and delay <= 0:
        await coordinator.close(code=unauthenticated_close_code, reason="credential_expired")
        return

    async def expire() -> None:
        await sleeper(cast("float", delay))
        await coordinator.close(code=unauthenticated_close_code, reason="credential_expired")
        task_group.cancel_scope.cancel()

    async def revoke() -> None:
        try:
            await cast("Callable[[], Awaitable[None]]", revocation_wait)()
        except Exception:  # noqa: BLE001 - application revocation failures are one sanitized transient outage
            await coordinator.close(code=unavailable_close_code, reason="verification_unavailable")
            task_group.cancel_scope.cancel()
            return
        await coordinator.close(code=unauthenticated_close_code, reason="credential_revoked")
        task_group.cancel_scope.cancel()

    async def refresh_snapshots() -> None:
        interval = cast("timedelta", refresh_interval).total_seconds()
        while True:
            await sleeper(interval)
            try:
                await cast("Callable[[], Awaitable[None]]", refresh)()
            except (NotAuthorizedException, PermissionDeniedException):
                await coordinator.close(code=unauthorized_close_code, reason="authorization_denied")
                task_group.cancel_scope.cancel()
                return
            except ServiceUnavailableException:
                await coordinator.close(code=unavailable_close_code, reason="verification_unavailable")
                task_group.cancel_scope.cancel()
                return
            except Exception:  # noqa: BLE001 - application refresh failures are one sanitized transient outage
                await coordinator.close(code=unavailable_close_code, reason="verification_unavailable")
                task_group.cancel_scope.cancel()
                return

    async with create_task_group() as task_group:
        if delay is not None:
            task_group.start_soon(expire)
        if revocation_wait is not None:
            task_group.start_soon(revoke)
        if refresh is not None:
            task_group.start_soon(refresh_snapshots)
        try:
            await handler()
        finally:
            task_group.cancel_scope.cancel()


def extract_websocket_handshake(
    connection: "ASGIConnection[Any, Any, Any, Any]", *, config: WebSocketSecurityConfig, uses_cookie_credentials: bool
) -> WebSocketHandshake:
    """Extract and validate one WebSocket handshake without verifying credentials.

    The caller derives ``uses_cookie_credentials`` from the existing common
    credential-slot extraction. Reusable header and cookie credentials remain
    owned by those common parsers; this function only applies WebSocket Origin
    and URL constraints.

    Args:
        connection: The incoming Litestar WebSocket connection.
        config: Validated WebSocket security configuration.
        uses_cookie_credentials: Whether a common credential slot found a
            cookie- or session-backed credential.

    Returns:
        A redacted description of the presented WebSocket transports.

    Raises:
        WebSocketException: If Origin policy fails or a reusable URL credential
            is presented.
    """
    headers = connection.scope["headers"]
    query_string = connection.scope["query_string"]
    origin_values: list[bytes] = []
    uses_authorization_header = False
    for name, value in headers:
        normalized_name = name.lower()
        if normalized_name == b"origin":
            origin_values.append(value)
        elif normalized_name == b"authorization":
            uses_authorization_header = True
    origin = _validated_request_origin(tuple(origin_values), config=config, required=uses_cookie_credentials)
    connect_token = _extract_connect_token(query_string, config=config)
    return WebSocketHandshake(
        origin=origin,
        uses_cookie_credentials=uses_cookie_credentials,
        uses_authorization_header=uses_authorization_header,
        connect_token=connect_token,
    )


def _canonical_origin(value: str, *, configuration: bool, invalid_close_code: int = _DEFAULT_UNAUTHORIZED_CLOSE) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeError, ValueError):
        return _invalid_origin(configuration=configuration, close_code=invalid_close_code)
    if (
        not value.isascii()
        or parsed.scheme not in _HTTP_DEFAULT_PORTS
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.hostname.endswith(".")
        or "*" in parsed.hostname
        or "%" in parsed.hostname
    ):
        return _invalid_origin(configuration=configuration, close_code=invalid_close_code)
    hostname = _canonical_hostname(parsed.hostname)
    if hostname is None:
        return _invalid_origin(configuration=configuration, close_code=invalid_close_code)
    serialized_host = f"[{hostname}]" if ":" in hostname else hostname
    serialized_port = "" if port is None or port == _HTTP_DEFAULT_PORTS[parsed.scheme] else f":{port}"
    canonical = f"{parsed.scheme}://{serialized_host}{serialized_port}"
    if canonical != value:
        return _invalid_origin(configuration=configuration, close_code=invalid_close_code)
    return canonical


def _validated_request_origin(
    values: tuple[bytes, ...], *, config: WebSocketSecurityConfig, required: bool
) -> str | None:
    if not values:
        if required:
            _transport_error(config.close_codes.unauthorized, "WebSocket Origin is required")
        return None
    if len(values) != 1:
        _transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    try:
        value = values[0].decode("ascii")
    except (AttributeError, UnicodeDecodeError):
        _transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    origin = _canonical_origin(value, configuration=False, invalid_close_code=config.close_codes.unauthorized)
    if origin not in config.allowed_origins:
        _transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    return origin


def _extract_connect_token(query_string: bytes, *, config: WebSocketSecurityConfig) -> str | None:
    if not query_string:
        return None
    try:
        encoded = query_string.decode("ascii")
        parameters = parse_qsl(encoded, keep_blank_values=True, encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        _transport_error(config.close_codes.unauthenticated, "WebSocket query credentials are invalid")
    if not _valid_percent_encoding(encoded):
        _transport_error(config.close_codes.unauthenticated, "WebSocket query credentials are invalid")
    connect_tokens: list[str] = []
    for name, value in parameters:
        if name.casefold() in _RESERVED_QUERY_PARAMETERS:
            _transport_error(config.close_codes.unauthenticated, "Reusable URL credentials are forbidden")
        if name == config.connect_token_query_parameter:
            connect_tokens.append(value)
    if len(connect_tokens) > 1 or (connect_tokens and not connect_tokens[0]):
        _transport_error(config.close_codes.unauthenticated, "WebSocket connect token is invalid")
    return connect_tokens[0] if connect_tokens else None


def _valid_percent_encoding(value: str) -> bool:
    index = 0
    while (index := value.find("%", index)) >= 0:
        if index + 2 >= len(value) or value[index + 1] not in hexdigits or value[index + 2] not in hexdigits:
            return False
        index += 3
    return True


def _canonical_hostname(value: str) -> str | None:
    if ":" in value:
        return IPv6Address(value).compressed
    try:
        return str(IPv4Address(value))
    except AddressValueError:
        pass
    labels = value.split(".")
    if (
        len(value) > _MAXIMUM_HOST_LENGTH
        or all(label.isdigit() for label in labels)
        or any(
            not label
            or len(label) > _MAXIMUM_HOST_LABEL_LENGTH
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        )
    ):
        return None
    return value


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


def _strict_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.__class__ is str
        and bool(value)
        and value == value.strip()
        and all(ord(character) >= _ASCII_CONTROL_LIMIT for character in value)
    )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        message = "WebSocket connect token timestamp must be timezone-aware"
        raise ValueError(message)
    return value.astimezone(timezone.utc)


def _duration(value: object, name: str) -> timedelta:
    if not isinstance(value, timedelta) or value.__class__ is not timedelta:
        _configuration_error(f"WebSocket {name} must be positive")
    duration = value
    if duration <= timedelta(0):
        _configuration_error(f"WebSocket {name} must be positive")
    return duration


def _normalize_allowed_origins(value: object) -> frozenset[str]:
    if isinstance(value, str):
        _configuration_error("WebSocket allowed origins must be a collection")
    try:
        origins = tuple(cast("Iterable[object]", value))
    except TypeError:
        _configuration_error("WebSocket allowed origins must be a collection")
    if any(origin.__class__ is not str for origin in origins):
        _configuration_error("WebSocket allowed origins must contain text")
    canonical = tuple(_canonical_origin(cast("str", origin), configuration=True) for origin in origins)
    if len(canonical) != len(set(canonical)):
        _configuration_error("WebSocket allowed origins contain a duplicate")
    return frozenset(canonical)


def _validate_connect_token_settings(config: WebSocketSecurityConfig) -> None:
    connect_token_store = cast("object | None", config.connect_token_store)
    if connect_token_store is not None and not isinstance(connect_token_store, WebSocketConnectTokenStore):
        _configuration_error("WebSocket connect token store must implement atomic create and consume")
    maximum_connect_token_ttl = _duration(config.maximum_connect_token_ttl, "maximum connect token TTL")
    if maximum_connect_token_ttl > _MAXIMUM_CONNECT_TOKEN_TTL:
        _configuration_error("WebSocket maximum connect token TTL cannot exceed two minutes")
    connect_token_ttl = _duration(config.connect_token_ttl, "connect token TTL")
    if connect_token_ttl > maximum_connect_token_ttl:
        _configuration_error("WebSocket connect token TTL cannot exceed its configured maximum")

    query_name_value = cast("object", config.connect_token_query_parameter)
    if not isinstance(query_name_value, str) or query_name_value.__class__ is not str:
        _configuration_error("WebSocket connect token query parameter must be text")
    query_name = query_name_value
    if (
        not query_name
        or query_name != query_name.strip()
        or not query_name.isascii()
        or any(character in query_name for character in "&#=;")
    ):
        _configuration_error("WebSocket connect token query parameter must be a non-empty safe name")
    if query_name.casefold() in _RESERVED_QUERY_PARAMETERS:
        _configuration_error("WebSocket connect token query parameter uses a reserved credential name")


def _validate_refresh_settings(config: WebSocketSecurityConfig) -> None:
    refresher = cast("object | None", config.snapshot_refresher)
    revocation_source = cast("object | None", config.revocation_source)
    if refresher is not None and not isinstance(refresher, AuthorizationSnapshotRefresher):
        _configuration_error("WebSocket snapshot refresher must define refresh")
    if revocation_source is not None and not isinstance(revocation_source, WebSocketRevocationSource):
        _configuration_error("WebSocket revocation source must define wait")
    if config.refresh_interval is not None:
        _duration(config.refresh_interval, "refresh interval")
        if refresher is None:
            _configuration_error("WebSocket refresh interval requires a snapshot refresher")


def _validate_close_codes(value: object) -> None:
    if not isinstance(value, WebSocketCloseCodes) or value.__class__ is not WebSocketCloseCodes:
        _configuration_error("WebSocket close codes must use WebSocketCloseCodes")
    codes = value
    values = (codes.unauthenticated, codes.unauthorized, codes.verification_unavailable)
    if (
        any(code.__class__ is not int for code in values)
        or not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.unauthenticated <= _PRIVATE_CLOSE_CODE_MAXIMUM
        or not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.unauthorized <= _PRIVATE_CLOSE_CODE_MAXIMUM
        or (
            codes.verification_unavailable != _DEFAULT_UNAVAILABLE_CLOSE
            and not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.verification_unavailable <= _PRIVATE_CLOSE_CODE_MAXIMUM
        )
        or len(set(values)) != len(values)
        or codes.unauthenticated == _DEFAULT_UNAUTHORIZED_CLOSE
        or codes.unauthorized == _DEFAULT_UNAUTHENTICATED_CLOSE
        or codes.verification_unavailable in {_DEFAULT_UNAUTHENTICATED_CLOSE, _DEFAULT_UNAUTHORIZED_CLOSE}
    ):
        _configuration_error("WebSocket close code assignments are invalid")


def _invalid_origin(*, configuration: bool, close_code: int) -> NoReturn:
    if configuration:
        _configuration_error("WebSocket allowed origins must be canonical HTTP(S) origins")
    raise WebSocketException(code=close_code, detail="WebSocket Origin is not trusted")


def _configuration_error(detail: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=detail)


def _transport_error(code: int, detail: str) -> NoReturn:
    raise WebSocketException(code=code, detail=detail)
