"""WebSocket transport policy, lifecycle supervision, and configuration."""

from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from importlib import import_module
from secrets import token_urlsafe
from string import hexdigits
from typing import Any, Literal, NoReturn, Protocol, TypeVar, cast, runtime_checkable
from urllib.parse import parse_qsl

from anyio import Lock, create_task_group, sleep
from litestar.connection import ASGIConnection
from litestar.exceptions import (
    ImproperlyConfiguredException,
    NotAuthorizedException,
    PermissionDeniedException,
    ServiceUnavailableException,
    WebSocketException,
)
from litestar.types import ASGIApp, Message, Receive, Scope, Send

from litestar_security.context import (
    AuthorizationSnapshot,
    Principal,
    SecurityContext,
    SessionHandle,
    resolve_authorization,
)
from litestar_security.websocket._connect_tokens import (
    DEFAULT_UNAUTHORIZED_CLOSE,
    MAXIMUM_CONNECT_TOKEN_TTL,
    WebSocketConnectTokenStore,
    WebSocketConnectTokenUnavailableError,
    authenticate_connect_token,
    aware_utc,
    canonical_hostname,
    canonical_origin,
    invalid_origin,
    strict_text,
    websocket_policy_fingerprint,
)

__all__ = (
    "DEFAULT_UNAUTHENTICATED_CLOSE",
    "DEFAULT_UNAUTHORIZED_CLOSE",
    "DEFAULT_UNAVAILABLE_CLOSE",
    "RESERVED_QUERY_PARAMETERS",
    "AuthorizationSnapshotRefresher",
    "WebSocketBinding",
    "WebSocketCloseCodes",
    "WebSocketCloseCoordinator",
    "WebSocketHandshake",
    "WebSocketRevocationSource",
    "WebSocketSecurityConfig",
    "aware_utc",
    "canonical_hostname",
    "canonical_origin",
    "close_websocket",
    "configuration_error",
    "create_websocket_binding",
    "duration",
    "extract_websocket_handshake",
    "handle_websocket",
    "invalid_origin",
    "normalize_allowed_origins",
    "strict_text",
    "supervise_websocket_lifetime",
    "transport_error",
    "valid_percent_encoding",
    "websocket_policy_fingerprint",
    "websocket_route_name",
)

DEFAULT_UNAUTHENTICATED_CLOSE = 4401
DEFAULT_UNAVAILABLE_CLOSE = 1013
_PRIVATE_CLOSE_CODE_MINIMUM = 4000
_PRIVATE_CLOSE_CODE_MAXIMUM = 4999
_LITESTAR_INTERNAL_ERROR_CLOSE = 4500
RESERVED_QUERY_PARAMETERS = frozenset({"access_token", "authorization", "bearer", "jwt", "token"})

UserT = TypeVar("UserT")


def duration(value: object, name: str) -> timedelta:
    """Validate and return a positive duration."""
    if not isinstance(value, timedelta) or value.__class__ is not timedelta:
        configuration_error(f"WebSocket {name} must be positive")
    duration_val = value
    if duration_val <= timedelta(0):
        configuration_error(f"WebSocket {name} must be positive")
    return duration_val


def normalize_allowed_origins(value: object) -> frozenset[str]:
    """Validate and return canonical allowed origins."""
    if isinstance(value, str):
        configuration_error("WebSocket allowed origins must be a collection")
    try:
        origins = tuple(cast("Iterable[object]", value))
    except TypeError:
        configuration_error("WebSocket allowed origins must be a collection")
    if any(origin.__class__ is not str for origin in origins):
        configuration_error("WebSocket allowed origins must contain text")
    canonical = tuple(canonical_origin(cast("str", origin), configuration=True) for origin in origins)
    if len(canonical) != len(set(canonical)):
        configuration_error("WebSocket allowed origins contain a duplicate")
    return frozenset(canonical)


def configuration_error(detail: str) -> NoReturn:
    """Raise an ImproperlyConfiguredException for WebSocket configuration."""
    raise ImproperlyConfiguredException(detail=detail)


def transport_error(code: int, detail: str) -> NoReturn:
    """Raise a WebSocketException with a close code and detail."""
    raise WebSocketException(code=code, detail=detail)


def valid_percent_encoding(value: str) -> bool:
    """Validate percent-encoding syntax in a query string."""
    index = 0
    while (index := value.find("%", index)) >= 0:
        if index + 2 >= len(value) or value[index + 1] not in hexdigits or value[index + 2] not in hexdigits:
            return False
        index += 3
    return True


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
            not strict_text(self.connection_id)
            or not strict_text(self.subject_id)
            or not strict_text(self.route_name)
            or any(not strict_text(value) for value in self.credential_ids)
            or (self.session_id is not None and not strict_text(self.session_id))
        ):
            message = "WebSocket revocation binding is invalid"
            raise ValueError(message)
        object.__setattr__(self, "credential_ids", frozenset(self.credential_ids))


@runtime_checkable
class WebSocketRevocationSource(Protocol):
    """Event-driven, secret-free application hook for one binding's revocation."""

    async def wait(self, binding: WebSocketBinding) -> None:
        """Block without polling until the supplied connection binding is revoked.

        Args:
            binding: The secret-free identity and route binding to supervise.

        Returns:
            None only after a genuine revocation of binding.

        Raises:
            Exception: When supervision fails. The connection lifetime treats
                this as unavailable and closes the connection.
        """
        ...


@runtime_checkable
class AuthorizationSnapshotRefresher(Protocol[UserT]):
    """Application hook returning one detached immutable authorization snapshot."""

    async def refresh(
        self, *, principal: Principal[UserT], previous: AuthorizationSnapshot, route_name: str
    ) -> AuthorizationSnapshot:
        """Resolve and return a new detached authorization snapshot.

        Args:
            principal: The authenticated principal for the connection.
            previous: The prior immutable snapshot, which is never mutated.
            route_name: The bound application route name.

        Returns:
            A new detached AuthorizationSnapshot; any other runtime type
            is treated as unavailable by connection lifetime supervision.

        Raises:
            Exception: When refresh fails. Connection lifetime supervision
                treats this as unavailable and closes the connection.
        """
        ...


@dataclass(frozen=True, slots=True)
class WebSocketCloseCodes:
    """Map stable security outcomes to WebSocket close codes."""

    unauthenticated: int = DEFAULT_UNAUTHENTICATED_CLOSE
    unauthorized: int = DEFAULT_UNAUTHORIZED_CLOSE
    verification_unavailable: int = DEFAULT_UNAVAILABLE_CLOSE


@dataclass(frozen=True, slots=True)
class WebSocketSecurityConfig:
    """Configure WebSocket transport validation and optional lifetime hooks."""

    allowed_origins: frozenset[str] = frozenset()
    connect_token_store: WebSocketConnectTokenStore | None = field(default=None, repr=False)
    connect_token_ttl: timedelta = timedelta(seconds=30)
    maximum_connect_token_ttl: timedelta = MAXIMUM_CONNECT_TOKEN_TTL
    connect_token_query_parameter: str = "connect_token"
    current_security_epoch: Callable[[str], Awaitable[int | None]] | None = field(
        default=None, repr=False, compare=False
    )
    refresh_interval: timedelta | None = None
    snapshot_refresher: AuthorizationSnapshotRefresher[Any] | None = field(default=None, repr=False)
    revocation_source: WebSocketRevocationSource | None = field(default=None, repr=False)
    close_codes: WebSocketCloseCodes = WebSocketCloseCodes()
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc), repr=False, compare=False)
    sleeper: Callable[[float], Awaitable[None]] = field(default=sleep, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate and freeze security-sensitive transport settings."""
        object.__setattr__(self, "allowed_origins", normalize_allowed_origins(self.allowed_origins))
        _validate_connect_token_settings(self)
        _validate_refresh_settings(self)
        _validate_close_codes(self.close_codes)
        if not callable(self.clock) or not callable(self.sleeper):
            configuration_error("WebSocket clock and sleeper must be callable")


def _validate_connect_token_settings(config: WebSocketSecurityConfig) -> None:
    connect_token_store = cast("object | None", config.connect_token_store)
    if connect_token_store is not None and not isinstance(connect_token_store, WebSocketConnectTokenStore):
        configuration_error("WebSocket connect token store must implement atomic create and consume")
    if config.current_security_epoch is not None and not callable(config.current_security_epoch):
        configuration_error("WebSocket current security epoch must be an async callback")
    maximum_connect_token_ttl = duration(config.maximum_connect_token_ttl, "maximum connect token TTL")
    if maximum_connect_token_ttl > MAXIMUM_CONNECT_TOKEN_TTL:
        configuration_error("WebSocket maximum connect token TTL cannot exceed two minutes")
    connect_token_ttl = duration(config.connect_token_ttl, "connect token TTL")
    if connect_token_ttl > maximum_connect_token_ttl:
        configuration_error("WebSocket connect token TTL cannot exceed its configured maximum")

    query_name_value = cast("object", config.connect_token_query_parameter)
    if not isinstance(query_name_value, str) or query_name_value.__class__ is not str:
        configuration_error("WebSocket connect token query parameter must be text")
    query_name = query_name_value
    if (
        not query_name
        or query_name != query_name.strip()
        or not query_name.isascii()
        or any(character in query_name for character in "&#=;")
    ):
        configuration_error("WebSocket connect token query parameter must be a non-empty safe name")
    if query_name.casefold() in RESERVED_QUERY_PARAMETERS:
        configuration_error("WebSocket connect token query parameter uses a reserved credential name")


def _validate_refresh_settings(config: WebSocketSecurityConfig) -> None:
    refresher = cast("object | None", config.snapshot_refresher)
    revocation_source = cast("object | None", config.revocation_source)
    if refresher is not None and not isinstance(refresher, AuthorizationSnapshotRefresher):
        configuration_error("WebSocket snapshot refresher must define refresh")
    if revocation_source is not None and not isinstance(revocation_source, WebSocketRevocationSource):
        configuration_error("WebSocket revocation source must define wait")
    if config.refresh_interval is not None:
        duration(config.refresh_interval, "refresh interval")
        if refresher is None:
            configuration_error("WebSocket refresh interval requires a snapshot refresher")


def _validate_close_codes(value: object) -> None:
    if not isinstance(value, WebSocketCloseCodes) or value.__class__ is not WebSocketCloseCodes:
        configuration_error("WebSocket close codes must use WebSocketCloseCodes")
    codes = value
    values = (codes.unauthenticated, codes.unauthorized, codes.verification_unavailable)
    if (
        any(code.__class__ is not int for code in values)
        or not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.unauthenticated <= _PRIVATE_CLOSE_CODE_MAXIMUM
        or not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.unauthorized <= _PRIVATE_CLOSE_CODE_MAXIMUM
        or (
            codes.verification_unavailable != DEFAULT_UNAVAILABLE_CLOSE
            and not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.verification_unavailable <= _PRIVATE_CLOSE_CODE_MAXIMUM
        )
        or len(set(values)) != len(values)
        or codes.unauthenticated == DEFAULT_UNAUTHORIZED_CLOSE
        or codes.unauthorized == DEFAULT_UNAUTHENTICATED_CLOSE
        or codes.verification_unavailable in {DEFAULT_UNAUTHENTICATED_CLOSE, DEFAULT_UNAUTHORIZED_CLOSE}
    ):
        configuration_error("WebSocket close code assignments are invalid")


def extract_websocket_handshake(
    connection: ASGIConnection[Any, Any, Any, Any], *, config: WebSocketSecurityConfig, uses_cookie_credentials: bool
) -> WebSocketHandshake:
    """Extract and validate one WebSocket handshake without verifying credentials.

    The caller derives uses_cookie_credentials from the existing common
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


def _validated_request_origin(
    values: tuple[bytes, ...], *, config: WebSocketSecurityConfig, required: bool
) -> str | None:
    if not values:
        if required:
            transport_error(config.close_codes.unauthorized, "WebSocket Origin is required")
        return None
    if len(values) != 1:
        transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    try:
        value = values[0].decode("ascii")
    except (AttributeError, UnicodeDecodeError):
        transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    origin = canonical_origin(value, configuration=False, invalid_close_code=config.close_codes.unauthorized)
    if origin not in config.allowed_origins:
        transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    return origin


def _extract_connect_token(query_string: bytes, *, config: WebSocketSecurityConfig) -> str | None:
    if not query_string:
        return None
    try:
        encoded = query_string.decode("ascii")
        parameters = parse_qsl(encoded, keep_blank_values=True, encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        transport_error(config.close_codes.unauthenticated, "WebSocket query credentials are invalid")
    if not valid_percent_encoding(encoded):
        transport_error(config.close_codes.unauthenticated, "WebSocket query credentials are invalid")
    connect_tokens: list[str] = []
    for name, value in parameters:
        if name.casefold() in RESERVED_QUERY_PARAMETERS:
            transport_error(config.close_codes.unauthenticated, "Reusable URL credentials are forbidden")
        if name == config.connect_token_query_parameter:
            connect_tokens.append(value)
    if len(connect_tokens) > 1 or (connect_tokens and not connect_tokens[0]):
        transport_error(config.close_codes.unauthenticated, "WebSocket connect token is invalid")
    return connect_tokens[0] if connect_tokens else None


async def close_websocket(send: Send, *, code: int, reason: str) -> None:
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

    send_callable: Send = field(repr=False)
    state: Literal["pending", "accepted", "closing", "closed"] = field(default="pending", init=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    async def send(self, message: Message) -> None:
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


async def supervise_websocket_lifetime(
    handler: Callable[[], Awaitable[None]],
    *,
    expires_at: datetime | None,
    coordinator: WebSocketCloseCoordinator,
    unauthenticated_close_code: int,
    unauthorized_close_code: int = DEFAULT_UNAUTHORIZED_CLOSE,
    unavailable_close_code: int = DEFAULT_UNAVAILABLE_CLOSE,
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
    delay = (aware_utc(expires_at) - aware_utc(clock())).total_seconds() if expires_at is not None else None
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
        except Exception:
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
            except Exception:
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


def websocket_route_name(scope: Scope) -> str:
    """Extract route name for a WebSocket ASGI scope."""
    route_handler = cast("Mapping[str, object]", scope).get("route_handler")
    return cast("str | None", getattr(route_handler, "name", None)) or cast(
        "str", getattr(route_handler, "handler_name", "")
    )


def create_websocket_binding(
    *, principal: Principal[Any], context: SecurityContext, route_name: str
) -> WebSocketBinding:
    """Create a unique binding tracking an authenticated WebSocket session."""
    session_value = context.session.get("_litestar_security")
    session_mapping = cast("Mapping[str, object]", session_value) if isinstance(session_value, Mapping) else None
    session_id = cast("str | None", session_mapping.get("session_id")) if session_mapping is not None else None
    return WebSocketBinding(
        connection_id=token_urlsafe(16),
        subject_id=cast("str", principal.id),
        credential_ids=frozenset(f"{evidence.mechanism}:{evidence.slot}" for evidence in context.evidence),
        session_id=session_id,
        route_name=route_name,
    )


async def handle_websocket(
    *,
    app: ASGIApp,
    config: object,
    evaluator: object,
    scope: Scope,
    receive: Receive,
    send: Send,
    session: SessionHandle,
    plan: object,
) -> None:
    """Execute authenticated WebSocket handshake and supervise connection lifetime."""
    plan_obj = cast("Any", plan)
    if plan_obj.bypass_authentication:
        await app(scope, receive, send)
        return
    config_obj = cast("Any", config)
    evaluator_obj = cast("Any", evaluator)
    connection = ASGIConnection[Any, Principal[Any], SecurityContext, Any](scope=scope, receive=receive, send=send)
    extracted = evaluator_obj.extract(connection)
    auth_module = import_module("litestar_security.authentication")
    uses_cookie_credentials = any(
        isinstance(extraction, auth_module.PresentedCredential)
        and (mechanism := config_obj.registry.get_mechanism_for_slot(slot_name)) is not None
        and mechanism.session_capable
        for slot_name, extraction in extracted
    )
    ws_config = config_obj.websocket
    try:
        handshake = extract_websocket_handshake(
            connection, config=ws_config, uses_cookie_credentials=uses_cookie_credentials
        )
        if handshake.connect_token is not None:
            principal, context = await authenticate_connect_token(
                scope=scope,
                connection=connection,
                handshake=handshake,
                session=session,
                plan=plan_obj,
                extracted=extracted,
                evaluator=evaluator_obj,
                config=config_obj,
            )
            scope["user"] = principal
            scope["auth"] = context
        elif plan_obj.authenticate:
            principal, context = await evaluator_obj.evaluate(connection, session, plan=plan_obj, extracted=extracted)
            scope["user"] = principal
            scope["auth"] = context
    except WebSocketException as exc:
        reason = "origin_denied" if exc.code == ws_config.close_codes.unauthorized else "authentication_required"
        await close_websocket(send, code=exc.code, reason=reason)
        return
    except NotAuthorizedException:
        await close_websocket(send, code=ws_config.close_codes.unauthenticated, reason="authentication_required")
        return
    except (ServiceUnavailableException, WebSocketConnectTokenUnavailableError):
        await close_websocket(
            send, code=ws_config.close_codes.verification_unavailable, reason="verification_unavailable"
        )
        return
    coordinator = WebSocketCloseCoordinator(send)
    current_context = cast("SecurityContext", scope["auth"])
    route_name = websocket_route_name(scope)
    revocation_hook: Callable[[], Awaitable[None]] | None = None
    refresh_hook: Callable[[], Awaitable[None]] | None = None
    if ws_config.revocation_source is not None and cast("Principal[Any]", scope["user"]).is_authenticated:
        source = ws_config.revocation_source
        binding = create_websocket_binding(
            principal=cast("Principal[Any]", scope["user"]), context=current_context, route_name=route_name
        )

        async def wait_for_revocation() -> None:
            await source.wait(binding)

        revocation_hook = wait_for_revocation

    if ws_config.snapshot_refresher is not None:
        refresher = ws_config.snapshot_refresher

        async def refresh_authorization() -> None:
            nonlocal current_context
            principal = cast("Principal[Any]", scope["user"])
            snapshot = await refresher.refresh(
                principal=principal, previous=current_context.authorization, route_name=route_name
            )
            if not isinstance(snapshot, AuthorizationSnapshot):
                raise ServiceUnavailableException(detail="Authentication service unavailable")
            current_context = replace(
                current_context, authorization=resolve_authorization(snapshot, current_context.restrictions)
            )
            scope["auth"] = current_context
            route_handler = cast("Any", cast("Mapping[str, object]", scope).get("route_handler"))
            if route_handler.resolve_guards():
                await route_handler.authorize_connection(connection=connection)

        refresh_hook = refresh_authorization

    async def send_with_guard_mapping(message: Message) -> None:
        if (
            message["type"] == "websocket.close"
            and coordinator.state == "pending"
            and message.get("code") == _LITESTAR_INTERNAL_ERROR_CLOSE
            and message.get("reason") in {"Authentication required", "Permission denied"}
        ):
            message = {
                "type": "websocket.close",
                "code": ws_config.close_codes.unauthorized,
                "reason": "authorization_denied",
            }
        await coordinator.send(message)

    try:

        async def handle() -> None:
            await app(scope, receive, send_with_guard_mapping)

        await supervise_websocket_lifetime(
            handle,
            expires_at=current_context.expires_at,
            coordinator=coordinator,
            unauthenticated_close_code=ws_config.close_codes.unauthenticated,
            unauthorized_close_code=ws_config.close_codes.unauthorized,
            unavailable_close_code=ws_config.close_codes.verification_unavailable,
            revocation_wait=revocation_hook,
            refresh=refresh_hook,
            refresh_interval=ws_config.refresh_interval,
            clock=ws_config.clock,
            sleeper=ws_config.sleeper,
        )
    except (NotAuthorizedException, PermissionDeniedException):
        await coordinator.close(code=ws_config.close_codes.unauthorized, reason="authorization_denied")
