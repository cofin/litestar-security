"""Close-code coordination and the supervised lifetime of a connection."""

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from importlib import import_module
from secrets import token_urlsafe
from typing import Any, Literal, TypeVar, cast

from anyio import Lock, create_task_group, sleep
from litestar.connection import ASGIConnection
from litestar.exceptions import (
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
from litestar_security.websocket._bindings import WebSocketBinding
from litestar_security.websocket._connect_tokens import (
    WebSocketConnectTokenUnavailableError,
    authenticate_connect_token,
)
from litestar_security.websocket._handshake import extract_websocket_handshake
from litestar_security.websocket._internal import (
    DEFAULT_UNAUTHORIZED_CLOSE,
    DEFAULT_UNAVAILABLE_CLOSE,
    aware_utc,
    websocket_policy_fingerprint,
)

__all__ = (
    "WebSocketCloseCoordinator",
    "close_websocket",
    "create_websocket_binding",
    "handle_websocket",
    "supervise_websocket_lifetime",
    "websocket_policy_fingerprint",
    "websocket_route_name",
)

UserT = TypeVar("UserT")
_LITESTAR_INTERNAL_ERROR_CLOSE = 4500


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


async def handle_websocket(  # noqa: C901, PLR0913, PLR0915
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
