"""Close-code coordination and the supervised lifetime of a connection."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from json import dumps
from typing import TYPE_CHECKING, Literal, TypeVar, cast

from anyio import Lock, create_task_group, sleep
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException, ServiceUnavailableException

if TYPE_CHECKING:
    from litestar.types import Message, Send


from litestar_security.websocket._internal import DEFAULT_UNAUTHORIZED_CLOSE, DEFAULT_UNAVAILABLE_CLOSE, aware_utc

__all__ = ("WebSocketCloseCoordinator", "close_websocket", "supervise_websocket_lifetime")

UserT = TypeVar("UserT")
_INVALID_POLICY_FINGERPRINT = "WebSocket policy fingerprint input is invalid"


def websocket_policy_fingerprint(plan: object) -> str:
    """Return a stable process-independent fingerprint for one compiled plan.

    Args:
        plan: The frozen compiled security plan.

    Returns:
        A hexadecimal SHA-256 fingerprint.
    """
    authenticate = getattr(plan, "authenticate", False)
    required = getattr(plan, "required", False)
    allow_anonymous = getattr(plan, "allow_anonymous", False)
    participant_names = getattr(plan, "participant_names", None)
    alternatives = getattr(plan, "alternatives", ())
    if (
        authenticate.__class__ is not bool
        or required.__class__ is not bool
        or allow_anonymous.__class__ is not bool
        or (participant_names is not None and participant_names.__class__ is not frozenset)
        or alternatives.__class__ is not tuple
    ):
        raise ValueError(_INVALID_POLICY_FINGERPRINT)
    participant_values = cast("frozenset[object]", participant_names or frozenset())
    if any(value.__class__ is not str or not value for value in participant_values):
        raise ValueError(_INVALID_POLICY_FINGERPRINT)
    serialized_participants = sorted(cast("frozenset[str]", participant_values))
    serialized_alternatives: list[list[dict[str, object]]] = []
    for alternative in cast("tuple[object, ...]", alternatives):
        if alternative.__class__ is not tuple:
            raise ValueError(_INVALID_POLICY_FINGERPRINT)
        serialized_alternative: list[dict[str, object]] = []
        for requirement in cast("tuple[object, ...]", alternative):
            name = cast("object", getattr(requirement, "name", None))
            scopes = cast("object", getattr(requirement, "scopes", None))
            if (
                name.__class__ is not str
                or not name
                or scopes.__class__ is not tuple
                or any(scope.__class__ is not str or not scope for scope in cast("tuple[object, ...]", scopes))
            ):
                raise ValueError(_INVALID_POLICY_FINGERPRINT)
            serialized_alternative.append({
                "name": cast("str", name),  # type: ignore[redundant-cast]  # pyright retains object narrowing
                "scopes": list(cast("tuple[str, ...]", scopes)),
            })
        serialized_alternatives.append(serialized_alternative)
    payload = dumps(
        {
            "allow_anonymous": allow_anonymous,
            "alternatives": serialized_alternatives,
            "authenticate": authenticate,
            "participant_names": serialized_participants,
            "required": required,
            "v": 1,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
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
