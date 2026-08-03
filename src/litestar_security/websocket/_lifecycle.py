"""Close-code coordination and the supervised lifetime of a connection."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import TYPE_CHECKING, Literal, TypeVar, cast

from anyio import Lock, create_task_group, sleep
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException, ServiceUnavailableException

if TYPE_CHECKING:
    from litestar.types import Message, Send


from litestar_security.websocket._internal import DEFAULT_UNAUTHORIZED_CLOSE, DEFAULT_UNAVAILABLE_CLOSE, aware_utc

__all__ = ("WebSocketCloseCoordinator", "close_websocket", "supervise_websocket_lifetime")

UserT = TypeVar("UserT")


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
