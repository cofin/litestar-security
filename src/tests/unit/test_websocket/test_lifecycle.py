"""Unit tests for WebSocket handshake transport policy."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import anyio
import anyio.lowlevel
import pytest
from litestar.exceptions import PermissionDeniedException, ServiceUnavailableException

from litestar_security.websocket import WebSocketCloseCoordinator, supervise_websocket_lifetime

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


def _connection(*, headers: tuple[tuple[bytes, bytes], ...] = (), query_string: bytes = b"") -> SimpleNamespace:
    return SimpleNamespace(scope={"headers": list(headers), "query_string": query_string})


async def test_websocket_expiry_closes_once_and_cancels_idle_handler() -> None:
    messages: list[dict[str, object]] = []
    handler_cleaned = anyio.Event()

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        try:
            await anyio.sleep_forever()
        finally:
            handler_cleaned.set()

    async def expire_immediately(_delay: float) -> None:
        return None

    coordinator = WebSocketCloseCoordinator(send)  # type: ignore[arg-type]
    await supervise_websocket_lifetime(
        handler,
        expires_at=_NOW + timedelta(minutes=1),
        coordinator=coordinator,
        unauthenticated_close_code=4401,
        clock=lambda: _NOW,
        sleeper=expire_immediately,
    )

    assert messages == [{"type": "websocket.close", "code": 4401, "reason": "credential_expired"}]
    assert handler_cleaned.is_set()
    assert coordinator.state == "closed"


async def test_websocket_handler_return_cancels_expiry_task_without_close() -> None:
    messages: list[dict[str, object]] = []
    sleeper_cleaned = anyio.Event()

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        return None

    async def wait_forever(_delay: float) -> None:
        try:
            await anyio.sleep_forever()
        finally:
            sleeper_cleaned.set()

    await supervise_websocket_lifetime(
        handler,
        expires_at=_NOW + timedelta(minutes=1),
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        clock=lambda: _NOW,
        sleeper=wait_forever,
    )

    assert messages == []
    assert sleeper_cleaned.is_set()


async def test_websocket_simultaneous_terminal_causes_emit_one_close() -> None:
    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    coordinator = WebSocketCloseCoordinator(send)  # type: ignore[arg-type]

    async def close(reason: str) -> None:
        await coordinator.close(code=4401, reason=reason)

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(close, "credential_expired")
        task_group.start_soon(close, "credential_revoked")

    assert len(messages) == 1
    assert messages[0]["reason"] in {"credential_expired", "credential_revoked"}


async def test_websocket_coordinator_ignores_events_after_close_and_duplicate_accept() -> None:
    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    coordinator = WebSocketCloseCoordinator(send)  # type: ignore[arg-type]
    await coordinator.send({"type": "websocket.accept"})  # type: ignore[arg-type]
    await coordinator.send({"type": "websocket.accept"})  # type: ignore[arg-type]
    await coordinator.send({"type": "websocket.send", "text": "open"})  # type: ignore[arg-type]
    await coordinator.send({"type": "websocket.close", "code": 4401})  # type: ignore[arg-type]
    await coordinator.send({"type": "websocket.send", "text": "late"})  # type: ignore[arg-type]

    assert messages == [
        {"type": "websocket.accept"},
        {"type": "websocket.send", "text": "open"},
        {"type": "websocket.close", "code": 4401},
    ]


async def test_websocket_supervisor_default_path_creates_no_tasks() -> None:
    called = False

    async def handler() -> None:
        nonlocal called
        called = True

    async def send(_message: dict[str, object]) -> None:
        return None

    await supervise_websocket_lifetime(
        handler,
        expires_at=None,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
    )

    assert called


async def test_websocket_already_expired_closes_without_starting_handler() -> None:
    messages: list[dict[str, object]] = []
    handler_called = False

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        nonlocal handler_called
        handler_called = True

    await supervise_websocket_lifetime(
        handler,
        expires_at=_NOW,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        clock=lambda: _NOW,
    )

    assert messages == [{"type": "websocket.close", "code": 4401, "reason": "credential_expired"}]
    assert handler_called is False


async def test_websocket_revocation_event_closes_and_cancels_handler() -> None:
    messages: list[dict[str, object]] = []
    cleaned = anyio.Event()

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        try:
            await anyio.sleep_forever()
        finally:
            cleaned.set()

    async def revoked() -> None:
        return None

    await supervise_websocket_lifetime(
        handler,
        expires_at=None,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        revocation_wait=revoked,
    )

    assert messages == [{"type": "websocket.close", "code": 4401, "reason": "credential_revoked"}]
    assert cleaned.is_set()


async def test_websocket_revocation_outage_closes_as_unavailable() -> None:
    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        await anyio.sleep_forever()

    async def unavailable() -> None:
        raise RuntimeError

    await supervise_websocket_lifetime(
        handler,
        expires_at=None,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        revocation_wait=unavailable,
    )

    assert messages == [{"type": "websocket.close", "code": 1013, "reason": "verification_unavailable"}]


@pytest.mark.parametrize(
    ("error", "code", "reason"),
    [
        (PermissionDeniedException(), 4403, "authorization_denied"),
        (ServiceUnavailableException(), 1013, "verification_unavailable"),
        (RuntimeError(), 1013, "verification_unavailable"),
    ],
)
async def test_websocket_refresh_failure_has_stable_close(error: Exception, code: int, reason: str) -> None:
    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        await anyio.sleep_forever()

    async def refresh() -> None:
        raise error

    async def refresh_now(_delay: float) -> None:
        return None

    await supervise_websocket_lifetime(
        handler,
        expires_at=None,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        revocation_wait=None,
        refresh=refresh,
        refresh_interval=timedelta(seconds=1),
        sleeper=refresh_now,
    )

    assert messages == [{"type": "websocket.close", "code": code, "reason": reason}]


async def test_websocket_refresh_completes_short_resource_scope_and_preserves_access() -> None:
    messages: list[dict[str, object]] = []
    refreshed = anyio.Event()
    resource_open = False
    sleep_calls = 0

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        await refreshed.wait()

    async def refresh() -> None:
        nonlocal resource_open
        resource_open = True
        try:
            await anyio.lowlevel.checkpoint()
        finally:
            resource_open = False
        refreshed.set()

    async def interval(_delay: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls > 1:
            await anyio.sleep_forever()

    await supervise_websocket_lifetime(
        handler,
        expires_at=None,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        refresh=refresh,
        refresh_interval=timedelta(seconds=1),
        sleeper=interval,
    )

    assert messages == []
    assert refreshed.is_set()
    assert resource_open is False
