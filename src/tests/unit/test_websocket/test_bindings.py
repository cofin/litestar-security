"""Unit tests for WebSocket handshake transport policy."""

from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import anyio
import anyio.lowlevel
import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.testing import InMemoryWebSocketRevocationSource
from litestar_security.websocket import WebSocketBinding, WebSocketSecurityConfig

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


def _connection(*, headers: tuple[tuple[bytes, bytes], ...] = (), query_string: bytes = b"") -> SimpleNamespace:
    return SimpleNamespace(scope={"headers": list(headers), "query_string": query_string})


@pytest.mark.parametrize("field_name", ["clock", "sleeper"])
def test_websocket_config_rejects_non_callable_runtime_hooks(field_name: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="clock and sleeper"):
        WebSocketSecurityConfig(**{field_name: None})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"connection_id": ""}, "binding"),
        ({"subject_id": " subject"}, "binding"),
        ({"route_name": "\n"}, "binding"),
        ({"credential_ids": frozenset({""})}, "binding"),
        ({"session_id": ""}, "binding"),
    ],
)
def test_websocket_binding_validates_and_freezes_identifiers(kwargs: dict[str, object], match: str) -> None:
    values = {
        "connection_id": "connection-1",
        "subject_id": "subject-1",
        "credential_ids": {"bearer:authorization"},  # type: ignore[dict-item]
        "session_id": "session-1",
        "route_name": "reports.socket",
        **kwargs,
    }
    if kwargs:
        with pytest.raises(ValueError, match=match):
            WebSocketBinding(**values)  # type: ignore[arg-type]
    else:  # pragma: no cover - parametrization always supplies one invalid field
        assert WebSocketBinding(**values).credential_ids == frozenset({"bearer:authorization"})  # type: ignore[arg-type]

    binding = WebSocketBinding(
        connection_id="connection-1",
        subject_id="subject-1",
        credential_ids={"bearer:authorization"},  # type: ignore[arg-type]
        session_id=None,
        route_name="reports.socket",
    )
    assert binding.credential_ids == frozenset({"bearer:authorization"})


async def test_in_memory_websocket_revocation_source_releases_only_the_matching_binding() -> None:
    source = InMemoryWebSocketRevocationSource()
    first = WebSocketBinding(
        connection_id="connection-1",
        subject_id="subject-1",
        credential_ids=frozenset({"bearer:authorization"}),
        session_id="session-1",
        route_name="reports.socket",
    )
    second = replace(first, connection_id="connection-2")
    released: list[WebSocketBinding] = []

    async def wait_for_revocation(binding: WebSocketBinding) -> None:
        await source.wait(binding)
        released.append(binding)

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(wait_for_revocation, first)
        task_group.start_soon(wait_for_revocation, second)
        await anyio.lowlevel.checkpoint()
        assert released == []

        source.revoke(first)
        await anyio.lowlevel.checkpoint()

        assert released == [first]
        task_group.cancel_scope.cancel()
