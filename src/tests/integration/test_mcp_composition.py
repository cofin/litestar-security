"""Security policy and principal propagation through native MCP and A2A plugins."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

import pytest
from litestar import Litestar, Request, get
from litestar.testing import AsyncTestClient

from litestar_security import (
    AUTH_POLICY_OPT_KEY,
    SecurityConfig,
    SecurityPlugin,
    required,
    requires_role,
    requires_scope,
)
from litestar_security.context import Principal
from litestar_security.providers.api_key import APIKeyCodec, APIKeyConfig
from tests.fixtures.collaborators import RecordingAPIKeyResolver, build_api_key_store

pytest.importorskip("litestar_mcp")
pytest.importorskip("a2a")

from a2a.server.agent_execution import AgentExecutor
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCard, AgentInterface
from litestar_mcp import LitestarMCP, MCPConfig
from litestar_mcp.a2a import A2AConfig, LitestarA2A

if TYPE_CHECKING:
    from httpx import Response

PROTOCOL_VERSION = "2026-07-28"


@pytest.fixture
async def app_builder() -> _AppBuilder:
    store = build_api_key_store()
    config = APIKeyConfig(store=store, pepper=b"p" * 32, identity_resolver=RecordingAPIKeyResolver())
    issued, record = APIKeyCodec(pepper=config.pepper).issue(subject_id="mcp-user")
    await store.create(record)
    return _AppBuilder(config, issued.value)


@pytest.mark.parametrize(
    ("require_default", "explicit_policy", "credential", "role_guard", "expected_status"),
    [
        pytest.param(True, False, None, False, 401, id="anonymous_required_default"),
        pytest.param(False, False, None, False, 401, id="default_participant_stays_required"),
        pytest.param(True, True, "valid", False, 200, id="explicit_policy_valid_key_discovery"),
        pytest.param(True, True, "invalid", False, 401, id="explicit_policy_invalid_key"),
        pytest.param(True, True, "valid", True, 403, id="router_guard_missing_engineer_role"),
        pytest.param(False, True, None, False, 401, id="explicit_policy_require_default_false"),
    ],
)
async def test_mcp_transport_policy(  # noqa: PLR0913 - explicit policy outcome matrix
    app_builder: _AppBuilder,
    *,
    require_default: bool,
    explicit_policy: bool,
    credential: str | None,
    role_guard: bool,
    expected_status: int,
) -> None:
    config = MCPConfig(
        route_opt={AUTH_POLICY_OPT_KEY: required("api-key")} if explicit_policy else None,
        guards=[requires_role("engineer")] if role_guard else None,
    )
    key = app_builder.key if credential == "valid" else credential
    async with AsyncTestClient(app_builder.build(config, require_default=require_default)) as client:
        response = await _mcp_request(client, "server/discover", key=key)

    assert response.status_code == expected_status
    if expected_status == 200:
        result = response.json()["result"]
        assert result["supportedVersions"] == [PROTOCOL_VERSION]
        assert "tools" in result["capabilities"]


async def test_mcp_without_default_mechanisms_is_public(app_builder: _AppBuilder) -> None:
    async with AsyncTestClient(replace(app_builder, api_key=None).build(require_default=False)) as client:
        response = await _mcp_request(client, "server/discover")
    assert response.status_code == 200
    assert response.json()["result"]["supportedVersions"] == [PROTOCOL_VERSION]


@pytest.mark.parametrize("guarded", [True, False], ids=["tool_guard_missing_scope", "tool_receives_principal"])
async def test_mcp_tool_policy_and_principal(app_builder: _AppBuilder, *, guarded: bool) -> None:
    seen: list[Principal[str]] = []

    @get("/identity", mcp_tool="identity", guards=[requires_scope("x")] if guarded else [])
    async def identity(request: Request[Any, Any, Any]) -> dict[str, str]:
        seen.append(request.user)
        return {"id": request.user.id}

    config = MCPConfig(route_opt={AUTH_POLICY_OPT_KEY: required("api-key")})
    async with AsyncTestClient(app_builder.build(config, handlers=(identity,))) as client:
        response = await _mcp_request(client, "tools/call", key=app_builder.key, name="identity")

    assert response.status_code == 200
    result = response.json()["result"]
    if guarded:
        assert result["isError"] is True
        assert seen == []
    else:
        assert result.get("isError", False) is False
        assert seen == [Principal(id="mcp-user", user="mcp-user")]
        assert json.loads(result["content"][0]["text"]) == {"id": "mcp-user"}


@pytest.mark.parametrize("card", [True, False], ids=["a2a_card_anonymous", "a2a_task_anonymous"])
async def test_a2a_anonymous_policy(app_builder: _AppBuilder, *, card: bool) -> None:
    async with AsyncTestClient(app_builder.build(a2a=True)) as client:
        response = (
            await client.get("/.well-known/agent-card.json")
            if card
            else await client.post(
                "/a2a",
                json={"jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": {"id": "missing"}},
                headers={"A2A-Version": "1.0"},
            )
        )
    assert response.status_code == (200 if card else 401)
    if card:
        assert response.json()["name"] == "Composition test agent"


async def test_a2a_auth_policy_startup(app_builder: _AppBuilder) -> None:
    async with AsyncTestClient(app_builder.build(a2a=True)) as client:
        response = await client.post(
            "/a2a",
            json={"jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": {"id": "missing"}},
            headers={"X-API-Key": app_builder.key, "A2A-Version": "1.0"},
        )
    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32001


class _UnusedExecutor(AgentExecutor):
    async def execute(self, context: Any, event_queue: Any) -> None:
        del context, event_queue
        pytest.fail("Discovery and task reads must not execute an agent")

    async def cancel(self, context: Any, event_queue: Any) -> None:
        del context, event_queue
        pytest.fail("Discovery and task reads must not cancel an agent")


@dataclass(frozen=True, slots=True)
class _AppBuilder:
    api_key: APIKeyConfig | None
    key: str = field(repr=False)

    def build(
        self,
        config: MCPConfig | None = None,
        *,
        require_default: bool = True,
        handlers: tuple[Any, ...] = (),
        a2a: bool = False,
    ) -> Litestar:
        plugins: list[Any] = [
            SecurityPlugin(SecurityConfig(require_default=require_default, api_key=self.api_key)),
            LitestarMCP(config or MCPConfig()),
        ]
        if a2a:
            card = AgentCard(
                name="Composition test agent",
                version="1.0.0",
                supported_interfaces=[
                    AgentInterface(url="https://example.com/a2a", protocol_binding="JSONRPC", protocol_version="1.0")
                ],
            )
            plugins.append(
                LitestarA2A(
                    card,
                    DefaultRequestHandler(_UnusedExecutor(), InMemoryTaskStore(), card),
                    A2AConfig(route_opt={AUTH_POLICY_OPT_KEY: required("api-key")}),
                )
            )
        return Litestar(route_handlers=list(handlers), plugins=plugins)


async def _mcp_request(
    client: AsyncTestClient[Litestar], method: str, *, key: str | None = None, name: str | None = None
) -> Response:
    params: dict[str, Any] = {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "Mcp-Method": method,
    }
    if key is not None:
        headers["X-API-Key"] = key
    if name is not None:
        params.update(name=name, arguments={})
        headers["Mcp-Name"] = name
    return await client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, headers=headers
    )
