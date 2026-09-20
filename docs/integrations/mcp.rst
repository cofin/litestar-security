Model Context Protocol (MCP) & A2A
===================================

`Litestar Security` natively secures `Litestar MCP`_ (v0.14.0+) endpoints and
tool execution without bespoke authorization wrappers or legacy authentication
classes.

.. _Litestar MCP: https://github.com/litestar-org/litestar-mcp

Architecture Overview
---------------------

In `litestar-mcp` v0.14.0+, custom authentication backends were deprecated and
removed in favor of first-class Litestar route options and guards. The MCP and
A2A (Agent-to-Agent) endpoints are standard Litestar routers:

* **Endpoint Security**: The MCP router at ``/mcp`` and A2A router at ``/a2a``
  receive standard Litestar route options via ``route_opt`` and guards via
  ``guards``.
* **Preserved Request Scope**: During tool execution (``execute_tool``), the
  caller's original ASGI scope is preserved (including ``scope["user"]``,
  ``scope["auth"]``, ``scope["session"]``, and ``scope["state"]``).
* **Tool Guard Evaluation**: Guards attached to individual MCP tool handlers
  are evaluated against a synthesized request carrying the caller's
  authenticated context before the tool body executes.
* **Agent Card Exemption**: In A2A deployments, the agent discovery card
  (``/.well-known/agent-card.json``) is automatically exempted from
  authentication and CSRF checks by ``LitestarA2A``, ensuring open discovery
  while strictly guarding operational agent task endpoints.

Securing the MCP Endpoint
-------------------------

To protect the MCP endpoint, pass the desired authentication policy in
``route_opt`` and any required guards in ``guards`` when initializing
``MCPConfig``:

.. code-block:: python

   from litestar import Litestar
   from litestar_mcp import LitestarMCP, MCPConfig
   from litestar_security import (
       AUTH_POLICY_OPT_KEY,
       SecurityConfig,
       SecurityPlugin,
       required,
       requires_role,
   )

   mcp_config = MCPConfig(
       path="/mcp",
       # Enforce authentication on all MCP routes (Streamable HTTP / SSE)
       route_opt={AUTH_POLICY_OPT_KEY: required("api-key", "bearer")},
       # Enforce organization or role access at the router boundary
       guards=[requires_role("engineer")],
   )

   security_plugin = SecurityPlugin(
       SecurityConfig(
           # Standard security configuration...
       )
   )

   app = Litestar(
       plugins=[security_plugin, LitestarMCP(mcp_config)],
   )

Tool-Level Authorization
------------------------

In addition to securing the entire ``/mcp`` endpoint, individual MCP tools can
enforce granular permissions and role checks. When a client invokes a tool via
``tools/call``, ``litestar-mcp`` evaluates the tool's configured guards against
the authenticated request scope:

.. code-block:: python

   from typing import Any
   from litestar import Request
   from litestar_mcp import mcp_tool
   from litestar_security import requires_scope, requires_role

   @mcp_tool(
       name="deploy_service",
       description="Deploy a production service",
       guards=[requires_role("admin"), requires_scope("services:write")],
   )
   async def deploy_service(service_id: str, request: Request[Any, Any, Any]) -> dict[str, str]:
       # Caller identity is readily available on the request
       user = request.user
       return {
           "status": "deployed",
           "service_id": service_id,
           "initiated_by": getattr(user, "email", str(user)),
       }

If a caller lacks the required permissions, the guard raises
``PermissionDeniedException`` (HTTP 403), which ``litestar-mcp`` converts into
a standard MCP tool error response without disclosing unauthorized internal state.

Securing Agent-to-Agent (A2A) Protocols
---------------------------------------

The Agent-to-Agent protocol enables autonomous multi-agent discovery and task
delegation. Because agents discover capabilities by reading the public Agent Card
(RFC 8615 well-known URI), the discovery endpoint must remain accessible while
task operations require strict workload authentication.

``LitestarA2A`` handles this distinction automatically:

1. The root A2A router applies ``route_opt`` and ``guards`` to task management,
   message exchange, and streaming endpoints.
2. The agent card route (``/.well-known/agent-card.json``) is mounted with
   ``opt={"exclude_from_auth": True, "exclude_from_csrf": True}``, ensuring
   it remains publicly discoverable by peer agents.

.. code-block:: python

   from litestar import Litestar
   from litestar_mcp.a2a import LitestarA2A, A2AConfig, AgentCard
   from litestar_security import (
       AUTH_POLICY_OPT_KEY,
       SecurityConfig,
       SecurityPlugin,
       required,
       requires_scope,
   )

   card = AgentCard(
       name="ResearchAgent",
       description="Conducts automated literature and code reviews",
       url="https://agent.example.com",
       version="1.0.0",
   )

   a2a_config = A2AConfig(
       path="/a2a",
       card=card,
       # Protect task dispatch and execution
       route_opt={AUTH_POLICY_OPT_KEY: required("workload-jwt", "api-key")},
       guards=[requires_scope("a2a:delegate")],
   )

   app = Litestar(
       plugins=[SecurityPlugin(SecurityConfig(...)), LitestarA2A(a2a_config)],
   )

Stdio Bridge Authentication
---------------------------

When running CLI-based local agent bridges (such as the stdio-to-streamable-HTTP
bridge in ``litestar_mcp.mcp.bridge``), client processes authenticate by passing
an API key or bearer token via environment variables or CLI flags into the
underlying HTTP client transport:

.. code-block:: python

   from litestar_mcp.mcp.bridge import run_stdio_streamable_http_bridge

   # Connect stdio to authenticated remote Litestar MCP server
   run_stdio_streamable_http_bridge(
       url="https://api.example.com/mcp",
       headers={"Authorization": f"Bearer {auth_token}"},
   )
