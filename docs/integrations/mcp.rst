Model Context Protocol (MCP) and A2A
========================================

Litestar Security authenticates native Litestar MCP endpoints through route
options and authorizes tool execution through Litestar guards. This guide is
verified against the ``litestar-mcp`` 0.14.0 source candidate at commit
``93d6b26f7c123acbc32adef0049deb9f1bdc7fcb`` and A2A SDK 1.1.2. The integration
tests install that Git revision; this is not a claim that a matching PyPI release
is available. See the `verified MCP source`_.

.. _verified MCP source: https://github.com/cofin/litestar-mcp/tree/93d6b26f7c123acbc32adef0049deb9f1bdc7fcb

Authenticate the MCP endpoint
----------------------------------------

Configure an authentication mechanism before referencing its name in a route
policy. This factory accepts your API-key store and identity resolver, and a
pepper loaded from your secret configuration. The identity resolver loads the
subject's current identity and returns its ``Principal``. The authorization
resolver supplies an ``AuthorizationSnapshot`` containing the roles and scopes
your guards require. API keys use the ``X-API-Key`` header by default.

.. code-block:: python

   from litestar import Litestar
   from litestar_mcp import LitestarMCP, MCPConfig
   from litestar_security import AUTH_POLICY_OPT_KEY, SecurityConfig, SecurityPlugin, required
   from litestar_security.authentication import AuthorizationResolver, IdentityResolver
   from litestar_security.providers.api_key import APIKeyClaims, APIKeyConfig, APIKeyStore

   def create_app(
       store: APIKeyStore,
       resolver: IdentityResolver[APIKeyClaims, object],
       authorization_resolver: AuthorizationResolver[object],
       pepper: bytes,
   ) -> Litestar:
       security = SecurityPlugin(
           SecurityConfig(
               api_key=APIKeyConfig(store=store, pepper=pepper, identity_resolver=resolver),
               authorization_resolver=authorization_resolver,
           )
       )
       mcp = LitestarMCP(
           MCPConfig(
               base_path="/mcp",
               route_opt={AUTH_POLICY_OPT_KEY: required("api-key")},
           )
       )
       return Litestar(plugins=[security, mcp])

Missing or invalid credentials are rejected before MCP dispatch. Add a guard
such as ``guards=[requires_role("engineer")]`` to ``MCPConfig`` when every
request to the transport requires that role; import ``requires_role`` from
``litestar_security``. A failed transport guard produces an HTTP 403 response.

Use an explicit policy so the endpoint's requirement remains clear as other
mechanisms are added. Without an explicit policy, default-participating
mechanisms determine authentication. A configured API-key mechanism participates
by default, so ``require_default=False`` does not make that application public.
With no default participants, ``require_default=False`` permits implicit public
routes; ``require_default=True`` rejects that configuration at startup.

The pinned MCP source implements stateless ``server/discover``, not an
``initialize`` handshake. Raw HTTP clients must send the protocol metadata and
headers required by that source's ``2026-07-28`` protocol. Authentication does
not replace protocol validation; use a compatible client or the bridge below.

Authorize individual tools
---------------------------

Attach guards to the Litestar handler decorator. ``mcp_tool(scopes=...)``
advertises scope metadata; it does not enforce authorization. Use
``requires_scope`` for that check, alongside any role requirement.

.. code-block:: python

   from typing import Any

   from litestar import Request, post
   from litestar_mcp import mcp_tool
   from litestar_security import requires_role, requires_scope

   @post("/deploy", guards=[requires_role("admin"), requires_scope("services:write")])
   @mcp_tool(name="deploy_service", scopes=["services:write"])
   async def deploy_service(request: Request[Any, Any, Any]) -> dict[str, str]:
       return {"requested_by": request.user.id}

Register ``deploy_service`` in the application's ``route_handlers``. Replace the
example response with your deployment operation. The tool request retains the
authenticated caller's ASGI scope, and ``request.user`` is the resolved
``Principal``. Guards run before the handler body. A failed tool guard produces
an MCP result with ``isError=True`` inside an HTTP 200 response; the handler does
not execute. This differs from a guard rejecting the transport itself.

Protect A2A operations
----------------------

Install the MCP package's ``a2a`` extra to use its optional A2A integration.
Build the card with the A2A SDK protobuf types, and pass the card, request
handler, and configuration separately to ``LitestarA2A``. The factory below
accepts your SDK ``AgentExecutor`` implementation. Use it alongside the
``SecurityPlugin`` configured above.

.. code-block:: python

   from a2a.server.agent_execution import AgentExecutor
   from a2a.server.request_handlers import DefaultRequestHandler
   from a2a.server.tasks import InMemoryTaskStore
   from a2a.types import AgentCard, AgentInterface
   from litestar_mcp.a2a import A2AConfig, LitestarA2A
   from litestar_security import AUTH_POLICY_OPT_KEY, required, requires_scope

   def create_a2a(executor: AgentExecutor) -> LitestarA2A:
       card = AgentCard(
           name="Research agent",
           description="Answers research requests",
           version="1.0.0",
           supported_interfaces=[
               AgentInterface(
                   url="https://agent.example.com/a2a",
                   protocol_binding="JSONRPC",
                   protocol_version="1.0",
               )
           ],
       )
       handler = DefaultRequestHandler(executor, InMemoryTaskStore(), card)
       return LitestarA2A(
           card,
           handler,
           A2AConfig(
               path="/a2a",
               route_opt={AUTH_POLICY_OPT_KEY: required("api-key")},
               guards=[requires_scope("a2a:delegate")],
           ),
       )

Add the returned plugin to the application's ``plugins`` list. The example
task store is process-local; select an SDK-compatible durable store when tasks
must survive restarts. Clients targeting this protocol send
``A2A-Version: 1.0`` in addition to their authentication header.

The default discovery card at ``/.well-known/agent-card.json`` is registered
separately with authentication and CSRF exclusions. ``A2AConfig`` route options
and guards apply to the operational endpoint, not the card. Anonymous card
discovery and protected task access are verified with the native plugins.
Application-level guards still apply according to Litestar's normal guard
inheritance; the card's authentication exclusion does not bypass those guards.

Authenticate a stdio bridge
----------------------------------------

The bridge is an async function whose first argument is the endpoint URL. This
example supplies the same API-key header expected by the server. The provider
is called for each request, allowing an application to substitute its own
credential refresh mechanism.

.. code-block:: python

   import os
   from functools import partial

   import anyio
   from litestar_mcp.mcp.bridge import run_stdio_streamable_http_bridge

   def provider() -> str:
       return os.environ["MCP_API_KEY"]

   if __name__ == "__main__":
       raise SystemExit(
           anyio.run(
               partial(
                   run_stdio_streamable_http_bridge,
                   "https://api.example.com/mcp",
                   token_provider=provider,
                   header_name="X-API-Key",
                   token_prefix="",
               )
           )
       )

Inside an existing async application, await the bridge directly. For a bearer
mechanism configured on the server, the bridge's default header and prefix are
``Authorization`` and ``Bearer ``. Static headers can instead be supplied with
``headers={...}``.
