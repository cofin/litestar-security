WebSocket security
==================

WebSocket authentication uses the same principal, context, policy, and guards
as HTTP. Browser cookie authentication additionally requires an exact allowed
``Origin``. Non-browser clients may use the ``Authorization`` header. Bearer
credentials in query strings are prohibited.

Authentication, authorization, and verification availability map to distinct
close codes. Long-lived sockets may use a bounded detached authorization
snapshot refresher and an application revocation event source. The runtime does
not retain a request database transaction for the socket lifetime.

One-time WebSocket connect tokens are short-lived, HMAC-digested,
route/origin/policy bound, and atomically consumed. They are useful when a
browser cannot present the normal credential transport. This is the pattern
often called a WebSocket *ticket*; it is named for what it authorizes here,
because the library already issues access and refresh tokens to users and
"ticket" gave no clue which one a value was. CSP ``connect-src`` is
complementary browser hardening, not server-side authentication or Origin
validation.

Configure ``SecurityConfig.websocket.connect_token_store`` to let the plugin
inject a ``WebSocketConnectTokenIssuer`` into an authenticated mint endpoint.
Use the registered WebSocket handler name and the exact browser Origin that
will open the connection:

.. code-block:: python

   from typing import Any

   from litestar import post
   from litestar.di import NamedDependency

   from litestar_security import (
       Principal,
       SecurityContext,
       WebSocketConnectTokenIssuer,
       required,
   )


   @post("/connect-tokens", auth=required())
   async def mint_connect_token(
       principal: NamedDependency[Principal[Any]],
       security_context: NamedDependency[SecurityContext],
       security_epoch: NamedDependency[int],
       websocket_connect_tokens: NamedDependency[WebSocketConnectTokenIssuer],
   ) -> dict[str, str]:
       issued = await websocket_connect_tokens.issue(
           "reports.socket",
           principal=principal,
           context=security_context,
           origin="https://browser.example",
           security_epoch=security_epoch,
       )
       return {"connect_token": issued.value}

The application-owned ``security_epoch`` dependency must return the account's
current authoritative epoch; password resets and other security changes then
invalidate outstanding connect tokens. Local-auth configuration automatically
wires its account store for handshake-time epoch revalidation.

The client supplies ``connect_token`` to the WebSocket handshake and presents
that exact Origin. ``issue_websocket_connect_token()`` and
``WebSocketConnectTokenService`` remain available when an application needs
manual control of the connect-token bindings or storage service.

Run the tested mode:

.. code-block:: console

   LITESTAR_SECURITY_EXAMPLE=websocket uv run litestar --app examples.app:create_app run
