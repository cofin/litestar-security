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

One-time WebSocket tickets are short-lived, HMAC-digested, route/origin/policy
bound, and atomically consumed. They are useful when a browser cannot present
the normal credential transport. CSP ``connect-src`` is complementary browser
hardening, not server-side authentication or Origin validation.

Run the tested mode:

.. code-block:: console

   LITESTAR_SECURITY_EXAMPLE=websocket uv run litestar --app examples.app:create_app run
