Runnable examples
=================

All modes use one environment-selected factory, ``examples.app:create_app``.
They are deterministic and secret-free by default:

.. code-block:: console

   LITESTAR_SECURITY_EXAMPLE=google-iap uv run litestar --app examples.app:create_app run
   LITESTAR_SECURITY_EXAMPLE=google-oauth uv run litestar --app examples.app:create_app run
   LITESTAR_SECURITY_EXAMPLE=github-oauth uv run litestar --app examples.app:create_app run
   LITESTAR_SECURITY_EXAMPLE=keycloak uv run litestar --app examples.app:create_app run
   LITESTAR_SECURITY_EXAMPLE=api-team-service uv run litestar --app examples.app:create_app run

The local modes generate ephemeral signing material and insecure loopback-only
cookies. Provider modes use stub transports and never fall back to placeholder
live credentials. Replace stores, secrets, key custody, HTTP transports,
delivery, egress policy, and deployment trust before production use.

See the repository ``examples/README.md`` for every mode, including local
transports, no-session, WebSocket, and custom-admin.
