Getting started
===============

Install Litestar Security:

.. code-block:: console

   pip install litestar-security

Add the plugin and mark public routes explicitly:

.. code-block:: python

   from litestar import Litestar, get

   from litestar_security import (
       SecurityConfig,
       SecurityContextDependency,
       SecurityPlugin,
       public,
       security,
   )


   @get("/", sync_to_thread=False, **security(public()))
   def index(security_context: SecurityContextDependency) -> dict[str, bool]:
       return {"authenticated": bool(security_context.evidence)}


   app = Litestar(
       route_handlers=[index],
       plugins=[SecurityPlugin(SecurityConfig())],
   )

``SecurityConfig`` requires authentication by default. The route above opts
out explicitly, so it remains public before a provider is configured.

Choose authentication
---------------------

Local accounts support three explicit transports:

* ``LocalAuth.session`` uses a native Litestar session plus an independent
  binding cookie and requires CSRF.
* ``LocalAuth.tokens`` issues short-lived access JWTs and rotating opaque
  refresh tokens without a session.
* ``LocalAuth.hybrid`` exposes separate browser and API routes.

For a session application, install Litestar's session middleware on the app.
``SecurityPlugin`` detects it; do not extract the backend from the middleware
configuration:

.. code-block:: python

   from litestar import Litestar
   from litestar.middleware.session.client_side import CookieBackendConfig

   session_config = CookieBackendConfig(secret=session_secret)

   app = Litestar(
       middleware=[session_config.middleware],
       plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth))],
   )

The application supplies ``session_secret``, ``local_auth``, and its account
store from its settings and persistence layers. See :doc:`accounts` for the
store contracts and :doc:`providers` for external authentication.

Pass the account store to ``LocalAuth.session(accounts=...)``. Native session
storage stays in Litestar's session middleware because Litestar owns the
session cookie and serialization lifecycle.

Run an example
--------------

The repository includes complete local factories:

.. code-block:: console

   LITESTAR_SECURITY_EXAMPLE=local-session uv run litestar --app examples.app:create_app run
   LITESTAR_SECURITY_EXAMPLE=local-token uv run litestar --app examples.app:create_app run
   LITESTAR_SECURITY_EXAMPLE=local-hybrid uv run litestar --app examples.app:create_app run
   LITESTAR_SECURITY_EXAMPLE=no-session uv run litestar --app examples.app:create_app run

The examples use ephemeral keys and in-memory stores. Replace them before
production. See :doc:`examples` for every available mode.
