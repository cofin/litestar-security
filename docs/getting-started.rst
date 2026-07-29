Getting started
===============

Install Litestar Security:

.. code-block:: console

   pip install litestar-security

Add the plugin and mark public routes explicitly:

.. code-block:: python

   from litestar import Litestar, get
   from litestar.di import NamedDependency

   from litestar_security import (
       SecurityConfig,
       SecurityContext,
       SecurityPlugin,
       public,
   )


   @get("/", auth=public(), sync_to_thread=False)
   def index(security_context: NamedDependency[SecurityContext]) -> dict[str, bool]:
       return {"authenticated": bool(security_context.evidence)}


   app = Litestar(
       route_handlers=[index],
       plugins=[SecurityPlugin(SecurityConfig())],
   )

With configured authentication mechanisms and no inherited ``auth`` policy,
routes use implicit ``required()``. Without any mechanisms they are public.
The route above stays explicit so adding a provider cannot silently change its
contract.

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
   from litestar.config.csrf import CSRFConfig
   from litestar.middleware.session.client_side import CookieBackendConfig

   session_config = CookieBackendConfig(secret=session_secret)

   app = Litestar(
       csrf_config=CSRFConfig(secret=csrf_secret),
       middleware=[session_config.middleware],
       plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth))],
   )

The application supplies ``session_secret``, ``csrf_secret``, ``local_auth``,
and its account store from its settings and persistence layers. Exactly one
native ``CSRFConfig`` or ``SecurityConfig.external_csrf`` integration is
required for session authentication.

Pass the account store to ``LocalAuth.session(accounts=...)``. Native session
storage stays in Litestar's session middleware because Litestar owns the
session cookie and serialization lifecycle. Client-side sessions need no
store. For server-side sessions, configure
``ServerSideSessionConfig(store="sessions")`` and register the matching
``Litestar(stores={"sessions": ...})`` value.

See :doc:`accounts` for the account-store contracts and :doc:`providers` for
external authentication.

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
