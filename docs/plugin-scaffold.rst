Plugin scaffold
===============

The plugin can be registered like any Litestar initialization plugin:

.. code-block:: python

   from litestar import Litestar
   from litestar_security import SecurityConfig, SecurityPlugin

   config = SecurityConfig()
   plugin = SecurityPlugin(config=config)

   app = Litestar(plugins=[plugin])

The plugin preserves an explicitly supplied configuration object by identity
and installs one typed security runtime per application. It composes with
Litestar's native sessions, CSRF middleware, dependency injection, lifespan,
route ownership, and OpenAPI facilities.

Configuration
-------------

``SecurityConfig`` is a slotted dataclass. Its defaults provide the typed
runtime without selecting an authentication mechanism. Configure credential
slots and mechanisms explicitly; provider-specific settings such as local JWKS
publication and remote JWKS lifespan ownership remain separate fields.

The plugin reserves ``principal``, ``security_context``, and ``current_user``
as typed dependencies. Conflicting application, router, controller, or handler
dependencies fail during startup instead of silently overriding security
state.

CLI
---

The installed package exposes one Litestar command group:

.. code-block:: console

   litestar security --help
   litestar security --version

The group is registered lazily and idempotently.
