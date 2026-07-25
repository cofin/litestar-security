Plugin scaffold
===============

The plugin can be registered like any Litestar initialization plugin:

.. code-block:: python

   from litestar import Litestar
   from litestar_security import SecurityConfig, SecurityPlugin

   config = SecurityConfig()
   plugin = SecurityPlugin(config=config)

   app = Litestar(plugins=[plugin])

The plugin preserves an explicitly supplied configuration object by identity.
Its application initialization hook returns Litestar's
:class:`~litestar.config.app.AppConfig` unchanged.

Configuration
-------------

``SecurityConfig`` is an empty slotted dataclass. The lack of fields is
intentional: no provider, middleware, guard, state, dependency, route,
authentication, or authorization contract has been established.

CLI
---

The installed package exposes one Litestar command group:

.. code-block:: console

   litestar security --help
   litestar security --version

The group is registered lazily and idempotently. Feature-specific commands will
be added with their implementations.
