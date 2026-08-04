=============================
Composing with other plugins
=============================

A Litestar application rarely contains only its own handlers. Static assets, a
job-queue dashboard, a schema browser, and a debug toolbar all arrive as routes
that another plugin registered, and none of them carry an ``auth`` policy of
their own.

With mechanisms configured, a route that declares no policy compiles to implicit
``required()``. That includes routes this application did not write, so a
freshly added static files router answers ``401`` until it is excluded.

This is Litestar's behavior, not a Litestar Security quirk
==========================================================

Plain Litestar does the same thing. An application using
:class:`~litestar.security.jwt.JWTAuth` without an exclusion also answers ``401``
for ``/static/app.css``: the authentication middleware runs for every path it is
not told to skip. Litestar's answer is the middleware's ``exclude`` argument,
and ``exclude`` on :class:`~litestar_security.SecurityConfig` is the same
mechanism, spelled the same way.

Litestar's other escape hatch, the ``exclude_from_auth`` opt, is deliberately
narrower here. It is honored on an individual route handler and rejected on a
router, controller, or application, because a layer-level exclusion opens an
entire subtree without naming what is in it. Routers built by another plugin
expose ``opt`` only at the router level, so ``exclude_from_auth`` is not the
route to take for them — path patterns are.

Excluding paths
===============

``exclude`` accepts one regular expression or a sequence of them:

.. code-block:: python

   from litestar import Litestar
   from litestar.static_files import create_static_files_router

   from litestar_security import SecurityConfig, SecurityPlugin

   config = SecurityConfig(
       mechanisms=[api_key_mechanism],
       exclude=["^/static", "^/assets"],
   )

   app = Litestar(
       route_handlers=[
           api_router,
           create_static_files_router(path="/static", directories=["public"]),
       ],
       plugins=[SecurityPlugin(config)],
   )

Patterns are matched against the **route path** as Litestar registered it, not
against the request URL. A static files router mounted at ``/static`` registers
``/static/{file_path:path}``, which ``^/static`` matches.

Exclusion is total. An excluded route is not authenticated, receives no
principal, and contributes an anonymous security requirement to OpenAPI rather
than the configured schemes. That last part is why the pattern is applied when
routes are compiled rather than per request: a runtime-only bypass would leave
the OpenAPI document claiming a route is protected while it is not.

.. warning::

   ``exclude`` removes authentication from every route it matches. Write the
   narrowest pattern that covers the mount point, and anchor it with ``^``.

What the compiler checks
========================

A pattern is anchored at the start of the route path. ``"^/static"`` and
``"/static"`` both exclude ``/static/{file_path:path}``; a bare ``"static"``
does not, because it does not match from position zero. Litestar's runtime
middleware searches anywhere in the path instead, so a pattern that Litestar
would treat as matching mid-path leaves the route protected here. The
difference only ever resolves towards keeping a route authenticated.

A route that declares its own ``auth`` **and** matches an exclusion pattern is
rejected at startup rather than resolved in either direction:

.. code-block:: text

   Route declares auth but matches a security exclusion pattern for GET /assets/report

The policy is resolved through Litestar's ownership layers, so an
application-wide ``opt={"auth": ...}`` default counts as a declaration for every
route beneath it, including excluded ones. Scope such a default to the router
that owns the application's own routes, and let policy-less routes take the
implicit default.

A pattern that matches no registered route is reported once at startup:

.. code-block:: text

   LitestarWarning: Litestar Security exclusion patterns match no registered route: ^/nowhere

It warns rather than raises. Litestar answers the strictly worse case — a
pattern greedily matching every path, disabling the middleware outright — with a
warning too, and a pattern written for a route that exists only in production or
only when an optional plugin is installed stays legitimate.

Patterns for route-registering plugins
======================================

Each of these registers routes the application did not declare. Exclude the
path the plugin is configured to mount at; the pattern is the mount path
anchored with ``^``.

.. list-table::
   :header-rows: 1
   :widths: 25 45 30

   * - Plugin
     - What it registers
     - Pattern to add
   * - ``litestar-vite``
     - A static files route serving the built frontend bundle, plus the dev
       server proxy while running in development.
     - ``^`` and the configured asset URL, for example ``"^/static"``
   * - ``litestar-saq``
     - The queue dashboard router and the API it reads from.
     - ``^`` and the configured web path, for example ``"^/saq"``
   * - ``litestar-queues``
     - The queue management and status routes.
     - ``^`` and the configured route prefix
   * - ``litestar-asyncapi``
     - The AsyncAPI schema document and its documentation UI.
     - ``^`` and the configured schema path
   * - ``debug-toolbar``
     - The toolbar panel routes and their assets.
     - ``^`` and the configured toolbar path

Read the mount path off the plugin's own configuration rather than assuming a
default, and confirm it against the routes the built application actually
registered:

.. code-block:: python

   for route in app.routes:
       print(route.path)

A pattern that names a path no route uses warns at startup, so a wrong guess
does not fail silently.

Leaving a plugin's routes protected
===================================

Excluding is a choice, not an obligation. A dashboard is often exactly what
should stay behind authentication, and leaving it out of ``exclude`` keeps the
implicit ``required()`` default. To give it a policy of its own instead, wrap
the plugin's router in one that carries the policy:

.. code-block:: python

   from litestar import Router

   from litestar_security import required

   operations = Router(path="/", route_handlers=[queue_router], opt={"auth": required("session")})

Because the wrapper declares a policy, the wrapped routes must not also match an
exclusion pattern.

See :doc:`authentication` for the policy helpers themselves.
