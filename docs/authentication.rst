Authentication and authorization
================================

Credential slots own physical transport locations. A presented malformed or
invalid credential is terminal; it is never treated as absence to unlock a
weaker alternative. Successful credentials must resolve to the same subject,
and credential-granted scopes, teams, roles, capabilities, tenants, and
resource permissions intersect.

Use ``public()``, ``required()``, ``any_of()``, ``all_of()``, or ``at_least()``
through the route ``auth`` keyword. Runtime admission and native OpenAPI
security projection compile from the same normalized policy. Authentication
failure is ``401``, guard denial is ``403``, and unavailable verification fails
closed as ``503``.

Native ownership
----------------

Route decorators accept ``auth`` directly:

.. code-block:: python

   @get("/", auth=public())
   async def index() -> None:
       return None

Applications, routers, and controllers inherit policy through Litestar's
native ``opt`` mapping:

.. code-block:: python

   app = Litestar(
       route_handlers=[api_router],
       opt={"auth": required()},
       plugins=[SecurityPlugin(config)],
   )

.. code-block:: python

   class AccountController(Controller):
       opt = {"auth": required("session")}

Prefer the typed base classes when a controller's default policy is known at
class-definition time:

.. code-block:: python

   from typing import ClassVar

   from litestar_security import AuthenticationPolicy, SecureController, required


   class AccountController(SecureController):
       auth: ClassVar[AuthenticationPolicy] = required("session")

``PublicController`` is ``SecureController`` defaulting to ``public()``.
Both compile into the same ``opt["auth"]`` key, and the nearest native owner
still wins, including a handler-level ``auth=`` override.

Custom controller class attributes are not propagated by Litestar; put
``auth`` in ``opt``. The nearest native owner wins. With configured mechanisms
and no inherited policy, the plugin uses implicit ``required()``; without
mechanisms it uses ``public()``.

The ``auth`` policy also compiles for WebSocket and raw ASGI handlers.
``csrf_required=True`` is HTTP-only and is reserved for exceptional public
routes that establish cookie-authenticated state. Session-capable policies
derive CSRF coverage automatically. A native CSRF exclusion key such as
``exclude_from_csrf=True`` is accepted only when the derived policy is not
session-capable.

Keep authorization in Litestar's native ``guards=[...]``. Litestar's
``security=`` parameter remains reserved for the OpenAPI requirements projected
from ``auth``. To protect schema endpoints, supply a custom OpenAPI router or
controller with ``opt={"auth": ...}``.

Schema endpoints are recognized by the handler Litestar generated for them, not
by their URL. An application route is authenticated by its own ``auth`` even
when it sits under the configured OpenAPI base path, so ``path="/api"`` on
:class:`~litestar.openapi.OpenAPIConfig` never relaxes ``/api/orders``. A route
served by an application handler is always treated as an application route; to
serve documentation from your own handlers, declare ``opt={"auth": public()}``
on the router or controller that owns them.

Authorization guards compose separately:

* ``requires_scope`` and ``requires_capability``;
* ``requires_role`` and ``requires_team_role``;
* ``requires_tenant``; and
* ``requires_assurance`` for recent or stronger evidence.

Compose predicates with ``requires_all_of``, ``requires_any_of``,
``requires_one_of``, and ``requires_at_least``. These names are distinct from the
unprefixed authentication-policy helpers, which compose mechanism names.

The ``principal`` and ``security_context`` dependencies remain typed on public
and protected routes. ``current_user`` is the explicit narrowing dependency
that rejects anonymous and userless service principals.

Where this differs from plain Litestar
======================================

Two differences are deliberate. An excluded route still receives the anonymous
``Principal`` and ``SecurityContext``; plain Litestar leaves ``scope["user"]``
and ``scope["auth"]`` unset, which would make the reserved dependencies
unusable on those routes. And only the OPTIONS handlers Litestar generates skip
authentication, where plain Litestar skips every ``OPTIONS`` request by default;
an application's own ``OPTIONS`` handler is authenticated like any other route.

Everything else follows the framework, including the parts that surprise people.
``exclude_from_auth`` is read by truthiness, and guards are cumulative, so an
excluded route beneath a guarded owner is still denied exactly as it would be
without this plugin.

Routes another plugin registered — static assets, a queue dashboard, a debug
toolbar — carry no ``auth`` of their own and so compile to implicit
``required()``. Exclude them by path with ``SecurityConfig(exclude=[...])``; see
:doc:`composition`.

See :doc:`providers` to choose and configure an authentication source.
