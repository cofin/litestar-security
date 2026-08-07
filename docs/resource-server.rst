==========================
OAuth 2.1 resource server
==========================

An application that accepts bearer tokens issued by somebody else is an OAuth
2.1 protected resource. This page covers the two things that follow from that:
telling clients so, and letting another plugin in the same application reuse the
verification you already configured instead of building a second one.

Advertising the resource
========================

:rfc:`9728` defines a metadata document that says which authorization servers
may issue tokens for this resource, which scopes it understands, and how a
token may be presented. Set ``protected_resource`` and the plugin publishes it:

.. code-block:: python

   from litestar import Litestar

   from litestar_security import SecurityConfig, SecurityPlugin
   from litestar_security.providers.oauth import ProtectedResourceConfig

   config = SecurityConfig(
       slots=[service_slot],
       mechanisms=[service_mechanism],
       protected_resource=ProtectedResourceConfig(
           resource="https://api.example.com",
           authorization_servers=["https://id.example.com"],
           scopes_supported=["reports:read", "reports:write"],
           resource_documentation="https://docs.example.com/api",
       ),
   )

   app = Litestar(route_handlers=[reports], plugins=[SecurityPlugin(config)])

``GET /.well-known/oauth-protected-resource`` then answers:

.. code-block:: json

   {
     "authorization_servers": ["https://id.example.com"],
     "bearer_methods_supported": ["header"],
     "resource": "https://api.example.com",
     "resource_documentation": "https://docs.example.com/api",
     "scopes_supported": ["reports:read", "reports:write"]
   }

The route is unauthenticated, as the specification requires, and it stays
unauthenticated even when every other route defaults to ``required()``. The
document, its strong ``ETag``, and its ``Cache-Control`` are computed once when
the configuration is built, so serving it costs one comparison and one write.
A conditional request carrying the matching ``If-None-Match`` gets ``304``.

Discovering the document from a bearer challenge
------------------------------------------------

When a route whose authentication policy includes an HTTP Bearer mechanism
rejects a request with ``401``, the response also points at the same document:

.. code-block:: text

   WWW-Authenticate: Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"

This is the :rfc:`9728` discovery flow layered onto the :rfc:`6750` bearer
challenge. The plugin derives the URL from the same resource identifier,
resource path, and ``route_prefix`` used to mount the document. It does not add
the parameter to API-key, session, public, or otherwise non-bearer routes, and
it preserves any Bearer challenge parameters already present.

Publication and challenge discovery are independent. To publish the document
without advertising it in rejected requests, set
``advertise_resource_metadata=False`` on ``ProtectedResourceConfig``.

Member names are the specification's, not this application's
------------------------------------------------------------

The member names in that document — ``resource``, ``authorization_servers``,
``bearer_methods_supported`` and the rest — come from :rfc:`9728`. They are read
by authorization servers and clients that know nothing about this application,
so they are fixed, and no field-naming policy applies to them.

Where the document is served
----------------------------

:rfc:`9728` inserts ``/.well-known/oauth-protected-resource`` between the host
and the path of the resource identifier. A resource identifier with no path is
advertised at the root:

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - ``resource``
     - Metadata path
   * - ``https://api.example.com``
     - ``/.well-known/oauth-protected-resource``
   * - ``https://api.example.com/mcp``
     - ``/.well-known/oauth-protected-resource/mcp``

``route_prefix`` mounts the whole thing somewhere else, for an application
served under a path. The same prefix appears in the advertised
``resource_metadata`` URL. Leave it alone unless the public URL genuinely
contains that prefix — a client that follows the specification looks at the
root otherwise.

What is validated at startup
----------------------------

Every advertised value is checked when the configuration is constructed, so a
wrong advertisement fails to start rather than reaching a client that trusts it.
``resource``, each authorization server, and ``resource_documentation`` must be
absolute URIs. ``resource`` carries no query and no fragment, because a resource
identifier that did could not be expressed as a metadata path.
``bearer_methods_supported`` accepts only ``header``, ``body``, and ``query``.

Delegating from another plugin
==============================

A plugin that registers authenticated routes into somebody else's application
has four needs. All four are met by the published surface; none of them requires
reading this package's internals.

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - What the plugin needs
     - What it uses
   * - A configured token verifier, without building one
     - The mechanism the application already configured. The plugin names it in
       ``auth=``.
   * - To contribute an OpenAPI security scheme without colliding
     - ``scheme_name`` on its mechanism. Two mechanisms may share a name only if
       they declare the identical scheme; anything else is rejected at startup.
   * - To register routes with a declared policy
     - ``auth=`` on its handlers, exactly as an application route does. See
       :doc:`composition`.
   * - To share one key set and one fetch schedule
     - The ``JWKSProvider`` the application constructed, or a ``JWKSCache``
       shared between providers.

A worked example
----------------

The application owns the shared objects. It builds one JWKS provider, one
workload-token boundary over it, and passes the resulting slot and mechanism to
``SecurityConfig``:

.. code-block:: python

   from litestar import Litestar

   from litestar_security import SecurityConfig, SecurityPlugin
   from litestar_security.providers.jwks import (
       CachedJWKSProvider,
       HttpxJWKSFetcher,
       JWKSCacheEntry,
   )
   from litestar_security.providers.oauth import ProtectedResourceConfig
   from litestar_security.providers.oidc import ServiceTokenConfig

   ISSUER = "https://id.example.com"
   JWKS_URI = "https://id.example.com/jwks.json"

   provider = CachedJWKSProvider(
       entries=(
           JWKSCacheEntry(
               issuer=ISSUER,
               jwks_uri=JWKS_URI,
               algorithms=frozenset({"ES256"}),
           ),
       ),
       fetcher=HttpxJWKSFetcher(),
       fetcher_owned=True,
   )
   slot, mechanism = ServiceTokenConfig(
       issuer=ISSUER,
       audiences=frozenset({"team-api"}),
       allowed_algorithms=frozenset({"ES256"}),
       jwks=provider,
       jwks_uri=JWKS_URI,
   ).build()

   security = SecurityConfig(
       slots=(slot,),
       mechanisms=(mechanism,),
       jwks_providers=(provider,),
       protected_resource=ProtectedResourceConfig(
           resource="https://api.example.com",
           authorization_servers=(ISSUER,),
       ),
   )

   app = Litestar(plugins=[SecurityPlugin(security), CompanionPlugin()])

The companion plugin registers its routes and names the mechanism. It builds no
verifier, opens no connection to the issuer, and holds no keys:

.. code-block:: python

   from litestar import get
   from litestar.config.app import AppConfig
   from litestar.di import NamedDependency
   from litestar.plugins import InitPlugin

   from litestar_security import SecurityPlugin, required
   from litestar_security.context import Principal, SecurityContext


   @get("/companion/reports", auth=required("service-jwt"))
   async def companion_reports(
       principal: NamedDependency[Principal[object]],
       security_context: NamedDependency[SecurityContext],
   ) -> dict[str, object]:
       scopes = frozenset[str]().union(*(value.scopes for value in security_context.restrictions))
       return {"actor": principal.id, "scopes": sorted(scopes)}


   class CompanionPlugin(InitPlugin):
       def on_app_init(self, app_config: AppConfig) -> AppConfig:
           security = next(
               plugin for plugin in app_config.plugins if isinstance(plugin, SecurityPlugin)
           )
           self.security_config = security.config
           app_config.route_handlers.append(companion_reports)
           return app_config

``SecurityPlugin.config`` is the configuration object the application passed in,
by identity, and it is readable from ``app_config.plugins`` during
``on_app_init`` or from ``app.plugins.get(SecurityPlugin)`` afterwards. Reading
it is how a plugin discovers what the application configured — which issuers are
trusted, which JWKS providers exist, whether ``protected_resource`` is set.

Scopes carried by a token arrive as ``SecurityContext.restrictions``. They
constrain what an authenticated caller may be granted; they are not themselves a
grant. Turning them into application permissions is the
``AuthorizationResolver``'s job, and a plugin should read the restrictions
rather than assume them.

Sharing one key set
-------------------

Handing the same ``JWKSProvider`` to everything that verifies against an issuer
is the simplest arrangement, and the one to prefer: one cache, one fetch
schedule, and refreshes coalesced across every caller.

When two providers genuinely have to exist — different policies, different
metrics sinks — give them one cache instead:

.. code-block:: python

   from litestar_security.providers.jwks import CachedJWKSProvider, InMemoryJWKSCache

   shared_keys = InMemoryJWKSCache()

   first = CachedJWKSProvider(entries=entries, fetcher=fetcher, cache=shared_keys)
   second = CachedJWKSProvider(entries=entries, fetcher=fetcher, cache=shared_keys)

Whichever provider fetches first populates the cache, and the other reads the
same parsed key set without a second request. See :doc:`jwt-and-jwks` for the
cache's freshness policy and for writing a ``JWKSCache`` of your own.

What a plugin must not touch
============================

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Do not
     - Instead
   * - Add to ``SecurityConfig.mechanisms`` from your own ``on_app_init``
     - Let the application configure mechanisms. Ordering between plugins is
       not something either of you controls.
   * - Install your own authentication middleware alongside this one
     - Declare ``auth=`` on your routes.
   * - Build a second JWKS cache or fetch loop for an issuer the application
       already configured
     - Take the application's ``JWKSProvider``, or share a ``JWKSCache``.
   * - Set ``exclude_from_auth`` on your router or controller
     - It is honored on a route handler only. For a whole subtree the
       application uses ``SecurityConfig.exclude``; see :doc:`composition`.
   * - Import from a ``_``-prefixed module
     - Everything supported is re-exported from a package. If something you
       need is not, it is not yet public.
