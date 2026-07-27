================
Generated routes
================

A configured local-auth profile contributes a native Litestar route tree. The
routes are ordinary handlers on ordinary controllers, so they appear in your
OpenAPI document alongside your own, and the same schema plugins and render
plugins apply to them.

Which routes exist depends on the profile. A session profile has no token
routes, a token profile has no session routes, and registration routes exist
only when a registration policy allows them.

Tag groups
==========

Generated operations are filed under five tags rather than one, so the rendered
document separates the ways to sign in from the flows that repair an account
nobody can sign in to:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Tag
     - Operations
   * - ``Local sessions``
     - ``LocalSessionLogin``, ``LocalSessionLogout``, ``LocalSessionList``,
       ``LocalSessionRevoke``
   * - ``Local tokens``
     - ``LocalTokenLogin``, ``LocalTokenRefresh``, ``LocalTokenRevoke``
   * - ``Local registration``
     - ``LocalRegister``
   * - ``Local passwords``
     - ``LocalPasswordChange``, ``LocalTokenPasswordChange``,
       ``LocalPasswordRecovery``, ``LocalPasswordReset``
   * - ``Local verification``
     - ``LocalVerificationResend``, ``LocalVerificationConfirm``

Descriptions for these tags are contributed to your OpenAPI config when local
authentication is configured. Declaring a tag of the same name yourself keeps
your description: the operations still land in that group, described the way you
chose.

.. code-block:: python

   from litestar.openapi import OpenAPIConfig
   from litestar.openapi.spec import Tag

   openapi_config = OpenAPIConfig(
       title="Example",
       version="1.0",
       tags=[Tag(name="Local sessions", description="Sign-in for the web client.")],
   )

The tags are also available directly, which is useful for ordering them among
your own:

.. code-block:: python

   from litestar_security.accounts import LOCAL_AUTH_TAGS

Operation identifiers
=====================

Every generated operation declares an explicit ``operationId``, so a generated
client keeps stable method names across releases. The identifiers are the same
whichever transport profile is active, with one exception: a hybrid profile
serves password change on two paths, so the bearer variant is
``LocalTokenPasswordChange`` while ``LocalPasswordChange`` stays on
``/password/change``.

Documented failures
===================

Generated operations declare the failures a client has to handle, not only the
success case:

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - ``400``
     - The request is invalid, or a token was rejected. Rejection reasons are
       deliberately not distinguished.
   * - ``401``
     - Authentication is required, or the presented credential no longer
       satisfies the account security epoch.
   * - ``429``
     - The operation exceeded its rate limit. Carries ``Retry-After`` when the
       limiter reports one. See :doc:`rate-limiting`.
   * - ``503``
     - An application-supplied dependency was unavailable. Security decisions
       fail closed, so this never means the request was allowed.

Enumeration resistance shows up in the schema as well. Recovery, verification,
and registration answer ``202`` with the same body for every identifier, so a
client cannot tell an existing account from an absent one by reading the
response.

Turning them off
================

Pass ``register_routes=False`` to build the services without the route tree, and
mount your own controllers against ``local_auth.services``:

.. code-block:: python

   local_auth = LocalAuth.tokens(
       accounts=accounts,
       secrets=secrets,
       key_ring=key_ring,
       token_audience="local-client",
       register_routes=False,
   )

No tag descriptions are contributed in that case, because no operations are
generated to file under them.
