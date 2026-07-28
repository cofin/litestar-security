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

MFA, passkeys, and step-up
==========================

``MFAConfig`` and ``PasskeyConfig`` add a second route bundle under the same
``/auth`` prefix. It contains TOTP enrollment and activation, recovery-code
replacement, passkey registration and authentication, safe credential
inventory and removal, and ``POST /auth/step-up/{purpose}``. Generated MFA
routes require an explicit recovery-code pepper ring and login-method store;
passkey routes require the same shared viability boundary. Startup rejects a
route configuration that could activate a factor without recording it for
final-method-safe removal. Factor creation, login-method registration, and the
durable event are one application-store atomic operation.

Step-up grants are short-lived, single-use values returned in JSON. The stored
record contains only a digest and is bound to the authenticated principal,
current security epoch, exact purpose, and current session or token transport.
A grant for one operation cannot authorize another operation.

All secret- and challenge-bearing responses set ``Cache-Control: no-store`` and
``Pragma: no-cache``. Generated schemas describe the typed camel-case JSON
models without embedding sample TOTP secrets, recovery codes, browser
credential responses, or public verification keys.

Passkey authentication options include a reveal-once ``binding`` alongside the
browser options. Return that value unchanged in the verification request; it is
redacted from representations and binds the public ceremony without relying on
an existing cookie or token.

Passkey authentication establishes the local transport selected by the
application profile. Session-capable profiles compile the unsafe verification
route with CSRF enforcement; token-only profiles do not require a browser CSRF
cookie. A hybrid profile exposes distinct
``/passkeys/authentication/session/verify`` and
``/passkeys/authentication/tokens/verify`` routes so CSRF policy is fixed by the
route rather than selected by an untrusted request field.

The synchronous WebAuthn adapter runs through a bounded worker limiter and
timeout. Attestation defaults to ``none``. Requesting direct attestation and
assigning the ``hardware-backed`` trait requires an application-supplied
``AttestationTrustMapper``. Its format-specific PEM roots are passed into
cryptographic attestation verification before its policy can approve the
verified AAGUID and format.

Successful passkey assurance is preserved by both transports. Sessions store
normalized evidence in their versioned payload, while local access tokens carry
strict ``amr`` and security-trait claims that the local bearer verifier
reconstructs as evidence.

Set ``register_routes=False`` independently on either feature configuration to
keep its service available for an application-owned controller without
registering its generated handlers.
