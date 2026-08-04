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

Session and hybrid profiles require application-owned Litestar session
middleware and exactly one native or external CSRF implementation. The local
profile receives neither a session backend nor a session store; configure
``CookieBackendConfig`` or ``ServerSideSessionConfig`` directly on
``Litestar``.

Wire format
===========

Every request and response body in the generated tree uses ``snake_case``
members, spelled exactly as the Python attribute is spelled, and rejects a
member it does not model. A body carrying an unrecognized field is a
``400``, not a silently discarded key.

Rejecting the member is what keeps a stale or misspelled optional field from
resolving to its default. A client sending ``returnTo`` where the schema
declares ``return_to`` gets an error naming the field, rather than a successful
request that quietly redirected somewhere else.

Two surfaces are snake_case because their specifications say so rather than
because of this convention: the JWKS document (:rfc:`7517`), the OIDC
back-channel logout body, and the ``token_type``/``expires_in``/
``refresh_token`` members of the token response (:rfc:`6749`, section 5.1).
Their member names are fixed by the specification and are not ours to rename.

Applications defining their own schemas alongside the generated routes can
inherit :class:`~litestar_security.WireStruct` to hold the same convention
across the whole tree:

.. code-block:: python

    from litestar_security import WireStruct


    class TeamInvitation(WireStruct, frozen=True):
        team_id: str
        invited_identifier: str

A schema that must tolerate members it does not model - a specification-defined
body whose sender may legitimately add them - overrides the policy for itself
with ``forbid_unknown_fields=False`` rather than relaxing the shared base.

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
       ``LocalSessionRevoke``, ``LocalSessionMFALogin``
   * - ``Local tokens``
     - ``LocalTokenLogin``, ``LocalTokenRefresh``, ``LocalTokenRevoke``,
       ``LocalTokenMFALogin``
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
   * - ``403``
     - A password was verified but a configured second factor is still owed.
       The typed ``LocalMFARequiredResponse`` contains ``code="mfa_required"``,
       ``detail``, ``account_id``, ``challenge``, ``expires_at``, and
       ``methods``.
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

Notification destinations reject control characters before the application
delivery command is created. In particular, a recovery or verification request
containing CRLF characters still receives the same ``202`` response but emits
no notification, preventing mail-header injection without becoming an account
enumeration signal.

The same guarantee extends to timing, and part of it is a store obligation.
On recovery request and verification resend, an eligible account commits
through :meth:`~litestar_security.accounts.RecoveryTokenStore.issue` while any
other identifier performs one equivalent durable round trip through
:meth:`~litestar_security.accounts.RecoveryTokenStore.issue_absent`, which must
cost the same and commit nothing — a store that answers quickly for unknown
accounts makes a present account measurably slower to probe. Registration
carries the matching obligation on
:meth:`~litestar_security.accounts.RegistrationStore.register`: a taken and a
new identifier must cost the same.

Turning them off
================

Pass ``register_routes=False`` to build the services without the route tree, and
mount your own controllers against ``local_auth.local_auth_service``:

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

When ``MFAConfig.require_at_login=True``, a successful password login can
return the documented ``403`` instead of establishing its transport. The
``challenge`` is reveal-once, bound to the returned ``account_id`` and client,
and expires after five minutes by default (never more than ten minutes). A
found challenge is burned before its account, epoch, expiry, or client binding
is checked; retrying a completion after any failed reveal attempt therefore
requires a new password login.

Session-capable profiles add ``POST /auth/login/mfa`` with operation ID
``LocalSessionMFALogin``. It establishes the native session and is CSRF
protected. Token-capable profiles add ``POST /auth/token/mfa`` with operation
ID ``LocalTokenMFALogin`` and issue the access/refresh pair. Both accept the
typed completion body: ``challenge``, ``account_id``, ``method``, ``code``,
and optional ``method_id``. They accept ``totp`` and ``recovery-code`` methods;
TOTP requires the ``method_id`` returned when that factor was enrolled. There
is no factor-discovery port, so clients must retain that identifier.

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

The ``{purpose}`` path segment is deny-by-default. Every purpose a generated
route consumes maps to an explicit allowlist of factors strong enough to
authorize it — password or passkey re-verification, never a second submission
of the factor being managed — and a purpose outside that map, or a factor the
purpose does not allow, receives the same sanitized ``401`` as a wrong
credential. An unrecognized purpose never mints a grant.

All secret- and challenge-bearing responses, including the login ``403``, set
``Cache-Control: no-store`` and ``Pragma: no-cache``. Generated schemas describe
the typed JSON models without embedding sample TOTP secrets, recovery codes,
browser credential responses, or public verification keys.

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
verified AAGUID and format. The verified format must select a configured root
set and the attestation statement must contain a certificate chain; packed
self-attestation is never promoted to hardware-backed assurance.

Successful passkey assurance is preserved by both transports. Sessions store
normalized evidence in their versioned payload, while local access tokens carry
strict ``amr``, ``auth_time``, and security-trait claims that the local bearer
verifier reconstructs as evidence. Refresh-family state preserves the same
secret-free evidence so rotation cannot renew its original freshness.

Set ``register_routes=False`` independently on either feature configuration to
keep its service available for an application-owned controller without
registering its generated handlers.
