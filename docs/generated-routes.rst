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

By default, every request and response body in the generated tree uses
``snake_case`` members, spelled exactly as the Python attribute is spelled, and
rejects a member it does not model. A body carrying an unrecognized field is a
``400``, not a silently discarded key.

Rejecting the member is what keeps a stale or misspelled optional field from
resolving to its default. A client sending ``returnTo`` where the schema
declares ``return_to`` gets an error naming the field, rather than a successful
request that quietly redirected somewhere else.

Choosing the casing
-------------------

Two settings on :class:`~litestar_security.SecurityConfig` decide how the
generated bodies are spelled. If your API is camelCase, say so once and the
whole ``/auth`` tree follows:

.. code-block:: python

   from litestar_security import SecurityConfig

   config = SecurityConfig(local_auth=local_auth, wire_rename="camel")

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Setting
     - Meaning
   * - ``wire_rename``
     - ``None`` (the default) keeps the names as Python spells them. Otherwise
       one of ``"lower"``, ``"upper"``, ``"camel"``, ``"pascal"``, and
       ``"kebab"``, or a ``Callable[[str], str]`` for a house convention
       outside those five.
   * - ``wire_forbid_unknown_fields``
     - ``True`` (the default) makes an unrecognized member in a request body a
       ``400``. ``False`` ignores it. Strictness applies to decoding, so it
       constrains request bodies only.

The choice reaches the request body, the response body, and the OpenAPI schema
together, so a client generated from the document is already speaking the right
convention. It does not change which routes exist, what they require, or what
their component type names are: a casing change moves members, never the type
names your generated client is compiled against.

A callable receives the Python attribute name and returns the wire name:

.. code-block:: python

   config = SecurityConfig(local_auth=local_auth, wire_rename=lambda name: name.upper())

Names that are not ours to rename
---------------------------------

A few members are fixed by the specification that defines them, and no casing
setting reaches them:

- the JWKS document (:rfc:`7517`) and the protected-resource metadata document
  (:rfc:`9728`), which are published as-is;
- the OIDC back-channel logout body, whose single member is the one the
  identity provider sends;
- the token response (:rfc:`6749`, section 5.1) — ``access_token``,
  ``refresh_token``, ``expires_in``, and ``token_type``.

The error body is left alone for a different reason: it is rendered by your
application's exception handling rather than by these routes, so renaming it in
the document would describe a body the route never sends.

Sharing the convention with your own schemas
--------------------------------------------

Applications defining their own schemas alongside the generated routes can
inherit :class:`~litestar_security.WireStruct` to hold the same default:

.. code-block:: python

    from litestar_security import WireStruct


    class TeamInvitation(WireStruct, frozen=True):
        team_id: str
        invited_identifier: str

``WireStruct`` defines the default spelling, not the effective one — the
setting above is applied to the generated routes when they are built, and a
schema of your own is spelled however the handler carrying it is configured.

A schema that must tolerate members it does not model - a specification-defined
body whose sender may legitimately add them - overrides the policy for itself
with ``forbid_unknown_fields=False`` rather than relaxing the shared base. A
schema whose member names belong to a specification rather than to your API
declares ``__wire_casing__ = False`` for the same reason, and no casing setting
touches it.

Tag groups
==========

Generated operations are filed under ten tags rather than one, so the rendered
document separates the ways to sign in from the flows that repair an account
nobody can sign in to. Each group is addressed in configuration by a stable key
that does not change when its display name does:

.. list-table::
   :header-rows: 1
   :widths: 20 22 58

   * - Key
     - Tag
     - Operations
   * - ``local.sessions``
     - ``Local sessions``
     - ``LocalSessionLogin``, ``LocalSessionLogout``, ``LocalSessionList``,
       ``LocalSessionRevoke``, ``LocalSessionMFALogin``
   * - ``local.tokens``
     - ``Local tokens``
     - ``LocalTokenLogin``, ``LocalTokenRefresh``, ``LocalTokenRevoke``,
       ``LocalTokenMFALogin``
   * - ``local.registration``
     - ``Local registration``
     - ``LocalRegister``
   * - ``local.passwords``
     - ``Local passwords``
     - ``LocalPasswordChange``, ``LocalTokenPasswordChange``,
       ``LocalPasswordRecovery``, ``LocalPasswordReset``
   * - ``local.verification``
     - ``Local verification``
     - ``LocalVerificationResend``, ``LocalVerificationConfirm``
   * - ``mfa``
     - ``Multi-factor authentication``
     - ``MFAEnrollTOTP``, ``MFAVerifyTOTPEnrollment``, ``MFARemoveTOTP``,
       ``MFAReplaceRecoveryCodes``
   * - ``passkeys``
     - ``Passkeys``
     - ``PasskeyRegistrationOptions``, ``PasskeyRegistrationVerify``,
       ``PasskeyAuthenticationOptions``, ``PasskeySessionAuthenticationVerify``,
       ``PasskeyTokenAuthenticationVerify``, ``PasskeyList``, ``PasskeyRemove``
   * - ``step_up``
     - ``Step-up authentication``
     - ``SecurityStepUp``
   * - ``oauth.providers``
     - ``OAuth providers``
     - ``OAuthLogin``, ``OAuthCallback``, ``OAuthLink``, ``OAuthUnlink``,
       ``OAuthScopeUpgrade``, ``OAuthRevoke``, ``OAuthLogout``
   * - ``oidc.logout``
     - ``OIDC logout``
     - ``OIDCFrontchannelLogout``, ``OIDCBackchannelLogout``

Descriptions for every group a configured feature generates routes for are
contributed to your OpenAPI config. Declaring a tag of the same name yourself
keeps your description: the operations still land in that group, described the
way you chose.

.. code-block:: python

   from litestar.openapi import OpenAPIConfig
   from litestar.openapi.spec import Tag

   openapi_config = OpenAPIConfig(
       title="Example",
       version="1.0",
       tags=[Tag(name="Local sessions", description="Sign-in for the web client.")],
   )

The defaults are also available directly, keyed by the stable key, which is
useful for ordering them among your own:

.. code-block:: python

   from litestar_security import ROUTE_TAGS

   ROUTE_TAGS["local.sessions"].name  # "Local sessions"

Documentation metadata
======================

Tag names, tag descriptions, operation identifiers, and route names are the
application's to set. Pass a :class:`~litestar_security.RouteDocs` to any
feature configuration:

.. code-block:: python

   from litestar_security import RouteDocs
   from litestar_security.accounts import LocalAuth

   local_auth = LocalAuth.session(
       accounts=accounts,
       secrets=secrets,
       binding=binding,
       docs=RouteDocs(
           tags={"local.sessions": "Sign-in", "local.passwords": "Account recovery"},
           tag_descriptions={"local.sessions": "Sign-in for the web client."},
       ),
   )

Routes regroup under the new name, and the renamed group carries either your
description or the built-in one. Renaming two groups to the same name merges
them into one group deliberately. A key that names no group raises
``ImproperlyConfiguredException`` at configuration time, so a typo never
silently does nothing.

``MFAConfig`` and ``PasskeyConfig`` generate one shared route bundle, and the
``step_up`` group belongs to both, so when both features are configured they
must carry the same ``RouteDocs``.

Renaming operations
-------------------

``operation_id`` and ``route_name`` take a callable receiving the built-in value
and returning the replacement, so a naming convention is one function rather
than an override per route. Under ``litestar-vite``'s ``TypeGenConfig`` the
operation identifier becomes the generated TypeScript client's function name,
which is usually why an application wants to change it:

.. code-block:: python

   from litestar_security import RouteDocs

   docs = RouteDocs(operation_id=lambda name: name[0].lower() + name[1:])
   # LocalSessionLogin -> localSessionLogin, PasskeyList -> passkeyList

The built-in identifiers are noun-first, so ``LocalSessionLogin`` and
``LocalSessionList`` sort next to each other in a generated client. A verb-first
convention is the same shape of transform:

.. code-block:: python

   _VERBS = {"Login", "Logout", "List", "Revoke", "Remove", "Refresh"}


   def verb_first(name: str) -> str:
       for verb in _VERBS:
           if name.endswith(verb):
               return verb + name[: -len(verb)]
       return name


   docs = RouteDocs(operation_id=verb_first)
   # LocalSessionLogin -> LoginLocalSession

Two routes resolving to the same operation identifier or the same route name
after a transform raise ``ImproperlyConfiguredException`` when the routes are
built. Litestar notices a duplicate operation identifier only when the OpenAPI
schema is first generated, and a duplicate route name silently misdirects
``route_reverse``, so both are rejected up front instead.

Documentation is never policy
-----------------------------

Nothing reachable through ``RouteDocs`` changes what a route requires. Renaming
a tag, rewriting an operation identifier, or replacing a route name leaves the
authentication requirement, the guards, the CSRF enforcement, and the rate
limits of every generated route exactly as they were. A route's protection is
selected by its configuration, never by how it is documented.

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
       The typed ``LocalMFAChallenge`` contains ``code="mfa_required"``,
       ``detail``, ``account_id``, ``challenge``, ``expires_at``, and
       ``methods``.
   * - ``429``
     - The operation exceeded its rate limit. Carries ``Retry-After`` when the
       limiter reports one. See :doc:`rate-limiting`.
   * - ``503``
     - An application-supplied dependency was unavailable. Security decisions
       fail closed, so this never means the request was allowed.

What an error body looks like
-----------------------------

Two different things produce a non-success status, and they produce different
bodies. The distinction is raised versus returned, not error versus success.

A **raised** status — ``400``, ``401``, ``429``, ``503``, and the OAuth
``409`` — never reaches the handler's return value. It travels through the
application's exception handling, so the body is
:class:`~litestar_security.RouteError`: the status repeated inside the payload,
a human-readable ``detail``, and ``extra`` when the failure carries structured
context. A request-validation failure always carries one, listing the members
it rejected.

.. code-block:: json

   {"status_code": 401, "detail": "Authentication required."}

A **returned** status is a value the handler produced, so its schema is the
handler's own type and no exception handling touches it. That covers every
``2xx``, the typed ``403`` second-factor challenge above, and the ``409``
conflict raised when a change would remove an account's last login method.

Registering your own error format on the application reaches the generated
routes, including the OAuth ones:

.. code-block:: python

   Litestar(exception_handlers={HTTPException: my_error_format}, ...)

When that format changes the body schema or media type, declare both on the
security configuration so generated clients receive the same contract:

.. code-block:: python

   from litestar_security import RaisedErrorSchema, SecurityConfig, SecurityPlugin

   SecurityPlugin(
       SecurityConfig(
           raised_error_schema=RaisedErrorSchema(
               schema=ApplicationError,
               media_type="application/vnd.example.error+json",
           ),
       ),
   )

The declaration only restates statuses generated handlers raise. Typed values
they return, including second-factor challenges and conflicts, retain their own
schemas. It also suppresses the customized-response-class warning because the
application has supplied the missing OpenAPI contract; runtime exception
handling remains entirely application-owned.

Problem details
~~~~~~~~~~~~~~~

An application can install Litestar's problem-details plugin and ask it to
convert every HTTP exception:

.. code-block:: python

   from litestar.plugins.problem_details import ProblemDetailsConfig, ProblemDetailsPlugin

   Litestar(
       plugins=[
           SecurityPlugin(config),
           ProblemDetailsPlugin(ProblemDetailsConfig(enable_for_all_http_exceptions=True)),
       ],
   )

Every raised status then arrives as ``application/problem+json`` carrying
:class:`~litestar_security.ProblemDetail`, and the published document says so.
Note what Litestar's conversion actually emits, which is not the :rfc:`9457`
five-member shape: the raised explanation moves to ``title``, ``detail`` falls
back to the HTTP reason phrase, structured context carries through as
``extra``, and ``type`` and ``instance`` are never produced.

.. code-block:: json

   {"status": 401, "title": "Authentication required.", "detail": "Unauthorized"}

``ProblemDetailsPlugin()`` on its own converts nothing. Its default
configuration registers a handler for ``ProblemDetailsException`` alone, which
the generated routes never raise, so the responses and the document both stay
exactly as they were. Returned statuses are unaffected in either mode.

If the application installs a response class of its own — its own, or one a
presentation plugin contributes — the generated routes warn once at startup,
naming the class. The documented schemas describe what the handlers return, and
a response class that reshapes the body makes them inaccurate. It is a warning
rather than an error: a customized response class is legitimate. A complete
``RaisedErrorSchema`` declaration suppresses the warning and restates every
raised denial using its schema and media type.

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
