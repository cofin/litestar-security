Changelog
=========

0.2.0
-----

Changed (breaking)
~~~~~~~~~~~~~~~~~~

* Every generated ``/auth`` body is now ``snake_case``. The MFA, passkey,
  step-up, and OAuth provider routes previously used camel-case members on both
  requests and responses: ``stepUpGrant``, ``methodId``, ``enrollmentId``,
  ``userName``, ``accountId``, ``providerAccountId``, ``credentialId``,
  ``displayName``, ``createdAt``, ``lastUsedAt``, ``expiresAt``,
  ``provisioningUri``, ``backupEligible``, ``backupState``, and ``returnTo``
  are now spelled with underscores. Local account, session, token, and password
  routes were already ``snake_case`` and are unchanged.
* Every generated ``/auth`` body now rejects a member it does not model with a
  ``400``. Previously an unrecognized field was silently discarded, so a client
  on a stale spelling of an optional field received a successful response with
  the field's default rather than an error.
* Six MFA and passkey routes advertised ``201 Created`` while returning
  ``200 OK``, and the OAuth revoke and logout routes returned ``201`` for
  operations that create nothing. Every route now declares the status it
  returns. Enrolling a TOTP factor and registering a passkey still return
  ``201``.
* The three removal routes moved from ``DELETE`` with a request body to
  ``POST``, since the step-up grant they require travels in that body:
  ``POST /auth/mfa/totp/{method_id}/remove``,
  ``POST /auth/passkeys/{credential_id}/remove``, and
  ``POST /auth/oauth/{provider}/links/{provider_account_id}/unlink``.
* The body those three share, and the recovery-code replacement body, was named
  ``RecoveryCodesRequest`` even where no recovery code was involved. It is now
  ``StepUpAuthorizedRequest``.
* ``LocalRouteResponse`` and ``MFAStatusResponse`` were identical single-field
  bodies and are replaced by one ``RouteStatusResponse``.
* The OAuth lifecycle response carried three unrelated values in
  ``provider_account_id``: the provider account, the local account, and a count
  of revoked sessions rendered as a string. These are now
  ``provider_account_id``, ``account_id``, and ``revoked_sessions``, and a
  response omits the members its operation did not resolve.

Added
~~~~~

* ``WireStruct``, the shared base carrying that convention, is exported from the
  package root so applications can define their own schemas on the same
  casing and strictness policy.

0.1.0
-----

Added
~~~~~

* Typed principal/context/session runtime, authentication policy, authorization
  guards, native OpenAPI, and strict failure outcomes.
* Explicit local session, token, and hybrid account lifecycle with rotating
  refresh families, MFA, passkeys, step-up, rate limiting, and generated routes.
* OAuth/OIDC, Google IAP, GitHub, Keycloak, opaque API-key, external workload
  JWT, team/tenant, and WebSocket integrations.
* Local signing/JWKS, strict discovery, bounded remote rotation, optional CSP,
  native security headers, conformance helpers, deterministic examples, and
  complete release automation.

Deferred
~~~~~~~~

* DPoP.
* Production mTLS.
* Full Keycloak UMA.
