Changelog
=========

Unreleased
----------

Added
~~~~~

* Typed ``SecureController`` / ``PublicController`` base classes compile their
  ``auth`` ``ClassVar`` into native ``opt``.
* ``LocalKeyRing`` can mint and verify bounded, purpose-specific capability
  JWTs for application-owned flows such as signed download URLs.
* ``MFAConfig.require_at_login`` adds password-login MFA completion routes:
  ``POST /auth/login/mfa`` (``LocalSessionMFALogin``) and
  ``POST /auth/token/mfa`` (``LocalTokenMFALogin``). A verified password now
  returns the typed ``MFARequired`` / ``LocalMFARequiredResponse`` outcome when
  completion is required. ``MFALoginChallengeStore`` and the testing-only
  ``InMemoryMFALoginChallengeStore`` provide the atomic, digest-only,
  reveal-once challenge boundary.

0.2.0
-----

Changed (breaking)
~~~~~~~~~~~~~~~~~~

* ``intersect_authorization`` is renamed ``resolve_authorization``. The old name
  described the implementation rather than the result, and ``resolve_`` matches
  the naming the rest of the surface uses. No alias ships for the old name.
* The WebSocket ticket family is renamed for what it authorizes, because the
  library already issues access and refresh tokens to users and "ticket" gave no
  clue which kind of value one was:

  .. list-table::
     :header-rows: 1

     * - Before
       - After
     * - ``WebSocketTicketRecord``
       - ``WebSocketConnectTokenRecord``
     * - ``IssuedWebSocketTicket``
       - ``IssuedWebSocketConnectToken``
     * - ``WebSocketTicketStore``
       - ``WebSocketConnectTokenStore``
     * - ``WebSocketTicketService``
       - ``WebSocketConnectTokenService``
     * - ``InMemoryWebSocketTicketStore``
       - ``InMemoryWebSocketConnectTokenStore``
     * - ``WebSocketTicketUnavailableError``
       - ``WebSocketConnectTokenUnavailableError``
     * - ``issue_websocket_ticket()``
       - ``issue_websocket_connect_token()``

* Fields on public WebSocket types move with that rename, so an application
  constructing them by keyword must be updated: ``WebSocketHandshake.ticket``
  becomes ``.connect_token``, ``WebSocketConnectTokenRecord.ticket_id`` becomes
  ``.connect_token_id``, and ``WebSocketSecurityConfig.ticket_store``,
  ``.ticket_ttl``, ``.maximum_ticket_ttl`` and ``.ticket_query_parameter`` take
  the matching ``connect_token`` names.
* Three WebSocket values on the wire change with the name. The handshake query
  parameter defaults to ``connect_token`` rather than ``ticket``, so a browser
  that builds the URL itself sends the new name unless the application sets
  ``connect_token_query_parameter`` back to ``ticket``. The issued credential is
  prefixed ``wsct.`` rather than ``wst.``. The HMAC domain separator becomes
  ``litestar-security/websocket-connect-token/v1``, which invalidates every
  stored digest; connect tokens are short-lived, so an in-flight credential
  fails closed and the client requests another. The evidence a connection
  records also reads ``websocket-connect-token``.
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
* ``litestar_security.typing`` exposes dependency-availability flags and
  ``require_dependency``, which raises where a capability is used and names the
  distribution to install. The flags resolve when they are read, so importing
  the module never imports what it describes.

Changed
~~~~~~~

* ``litestar_security.accounts`` and ``litestar_security.websocket`` were
  reorganized internally. Every public import path is unchanged: the account
  wire schemas and generated controllers moved into ``schemas`` and
  ``controllers`` sub-packages, and the WebSocket module became a package of
  layered modules. The worker budget, metrics port, and blocking-call bridge now
  live in ``litestar_security.workers``; ``litestar_security.config`` re-exports
  them, so the documented import path still resolves.

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
