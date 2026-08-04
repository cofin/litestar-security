Changelog
=========

Unreleased
----------

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
* ``OIDCSessionLogoutStore`` now owns atomic back-channel ``jti`` replay
  consumption. ``revoke_frontchannel()`` additionally requires the caller's
  browser-binding digest and returns ``int | None`` so a rejected binding is
  distinguishable from a successful zero-session revocation. Custom stores must
  implement the widened protocol.
* WebSocket connect-token stores and callers must preserve the account
  ``security_epoch``. Issuance requires the epoch, and consumption requires an
  authoritative asynchronous epoch callback so a burned token cannot establish
  a connection after account-wide revocation.
* Argon2, TOTP, and WebAuthn are no longer installed by the core distribution.
  Applications using local passwords, MFA, or passkeys must install
  ``litestar-security[argon2]``, ``litestar-security[mfa]``, or
  ``litestar-security[passkeys]`` respectively; ``litestar-security[all]``
  installs every optional feature.

Added
~~~~~

* ``WireStruct``, the shared base carrying that convention, is exported from the
  package root so applications can define their own schemas on the same
  casing and strictness policy.
* ``litestar_security.typing`` exposes dependency-availability flags and
  ``require_dependency``, which raises where a capability is used and names the
  distribution to install. The flags resolve when they are read, so importing
  the module never imports what it describes.
* Typed ``SecureController`` and ``PublicController`` base classes compile an
  ``auth`` ``ClassVar`` into native Litestar route metadata, with explicit
  precedence and bypass-conflict validation.
* ``exclude()`` is a first-class authentication policy for routes that bypass
  the security evaluator while retaining ordinary CSRF derivation. It rejects
  contradictory authentication policy at application startup.
* ``LocalKeyRing`` can mint and verify bounded, purpose-specific capability
  JWTs for application-owned flows such as signed download URLs.
* ``MFAConfig.require_at_login`` adds password-login MFA completion routes:
  ``POST /auth/login/mfa`` and ``POST /auth/token/mfa``. A verified password can
  now return the typed ``MFARequired`` outcome backed by an atomic,
  digest-only, reveal-once ``MFALoginChallengeStore``.
* ``HttpxJWKSFetcher`` provides a default bounded httpx transport with ETag
  revalidation, redirect and environment-proxy refusal, public-address
  validation, injectable DNS/transport seams, and owned-client lifecycle.
* ``forwarded_client_key()`` derives rate-limit keys from explicitly trusted
  proxy CIDRs using a bounded right-to-left ``X-Forwarded-For`` walk and safe
  peer fallback.
* ``AESGCMSecretProtector`` and ``AESGCMOAuthTransactionProtector`` provide
  versioned, non-deterministic authenticated encryption with associated-data
  binding for MFA secrets and OAuth transaction/vault state.
* ``WebSocketConnectTokenIssuer`` resolves a named WebSocket handler's compiled
  security plan and mints a policy-bound connect token through the
  ``websocket_connect_tokens`` dependency.
* ``InMemoryLocalAccountStore`` and ``InMemorySecurityBackend.accounts`` provide
  deterministic references for local-account, native-session, refresh-family,
  registration, recovery, purpose-token, and login-method ports. The aggregate
  backend exposes separate MFA, passkey, OAuth/OIDC, API-key, and WebSocket
  reference attributes.
* ``litestar_security.testing`` now exports reference resolvers, revocation
  sources, and conformance helpers for the shipped atomic security contracts and
  protectors. ``StoreConformanceFactories`` and
  ``assert_security_backend_conformance`` run an application's selected
  backend scenarios.
* ``StepUpOAuthAuthorizer`` bridges OAuth link/unlink operations to local
  step-up grants. The OAuth testing surface also includes an encrypted
  revocation-retry store and atomic OIDC session-logout references.

Security
~~~~~~~~

* Bearer and session assurance is anchored to the original authentication
  time, preserves evidence expiry through session establishment, and fails
  closed when a token omits or corrupts the required freshness claims.
* Recovery-code digests are account-bound. Passkey counters remain monotonic
  from zero, clone-risk state cannot be silently cleared, and the attestation
  trait is set only after cryptographic chain verification.
* Discovered OIDC authorization, token, and end-session endpoints must share the
  issuer origin or appear in ``allowed_oauth_origins``. OAuth token and
  revocation requests pin a freshly resolved public IP while retaining the
  original HTTP Host and TLS SNI, reject mixed/private DNS answers, compression,
  redirects, and oversized responses, and keep JWKS trust separate. GitHub
  profile responses are independently bounded and reject compression.
* WebSocket connect tokens carry the account security epoch and revalidate it
  after atomic consumption. Policy fingerprints use a versioned canonical JSON
  encoding rather than representation-dependent values.
* Static security headers are backfilled onto error responses as well as
  successful responses. Dynamic nonce CSP replaces stale/conflicting response
  values deterministically, ``SecurityHeadersConfig.hardened()`` supplies an
  opt-in baseline, and notification destinations reject control characters.
* Front-channel OIDC logout is browser-binding aware and rate limited. Security
  evaluators and generated routes classify application-port failures and fail
  closed without exposing provider or credential details.

Changed
~~~~~~~

* ``litestar_security.accounts`` and ``litestar_security.websocket`` were
  reorganized internally. Unrenamed account and configuration imports remain
  available from their documented package exports: account wire schemas and
  generated controllers moved into ``schemas`` and ``controllers``
  sub-packages, and the WebSocket module became a package of layered modules.
  The worker budget, metrics port, and blocking-call bridge now live in
  ``litestar_security.workers``; ``litestar_security.config`` re-exports them.
* OAuth now has a formal zero-dependency ``oauth`` feature marker. Core and
  ``accounts`` imports remain usable when optional feature packages are absent;
  accessing an unavailable feature raises an actionable installation error.
* ``RateLimiter.acquire()`` now promises exact atomic admission. The reference
  ``StoreRateLimiter`` serializes complete multi-bucket accounting across
  instances in one process and documents that applications need an atomic
  backend for multi-process deployment.
* The default local-account rate-limit map is exhaustive and deny-by-default,
  covering factor removal, verification confirmation, OAuth logout, and
  step-up operations. Recovery and verification requests equalize durable-store
  work for absent and present identifiers.
* Authorization resolution only narrows credential-derived team roles, verifier
  caches share configured worker budgets, and local password reauthentication
  checks current account state and security epoch.
* Public routes remain excluded from native CSRF unless they declare
  ``csrf_required=True``; authentication bypass routes retain ordinary CSRF
  derivation instead of inheriting the public-route exception.

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
