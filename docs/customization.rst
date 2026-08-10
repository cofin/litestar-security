Customization and application ownership
=======================================

Core integration ports are deliberately small and atomic. Implement the
protocols needed by the selected feature, then run the matching helpers from
``litestar_security.testing``. ``InMemorySecurityBackend`` and deterministic
provider transports are references for tests and examples, not production
persistence.

Verify your backend
===================

Pass a fresh, isolated instance of each application-owned atomic port to its
matching conformance helper. The in-memory backend is a deterministic reference
for the store contracts; it is not a production persistence implementation.

.. list-table::
   :header-rows: 1
   :widths: 30 42 28

   * - Protocol
     - Conformance helper
     - Reference
   * - ``APIKeyStore``
     - :func:`~litestar_security.testing.assert_api_key_store_conformance`
     - ``InMemorySecurityBackend.api_keys``
   * - ``LocalAccountCapabilities``
     - :func:`~litestar_security.testing.assert_local_account_store_conformance`
     - ``InMemorySecurityBackend.accounts``
   * - ``MFALoginChallengeStore``
     - :func:`~litestar_security.testing.assert_mfa_login_challenge_store_conformance`
     - ``InMemorySecurityBackend.mfa_login``
   * - ``MFAStore``
     - :func:`~litestar_security.testing.assert_mfa_store_conformance`
     - ``InMemorySecurityBackend.mfa``
   * - ``OIDCSessionLogoutStore``
     - :func:`~litestar_security.testing.assert_oidc_session_logout_store_conformance`
     - ``InMemoryOIDCSessionLogoutStore`` with the documented seed
   * - ``OAuthAccountStore``
     - :func:`~litestar_security.testing.assert_oauth_account_store_conformance`
     - ``InMemorySecurityBackend.oauth_accounts``
   * - ``OAuthTransactionStore``
     - :func:`~litestar_security.testing.assert_oauth_transaction_store_conformance`
     - ``InMemorySecurityBackend.oauth_transactions``
   * - ``PasskeyStore``
     - :func:`~litestar_security.testing.assert_passkey_store_conformance`
     - ``InMemorySecurityBackend.passkeys``
   * - ``RefreshTokenFamilyStore``
     - :func:`~litestar_security.testing.assert_refresh_family_store_conformance`
     - ``InMemorySecurityBackend.accounts``
   * - ``SessionRegistry``
     - :func:`~litestar_security.testing.assert_session_registry_conformance`
     - ``InMemorySecurityBackend.accounts``
   * - ``StepUpStore``
     - :func:`~litestar_security.testing.assert_step_up_store_conformance`
     - ``InMemoryStepUpStore``
   * - ``OAuthAccountStore``
     - OAuth account-store conformance helpers
     - ``MemoryOAuthAccountStore`` with an AEAD protector
   * - ``WebAuthnChallengeStore``
     - :func:`~litestar_security.testing.assert_webauthn_challenge_store_conformance`
     - ``InMemorySecurityBackend.challenges``
   * - ``WebSocketConnectTokenStore``
     - :func:`~litestar_security.testing.assert_websocket_connect_token_store_conformance`
     - ``InMemorySecurityBackend.websocket_connect_tokens``

For example, supply only the capabilities that the application implements. A
factory must return a new store each time so the isolation checks can detect
shared state:

.. code-block:: python

   from litestar_security.testing import (
       InMemoryMFAStore,
       InMemorySecurityBackend,
       StoreConformanceFactories,
       assert_security_backend_conformance,
   )


   async def verify_backend() -> None:
       await assert_security_backend_conformance(
           StoreConformanceFactories(
               api_key_store=lambda: InMemorySecurityBackend().api_keys,
               mfa_store=InMemoryMFAStore,
           )
       )

Rate limiters use the standalone
:func:`~litestar_security.testing.assert_rate_limiter_conformance` helper,
because their factory is not a security-store factory.

The OIDC logout helper requires each fresh factory to seed two matching local
session mappings, one unrelated mapping, and the exact front-channel browser
binding described by the helper docstring. This fixed scenario makes replay,
ownership, binding, and contention results portable across backends.

``InMemoryOAuthRevocationRetryStore`` is an encrypted retry-persistence
reference, not a universal conformance scenario: the retry protocol deliberately
does not expose stored payloads. It accepts an ``OAuthTransactionProtector`` and
exposes only immutable, secret-free failure metadata.

Testing-only resolver and WebSocket lifetime references keep examples small:

.. code-block:: python

   from litestar_security import Principal
   from litestar_security.context import AuthorizationSnapshot
   from litestar_security.testing import (
       InMemoryWebSocketRevocationSource,
       StaticAuthorizationResolver,
       StaticAuthorizationSnapshotRefresher,
       StaticIdentityResolver,
   )


   identity = StaticIdentityResolver(Principal(id="test-user"))
   authorization = StaticAuthorizationResolver(
       AuthorizationSnapshot(scopes={"reports:read"})
   )
   revocations = InMemoryWebSocketRevocationSource()
   refresher = StaticAuthorizationSnapshotRefresher(
       AuthorizationSnapshot(scopes={"reports:read"})
   )

These deterministic objects are for tests and examples, not production identity
resolution, authorization, or cross-worker revocation delivery.

Async implementations stay on the event loop. Wrap a complete synchronous port
in ``BlockingIntegration`` so the runtime can use the configured bounded worker
budget. Do not wrap individual calls or perform hidden blocking I/O in async
methods.

Litestar Security does not install a general administrator API. The
``custom-admin`` example owns a controller and applies application guards while
orchestrating disable, forced reset, and credential/factor/session/key
revocation services:

.. code-block:: console

   LITESTAR_SECURITY_EXAMPLE=custom-admin uv run litestar --app examples.app:create_app run

Provider HTTP transports, delivery commands, audit sinks, metrics, rate-limit
stores, user resolution, role/team/tenant snapshots, and key-management clients
remain application choices.
