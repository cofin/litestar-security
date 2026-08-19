Authentication providers
========================

Choose the provider that matches where identity is established:

* Local accounts support session, token, and hybrid applications.
* OAuth and OpenID Connect support browser sign-in and account linking.
* Google IAP verifies the assertion added by the IAP proxy for one exact
  audience.
* API keys authenticate service clients from a digest-only application store.
* Workload JWTs authenticate non-user services through a pinned issuer,
  audience, and JWKS endpoint.

Adding a provider makes its authentication mechanism available. Route policy
decides where it is accepted, and an application ``authorization_resolver``
loads scopes, roles, capabilities, teams, and tenants for the verified
principal.

OAuth transaction and token protection
--------------------------------------

The in-memory OAuth references require an ``OAuthTransactionProtector`` so
that the PKCE verifier, nonce, and refreshable provider tokens are not kept as
plaintext. The first-party AES-256-GCM protector supplies that port to the
transaction store and aggregate account store:

.. code-block:: python

   from litestar_security.providers.oauth import (
       AESGCMOAuthTransactionProtector,
       MemoryOAuthAccountStore,
       MemoryOAuthTransactionStore,
       OAuthTransactionProtectorKey,
   )


   protector = AESGCMOAuthTransactionProtector(
       active_key=OAuthTransactionProtectorKey(
           "v2",
           application_secret_store.get_bytes("oauth-transaction-protector/v2"),
       ),
       retained_keys=(
           OAuthTransactionProtectorKey(
               "v1",
               application_secret_store.get_bytes("oauth-transaction-protector/v1"),
           ),
       ),
   )
   transactions = MemoryOAuthTransactionStore(protector=protector)
   accounts = MemoryOAuthAccountStore(
       provider="github",
       client_id="github-client-id",
       protector=protector,
   )

The values returned by ``application_secret_store`` are application-owned,
exactly 32-byte key material from a KMS or secret store, never hard-coded
literals. During rotation, retain the previous key before making the new key
active, then remove it only after envelopes under the earlier version have
expired or been replaced.

An application may instead supply its own protector. Run
:func:`~litestar_security.testing.assert_oauth_transaction_protector_conformance`
against a fresh instance factory to verify the public protection contract.

``OAuthAccountStore`` is the durable application boundary for provisioning,
exact identity linking, grants, retained tokens, refresh compare-and-swap, and
revocation retry staging. Implement each operation as one database transaction;
the library ships no ORM or database-specific adapter.

Provider confirmation
~~~~~~~~~~~~~~~~~~~~~

``POST /auth/oauth/{provider}/revalidate`` confirms that the browser still
controls the exact identity linked to the local account. It does not assert
fresh authentication and cannot issue a step-up credential.

``POST /auth/oauth/{provider}/reauthenticate/{purpose}`` is available only for
providers implementing ``OAuthReauthenticationProvider`` and purposes present
in that provider's ``OIDCReauthenticationPolicy`` mapping. OIDC reauthentication
uses ``max_age`` (zero forces authentication), requires signed ``auth_time``,
and checks the configured ACR and AMR requirements before issuing a one-use,
purpose-bound ``StepUpCredential``. GitHub account selection is not fresh
authentication and therefore cannot provide this capability.

Use ``discover_oidc_provider()`` or ``discover_google_oidc_provider()`` when the
application owns shared ``OIDCDiscoveryClient`` and ``JWKSProvider`` resources.
The returned provider owns only its OAuth HTTP client; closing it does not close
the shared discovery or JWKS resources.

Tenant authorization
--------------------

Once authentication and authorization resolution are configured, a guard can
check the tenant named by the route:

.. code-block:: python

   from litestar import get

   from litestar_security import requires_tenant_role, required


   @get(
       "/tenants/{tenant_id:str}",
       auth=required(),
       guards=[requires_tenant_role(tenant_parameter="tenant_id", roles={"owner"})],
   )
   async def tenant_settings(tenant_id: str) -> dict[str, str]:
       return {"tenant_id": tenant_id}

The guard compares the path value with the server-resolved authorization
snapshot. A client cannot gain access by changing ``tenant_id``.

See :doc:`jwt-and-jwks` for local signing, OIDC discovery, remote keys, and
rotation. The repository's ``api-tenant-service`` example combines an API key,
a workload JWT, and tenant authorization.
