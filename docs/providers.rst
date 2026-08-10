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

Team authorization
------------------

Once authentication and authorization resolution are configured, a guard can
check the team named by the route:

.. code-block:: python

   from litestar import get

   from litestar_security import require_team_role, required


   @get(
       "/teams/{team_id:str}",
       auth=required(),
       guards=[require_team_role(team_parameter="team_id", roles={"owner"})],
   )
   async def team_settings(team_id: str) -> dict[str, str]:
       return {"team_id": team_id}

The guard compares the path value with the server-resolved authorization
snapshot. A client cannot gain access by changing ``team_id``.

See :doc:`jwt-and-jwks` for local signing, OIDC discovery, remote keys, and
rotation. The repository's ``api-team-service`` example combines an API key,
a workload JWT, and team authorization.
