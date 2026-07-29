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

Team authorization
------------------

Once authentication and authorization resolution are configured, a guard can
check the team named by the route:

.. code-block:: python

   from litestar import get

   from litestar_security import required, requires_team_role


   @get(
       "/teams/{team_id:str}",
       auth=required(),
       guards=[requires_team_role(team_parameter="team_id", roles={"owner"})],
   )
   async def team_settings(team_id: str) -> dict[str, str]:
       return {"team_id": team_id}

The guard compares the path value with the server-resolved authorization
snapshot. A client cannot gain access by changing ``team_id``.

See :doc:`jwt-and-jwks` for local signing, OIDC discovery, remote keys, and
rotation. The repository's ``api-team-service`` example combines an API key,
a workload JWT, and team authorization.
