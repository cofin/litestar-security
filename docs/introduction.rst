Introduction
============

Litestar Security provides typed, backend-agnostic security primitives for
Litestar applications. The project remains pre-alpha while the initial runtime
is implemented chapter by chapter.

What exists
-----------

The current runtime provides:

* an installable ``litestar-security`` distribution;
* a typed ``litestar_security`` package;
* typed principal, security-context, session, and authentication outcomes;
* composable authentication policies and authorization guards;
* native Litestar plugin, middleware, dependency, and OpenAPI integration;
* explicit local JWT signing and public JWKS;
* strict OIDC discovery and bounded remote JWKS rotation;
* a ``litestar security`` CLI group; and
* development, test, documentation, and build automation.

What does not exist
-------------------

Provider login and callback flows, local account/password management, OAuth
grants, API keys, service authentication, team membership, and administrative
workflows are not implemented yet. The core does not choose a database,
identity model, key store, or HTTP transport for the application.
