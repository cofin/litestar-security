Changelog
=========

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
