Hardening and operations
========================

Browser sessions require native CSRF coverage. Static security headers use
Litestar's native response-header configuration. Optional CSP has no guessed
allowlist: applications provide every directive. Static CSP adds no send hook;
nonce CSP generates at least 128 random bits per response and uses one native
``before_send`` hook. Report-only mode emits the standard report-only header.
No CSP report collector is included.

Pin issuer, audience, algorithms, redirect URIs, discovery origins, JWKS URLs,
network egress, and IAP ingress. JWKS fresh hits are lock-free; misses use
single-flight refresh, bounded documents, negative caching, stale policy, and
explicit sync-worker normalization. Keep retired verification keys through the
maximum issued-token lifetime.

Store private keys, peppers, OAuth client secrets, session secrets, and
attestation roots in application secret management. Never log raw credentials,
nonces, refresh tokens, API keys, recovery codes, or passkey challenges. Use
shared atomic rate-limit and revocation stores across workers and monitor
verification-unavailable outcomes.

The three intentional post-1.0 deferrals are DPoP, production mTLS, and full
Keycloak UMA. No other deferred integration is implied.
