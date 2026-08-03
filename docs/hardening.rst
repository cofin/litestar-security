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
nonces, refresh tokens, API keys, recovery codes, passkey challenges, or MFA
login challenges. Use shared atomic rate-limit, revocation, and MFA-login
challenge stores across workers and monitor verification-unavailable outcomes.

Before enabling ``MFAConfig.require_at_login`` in a deployment, enroll a viable
factor for every affected account and verify the completion routes with the
same CSRF and session middleware used in production. The MFA-login challenge
store must atomically burn a revealed challenge; a process-local implementation
is suitable only for a single worker. Treat the reveal-once challenge and the
completion proof like passwords: keep both out of application, proxy, and
audit logs.
