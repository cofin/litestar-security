Hardening and operations
========================

Browser sessions require native CSRF coverage. Static security headers use
Litestar's native response-header configuration and are backfilled onto every
response, including framework error responses. Use
``SecurityHeadersConfig.hardened()`` as the recommended opt-in baseline for
HSTS, frame, content-type, and referrer protection; a handler that explicitly
sets a configured header keeps its value. Optional CSP has no guessed
allowlist: applications provide every directive. Static CSP adds no send hook;
nonce CSP generates at least 128 random bits per response and uses one native
``before_send`` hook. Report-only mode emits the standard report-only header.
No CSP report collector is included.

``auth=public()`` excludes a stateless route from native CSRF. Public handlers
that establish cookie-authenticated state must instead declare
``csrf_required=True``. Conversely, ``auth=exclude()`` bypasses authentication
only: session-capable excluded routes retain their derived CSRF coverage.

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

MFA and OAuth transaction protectors also use application-owned AES-256-GCM
key material. Load each exact 32-byte key from a KMS or secret store rather
than placing it in source code. Construct ``AESGCMSecretProtector`` for
``MFAConfig.secret_protector`` and ``AESGCMOAuthTransactionProtector`` for the
OAuth transaction store and token vault. Rotate without invalidating still-live
envelopes: add the former active ``SecretProtectorKey`` or
``OAuthTransactionProtectorKey`` to ``retained_keys`` before promoting a new
``active_key``. An application-owned replacement can be checked with
:func:`~litestar_security.testing.assert_secret_protector_conformance` or
:func:`~litestar_security.testing.assert_oauth_transaction_protector_conformance`.

Before enabling ``MFAConfig.require_at_login`` in a deployment, enroll a viable
factor for every affected account and verify the completion routes with the
same CSRF and session middleware used in production. The MFA-login challenge
store must atomically burn a revealed challenge; a process-local implementation
is suitable only for a single worker. Treat the reveal-once challenge and the
completion proof like passwords: keep both out of application, proxy, and
audit logs.
