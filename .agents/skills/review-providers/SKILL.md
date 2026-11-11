---
name: review-providers
description: Use when reviewing changes to JWT, CompositeBearerConfig, JWKS, APIKeyConfig, GoogleIAPConfig, OAuthConfig, OIDCProvider, or ServiceTokenConfig. Not for local account or WebSocket reviews.
---

# Review Skill: Token, Assertion, & Federated Identity Providers

Review capability skill for auditing changes in `src/litestar_security/providers/{jwt,jwks,api_key,iap,oauth,oidc}/` and Bearer slot coordination in `src/litestar_security/authentication.py`.

## Review Invariants

<!-- truth: start -->
- **JWT & Composite Bearer (`PRV-01`, `PRV-02`)**: Require explicit non-empty `JWTValidationConfig.algorithms` (`EdDSA`, `ES256`, `RS256`, `HS256`), reject `alg="none"` and forbidden JOSE headers, require default `{"iss", "sub", "aud", "exp", "iat"}` (plus `client_id`/`jti` when `access_token_profile=True`), and dispatch multi-issuer Bearer tokens via `CompositeBearerConfig` / `BearerSlotSelector` (`issuers`, `audiences`, `token_types`). Keep `APIKeyConfig(accept_authorization_bearer=True)` on `"api-key"`, coordinated by `AuthenticationRegistry._coordinate_bearer_slots` (`_PrefixExcludingBearerSlot` for custom slots) and `SecurityMiddleware._plan_uses_bearer` (`additional_security_schemes`).
- **JWKS & API Keys (`PRV-03`, `PRV-04`)**: Preserve lock-free fresh reads, `asyncio.shield` single-flight refresh, and generation-scoped `JWKSCachePolicy.maximum_unknown_keys` (`1_024`) bounds. Enforce single 32+-byte `pepper` on `APIKeyCodec`/`APIKeyConfig`, reject `header_name.lower() == "authorization"`, verify digests via `hmac.compare_digest` against `APIKeyState.digest`, and flush `BufferedAPIKeyUsage` on `close()` (dropping when `len(_pending) >= capacity`).
- **Google IAP & OAuth/OIDC SSRF (`PRV-05`, `PRV-06`, `PRV-07`)**: Pin `GoogleIAPConfig` to `ES256` and `https://cloud.google.com/iap` (configurable `header_name`, default `"X-Goog-IAP-JWT-Assertion"`), route JWKS-backed JWT verification through shared `jwks/_verification.py::verify_jwks_jwt` over `DynamicVerifierCache` and `PyJWTVerifier`, enforce strict `GoogleIAPClaims.spiffe_id` URI/authority/segment validation, digest OAuth `state`/`browser_binding` via HMAC-SHA256, seal `pkce_verifier`/`nonce` via `OAuthTransactionProtector`, enforce `OAuthProviderClient.stream_pinned` -> `OAuthProviderClient._pinned_endpoint` literal-IP pinning with `sni_hostname` across `OAuthProviderClient` and `GitHubOAuthProvider(..., resolver=...)`, and delegate `HttpxJWKSFetcher` / `OIDCDiscoveryClient` public-IP DNS and bounded streaming checks to `providers._internal.resolve_public_addresses` and `providers._internal.read_bounded_body` (`allow_private_hosts=False` default).
- **Coverage & Offline Isolation (`PRV-08`)**: Maintain `100%` branch coverage (`CORE_COVERAGE`) on `providers/jwt/*` and `providers/oauth/_transactions.py`, using `MockTransport`, `FakeOAuthHTTPTransport`, or `FakeOAuthProvider` with `FakeClock` instead of live network calls.
<!-- truth: end -->

## Review Protocol

1. **Inspect Modified Provider Modules & Tests**: Read the changed files under `src/litestar_security/providers/` (and `authentication.py` for slot coordination) plus tests in `src/tests/unit/` and `src/tests/integration/`.
2. **Audit Against Provider Checklist (`PRV-01`..`PRV-08`)**: Evaluate every item in [references/checklist.md](./references/checklist.md).
3. **Apply False-Positive Suppressions (`FP-PRV-01`..`FP-PRV-06`)**: Filter out intentional patterns documented in [references/false-positive-suppressions.md](./references/false-positive-suppressions.md).
4. **Run Verification Commands**:
   ```bash
   uv run pytest src/tests/unit/test_providers/ src/tests/integration/test_oauth_routes.py src/tests/integration/test_resource_server.py src/tests/integration/test_authentication_composition.py -q
   uv run slotscheck src/litestar_security/
   ```

## Required Finding Format

Report only verified findings with `path/to/file.py:line`, violated check ID (`PRV-XX`), exploit or regression scenario, and concrete fix.

## References

- [Review Checklist (`PRV-01`..`PRV-08`)](./references/checklist.md)
- [False-Positive Suppressions (`FP-PRV-01`..`FP-PRV-06`)](./references/false-positive-suppressions.md)
