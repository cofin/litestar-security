---
name: providers
description: Use when editing JWT, CompositeBearerConfig, JWKS, APIKeyConfig, GoogleIAPConfig, OAuthConfig, OIDCProvider, or ServiceTokenConfig. Not for local accounts or WebSocket tokens.
---

# Token, Assertion, & Federated Identity Providers

Domain skill for `src/litestar_security/providers/{jwt,jwks,api_key,iap,oauth,oidc}/`.

## Canonical Modules & Seams

- **JWT & Composite Bearer (`providers/jwt/`)**: `JWTValidationConfig` (`_claims.py`), `PyJWTVerifier` (`_verification.py`), `LocalKeyRing` & `VerificationKeySet` (`_keyring.py`), `CompositeBearerConfig`, `BearerTokenSlot`, `BearerSlotSelector`, `extend_composite_bearer` (`_bearer.py`).
- **JWKS Caching (`providers/jwks/`)**: `CachedJWKSProvider` (`_provider.py`), `InMemoryJWKSCache`, `JWKSCache`, `JWKSCachePolicy` (`_cache.py`), `HttpxJWKSFetcher` (`_httpx.py`).
- **API Keys (`providers/api_key/`)**: `APIKeyConfig`, `APIKeyCodec`, `APIKeyState`, `IssuedAPIKey`, `APIKeyStore`, `APIKeyUsageSink` (`_api_key.py`), `APIKeyService`, `BufferedAPIKeyUsage` (`_runtime.py`).
- **Google IAP (`providers/iap/`)**: `GoogleIAPConfig`, `GoogleIAPClaims`, `GoogleIAPExternalIdentity` (`_iap.py`).
- **OAuth & OIDC (`providers/oauth/`, `providers/oidc/`)**: `OAuthConfig`, `OAuthLifecycleService`, `OIDCLogoutLifecycleService` (`_routes.py`), `OAuthProviderClient`, `GitHubOAuthProvider` (`_provider.py`), `OAuthTransactionService`, `MemoryOAuthTransactionStore`, `OAuthRedirectPolicy`, `AESGCMOAuthTransactionProtector` (`_transactions.py`), `ProtectedResourceConfig` (`_resource_server.py`), `OIDCProvider`, `OIDCDiscoveryClient`, `DiscoveryPolicy`, `ServiceTokenConfig` (`oidc/`).

## Non-Negotiable Rules

<!-- truth: start -->
1. **`authorization.bearer` Slot Ownership & API-Key Prefix Coordination**:
   - `_BearerCredentialSlot` (`_bearer.py`) owns physical slot `"authorization.bearer"`; combine multiple JWT, service-token, or OIDC Bearer verifiers via `CompositeBearerConfig` / `extend_composite_bearer` with disjoint `BearerSlotSelector` discriminators (`issuers`, `audiences`, `token_types` — default `{"at+jwt", "application/at+jwt"}`).
   - Do **not** place `APIKeyConfig(accept_authorization_bearer=True)` inside `CompositeBearerConfig`: `_APIKeyCredentialSlot` retains physical slot `"api-key"` (`header_name.lower() != "authorization"`), `AuthenticationRegistry._coordinate_bearer_slots` (`authentication.py:635-663`) sets `f"{prefix}_"` on `_BearerCredentialSlot.excluded_prefixes` (or wraps custom Bearer slots in `_PrefixExcludingBearerSlot` at `authentication.py:667-690`), and `_plan_uses_bearer` (`authentication.py:1061-1074`) inspects `additional_security_schemes` (`APIKeyBearer`) so `ProtectedResourceConfig` emits RFC 9728 `WWW-Authenticate: Bearer resource_metadata="..."` on `401` challenges.
2. **JWKS Concurrency & Negative `kid` Caching**: `CachedJWKSProvider` reads fresh cached snapshots lock-free, coalesces concurrent cache-miss or unknown-`kid` refreshes under `asyncio.shield`, supports `stale_if_error`, and bounds generation-scoped unknown-`(kid, alg)` caching via `JWKSCachePolicy.maximum_unknown_keys: int = 1_024` (cleared when snapshot `generation` increments).
3. **API Key Format, Peppering, Bearer Coexistence, & Usage**:
   - Format: `<prefix>_<16-char-key_id>_<43-char-secret>`; `APIKeyService.issue` and `rotate` return reveal-once `IssuedAPIKey(key_id=..., value=...)`.
   - `APIKeyCodec` and `APIKeyConfig` accept a single 32+-byte `pepper: bytes`, compute domain-separated HMAC-SHA256 digests (`APIKeyProof`), and compare against `APIKeyState.digest` with `hmac.compare_digest`.
   - `APIKeyConfig.__post_init__` rejects `header_name.lower() == "authorization"` unconditionally; when `accept_authorization_bearer=True`, conflicting tokens across `header_name` and `Authorization: Bearer <prefix>_...` fail authentication (`InvalidCredentials`).
   - `APIKeyUsageSink.record(key_id=..., used_at=...)` batches best-effort telemetry via `BufferedAPIKeyUsage`: `observe()` drops new keys when `len(_pending) >= self.capacity`, and `BufferedAPIKeyUsage.close()` / `APIKeyService.close()` flushes pending observations (`force=True`) on shutdown.
4. **Google IAP Pinning & Machine/SPIFFE Classification**: `GoogleIAPConfig` pins issuer `"https://cloud.google.com/iap"`, algorithm `"ES256"`, `token_types={"JWT"}`, and exact audiences while allowing configurable valid HTTP `header_name` (default `"X-Goog-IAP-JWT-Assertion"`). `GoogleIAPClaims.is_service_account` requires `external_identity is None`, `hosted_domain is None`, valid email, and domain equal to `"gserviceaccount.com"` or ending with `".gserviceaccount.com"`. `GoogleIAPClaims.spiffe_id` rejects `external_identity`, `?`, `#`, control/whitespace chars, empty or leading/trailing `.` authority, and empty, `.`, or `..` path segments (including trailing slashes).
5. **OAuth/OIDC SSRF Defenses & Transaction Sealing**:
   - Enforce HTTPS with `follow_redirects=False` and `trust_env=False`: `OAuthProviderClient._pinned_endpoint` resolves DNS and rewrites the request URL host to the literal public IP with `Host` and `extensions={"sni_hostname": hostname}` (no private-network opt-out); `HttpxJWKSFetcher` and `OIDCDiscoveryClient` (`DiscoveryPolicy`) validate resolved public IPs unless `allow_private_hosts: bool = False` is set `True`, then stream the original HTTPS URL.
   - `OAuthTransactionService` HMAC-SHA256 digests `state` and `browser_binding` and stores validated `return_to` plaintext (`OAuthRedirectPolicy` permits safe relative `/` non-`//` paths or exact HTTPS origins matching `callback_uris`), while `MemoryOAuthTransactionStore` seals only `pkce_verifier` and `nonce` via `OAuthTransactionProtector` (`AESGCMOAuthTransactionProtector`) and consumes atomically once via `OAuthTransactionStore.consume`.
<!-- truth: end -->

## Verification Commands

```bash
uv run pytest src/tests/unit/test_providers/ -q
uv run pytest src/tests/integration/test_oauth_routes.py src/tests/integration/test_resource_server.py src/tests/integration/test_authentication_composition.py -q
uv run slotscheck src/litestar_security/
```

## References

- [Implementation Checklist](./references/checklist.md)
- [False-Positive Suppressions](./references/false-positive-suppressions.md)
- [Accounts & Federation Domain](../../bundles/knowledge/domains/accounts-and-federation.md)
- [Provider & Store Ports](../../bundles/knowledge/architecture/provider-and-store-ports.md)
