---
type: Domain
title: "Accounts, Sessions, High-Assurance Auth, & Federation Domain"
description: "Lifecycle invariants for local accounts, dual-cookie sessions, refresh token families, purpose tokens, MFA, passkeys, step-up, and OAuth/OIDC."
status: stable
tags: [domains, accounts, sessions, refresh-tokens, mfa, passkeys, oauth, oidc]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: "agent:flow-setup"
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: accounts-init
    resource: "src/litestar_security/accounts/__init__.py"
    title: "Accounts domain exports: pure contracts, lazy controller exports, and instantiation-gated SDK adapters"
  - id: login-py
    resource: "src/litestar_security/accounts/_login.py::PasswordLoginService"
    title: "PasswordLoginService constant-work login and reauthentication verification"
  - id: session-py
    resource: "src/litestar_security/accounts/_sessions.py::NativeSessionAuth"
    title: "NativeSessionAuth dual-cookie session binding, __Host- validation, and touch throttling"
  - id: refresh-py
    resource: "src/litestar_security/accounts/_refresh.py::RefreshTokenService"
    title: "RefreshTokenService family rotation, REPLAY_DETECTED revocation, and receipt recovery"
  - id: receipts-py
    resource: "src/litestar_security/accounts/_receipts.py::RefreshReceiptSealer"
    title: "RefreshReceiptSealer AES-256-GCM sealing and _receipt_aad binding"
  - id: purpose-tokens
    resource: "src/litestar_security/accounts/_purpose_tokens.py::PurposeTokenCodec"
    title: "PurposeTokenCodec HMAC domain separation for invitation, verification, and recovery tokens"
  - id: mfa-py
    resource: "src/litestar_security/accounts/_mfa.py::MFAService"
    title: "MFAService, AESGCMSecretProtector, RecoveryCodePepper, and StepUpService"
  - id: mfa-login-py
    resource: "src/litestar_security/accounts/_mfa_login.py::MFALoginService"
    title: "MFALoginService digest-only second-factor login challenges"
  - id: passkeys-py
    resource: "src/litestar_security/accounts/_passkeys.py::PasskeyService"
    title: "PasskeyService single-use WebAuthn challenges and sign-count clone-risk policy"
  - id: recovery-py
    resource: "src/litestar_security/accounts/_recovery.py::RecoveryTokenService"
    title: "RecoveryTokenService and PasswordChangeService epoch-advancing password mutation"
  - id: registration-py
    resource: "src/litestar_security/accounts/_registration.py::VerificationTokenService"
    title: "RegistrationService and VerificationTokenService enumeration-resistant token flows"
  - id: oauth-tx
    resource: "src/litestar_security/providers/oauth/_transactions.py::MemoryOAuthTransactionStore"
    title: "MemoryOAuthTransactionStore PKCE/nonce sealing and OAuthRedirectPolicy validation"
  - id: oauth-provider
    resource: "src/litestar_security/providers/oauth/_provider.py::OAuthProviderClient"
    title: "OAuthProviderClient SSRF public-IP DNS pinning with sni_hostname rewrite"
  - id: oidc-discovery
    resource: "src/litestar_security/providers/oidc/_discovery.py::DiscoveryPolicy"
    title: "DiscoveryPolicy allowlist and allow_private_hosts outbound boundary"
  - id: jwks-httpx
    resource: "src/litestar_security/providers/jwks/_httpx.py::HttpxJWKSFetcher"
    title: "HttpxJWKSFetcher HTTPS guard and allow_private_hosts outbound boundary"
---

# Accounts, Sessions, High-Assurance Auth, & Federation Domain

<!-- truth: start -->
- **Pure Domain Contracts vs. Instantiation-Gated SDK Adapters**: `litestar_security.accounts` eagerly exports pure protocols, records, `AESGCMSecretProtector`, `StepUpService`, `PasskeyService` (usable without `webauthn` when given a custom `WebAuthnVerifier`), `LocalAuth` / `LocalAuthConfig` (usable without `argon2` when given a custom `PasswordHasher`), and the optional-extra adapter classes while keeping `_CONTROLLER_EXPORTS` lazy. Only instantiating `Argon2PasswordHasher`, `MFAService`, `MFALoginService`, or `PyWebAuthnVerifier` enforces `[argon2]`, `[mfa]`, or `[passkeys]`.[^accounts-init]
- **Dual-Cookie Session Binding & Fixed Expiry (`NativeSessionAuth`)**: Browser sessions pair Litestar's native session payload (`_litestar_security`) with an independent constant-time HMAC-bound `HttpOnly` cookie (`__Host-` names enforce `secure=True`, `path="/"`, `domain=None` via `SessionBindingConfig._validate_binding_cookie_scope`). `authenticate()` does not slide `expires_at` (`_valid_current_state` enforces `record.expires_at == authentication.expires_at`) and only updates `last_seen_at` via `accounts.touch()` throttled by `touch_interval`.[^session-py]
- **Refresh-Token Family Rotation & Store-Persisted Receipts (`RefreshTokenService`)**: Refresh tokens belong to a `family_id`. Replaying a consumed token without a matching `Idempotency-Key` header inside `receipt_window` (`<= timedelta(seconds=30)`) emits `RefreshRotationStatus.REPLAY_DETECTED` and revokes the entire `family_id`. On rotation, `RefreshReceiptSealer` (`AES-256-GCM`) seals `TokenPair` into store-persisted `sealed_receipt` bytes with `_receipt_aad` binding `(account_id, expiry, family_id, idempotency, key_id, security_epoch, token_id, version="rr1")` so retries with matching `RefreshTokenCodec.digest_idempotency_key` recover the original pair via `RefreshReceiptReplay`.[^refresh-py][^receipts-py]
- **Purpose Tokens vs. MFA Login Challenges**: `PurposeTokenCodec` binds `TokenPurpose` (`INVITATION`, `VERIFICATION`, `RECOVERY`) into HMAC-SHA256 digests consumed atomically via `RegistrationStore.register`, `VerificationTokenStore.consume_and_verify`, and `RecoveryTokenStore.consume_and_reset`. Second-factor password-login challenges use `MFALoginService` and `MFALoginChallengeStore`.[^purpose-tokens][^mfa-login-py]
- **MFA, Passkeys, & Step-Up (`MFAService`, `PasskeyService`, `StepUpService`)**: `AESGCMSecretProtector` encrypts TOTP secrets into `ProtectedSecret(ciphertext: bytes, key_version: str)` (`nonce + ciphertext`, no `"v1:"` ciphertext prefix) and `MFAService.consume_recovery_code` delegates HMAC digest verification (`RecoveryCodePepper`) to `MFAStore.consume_recovery_code`. `PasskeyService` evaluates `clone_risk = credential.sign_count > 0 and verified.sign_count <= credential.sign_count` (`CloneRiskPolicy.AUDIT_ONLY` records `clone_risk=True` and emits `OUTCOME_CLONE_RISK` without rejecting). `StepUpService` persists `StepUpGrantState(grant_digest, transport_digest, principal_id, security_epoch, purpose, methods, traits, authenticated_at, expires_at)` using `clock: Callable[[], datetime]`.[^mfa-py][^passkeys-py]
- **OAuth/OIDC Transactions & Outbound Network Pinning**: `MemoryOAuthTransactionStore` seals only `pkce_verifier` and `nonce` (`state` is HMAC-hashed; `return_to` is stored plaintext after `OAuthRedirectPolicy` validation) before atomic `OAuthTransactionStore.consume`. `OAuthProviderClient._pinned_endpoint` always enforces public IPs and connects directly with `extensions={"sni_hostname": sni_hostname}`, whereas `DiscoveryPolicy` and `HttpxJWKSFetcher` expose `allow_private_hosts: bool = False` without `sni_hostname` literal-IP connection rewrites.[^oauth-tx][^oauth-provider][^oidc-discovery][^jwks-httpx]
<!-- truth: end -->

## Account & Credential Enumeration Protection

Login (`PasswordLoginService.authenticate`, invoked by `LocalAuthService.session_login` and `LocalAuthService.token_login`) resolves identifiers via `AccountLookup.find_for_login` and executes dummy password verification (`hasher.verify(None, password)`) when absent so timing does not leak account existence.[^login-py] Password recovery (`RecoveryTokenService.request`) and verification resend (`VerificationTokenService.resend`) perform a parity `issue_absent()` call when no eligible account exists, swallow store/delivery exceptions, and return uniform `202 Accepted` (`LifecycleAccepted`) responses.[^recovery-py][^registration-py]

## Argon2 Worker Offloading & Audit Operations

`Argon2PasswordHasher` offloads CPU-bound hashing and verification through `_run_password_worker` bounded by `WorkerLimits.crypto_limiter`, preserving constant work across absent, mismatched, and malformed hashes. `LocalAuthConfig` instantiates `Argon2PasswordHasher` by default unless callers provide a custom `PasswordHasher`.[^accounts-init]

## References

[^accounts-init]: `src/litestar_security/accounts/__init__.py` — Accounts domain exports: pure contracts, lazy controller exports, and instantiation-gated SDK adapters
[^login-py]: `src/litestar_security/accounts/_login.py` — `PasswordLoginService` constant-work login and reauthentication verification
[^session-py]: `src/litestar_security/accounts/_sessions.py` — `NativeSessionAuth` dual-cookie session binding, `__Host-` validation, and touch throttling
[^refresh-py]: `src/litestar_security/accounts/_refresh.py` — `RefreshTokenService` family rotation, `REPLAY_DETECTED` revocation, and receipt recovery
[^receipts-py]: `src/litestar_security/accounts/_receipts.py` — `RefreshReceiptSealer` AES-256-GCM sealing and `_receipt_aad` binding
[^purpose-tokens]: `src/litestar_security/accounts/_purpose_tokens.py` — `PurposeTokenCodec` HMAC domain separation for invitation, verification, and recovery tokens
[^mfa-py]: `src/litestar_security/accounts/_mfa.py` — `MFAService`, `AESGCMSecretProtector`, `RecoveryCodePepper`, and `StepUpService`
[^mfa-login-py]: `src/litestar_security/accounts/_mfa_login.py` — `MFALoginService` digest-only second-factor login challenges
[^passkeys-py]: `src/litestar_security/accounts/_passkeys.py` — `PasskeyService` single-use WebAuthn challenges and sign-count clone-risk policy
[^recovery-py]: `src/litestar_security/accounts/_recovery.py` — `RecoveryTokenService` and `PasswordChangeService` epoch-advancing password mutation
[^registration-py]: `src/litestar_security/accounts/_registration.py` — `RegistrationService` and `VerificationTokenService` enumeration-resistant token flows
[^oauth-tx]: `src/litestar_security/providers/oauth/_transactions.py` — `MemoryOAuthTransactionStore` PKCE/nonce sealing and `OAuthRedirectPolicy` validation
[^oauth-provider]: `src/litestar_security/providers/oauth/_provider.py` — `OAuthProviderClient` SSRF public-IP DNS pinning with `sni_hostname` rewrite
[^oidc-discovery]: `src/litestar_security/providers/oidc/_discovery.py` — `DiscoveryPolicy` allowlist and `allow_private_hosts` outbound boundary
[^jwks-httpx]: `src/litestar_security/providers/jwks/_httpx.py` — `HttpxJWKSFetcher` HTTPS guard and `allow_private_hosts` outbound boundary
