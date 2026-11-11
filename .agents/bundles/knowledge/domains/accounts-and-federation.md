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
  - by: agent:flow-learn
    at: "2026-11-11T20:45:00Z"
    commit: "dcce78d"
sources:
  - id: accounts-init
    resource: "src/litestar_security/accounts/__init__.py"
    title: "Accounts domain exports: pure contracts, lazy controller exports, and instantiation-gated SDK adapters"
  - id: login-py
    resource: "src/litestar_security/accounts/_login.py::PasswordLoginService"
    title: "PasswordLoginService constant-work login and reauthentication verification"
  - id: auth-service-py
    resource: "src/litestar_security/accounts/_auth_service.py::LocalAuthService"
    title: "LocalAuthService._authenticate_password_step local login orchestration"
  - id: passwords-py
    resource: "src/litestar_security/accounts/_passwords.py::Argon2PasswordHasher"
    title: "Argon2PasswordHasher._run_worker and PasswordPolicy validation methods"
  - id: session-py
    resource: "src/litestar_security/accounts/_sessions.py::NativeSessionAuth"
    title: "NativeSessionAuth dual-cookie session binding, SessionBindingConfig._validate_binding_cookie_scope, and touch throttling"
  - id: refresh-py
    resource: "src/litestar_security/accounts/_refresh.py::RefreshTokenService"
    title: "RefreshTokenService family rotation, REPLAY_DETECTED revocation, and receipt recovery"
  - id: receipts-py
    resource: "src/litestar_security/accounts/_receipts.py::RefreshReceiptSealer"
    title: "RefreshReceiptSealer AES-256-GCM sealing and RefreshReceiptSealer._receipt_aad binding"
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
    title: "RecoveryTokenService, check_identifier_rate_limit, and PasswordChangeService epoch-advancing password mutation"
  - id: registration-py
    resource: "src/litestar_security/accounts/_registration.py::VerificationTokenService"
    title: "RegistrationService and VerificationTokenService enumeration-resistant token flows"
  - id: accounts-internal
    resource: "src/litestar_security/accounts/_internal.py::valid_compact_jwt"
    title: "Shared account structural constants, valid_compact_jwt, and decode_random"
  - id: accounts-records
    resource: "src/litestar_security/accounts/_records.py::lifecycle_event"
    title: "DEFAULT_REAUTHENTICATION_TTL, lifecycle_event, and emit_security_event"
  - id: accounts-controllers
    resource: "src/litestar_security/accounts/controllers/_local.py::route_error"
    title: "Local and MFA /auth controller helpers including route_error, principal_id, and _authorize_step_up"
  - id: oauth-tx
    resource: "src/litestar_security/providers/oauth/_transactions.py::MemoryOAuthTransactionStore"
    title: "MemoryOAuthTransactionStore PKCE/nonce sealing and OAuthRedirectPolicy validation"
  - id: oauth-provider
    resource: "src/litestar_security/providers/oauth/_provider.py::OAuthProviderClient"
    title: "OAuthProviderClient.stream_pinned and GitHubOAuthProvider SSRF public-IP DNS pinning"
  - id: oidc-discovery
    resource: "src/litestar_security/providers/oidc/_discovery.py::DiscoveryPolicy"
    title: "DiscoveryPolicy and OIDCDiscoveryClient allowlist and allow_private_hosts outbound boundary"
  - id: jwks-httpx
    resource: "src/litestar_security/providers/jwks/_httpx.py::HttpxJWKSFetcher"
    title: "HttpxJWKSFetcher HTTPS guard and allow_private_hosts outbound boundary"
  - id: providers-internal
    resource: "src/litestar_security/providers/_internal.py::resolve_public_addresses"
    title: "Shared resolve_public_addresses and read_bounded_body outbound helpers"
---

# Accounts, Sessions, High-Assurance Auth, & Federation Domain

<!-- truth: start -->
- **Pure Domain Contracts vs. Instantiation-Gated SDK Adapters**: `litestar_security.accounts` eagerly exports pure protocols, records, `AESGCMSecretProtector`, `StepUpService`, `PasskeyService` (usable without `webauthn` when given a custom `WebAuthnVerifier`), `LocalAuth` / `LocalAuthConfig` (usable without `argon2` when given a custom `PasswordHasher`), and the optional-extra adapter classes while keeping `_CONTROLLER_EXPORTS` lazy. Only instantiating `Argon2PasswordHasher`, `MFAService`, `MFALoginService`, or `PyWebAuthnVerifier` enforces `[argon2]`, `[mfa]`, or `[passkeys]`.[^accounts-init]
- **Dual-Cookie Session Binding & Fixed Expiry (`NativeSessionAuth`)**: Browser sessions pair Litestar's native session payload (`_litestar_security`) with an independent constant-time HMAC-bound `HttpOnly` cookie (`__Host-` names enforce `secure=True`, `path="/"`, `domain=None` via `SessionBindingConfig._validate_binding_cookie_scope`). `authenticate()` does not slide `expires_at` (`_valid_current_state` enforces `record.expires_at == authentication.expires_at`) and only updates `last_seen_at` via `accounts.touch()` throttled by `touch_interval`.[^session-py]
- **Refresh-Token Family Rotation & Store-Persisted Receipts (`RefreshTokenService`)**: Refresh tokens belong to a `family_id`. Replaying a consumed token without a matching `Idempotency-Key` header inside `receipt_window` (`<= timedelta(seconds=30)`) emits `RefreshRotationStatus.REPLAY_DETECTED` and revokes the entire `family_id`. On rotation, `RefreshReceiptSealer` (`AES-256-GCM`) seals `TokenPair` into store-persisted `sealed_receipt` bytes with `RefreshReceiptSealer._receipt_aad` binding `(account_id, expiry, family_id, idempotency, key_id, security_epoch, token_id, version="rr1")` so retries with matching `RefreshTokenCodec.digest_idempotency_key` recover the original pair via `RefreshReceiptReplay`.[^refresh-py][^receipts-py]
- **Purpose Tokens vs. MFA Login Challenges**: `PurposeTokenCodec` binds `TokenPurpose` (`INVITATION`, `VERIFICATION`, `RECOVERY`) into HMAC-SHA256 digests consumed atomically via `RegistrationStore.register`, `VerificationTokenStore.consume_and_verify`, and `RecoveryTokenStore.consume_and_reset`. Second-factor password-login challenges use `MFALoginService` and `MFALoginChallengeStore`.[^purpose-tokens][^mfa-login-py]
- **MFA, Passkeys, & Step-Up (`MFAService`, `PasskeyService`, `StepUpService`)**: `AESGCMSecretProtector` encrypts TOTP secrets into `ProtectedSecret(ciphertext: bytes, key_version: str)` (`nonce + ciphertext`, no `"v1:"` ciphertext prefix) and `MFAService.consume_recovery_code` delegates HMAC digest verification (`RecoveryCodePepper`) to `MFAStore.consume_recovery_code`. `PasskeyService` evaluates `clone_risk = credential.sign_count > 0 and verified.sign_count <= credential.sign_count` (`CloneRiskPolicy.AUDIT_ONLY` records `clone_risk=True` and emits `OUTCOME_CLONE_RISK` without rejecting). `StepUpService` persists `StepUpGrantState(grant_digest, transport_digest, principal_id, security_epoch, purpose, methods, traits, authenticated_at, expires_at)` using `clock: Callable[[], datetime]`.[^mfa-py][^passkeys-py]
- **OAuth/OIDC Transactions & Outbound Network Pinning**: `MemoryOAuthTransactionStore` seals only `pkce_verifier` and `nonce` (`state` is HMAC-hashed; `return_to` is stored plaintext after `OAuthRedirectPolicy` validation) before atomic `OAuthTransactionStore.consume`. `OAuthProviderClient.stream_pinned` (invoking `OAuthProviderClient._pinned_endpoint`, shared by `GitHubOAuthProvider(..., resolver=...)`) enforces public IPs and connects directly with `extensions={"sni_hostname": sni_hostname}`, whereas `OIDCDiscoveryClient` (`DiscoveryPolicy`, via `_validate_addresses`, `_validate_document_response`, and `_read_bounded_body`) and `HttpxJWKSFetcher` delegate to `providers._internal.resolve_public_addresses` and `providers._internal.read_bounded_body` with `allow_private_hosts: bool = False`.[^oauth-tx][^oauth-provider][^oidc-discovery][^jwks-httpx][^providers-internal]
<!-- truth: end -->

## Account & Credential Enumeration Protection

Login (`PasswordLoginService.authenticate`, orchestrated via `LocalAuthService._authenticate_password_step` in `LocalAuthService.session_login` and `LocalAuthService.token_login`) resolves identifiers via `AccountLookup.find_for_login` and executes dummy password verification (`hasher.verify(None, password)`) when absent so timing does not leak account existence.[^login-py][^auth-service-py] Password recovery (`RecoveryTokenService.request`) and verification resend (`VerificationTokenService.resend`) share `accounts/_recovery.py::check_identifier_rate_limit`, execute a parity `issue_absent()` call when no eligible account exists, swallow store/delivery exceptions, and return uniform `202 Accepted` (`LifecycleAccepted`) responses.[^recovery-py][^registration-py]

## Argon2 Worker Offloading & Consolidated Account Helpers

`Argon2PasswordHasher` offloads CPU-bound hashing and verification through `Argon2PasswordHasher._run_worker` bounded by `WorkerLimits.crypto_limiter` (alongside `_build_engine`, `_password_bytes`, `_verification_input`, `_validate_argon2_configuration`, `_safe_argon2_parameters`, and `_parameters_match_hasher`, while `PasswordPolicy` owns `_password_shape_violations` and `_password_matches_identifier`), preserving constant work across absent, mismatched, and malformed hashes. `LocalAuthConfig` instantiates `Argon2PasswordHasher` by default unless callers provide a custom `PasswordHasher`.[^passwords-py][^accounts-init]

Domain classes consolidate single-owner validators and codecs as methods while keeping cross-module helpers un-underscored and omitted from `__all__`:

- **Session & Refresh Receipt Methods**: `SessionBindingConfig` (`_validate_binding_cookie_config`, `SessionBindingConfig._validate_binding_cookie_scope`, `_validate_binding_lifetime_config`, `_validate_preserved_session_keys`), `NativeSessionAuth` (`_validate_native_session_store`, `_queue_binding_cookie`, `_SESSION_PAYLOAD_KEYS`), `RefreshReceiptSealer` (`_require_receipt_key`, `_receipt_expiry`, `_timestamp_microseconds`, `RefreshReceiptSealer._receipt_aad`, `_parse_receipt_envelope`), and `RefreshTokenService._narrow_access_token_failure`.[^session-py][^refresh-py][^receipts-py]
- **MFA & Passkey Methods**: `MFAService` (`_verify_pending_totp`, `_build_recovery_codes`, `_validate_secret`, `_totp`, `_accepted_counter`, `_totp_associated_data`, `_validate_recovery_configuration`, `_generate_recovery_codes`, `_recovery_code_version`, `_recovery_digest`), `MFALoginService` (`_challenge_digest`, `_strict_ascii_context`, `_valid_client_key`, `_valid_methods`, `_client_keys_match`), and `PasskeyService` (`_binding_digest`, `_credential_summary`, `_passkey_method_id`, `_valid_attestation_roots`, `_valid_attestation_root_entry`, `_valid_origin`).[^mfa-py][^mfa-login-py][^passkeys-py]
- **Cross-Module Internal & Controller Helpers**: `accounts/_internal.py` (`ASCII_CONTROL_LIMIT`, `MAXIMUM_SECURITY_EPOCH`, `AES_256_KEY_BYTES`, `valid_compact_jwt`, `decode_random`), `accounts/_records.py` (`DEFAULT_REAUTHENTICATION_TTL`, `lifecycle_event`, `emit_security_event`), and `/auth` controller helpers (`controllers/_local.py::{route_error, principal_id}` and controller `_authorize_step_up` on password and factor management routes).[^accounts-internal][^accounts-records][^accounts-controllers]

## References

[^accounts-init]: `src/litestar_security/accounts/__init__.py` — Accounts domain exports: pure contracts, lazy controller exports, and instantiation-gated SDK adapters
[^login-py]: `src/litestar_security/accounts/_login.py::PasswordLoginService` — `PasswordLoginService` constant-work login and reauthentication verification
[^auth-service-py]: `src/litestar_security/accounts/_auth_service.py::LocalAuthService` — `LocalAuthService._authenticate_password_step` local login orchestration
[^passwords-py]: `src/litestar_security/accounts/_passwords.py::Argon2PasswordHasher` — `Argon2PasswordHasher._run_worker` and `PasswordPolicy` validation methods
[^session-py]: `src/litestar_security/accounts/_sessions.py::NativeSessionAuth` — `NativeSessionAuth` dual-cookie session binding, `SessionBindingConfig._validate_binding_cookie_scope`, and touch throttling
[^refresh-py]: `src/litestar_security/accounts/_refresh.py::RefreshTokenService` — `RefreshTokenService` family rotation, `REPLAY_DETECTED` revocation, and receipt recovery
[^receipts-py]: `src/litestar_security/accounts/_receipts.py::RefreshReceiptSealer` — `RefreshReceiptSealer` AES-256-GCM sealing and `RefreshReceiptSealer._receipt_aad` binding
[^purpose-tokens]: `src/litestar_security/accounts/_purpose_tokens.py::PurposeTokenCodec` — `PurposeTokenCodec` HMAC domain separation for invitation, verification, and recovery tokens
[^mfa-py]: `src/litestar_security/accounts/_mfa.py::MFAService` — `MFAService`, `AESGCMSecretProtector`, `RecoveryCodePepper`, and `StepUpService`
[^mfa-login-py]: `src/litestar_security/accounts/_mfa_login.py::MFALoginService` — `MFALoginService` digest-only second-factor login challenges
[^passkeys-py]: `src/litestar_security/accounts/_passkeys.py::PasskeyService` — `PasskeyService` single-use WebAuthn challenges and sign-count clone-risk policy
[^recovery-py]: `src/litestar_security/accounts/_recovery.py::RecoveryTokenService` — `RecoveryTokenService`, `check_identifier_rate_limit`, and `PasswordChangeService` epoch-advancing password mutation
[^registration-py]: `src/litestar_security/accounts/_registration.py::VerificationTokenService` — `RegistrationService` and `VerificationTokenService` enumeration-resistant token flows
[^accounts-internal]: `src/litestar_security/accounts/_internal.py::valid_compact_jwt` — Shared account structural constants, `valid_compact_jwt`, and `decode_random`
[^accounts-records]: `src/litestar_security/accounts/_records.py::lifecycle_event` — `DEFAULT_REAUTHENTICATION_TTL`, `lifecycle_event`, and `emit_security_event`
[^accounts-controllers]: `src/litestar_security/accounts/controllers/_local.py::route_error` — Local and MFA `/auth` controller helpers including `route_error`, `principal_id`, and `_authorize_step_up`
[^oauth-tx]: `src/litestar_security/providers/oauth/_transactions.py::MemoryOAuthTransactionStore` — `MemoryOAuthTransactionStore` PKCE/nonce sealing and `OAuthRedirectPolicy` validation
[^oauth-provider]: `src/litestar_security/providers/oauth/_provider.py::OAuthProviderClient` — `OAuthProviderClient.stream_pinned` and `GitHubOAuthProvider` SSRF public-IP DNS pinning
[^oidc-discovery]: `src/litestar_security/providers/oidc/_discovery.py::DiscoveryPolicy` — `DiscoveryPolicy` and `OIDCDiscoveryClient` allowlist and `allow_private_hosts` outbound boundary
[^jwks-httpx]: `src/litestar_security/providers/jwks/_httpx.py::HttpxJWKSFetcher` — `HttpxJWKSFetcher` HTTPS guard and `allow_private_hosts` outbound boundary
[^providers-internal]: `src/litestar_security/providers/_internal.py::resolve_public_addresses` — Shared `resolve_public_addresses` and `read_bounded_body` outbound helpers
