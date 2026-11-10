---
name: accounts
description: Use when editing LocalAuthConfig, sessions, refresh tokens, purpose tokens, MFA/TOTP, passkeys, step-up grants, rate limits, or /auth controllers. Not for OAuth, JWT, or WebSockets.
---

# Local Accounts, Sessions, High-Assurance Auth, & Rate Limiting

Domain skill for `src/litestar_security/accounts/` (`_auth_service.py`, `_access_tokens.py`, `_internal.py`, `_login.py`, `_mfa_login.py`, `_mfa.py`, `_operations.py`, `_passkeys.py`, `_passwords.py`, `_profiles.py`, `_purpose_tokens.py`, `_rate_limits.py`, `_receipts.py`, `_records.py`, `_recovery.py`, `_refresh.py`, `_refresh_tokens.py`, `_registration.py`, `_sessions.py`, `_stores.py`, `controllers/`, `schemas/`).

## Canonical Modules & Seams

- **Accounts & Passwords**: `LocalAuth`, `LocalAuthConfig`, `LocalAuthSecrets`, `LocalAuthService` (`_profiles.py`, `_auth_service.py`), `PasswordLoginService`, `PasswordReauthenticationService` (`_login.py`), `Argon2PasswordHasher`, `PasswordPolicy` (`_passwords.py`), `PasswordChangeService`, `RecoveryTokenService` (`_recovery.py`), `RegistrationService`, `VerificationTokenService` (`_registration.py`), `_internal.py`, `_operations.py`, `_records.py`, `_stores.py`.
- **Dual-Cookie Sessions**: `SessionBindingConfig`, `NativeSessionAuth`, `NativeSessionStore`, `SessionRegistry`, `UserAuthSessionResolver` (`_sessions.py`).
- **Refresh-Token Families & Receipts**: `RefreshTokenService`, `RefreshTokenFamilyStore` (`_refresh.py`), `RefreshTokenCodec`, `RefreshRotationStatus` (`_refresh_tokens.py`), `RefreshReceiptSealer`, `RefreshReceiptReplay` (`_receipts.py`).
- **Access & Purpose Tokens**: `LocalAccessTokenIssuer`, `LocalAccessVerifier`, `LocalBearerIdentityResolver` (`_access_tokens.py`), `PurposeTokenCodec`, `PurposeTokenDelivery`, `PurposeTokenProof` (`_purpose_tokens.py`).
- **High-Assurance Auth**: `MFAService`, `MFAStore`, `AESGCMSecretProtector`, `RecoveryCodePepper`, `StepUpService`, `StepUpStore`, `StepUpGrantState` (`_mfa.py`), `MFALoginService`, `MFALoginChallengeStore`, `MFARequired` (`_mfa_login.py`), `PasskeyService`, `PyWebAuthnVerifier`, `PasskeyStore`, `WebAuthnChallengeStore`, `CloneRiskPolicy` (`_passkeys.py`), and centralized optional-extra shims (`src/litestar_security/typing.py`).
- **Rate Limiting & Controllers**: `RateLimitPolicy`, `RateLimitGuard`, `StoreRateLimiter` (`_rate_limits.py`), `accounts/controllers/{_local.py,_mfa.py}`, `accounts/schemas/{_local.py,_mfa.py}`.

## Non-Negotiable Rules

<!-- truth: start -->
1. **Optional-Extra Isolation (`litestar_security.typing`)**: Pure contracts, `AESGCMSecretProtector`, `StepUpService`, `PasskeyService` (with custom `WebAuthnVerifier`), `LocalAuthConfig` / `LocalAuth` (with custom `PasswordHasher`), and `controllers` must import and execute without `[argon2]`, `[mfa]`, or `[passkeys]`. Keep `_CONTROLLER_EXPORTS` lazy in `accounts/__init__.py`, import optional SDK symbols from `litestar_security.typing`, and gate only `Argon2PasswordHasher`, `MFAService`, `MFALoginService`, and `PyWebAuthnVerifier` at instantiation (`ensure_argon2`, `ensure_pyotp`, `ensure_webauthn`).
2. **Enumeration-Resistant Login & Recovery**:
   - `PasswordLoginService.authenticate` (called by `LocalAuthService.session_login` / `token_login` via `AccountLookup.find_for_login`) must run dummy `hasher.verify(None, password)` when no account matches.
   - `RecoveryTokenService.request` and `VerificationTokenService.resend` must invoke `issue_absent()` on missing/ineligible identifiers, swallow store/delivery failures, and return uniform `202 Accepted` (`LifecycleAccepted`) responses.
3. **Dual-Cookie Session Binding & Fixed Expiry**: `NativeSessionAuth` verifies the `HttpOnly` binding cookie with `hmac.compare_digest` and `_validate_binding_cookie_scope` enforces `secure=True`, `path="/"`, `domain=None` on `__Host-` cookie names. `authenticate()` does not slide `expires_at` (`record.expires_at == authentication.expires_at`) and only updates `last_seen_at` via `accounts.touch()` throttled by `touch_interval`.
4. **Refresh-Token Family Reuse & Idempotent Receipts**: Replaying a consumed token without a valid `Idempotency-Key` header inside `receipt_window` (`<= 30s`) emits `RefreshRotationStatus.REPLAY_DETECTED` and revokes the full `family_id`. `RefreshReceiptSealer` (`AES-256-GCM`) binds `_receipt_aad` to `(account_id, expiry, family_id, idempotency, key_id, security_epoch, token_id, version="rr1")` and persists `sealed_receipt` bytes in the store (`RefreshReceiptReplay`).
5. **Domain-Separated Purpose Tokens vs. MFA Challenges**: `PurposeTokenCodec` binds `TokenPurpose` (`INVITATION`, `VERIFICATION`, `RECOVERY`) into HMAC-SHA256 digests consumed atomically via `RegistrationStore.register`, `VerificationTokenStore.consume_and_verify`, and `RecoveryTokenStore.consume_and_reset`. Password-login MFA challenges use `MFALoginService` (`MFALoginChallengeStore.consume`).
6. **MFA Sealing, Passkey Clone Risk, Step-Up, & Argon2 Workers**: Seal TOTP secrets with `AESGCMSecretProtector` (`ProtectedSecret(ciphertext, key_version)`, no `"v1:"` prefix) and delegate HMAC recovery-code verification (`RecoveryCodePepper`) to `MFAStore.consume_recovery_code`. `PasskeyService` flags `clone_risk` only when `credential.sign_count > 0 and verified.sign_count <= credential.sign_count` (`CloneRiskPolicy.AUDIT_ONLY` records `clone_risk=True` and emits `OUTCOME_CLONE_RISK` without rejecting). `StepUpService` persists `StepUpGrantState(grant_digest, transport_digest, principal_id, security_epoch, purpose, methods, traits, authenticated_at, expires_at)` using `clock` and returns `AuthenticationEvidence(mechanism="step-up", slot="mfa", ..., traits=record.traits | {f"purpose:{purpose}"})`. `Argon2PasswordHasher` offloads work via `_run_password_worker` using `WorkerLimits.crypto_limiter`.
<!-- truth: end -->

## Verification Commands

```bash
uv run pytest src/tests/unit/test_accounts/ -q
uv run pytest src/tests/integration/test_accounts/ -q
uv run slotscheck src/litestar_security/
```

## References

- [Implementation Checklist](./references/checklist.md)
- [False-Positive Suppressions](./references/false-positive-suppressions.md)
- [Accounts & Federation Domain](../../bundles/knowledge/domains/accounts-and-federation.md)
- [ADR-003: Centralized Optional-Extra Shims](../../bundles/knowledge/decisions/adr-003-centralized-optional-extra-shims.md)
