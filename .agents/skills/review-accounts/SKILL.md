---
name: review-accounts
description: Use when reviewing changes to LocalAuthConfig, sessions, refresh tokens, purpose tokens, MFA/TOTP, passkeys, step-up grants, rate limits, or /auth controllers. Not for OAuth or JWT reviews.
---

# Review Skill: Local Accounts, Sessions, High-Assurance Auth, & Rate Limiting

Review capability skill for auditing changes in `src/litestar_security/accounts/`.

## Core Review Invariants

<!-- truth: start -->
- **Optional-Extra Decoupling (`ACC-09`)**: Pure contracts, `AESGCMSecretProtector`, `StepUpService`, `PasskeyService` (with custom `WebAuthnVerifier`), `LocalAuthConfig` (with custom `PasswordHasher`), and `controllers` must run without `[argon2]`, `[mfa]`, or `[passkeys]`; `_CONTROLLER_EXPORTS` stays lazy in `accounts/__init__.py`, and only `Argon2PasswordHasher`, `MFAService`, `MFALoginService`, and `PyWebAuthnVerifier` gate at instantiation via `litestar_security.typing`.
- **Enumeration & Timing Resistance (`ACC-01`)**: `PasswordLoginService.authenticate` (via `AccountLookup.find_for_login`) runs dummy `hasher.verify(None, password)` on missing accounts; `RecoveryTokenService.request` and `VerificationTokenService.resend` call `issue_absent()`, swallow store/delivery exceptions, and return `202 Accepted` (`LifecycleAccepted`).
- **Dual-Cookie Binding & Fixed Session Expiry (`ACC-02`)**: `NativeSessionAuth` verifies binding cookies with `hmac.compare_digest`, enforces `secure=True`, `path="/"`, `domain=None` on `__Host-` names via `_validate_binding_cookie_scope`, rejects sliding `expires_at` renewal (`record.expires_at == authentication.expires_at`), and throttles `accounts.touch()` by `touch_interval`.
- **Refresh Reuse Revocation & Store Receipts (`ACC-03`)**: Replaying a consumed token without a matching `Idempotency-Key` header inside `receipt_window` (`<= 30s`) emits `RefreshRotationStatus.REPLAY_DETECTED` and revokes the full `family_id`; `RefreshReceiptSealer` seals `TokenPair` into store-persisted `sealed_receipt` bytes (`RefreshReceiptReplay`) with `_receipt_aad` binding `(account_id, expiry, family_id, idempotency, key_id, security_epoch, token_id, version="rr1")`.
- **Purpose Tokens vs. MFA Challenges (`ACC-04`)**: `PurposeTokenCodec` binds `TokenPurpose` (`INVITATION`, `VERIFICATION`, `RECOVERY`) for atomic `RegistrationStore.register`, `VerificationTokenStore.consume_and_verify`, and `RecoveryTokenStore.consume_and_reset`, whereas login MFA challenges use `MFALoginService` (`MFALoginChallengeStore.consume`).
- **MFA Sealing, Passkey Clone Risk, Step-Up, & Argon2 (`ACC-05`..`ACC-07`)**: `AESGCMSecretProtector` emits `ProtectedSecret(ciphertext, key_version)` (`nonce + ciphertext`, no `"v1:"` prefix), `MFAService.consume_recovery_code` delegates constant-time check to `MFAStore.consume_recovery_code`, `Argon2PasswordHasher` uses `_run_password_worker` (`WorkerLimits.crypto_limiter`), `PasskeyService` triggers `clone_risk` only when `credential.sign_count > 0 and verified.sign_count <= credential.sign_count` (`AUDIT_ONLY` records and emits `OUTCOME_CLONE_RISK` without rejecting), and `StepUpService` persists `StepUpGrantState(grant_digest, transport_digest, principal_id, security_epoch, purpose, methods, traits, authenticated_at, expires_at)` using `clock`.
- **Branch Coverage & Conformance Sync (`ACC-08`)**: Retain `100%` branch coverage on `src/litestar_security/accounts/_refresh.py` (`CORE_COVERAGE`) and mirror store protocol updates in `InMemorySecurityBackend` and `assert_security_backend_conformance` (`src/litestar_security/testing.py`).
<!-- truth: end -->

## Review Protocol

1. **Inspect Modified Account Modules & Tests**: Read changed files in `src/litestar_security/accounts/` and their unit (`src/tests/unit/`) and integration (`src/tests/integration/`) tests.
2. **Audit Against Account Checklist (`ACC-01`..`ACC-09`)**: Check every invariant in [references/checklist.md](./references/checklist.md).
3. **Filter False Positives (`FP-ACC-01`..`FP-ACC-06`)**: Consult [references/false-positive-suppressions.md](./references/false-positive-suppressions.md) before reporting findings.
4. **Verify Coverage & Conformance**:
   - Confirm `src/litestar_security/accounts/_refresh.py` retains `100%` branch coverage (`CORE_COVERAGE`).
   - Confirm any store `Protocol` change updates `InMemorySecurityBackend` and `assert_security_backend_conformance` in `src/litestar_security/testing.py`.
5. **Run Verification Commands**:
   ```bash
   uv run pytest src/tests/unit/test_accounts/ src/tests/integration/test_accounts/ -q
   uv run slotscheck src/litestar_security/
   ```

## Required Finding Format

Report only verified findings anchored to `path/to/file.py:line` with violated check ID (`ACC-XX`), concrete failure or bypass scenario, and minimal fix.

## References

- [Review Checklist (`ACC-01`..`ACC-09`)](./references/checklist.md)
- [False-Positive Suppressions (`FP-ACC-01`..`FP-ACC-06`)](./references/false-positive-suppressions.md)
- [Accounts & Federation Domain](../../bundles/knowledge/domains/accounts-and-federation.md)
- [ADR-003: Centralized Optional-Extra Shims](../../bundles/knowledge/decisions/adr-003-centralized-optional-extra-shims.md)
