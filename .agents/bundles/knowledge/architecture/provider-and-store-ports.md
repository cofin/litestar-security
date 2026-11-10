---
type: Architecture
title: "Provider & Store Ports, Sync Bridging, & Lazy Boundaries"
description: "Protocol port design, startup BlockingIntegration and worker bridging, centralized optional-extra shims, and lazy OAuth/test-kit boundaries."
status: stable
tags: [architecture, ports, protocols, workers, lazy-loading, boundaries]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-setup
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: workers-py
    resource: "src/litestar_security/workers.py::BlockingCallRunner"
    title: "WorkerLimits, BlockingIntegration, and BlockingCallRunner"
  - id: lazy-py
    resource: "src/litestar_security/_lazy.py::import_optional_attribute"
    title: "Lazy optional-feature attribute loader"
  - id: root-init
    resource: "src/litestar_security/__init__.py"
    title: "Root package exports and lazy _OAUTH_EXPORTS resolution"
  - id: private-typing
    resource: "src/litestar_security/_typing.py::OptionalDependencyFlag"
    title: "Centralized OptionalDependencyFlag, MissingDependencyError _EXTRAS, and fallback shims"
  - id: typing-py
    resource: "src/litestar_security/typing.py::OptionalDependencyFlag"
    title: "Public optional-dependency availability and typing facade"
  - id: accounts-init
    resource: "src/litestar_security/accounts/__init__.py"
    title: "Eager account exports with instantiation-time optional-extra checks"
  - id: api-key-py
    resource: "src/litestar_security/providers/api_key/_api_key.py::_BlockingAPIKeyStore"
    title: "Startup BlockingIntegration wrapping via BlockingCallRunner"
  - id: check-boundaries
    resource: "tools/check_import_boundaries.py"
    title: "R4/R5 import boundary and inspect.isawaitable static check"
  - id: check-downstream
    resource: "tools/check_downstream_consumer.py"
    title: "Wheel Requires-Dist and banned third-party adapter check"
---

# Provider & Store Ports, Sync Bridging, & Lazy Boundaries

<!-- truth: start -->
- **Zero-Adapter Protocol Mix**: Runtime source (`src/litestar_security/`) never imports database drivers or ORM packages (Ruff `TID251` and wheel metadata checks).[^check-downstream] Store ports (`APIKeyStore`, `APIKeyUsageSink`, `OAuthTransactionStore`, `OAuthAccountStore`, `OIDCSessionLogoutStore`, `WebSocketConnectTokenStore`, and account/MFA/passkey/session/refresh stores) plus `AuthorizationSnapshotRefresher` (`async def refresh`), `WebSocketRevocationSource`, `AsyncJWKSFetcher`, `JWKSProvider`, `TokenSigner`, `PasswordHasher`, `RateLimiter`, `SecurityEventSink`, `OIDCLogoutTokenConsumer`, and `OAuthLocalTransport` are async `@runtime_checkable` `Protocol`s.[^workers-py]
- **Sync & Unannotated Protocols**: `SecurityMetrics`, `SessionHandle`, `JWKSCache`, `SyncJWKSFetcher`, `SyncJWTVerifier`, `SyncTokenSigner`, `WebAuthnVerifier`, and `AttestationTrustMapper` are synchronous `@runtime_checkable` `Protocol`s (`JWTVerifier`, `SecretProtector`, `OAuthTransactionProtector`, `OAuthProvider`, `OAuthReauthenticationProvider`, `OAuthStepUpAuthorizer`, and `OAuthLifecycle` expose sync helpers/properties alongside async methods).[^workers-py] Request-pipeline extension ports (`CredentialSlot`, `CredentialVerifier`, `IdentityResolver`, `AuthorizationResolver`) are `Protocol`s without `@runtime_checkable` (`CredentialSlot.extract` is sync; the other three are async).
- **Startup Sync Bridging & `WorkerLimits` (`R4`)**: Per-call `inspect.isawaitable` branching is forbidden (`R4`).[^check-boundaries] `WorkerLimits` (`workers.py:109-130`) configures `network_tokens: int = 8`, `crypto_tokens: int = 32`, and `timeout: float = 10.0` (creating `network_limiter` and `crypto_limiter` `CapacityLimiter` instances).[^workers-py] `APIKeyConfig.build()` wraps `BlockingIntegration(_SyncAPIKeyStore)` once into `_BlockingAPIKeyStore` using `BlockingCallRunner().run(...)` (`to_thread.run_sync(..., abandon_on_cancel=False, limiter=self.limiter)`).[^api-key-py] `normalize_fetcher` (`network_limiter`), `normalize_verifier`/`normalize_signer` (`crypto_limiter`), and `Argon2PasswordHasher` (`_run_password_worker` on `workers.crypto_limiter`) offload sync or CPU-bound work onto bounded `anyio.to_thread` workers.[^workers-py]
- **Optional-Extra Isolation (`_typing.py` & `typing.py`)**: All optional imports (`argon2`, `pyotp`, `webauthn`), `*_INSTALLED` `OptionalDependencyFlag` probes (`find_spec`), `ensure_argon2`/`ensure_pyotp`/`ensure_webauthn` gates, and slotted runtime fallback shims live in `src/litestar_security/_typing.py` (re-exported via `src/litestar_security/typing.py`).[^private-typing][^typing-py] `MissingDependencyError` maps `_DISTRIBUTIONS` and `_EXTRAS` (`{"argon2": "argon2", "pyotp": "mfa", "webauthn": "passkeys"}`) so `[extra]` install hints appear only when a matching package extra exists.[^private-typing]
- **Lazy Root OAuth & Isolated Test-Kit Boundary (`R5`)**: `src/litestar_security/__init__.py` lazy-loads only `_OAUTH_EXPORTS` via `import_optional_attribute` (`_lazy.py`).[^lazy-py][^root-init] `litestar_security.testing` (`InMemorySecurityBackend`, `FakeClock`, `FakeOAuthProvider`, `assert_security_backend_conformance`) is isolated from root/runtime imports by Ruff `TID251` and `tools/check_import_boundaries.py` (`R5`: `assert not hasattr(litestar_security, 'InMemorySecurityBackend')`).[^check-boundaries]
<!-- truth: end -->

## Optional Extra Boundaries

`src/litestar_security/accounts/__init__.py` eagerly exports all account protocols, value records, and concrete adapters (`Argon2PasswordHasher`, `MFAService`, `MFALoginService`, `PyWebAuthnVerifier`) while resolving controller route builders lazily via `_CONTROLLER_EXPORTS`.[^accounts-init] Importing those adapter classes for runtime type annotations succeeds with zero optional extras installed; constructing them without their required extra raises `ImportError("litestar-security feature requires the [<extra>] extra: pip install 'litestar-security[<extra>]'")` via `ensure_argon2`, `ensure_pyotp`, or `ensure_webauthn`.[^private-typing][^accounts-init]

Similarly, `src/litestar_security/providers/__init__.py` resolves `_OAUTH_EXPORTS` lazily through `import_optional_attribute(..., extras="oauth", ...)` and `_OIDC_EXPORTS` through `import_module`, while `src/litestar_security/providers/oauth/__init__.py` resolves `OAuthLocalAuthTransport` lazily via `__getattr__` to break provider/local-account import cycles.[^lazy-py]

## References

[^workers-py]: `src/litestar_security/workers.py::BlockingCallRunner` — `WorkerLimits`, `BlockingIntegration`, and `BlockingCallRunner`
[^lazy-py]: `src/litestar_security/_lazy.py::import_optional_attribute` — Lazy optional-feature attribute loader
[^root-init]: `src/litestar_security/__init__.py` — Root package exports and lazy `_OAUTH_EXPORTS` resolution
[^private-typing]: `src/litestar_security/_typing.py::OptionalDependencyFlag` — Centralized `OptionalDependencyFlag`, `MissingDependencyError` `_EXTRAS`, and fallback shims
[^typing-py]: `src/litestar_security/typing.py::OptionalDependencyFlag` — Public optional-dependency availability and typing facade
[^accounts-init]: `src/litestar_security/accounts/__init__.py` — Eager account exports with instantiation-time optional-extra checks
[^api-key-py]: `src/litestar_security/providers/api_key/_api_key.py::_BlockingAPIKeyStore` — Startup `BlockingIntegration` wrapping via `BlockingCallRunner`
[^check-boundaries]: `tools/check_import_boundaries.py` — `R4`/`R5` import boundary and `inspect.isawaitable` static check
[^check-downstream]: `tools/check_downstream_consumer.py` — Wheel `Requires-Dist` and banned third-party adapter check
