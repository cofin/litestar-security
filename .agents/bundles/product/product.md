---
type: Product
title: "litestar-security Product Definition"
description: "Unified, storage-agnostic authentication, authorization, provider verification, account lifecycle, and WebSocket security framework for Litestar."
status: stable
tags: [product, security, litestar, authentication, authorization]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-setup
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: pyproject
    resource: "pyproject.toml"
    title: "litestar-security package metadata, dependencies, and optional extras"
  - id: readme
    resource: "README.md"
    title: "litestar-security package overview and public capabilities"
  - id: init-exports
    resource: "src/litestar_security/__init__.py"
    title: "Top-level public API surface and lazy OAuth exports"
---

# Product Definition

<!-- truth: start -->
- **Product**: `litestar-security` (`v0.7.1`) is the unified authentication and authorization plugin for Litestar (`>=2.24.0`), configured through a single `SecurityPlugin(SecurityConfig(...))` entry point.[^pyproject][^readme]
- **Target Consumers**: Litestar backend services, API gateways, SaaS multi-tenant applications, and downstream packages (`litestar-mcp`, database-backed services) that require composable authentication, predicate authorization, and OpenAPI 3.1 security projection without coupling to a specific ORM or cache.[^pyproject][^readme]
- **Storage-Agnostic & Extra-Decoupled Contract**: The runtime package defines `@runtime_checkable` `Protocol` ports (`AccountLookup`, `RegistrationStore`, `SessionRegistry`, `NativeSessionStore`, `RefreshTokenFamilyStore`, `APIKeyStore`, `OAuthAccountStore`, `OAuthTransactionStore`, `MFAStore`, `PasskeyStore`, `StepUpStore`, `RateLimiter`, `SecurityEventSink`, `SecurityMetrics`), ships zero database/cache/cloud SDK adapters in its wheel, and keeps pure domain contracts and `litestar_security.testing` usable without optional extras.[^pyproject][^init-exports]
- **Core Capability Pillars**:
  1. **Route-Compiled Authentication & Predicate Guards**: Declarative `AuthenticationPolicy` (`required`, `optional`, `public`, `exclude`, `any_of`, `all_of`, `at_least`, `mechanism`) and boolean-composable `AuthorizationPredicate` guards (`requires_role`, `requires_scope`, `requires_capability`, `requires_tenant`, `requires_tenant_role`, `requires_assurance`).[^init-exports]
  2. **Token & Federated Providers**: JWT (`PyJWTVerifier`, `CompositeBearerConfig`), JWKS (`CachedJWKSProvider`), API keys (`APIKeyConfig` with header and opt-in `Authorization: Bearer` extraction, `APIKeyService`, `BufferedAPIKeyUsage`), Google IAP (`GoogleIAPConfig`, `GoogleIAPClaims` human, service-account, and SPIFFE agent classification), and OAuth/OIDC (`OAuthConfig`, `OIDCProvider`, `ServiceTokenConfig`, `ProtectedResourceConfig`).[^init-exports]
  3. **Local Accounts & High-Assurance Auth**: Argon2id passwords, dual-cookie sessions (`NativeSessionAuth`), rotating refresh-token families (`RefreshTokenService`), single-use purpose tokens, TOTP/recovery-code MFA (`MFAService`, `MFALoginService`), WebAuthn passkeys (`PasskeyService`), step-up grants (`StepUpService`), and rate limiting (`StoreRateLimiter`).[^init-exports]
  4. **WebSocket Security & Conformance Test Kit**: Handshake extraction, single-use connect tokens, and live lifetime supervision (`WebSocketSecurityConfig`), paired with `litestar_security.testing` (`InMemorySecurityBackend`, `assert_security_backend_conformance`, `FakeClock`, `FakeOAuthProvider`).[^init-exports]
<!-- truth: end -->

## Scope & Non-Goals

`litestar-security` owns protocol verification, cryptographic token/cookie sealing, route policy compilation, OpenAPI security scheme projection, and controller/guard wiring.[^readme][^init-exports] Concrete persistence adapters (SQLAlchemy, SQLSpec, Redis, Google Cloud, AWS) are intentionally excluded from the runtime wheel and verified against the library's port contracts using `assert_security_backend_conformance`.[^pyproject][^init-exports]

## References

[^pyproject]: `pyproject.toml` — `litestar-security` package metadata, dependencies, and optional extras
[^readme]: `README.md` — `litestar-security` package overview and public capabilities
[^init-exports]: `src/litestar_security/__init__.py` — Top-level public API surface and lazy OAuth exports
