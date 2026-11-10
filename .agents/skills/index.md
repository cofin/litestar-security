---
title: "Project-Local Skills Index"
summary: "Index of project-local engineering and review skills for litestar-security."
updated: "2026-11-10"
---

# Project-Local Skills

Consolidated domain engineering and review capability skills for `litestar-security`.

## Domain Routing Matrix

| Domain | Rule Prefix | Engineering Skill | Review Skill | Reviewer Subagent | Specialist Subagent | Knowledge Chapters |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Runtime & Policy** | `RUN` | [`runtime-and-policy`](./runtime-and-policy/SKILL.md) | [`review-runtime-and-policy`](./review-runtime-and-policy/SKILL.md) | [`runtime-and-policy-reviewer`](../agents/runtime-and-policy-reviewer.md) | [`runtime-and-policy-specialist`](../agents/runtime-and-policy-specialist.md) | [`runtime-pipeline.md`](../bundles/knowledge/architecture/runtime-pipeline.md), [`wire-schemas-and-dtos.md`](../bundles/knowledge/patterns/wire-schemas-and-dtos.md), [`immutable-contracts-and-typing.md`](../bundles/knowledge/patterns/immutable-contracts-and-typing.md), [`route-compilation-and-csrf.md`](../bundles/knowledge/gotchas/route-compilation-and-csrf.md) |
| **Providers** | `PRV` | [`providers`](./providers/SKILL.md) | [`review-providers`](./review-providers/SKILL.md) | [`providers-reviewer`](../agents/providers-reviewer.md) | [`providers-specialist`](../agents/providers-specialist.md) | [`authentication-and-authorization.md`](../bundles/knowledge/domains/authentication-and-authorization.md), [`provider-and-store-ports.md`](../bundles/knowledge/architecture/provider-and-store-ports.md), [`route-compilation-and-csrf.md`](../bundles/knowledge/gotchas/route-compilation-and-csrf.md) |
| **Accounts** | `ACC` | [`accounts`](./accounts/SKILL.md) | [`review-accounts`](./review-accounts/SKILL.md) | [`accounts-reviewer`](../agents/accounts-reviewer.md) | [`accounts-specialist`](../agents/accounts-specialist.md) | [`accounts-and-federation.md`](../bundles/knowledge/domains/accounts-and-federation.md), [`adr-003-centralized-optional-extra-shims.md`](../bundles/knowledge/decisions/adr-003-centralized-optional-extra-shims.md) |
| **WebSocket & Testing** | `WST` | [`websocket-and-testing`](./websocket-and-testing/SKILL.md) | [`review-websocket-and-testing`](./review-websocket-and-testing/SKILL.md) | [`websocket-and-testing-reviewer`](../agents/websocket-and-testing-reviewer.md) | [`websocket-and-testing-specialist`](../agents/websocket-and-testing-specialist.md) | [`test-organization-and-conformance.md`](../bundles/knowledge/testing/test-organization-and-conformance.md), [`adr-001-protocol-ports-without-runtime-adapters.md`](../bundles/knowledge/decisions/adr-001-protocol-ports-without-runtime-adapters.md) |

## Engineering Domain Skills

- **[runtime-and-policy](./runtime-and-policy/SKILL.md)** — `SecurityPlugin`, `SecurityConfig`, `AuthenticationPolicy`, `RouteCompiler`, `AuthorizationPredicate` guards, `SecurityContext`, `WireDTO`, and `SecurityHeadersConfig`.
  - [Implementation Checklist](./runtime-and-policy/references/checklist.md)
  - [False-Positive Suppressions](./runtime-and-policy/references/false-positive-suppressions.md)
- **[providers](./providers/SKILL.md)** — JWT/JWS (`PyJWTVerifier`, `CompositeBearerConfig`), JWKS (`CachedJWKSProvider`), API keys (`APIKeyService`), Google IAP (`GoogleIAPConfig`), and OAuth/OIDC (`OAuthConfig`, `OIDCProvider`).
  - [Implementation Checklist](./providers/references/checklist.md)
  - [False-Positive Suppressions](./providers/references/false-positive-suppressions.md)
- **[accounts](./accounts/SKILL.md)** — `LocalAuthConfig`, `NativeSessionAuth`, `RefreshTokenService`, `PurposeTokenCodec`, `MFAService`, `PasskeyService`, `StepUpService`, `StoreRateLimiter`, and `/auth` controllers.
  - [Implementation Checklist](./accounts/references/checklist.md)
  - [False-Positive Suppressions](./accounts/references/false-positive-suppressions.md)
- **[websocket-and-testing](./websocket-and-testing/SKILL.md)** — `WebSocketSecurityConfig`, connect tokens, lifetime supervision, `InMemorySecurityBackend`, `assert_security_backend_conformance`, and test suite boundaries.
  - [Implementation Checklist](./websocket-and-testing/references/checklist.md)
  - [False-Positive Suppressions](./websocket-and-testing/references/false-positive-suppressions.md)

## Review Capability Skills

- **[review-runtime-and-policy](./review-runtime-and-policy/SKILL.md)** — Audit changes to plugin wiring, route compilation, authentication evaluation, guards, DTOs, and security headers.
  - [Review Checklist](./review-runtime-and-policy/references/checklist.md)
  - [False-Positive Suppressions](./review-runtime-and-policy/references/false-positive-suppressions.md)
- **[review-providers](./review-providers/SKILL.md)** — Audit changes to JWT, composite bearer, JWKS caching, API keys, Google IAP, and OAuth/OIDC providers.
  - [Review Checklist](./review-providers/references/checklist.md)
  - [False-Positive Suppressions](./review-providers/references/false-positive-suppressions.md)
- **[review-accounts](./review-accounts/SKILL.md)** — Audit changes to local accounts, sessions, refresh rotation, purpose tokens, MFA, passkeys, step-up, and rate limiting.
  - [Review Checklist](./review-accounts/references/checklist.md)
  - [False-Positive Suppressions](./review-accounts/references/false-positive-suppressions.md)
- **[review-websocket-and-testing](./review-websocket-and-testing/SKILL.md)** — Audit changes to WebSocket security, connect tokens, `testing.py` conformance suites, and `src/tests/` boundaries.
  - [Review Checklist](./review-websocket-and-testing/references/checklist.md)
  - [False-Positive Suppressions](./review-websocket-and-testing/references/false-positive-suppressions.md)
