---
type: Decision
title: "ADR-001: Protocol Store Ports Without Bundled Runtime Adapters"
description: "Architectural decision to ship @runtime_checkable Protocol ports and a conformance test kit while banning ORM and cache drivers from the wheel."
status: stable
tags: [decisions, adr, architecture, ports, conformance, packaging]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-setup
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: adr1-pyproject
    resource: "pyproject.toml"
    title: "Banned third-party adapter imports (TID251) and core dependency declarations"
  - id: adr1-downstream
    resource: "tools/check_downstream_consumer.py"
    title: "Wheel Requires-Dist and runtime import boundary enforcement"
  - id: adr1-boundaries
    resource: "tools/check_import_boundaries.py"
    title: "R4 awaitability and R5 unimported test-kit boundary verification"
  - id: adr1-workers
    resource: "src/litestar_security/workers.py::SecurityMetrics"
    title: "Synchronous telemetry sink and BlockingIntegration startup normalization"
  - id: adr1-auth
    resource: "src/litestar_security/authentication.py::CredentialSlot"
    title: "Synchronous non-blocking CredentialSlot.extract boundary"
  - id: adr1-testing
    resource: "src/litestar_security/testing.py::assert_security_backend_conformance"
    title: "InMemorySecurityBackend, StoreConformanceFactories, and conformance suites"
---

# ADR-001: Protocol Store Ports Without Bundled Runtime Adapters

<!-- truth: start -->
- **Status**: Accepted (`v0.7.1`).[^adr1-pyproject]
- **Context**: Litestar applications use diverse persistence stacks (SQLSpec, Advanced Alchemy / SQLAlchemy, Redis/Valkey, Spanner, DynamoDB, or stateless JWTs). Bundling ORM models or cache drivers inside `litestar-security` would force version lockstep, bloat dependency trees, and leak storage schema opinions into security protocol logic.[^adr1-pyproject][^adr1-downstream]
- **Decision**: Define all persistence, verification, resolution, event, and telemetry boundaries as `@runtime_checkable` `Protocol` ports with slotted frozen value objects, ban all storage/adapter packages from `src/litestar_security/` and wheel `Requires-Dist`, and ship `InMemorySecurityBackend` plus all 15 conformance suites in `litestar_security.testing`.[^adr1-pyproject][^adr1-downstream][^adr1-testing]
- **Port Execution Model**: Persistence stores, verifiers, resolvers, and event sinks are async `Protocol` ports. Non-blocking hot-path and configuration hooks are explicitly synchronous (`SecurityMetrics` in `workers.py`, `CredentialSlot.extract` in `authentication.py`, `SessionHandle`, `JWKSCache`, `WebAuthnVerifier`, `AttestationTrustMapper`), while blocking third-party implementations implement `Sync*` protocols (`SyncJWKSFetcher`, `SyncTokenSigner`, `SyncJWTVerifier`) or wrap via `BlockingIntegration` at startup (`R4`).[^adr1-workers][^adr1-auth][^adr1-boundaries]
- **Consequences**:
  - **Positive**: Zero ORM/driver version conflicts; stateless JWT/IAP/OIDC apps pay zero storage overhead; consumer adapters verify exact behavioral parity (atomic token consumption, family revocation, grace receipts, rate-limit windows) via `await assert_security_backend_conformance(...)` and `await assert_rate_limiter_conformance(...)` without optional extras installed.[^adr1-testing]
  - **Trade-off**: Downstream applications must wire store implementations (or use `InMemorySecurityBackend` in tests), and any new store method added to a `Protocol` requires lockstep updates to `InMemorySecurityBackend` and the conformance suite in `src/litestar_security/testing.py`.[^adr1-testing]
<!-- truth: end -->

## Test-Kit Isolation (`R5`) & Enforcement Gates

- `src/litestar_security/testing.py` directly exports all 15 `StoreConformanceFactories` conformance suites, standalone `assert_rate_limiter_conformance`, and test doubles (`InMemorySecurityBackend`, `FakeClock`, `FakeOAuthProvider`) in `__all__` with no lazy gating and no optional extras required.[^adr1-testing]
- `litestar_security.testing` stays completely unimported by runtime code: `src/litestar_security/__init__.py` resolves only `_OAUTH_EXPORTS` via `__getattr__`, Ruff `TID251` (`[tool.ruff.lint.flake8-tidy-imports.banned-api]` paired with `ban-relative-imports = "all"`) bans `litestar_security.testing` and third-party adapters in `src/litestar_security/`, `tools/check_import_boundaries.py` (`R5`) asserts `'litestar_security.testing' not in sys.modules` and `not hasattr(litestar_security, 'InMemorySecurityBackend')`, and `tools/check_downstream_consumer.py` verifies the built wheel's `METADATA`.[^adr1-pyproject][^adr1-downstream][^adr1-boundaries]

## References

[^adr1-pyproject]: `pyproject.toml` — Banned third-party adapter imports (`TID251`) and core dependency declarations
[^adr1-downstream]: `tools/check_downstream_consumer.py` — Wheel `Requires-Dist` and runtime import boundary enforcement
[^adr1-boundaries]: `tools/check_import_boundaries.py` — `R4` awaitability and `R5` unimported test-kit boundary verification
[^adr1-workers]: `src/litestar_security/workers.py::SecurityMetrics` — Synchronous telemetry sink and `BlockingIntegration` startup normalization
[^adr1-auth]: `src/litestar_security/authentication.py::CredentialSlot` — Synchronous non-blocking `CredentialSlot.extract` boundary
[^adr1-testing]: `src/litestar_security/testing.py::assert_security_backend_conformance` — `InMemorySecurityBackend`, `StoreConformanceFactories`, and conformance suites
