# Institutional Knowledge

Synthesized institutional knowledge for `litestar-security`, organized by engineering concern.

## Workflow & Verification

- **[Verification Workflow](./workflow.md)** — Verified host inner-loop commands, TDD cycle, coverage gates, and boundary checks.

## Architecture (`architecture/`)

- **[Runtime Pipeline & Deep Modules](./architecture/runtime-pipeline.md)** — `SecurityPlugin` initialization, `RouteCompiler`, `SecurityMiddleware`, `_AuthenticationEvaluator`, `AuthorizationPredicate` guards, and dependency category map.
- **[Provider & Store Ports](./architecture/provider-and-store-ports.md)** — Zero-adapter boundary, `@runtime_checkable` `Protocol` ports, `BlockingIntegration` / `BlockingCallRunner`, and optional extra isolation.

## Patterns (`patterns/`)

- **[Wire Schemas & DTOs](./patterns/wire-schemas-and-dtos.md)** — `WireStruct`, `WirePolicy`, `WireDTO`, `WireBackend`, `WireUnionDTO`, and structured error responses (`RouteError`, `ProblemDetail`, `OperationMessage`).
- **[Immutable Contracts & Typing](./patterns/immutable-contracts-and-typing.md)** — Slotted frozen dataclasses, runtime-inspected annotations without `from __future__ import annotations`, and secret redaction.

## Domains (`domains/`)

- **[Authentication & Authorization Domain](./domains/authentication-and-authorization.md)** — Ubiquitous glossary and invariants for `CredentialSlot`, `CredentialVerifier`, `IdentityResolver`, `AuthorizationResolver`, `AuthenticationEvidence`, `AuthorizationSnapshot`, `Principal`, and `SecurityContext`.
- **[Accounts & Federation Domain](./domains/accounts-and-federation.md)** — Local accounts, dual-cookie sessions, refresh-token family rotation and receipts, purpose tokens, MFA, passkeys, step-up grants, and OAuth/OIDC transaction sealing.

## Testing (`testing/`)

- **[Test Organization & Store Conformance](./testing/test-organization-and-conformance.md)** — Strict `src/tests/unit/` vs `src/tests/integration/` split, `FakeClock`, `InMemorySecurityBackend`, `assert_security_backend_conformance`, and `100%` branch coverage on `CORE_COVERAGE`.

## Gotchas (`gotchas/`)

- **[Route Compilation, CSRF, & Slot Ownership Gotchas](./gotchas/route-compilation-and-csrf.md)** — `AuthenticationPolicy.public()` vs `exclude()` CSRF semantics, `APIKeyConfig(accept_authorization_bearer=True)` prefix coordination vs `CompositeBearerConfig`, and Python 3.10/3.11 AST/dataclass traps.

## Architectural Decisions (`decisions/`)

- **[ADR-001: Protocol Ports Without Runtime Adapters](./decisions/adr-001-protocol-ports-without-runtime-adapters.md)** — Why `litestar-security` ships `@runtime_checkable` `Protocol` ports + `assert_security_backend_conformance` instead of bundling ORM/cache drivers.
- **[ADR-002: Startup Route Compilation & Msgspec Wire DTOs](./decisions/adr-002-compile-time-route-plans-and-wire-dtos.md)** — Why route authentication policies, OpenAPI security requirements, and wire DTO projections are compiled once at startup.
- **[ADR-003: Centralized Optional-Extra Shims Without Postponed Annotations](./decisions/adr-003-centralized-optional-extra-shims.md)** — Why optional third-party availability flags and slotted runtime fallback shims live exclusively in `litestar_security._typing` (`litestar_security.typing`).
