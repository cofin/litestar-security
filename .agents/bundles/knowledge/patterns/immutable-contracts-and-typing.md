---
type: Pattern
title: "Immutable Domain Contracts, Runtime Annotations, & Secret Redaction"
description: "Frozen versus mutable slotted dataclasses, MappingProxyType default factories, runtime annotations, centralized optional-extra shims, and secret redaction."
status: stable
tags: [patterns, typing, dataclasses, slotscheck, secrets]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-setup
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: context-py
    resource: "src/litestar_security/context.py::SecurityContext"
    title: "Slotted frozen domain contracts: Principal, SecurityContext, AuthenticationEvidence"
  - id: config-py
    resource: "src/litestar_security/config.py::SecurityConfig"
    title: "Mutable slotted SecurityConfig versus frozen value configs"
  - id: iap-py
    resource: "src/litestar_security/providers/iap/_iap.py::GoogleIAPExternalIdentity"
    title: "MappingProxyType default_factory pattern on slotted frozen dataclasses"
  - id: precommit-cfg
    resource: ".pre-commit-config.yaml"
    title: "Pre-commit scope restricting no_future_annotations.py to src/litestar_security/"
  - id: no-future-hook
    resource: "tools/hooks/no_future_annotations.py"
    title: "AST/line verifier forbidding from __future__ import annotations"
  - id: local-controller
    resource: "src/litestar_security/accounts/controllers/_local.py"
    title: "Controller route handlers with runtime-resolved Request and DI annotations"
  - id: typing-shim
    resource: "src/litestar_security/_typing.py::MissingDependencyError"
    title: "Centralized optional-extra flags, shims, and MissingDependencyError extra mapping"
  - id: accounts-init
    resource: "src/litestar_security/accounts/__init__.py"
    title: "Eager annotation exports with instantiation-time extra enforcement"
  - id: oauth-tx
    resource: "src/litestar_security/providers/oauth/_transactions.py::SecretStr"
    title: "Redacted SecretStr wrapper for OAuth transactions and credentials"
  - id: local-schemas
    resource: "src/litestar_security/accounts/schemas/_local.py::LocalCredentials"
    title: "Custom __repr__ redaction on wire payloads and non-OAuth secrets"
---

# Immutable Domain Contracts, Runtime Annotations, & Secret Redaction

<!-- truth: start -->
- **Frozen vs. Mutable Slotted Dataclasses**: Domain, principal, evidence, snapshot, restriction, outcome, and immutable value contracts (`Principal`, `SecurityContext`, `AuthenticationEvidence`, `AuthorizationSnapshot`, `CredentialRestrictions`, `SecurityRuntimePlan`, `WirePolicy`, `RaisedErrorSchema`, `ExternalCSRF`) use `@dataclass(frozen=True, slots=True)`. Mutable runtime orchestrators, compilers, and runners (`SecurityConfig`, `RouteCompiler`, `PolicyCompiler`, `BlockingCallRunner`, `_PrefixExcludingBearerSlot`) use `@dataclass(slots=True)`, while non-dataclass runtime classes declare `__slots__`, all validated by `uv run slotscheck src/litestar_security/`.[^context-py][^config-py]
- **`MappingProxyType` Dataclass Defaults**: Because `MappingProxyType` defines `__hash__ = None`, Python 3.11+ `dataclasses` rejects `default=MappingProxyType({})` as an unhashable mutable default; declare read-only mapping defaults with `field(default_factory=lambda: MappingProxyType({}))`.[^iap-py]
- **No `from __future__ import annotations` in Package Code**: `.pre-commit-config.yaml` enforces `tools/hooks/no_future_annotations.py` across `^src/litestar_security/.*\.py$` (some `src/tests/` modules still use it, whereas package source omits it completely). Litestar inspects route signatures, dependency providers, and DTO annotations at runtime; keep Litestar route/DI/DTO types imported at module scope while isolating type-only imports inside `if TYPE_CHECKING:`.[^precommit-cfg][^no-future-hook][^local-controller]
- **Optional-Extra Shims & Instantiation Enforcement**: `src/litestar_security/_typing.py` (re-exported via `src/litestar_security/typing.py`) centralizes lazy `OptionalDependencyFlag` probes, runtime fallback shims, and `MissingDependencyError` (`_EXTRAS = {"argon2": "argon2", "pyotp": "mfa", "webauthn": "passkeys"}`). `src/litestar_security/accounts/__init__.py` eagerly exports `Argon2PasswordHasher`, `MFAService`, `MFALoginService`, and `PyWebAuthnVerifier` so runtime annotations resolve without optional packages installed, enforcing extras at instantiation.[^typing-shim][^accounts-init]
- **Secret Redaction (`SecretStr`, `repr=False`, & Custom `__repr__`)**: OAuth transactions and credentials wrap secrets in `SecretStr` (`providers/oauth/_transactions.py`), while non-OAuth contracts use `field(repr=False)` (on dataclass secrets such as `PresentedCredential.value`, `Authenticated.claims`, `APIKeyConfig.pepper`, and `SessionBindingConfig.pepper`) or custom `__repr__` methods (such as `LocalCredentials`).[^oauth-tx][^local-schemas]
<!-- truth: end -->

## Canonical Value-Object Pattern

```python
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class TokenSigningKey:
    key_id: str
    secret: bytes = field(repr=False)
```

## References

[^context-py]: `src/litestar_security/context.py::SecurityContext` — Slotted frozen domain contracts: `Principal`, `SecurityContext`, `AuthenticationEvidence`
[^config-py]: `src/litestar_security/config.py::SecurityConfig` — Mutable slotted `SecurityConfig` versus frozen value configs
[^iap-py]: `src/litestar_security/providers/iap/_iap.py::GoogleIAPExternalIdentity` — `MappingProxyType` `default_factory` pattern on slotted frozen dataclasses
[^precommit-cfg]: `.pre-commit-config.yaml` — Pre-commit hook scoping `no_future_annotations.py` to `^src/litestar_security/.*\.py$`
[^no-future-hook]: `tools/hooks/no_future_annotations.py` — AST/line verifier forbidding `from __future__ import annotations`
[^local-controller]: `src/litestar_security/accounts/controllers/_local.py` — Controller route handlers with runtime-resolved `Request` and DI annotations
[^typing-shim]: `src/litestar_security/_typing.py::MissingDependencyError` — Centralized optional-extra flags, shims, and `MissingDependencyError` extra mapping
[^accounts-init]: `src/litestar_security/accounts/__init__.py` — Eager annotation exports with instantiation-time extra enforcement
[^oauth-tx]: `src/litestar_security/providers/oauth/_transactions.py::SecretStr` — Redacted `SecretStr` wrapper for OAuth transactions and credentials
[^local-schemas]: `src/litestar_security/accounts/schemas/_local.py::LocalCredentials` — Custom `__repr__` redaction on wire payloads and non-OAuth secrets
