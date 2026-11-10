---
type: Decision
title: "ADR-003: Centralized Optional-Extra Shims Without Postponed Annotations"
description: "Architectural decision to centralize optional third-party availability flags and runtime fallback shims in litestar_security._typing rather than using postponed annotations or splitting domain modules."
status: stable
tags: [decisions, adr, typing, optional-extras, accounts, testing]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: "agent:flow-setup"
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: adr3-private-typing
    resource: "src/litestar_security/_typing.py::OptionalDependencyFlag"
    title: "Centralized find_spec availability flags, _module_blocked, ensure_* gates, MissingDependencyError, and slotted runtime fallback shims"
  - id: adr3-public-typing
    resource: "src/litestar_security/typing.py"
    title: "Public typing and optional-dependency availability facade"
  - id: adr3-accounts
    resource: "src/litestar_security/accounts/__init__.py"
    title: "Eager accounts exports, lazy _CONTROLLER_EXPORTS, and instantiation-time optional-extra enforcement"
  - id: adr3-profiles
    resource: "src/litestar_security/accounts/_profiles.py::LocalAuthConfig"
    title: "LocalAuthConfig default Argon2PasswordHasher factory requiring custom PasswordHasher without [argon2]"
  - id: adr3-no-future
    resource: "tools/hooks/no_future_annotations.py"
    title: "Repository-wide ban on from __future__ import annotations"
---

# ADR-003: Centralized Optional-Extra Shims Without Postponed Annotations

<!-- truth: start -->
- **Status**: Accepted (`v0.7.1`).[^adr3-private-typing][^adr3-public-typing]
- **Context**: `litestar-security` bans `from __future__ import annotations` (`FA102`) because Litestar evaluates route, DI, and DTO annotations at runtime.[^adr3-no-future] Downstream packages using custom `PasswordHasher` or `WebAuthnVerifier` adapters — or running `assert_security_backend_conformance` from `litestar_security.testing` — require pure `accounts` protocols, value records, services (`AESGCMSecretProtector`, `StepUpService`, `PasskeyService`, `LocalAuthConfig`), and controller builders to import cleanly without `[argon2]`, `[mfa]`, or `[passkeys]`. Running `LocalAuthConfig` or `LocalAuth` without `[argon2]` requires supplying a custom `PasswordHasher` because their default factory instantiates `Argon2PasswordHasher`.[^adr3-accounts][^adr3-profiles]
- **Decision**: Centralize `importlib.util.find_spec` probes (`OptionalDependencyFlag` / `*_INSTALLED`), `require_dependency`, `MissingDependencyError`, `ensure_argon2` / `ensure_pyotp` / `ensure_webauthn` guards, and slotted fallback shims (`_Argon2EngineShim`, `_PyOTPShim`, `_WebAuthn*Shim`) in `src/litestar_security/_typing.py`, re-exported via `src/litestar_security/typing.py`.[^adr3-private-typing][^adr3-public-typing] Eagerly export all `accounts` contracts and optional-extra adapters in `accounts/__init__.py` while keeping `_CONTROLLER_EXPORTS` (`LOCAL_AUTH_TAGS`, `build_local_auth_routes`, `build_mfa_routes`, `require_local_bearer`) lazy via `__getattr__`, enforcing `[argon2]`, `[mfa]`, and `[passkeys]` strictly at instantiation (`Argon2PasswordHasher`, `MFAService`, `MFALoginService`, `PyWebAuthnVerifier`).[^adr3-accounts]
- **Alternatives Rejected**:
  - *Enabling `from __future__ import annotations`*: Breaks Litestar runtime dependency and DTO type evaluation when symbols sit under `if TYPE_CHECKING:`.[^adr3-no-future]
  - *Splitting every domain module into `_*_types.py` and `_*_service.py` pairs*: Fragments cohesive domain modules while still blocking `PasskeyService` or `LocalAuthConfig` callers supplying custom verifiers or hashers.
  - *Scattering `try: import ... except ImportError` blocks across domain and test-kit modules*: Duplicates fallback logic and `pragma: no cover` exclusions across domain files.
- **Consequences**:
  - **Positive**: Domain modules import cleanly from `litestar_security.typing`; `litestar_security.testing` runs with zero optional extras; `_module_blocked()` supports dynamic `sys.modules[pkg] = None` test isolation without clearing caches, while `reset_dependency_cache()` invalidates `_dependency_cache` and `_optional_module_cache` after `sys.path` or package mutations.[^adr3-private-typing][^adr3-accounts]
  - **Trade-off**: Callers omitting `[argon2]` must pass a custom `PasswordHasher` to `LocalAuthConfig` / `LocalAuth`, and adding a new optional dependency requires registering lazy exports and slotted fallback shims in `_typing.py` and `typing.py`.[^adr3-private-typing][^adr3-profiles]
<!-- truth: end -->

## Cache Isolation & Optional-Extra Error Semantics

- **`_module_blocked()` vs. `reset_dependency_cache()`**: `module_available()` and `import_optional()` evaluate `_module_blocked(module_name)` (checking whether `sys.modules` maps the root or full module name to `None`) before consulting `_dependency_cache` or `_optional_module_cache`, so tests patching `sys.modules[pkg] = None` take immediate effect; `reset_dependency_cache()` clears both caches when `sys.path` or installed distributions change.[^adr3-private-typing]
- **`MissingDependencyError` vs. `ensure_*` Exceptions**: `require_dependency()` raises `MissingDependencyError` (a subclass of `ImportError`) which consults `_EXTRAS` (`{"argon2": "argon2", "pyotp": "mfa", "webauthn": "passkeys"}`) to suggest `'pip install litestar-security[<extra>]' or 'pip install <target>'` for mapped packages and `'pip install <target>'` otherwise (such as `jwt`). By contrast, `ensure_argon2()`, `ensure_pyotp()`, and `ensure_webauthn()` raise plain `ImportError` naming the required `[argon2]`, `[mfa]`, or `[passkeys]` extra directly.[^adr3-private-typing]

## References

[^adr3-private-typing]: `src/litestar_security/_typing.py::OptionalDependencyFlag` — Centralized `find_spec` availability flags, `_module_blocked`, `ensure_*` gates, `MissingDependencyError`, and slotted runtime fallback shims
[^adr3-public-typing]: `src/litestar_security/typing.py` — Public typing and optional-dependency availability facade
[^adr3-accounts]: `src/litestar_security/accounts/__init__.py` — Eager `accounts` exports, lazy `_CONTROLLER_EXPORTS`, and instantiation-time optional-extra enforcement
[^adr3-profiles]: `src/litestar_security/accounts/_profiles.py::LocalAuthConfig` — `LocalAuthConfig` default `Argon2PasswordHasher` factory requiring custom `PasswordHasher` without `[argon2]`
[^adr3-no-future]: `tools/hooks/no_future_annotations.py` — Repository-wide ban on `from __future__ import annotations`
