---
type: Standard
title: "Product & Engineering Guidelines"
description: "Mandatory architectural boundaries, typing conventions, slotted value-object contracts, and verification discipline for litestar-security."
status: stable
tags: [guidelines, architecture, typing, boundaries, security]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-setup
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: pyproject-lint
    resource: "pyproject.toml"
    title: "Ruff, mypy, pyright, slotscheck, and coverage configuration"
  - id: no-future
    resource: "tools/hooks/no_future_annotations.py"
    title: "Hook forbidding from __future__ import annotations across the repository"
  - id: import-boundaries
    resource: "tools/check_import_boundaries.py"
    title: "AST and subprocess boundary verifier for R4/R5 invariants"
  - id: downstream-check
    resource: "tools/check_downstream_consumer.py"
    title: "Wheel metadata and forbidden adapter dependency verifier"
  - id: workers-mod
    resource: "src/litestar_security/workers.py"
    title: "BlockingIntegration and BlockingCallRunner startup sync-port wrapper"
  - id: typing-mod
    resource: "src/litestar_security/typing.py"
    title: "Centralized optional-dependency availability flags and lazy fallback facade"
---

# Product & Engineering Guidelines

<!-- truth: start -->
- **Never use `from __future__ import annotations`**: Litestar evaluates route handler, dependency, and DTO annotations at runtime. Both `tools/hooks/no_future_annotations.py` and Ruff `FA102` reject `from __future__ import annotations` in every `.py` file.[^pyproject-lint][^no-future]
- **Modern Python `>=3.10` Typing & Cross-Version AST Compatibility**: Use PEP 585 built-in generics (`list`, `dict`, `tuple`, `set`, `type`) and PEP 604 unions (`X | Y`, `X | None`). Bind starred tuple keys to a local variable (`key = (*prefix, item)`) before indexing `mapping[key]` so `mypy>=2.4.1` (`ast-serialize`) accepts the module when type-checking Python 3.10 consumers.[^pyproject-lint]
- **Centralized Optional-Extra Shims (`litestar_security.typing`)**: Route all optional third-party imports (`argon2`, `pyotp`, `webauthn`), `*_INSTALLED` flags, and runtime fallback shims through `src/litestar_security/_typing.py` and `src/litestar_security/typing.py`; never place ad-hoc `try: import ... except ImportError` blocks in domain modules.[^typing-mod]
- **Zero Storage/Adapter Runtime Dependencies**: Never import `sqlalchemy`, `advanced_alchemy`, `sqlspec`, `redis`, `asyncpg`, `aiosqlite`, `aiomysql`, `motor`, `pymongo`, `boto3`, `aioboto3`, `google.cloud`, or `litestar_mcp` in `src/litestar_security/`. Enforce via Ruff `TID251` and `tools/check_downstream_consumer.py`.[^pyproject-lint][^downstream-check]
- **Isolated Test-Kit Boundary (`R5`)**: Runtime modules under `src/litestar_security/` must never import `litestar_security.testing`. Enforced via Ruff `TID251` and `tools/check_import_boundaries.py`, which also asserts `import litestar_security` never loads `litestar_security.testing` or exposes `InMemorySecurityBackend`; `src/litestar_security/__init__.py` uses `_lazy.py` only for curated `_OAUTH_EXPORTS`.[^import-boundaries]
- **Zero Per-Call `inspect.isawaitable` Branches (`R4`)**: Runtime code must never branch on `inspect.isawaitable(...)` per request. Synchronous store or verifier implementations must be wrapped once at startup in `BlockingIntegration(sync_impl)` and executed off the event loop via `BlockingCallRunner` (`anyio.to_thread.run_sync(..., abandon_on_cancel=False)`).[^import-boundaries][^workers-mod]
- **Slotted Value Objects & Wire Schemas**: Domain, evidence, and outcome dataclasses declare `@dataclass(frozen=True, slots=True)` (using `field(default_factory=lambda: MappingProxyType({}))` for empty read-only mapping defaults), while mutable configuration/compiler types (`SecurityConfig`, `RouteCompiler`, `PolicyCompiler`, `BlockingCallRunner`) declare `@dataclass(slots=True)`, all verified by `uv run slotscheck src/litestar_security/`. Wire payloads inherit `WireStruct(msgspec.Struct, frozen=True, forbid_unknown_fields=True)`.[^pyproject-lint]
- **Documentation & Comment Hygiene**: Use Google-style docstrings explaining why a design choice or security invariant exists. Do not add inline `#` explanatory comments in Python modules; keep module layout clean with `__all__` and public symbols defined before private `_` helpers.[^pyproject-lint]
<!-- truth: end -->

## Security & Secret-Handling Standards

- **Fail-Closed Verification**: Any malformed token, unknown version byte, expired timestamp, mismatched audience/issuer, or revoked session/family/grant must return a structured failure outcome without leaking secret material or internal exception traces.[^pyproject-lint]
- **Constant-Time Digest Comparisons**: Always use `hmac.compare_digest` when comparing HMAC tags, API key digests, CSRF tokens, or recovery codes.
- **Secret Redaction**: Wrap raw secrets in `SecretStr` or configure `field(repr=False)` on dataclasses holding keys, peppers, or tokens so `repr()` and structured logs never emit plaintext credentials.

## References

[^pyproject-lint]: `pyproject.toml` — Ruff, mypy, pyright, slotscheck, and coverage configuration
[^no-future]: `tools/hooks/no_future_annotations.py` — Hook forbidding `from __future__ import annotations` across the repository
[^import-boundaries]: `tools/check_import_boundaries.py` — AST and subprocess boundary verifier for R4/R5 invariants
[^downstream-check]: `tools/check_downstream_consumer.py` — Wheel metadata and forbidden adapter dependency verifier
[^workers-mod]: `src/litestar_security/workers.py` — `BlockingIntegration` and `BlockingCallRunner` startup sync-port wrapper
[^typing-mod]: `src/litestar_security/typing.py` — Centralized optional-dependency availability flags and lazy fallback facade
