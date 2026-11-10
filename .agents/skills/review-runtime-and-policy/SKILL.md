---
name: review-runtime-and-policy
description: Use when reviewing changes to SecurityPlugin, SecurityConfig, AuthenticationPolicy, RouteCompiler, guards, SecurityContext, WireDTO, or headers. Not for provider or account reviews.
---

# Review Skill: Runtime, Policy, Guards, & Wire DTOs

Review capability skill for auditing changes in `src/litestar_security/{__init__,_lazy,_typing,typing,_docs,_internal,plugin,config,authentication,guards,context,_openapi,schema,_dto,headers,controllers,workers,_cli}.py`.

## Review Invariants

<!-- truth: start -->
1. **No `from __future__ import annotations` in `src/litestar_security/`**: Verify DI/route annotations resolve at runtime and optional-extra shims (`_typing.py` / `typing.py` / `accounts/__init__.py`) enforce extras at instantiation.
2. **Slotted Contracts**: Domain/evidence/snapshot/policy value objects declare `@dataclass(frozen=True, slots=True)` with `MappingProxyType` `default_factory`, mutable orchestrators (`SecurityConfig`, `RouteCompiler`, `PolicyCompiler`, `BlockingCallRunner`) declare `@dataclass(slots=True)`, and non-dataclass runtime classes declare `__slots__`.
3. **`public()` vs. `exclude()` Parity**: `public()` emits `[{}]` and sets `opt[csrf_exclude_key] = True` unless `csrf_required=True` is set on the HTTP handler; `exclude()` emits `[{}]` and leaves native CSRF untouched unless `csrf_required=True`.
4. **Bearer Coordination & RFC 9728**: `_coordinate_bearer_slots` wraps custom non-dataclass `authorization.bearer` slots in `_PrefixExcludingBearerSlot`; `_plan_uses_bearer` inspects `additional_security_schemes`.
5. **Boundaries (`R4`/`R5`/`TID251`) & Wire DTOs**: Zero runtime `inspect.isawaitable` or `litestar_security.testing` imports; `WireBackend` binds `cache_key = (*name_key, shape)` before indexing; `WireUnionDTO` stays response-only; `RouteError`/`ProblemDetail`/`RaisedErrorSchema` match Litestar conversion.
<!-- truth: end -->

## Review Protocol

1. **Read the Diff & Surrounding Seams**: Inspect modified files in `src/litestar_security/` and corresponding tests in `src/tests/unit/` and `src/tests/integration/`.
2. **Evaluate Domain Invariants (`RUN-01`..`RUN-09`)**: Load [references/checklist.md](./references/checklist.md) and check every item against the diff.
3. **Filter False Positives (`FP-RUN-01`..`FP-RUN-06`)**: Cross-check candidate findings against [references/false-positive-suppressions.md](./references/false-positive-suppressions.md) before reporting.
4. **Verify Test Strength & Tier Boundaries**:
   - Confirm `authentication.py`, `guards.py`, and `context.py` retain `100%` branch coverage (`CORE_COVERAGE`).
   - Confirm unit tests in `src/tests/unit/` do not instantiate `Litestar`, `TestClient`, or `AsyncTestClient` (noting legacy exceptions `src/tests/unit/test_cli.py` and `src/tests/unit/test_dto.py` so unrelated PRs are not blocked unless touching them).
5. **Run Verification Commands**:
   ```bash
   uv run pytest src/tests/unit/test_config.py src/tests/unit/test_dto.py src/tests/unit/test_openapi.py src/tests/unit/test_headers.py src/tests/unit/test_cli.py src/tests/unit/test_docs.py src/tests/unit/test_authentication_evaluator.py src/tests/unit/test_authentication_registry.py src/tests/unit/test_guards.py src/tests/unit/test_context.py -q
   uv run pytest src/tests/integration/test_plugin.py src/tests/integration/test_openapi_document.py src/tests/integration/test_route_exclusion.py src/tests/integration/test_error_responses.py src/tests/integration/test_authentication_composition.py src/tests/integration/test_resource_server.py src/tests/integration/test_wire_casing.py src/tests/integration/test_runtime.py -q
   uv run ruff check src/litestar_security/ src/tests/
   uv run mypy && uv run pyright
   uv run slotscheck src/litestar_security/
   uv run python tools/check_import_boundaries.py
   ```

## Required Finding Format

Report only verified, actionable findings anchored to `path/to/file.py:line` with the violated invariant (`RUN-XX`), concrete failure scenario, and minimal fix.

## References

- [Review Checklist (`RUN-01`..`RUN-09`)](./references/checklist.md)
- [False-Positive Suppressions (`FP-RUN-01`..`FP-RUN-06`)](./references/false-positive-suppressions.md)
