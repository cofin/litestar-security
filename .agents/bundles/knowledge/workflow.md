---
type: Guide
title: "Development & Verification Workflow"
description: "Verified inner-loop test, lint, typecheck, slotscheck, import-boundary, and coverage commands for litestar-security."
status: stable
tags: [workflow, verification, tdd, pytest, ruff, mypy, pyright]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-setup
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: makefile-gates
    resource: "Makefile"
    title: "Makefile verification and quality gate targets"
  - id: pyproject-test
    resource: "pyproject.toml"
    title: "Pytest, coverage, ruff, mypy, and pyright tool settings"
  - id: boundary-tool
    resource: "tools/check_import_boundaries.py"
    title: "Import boundary and lazy test-kit verifier"
  - id: downstream-tool
    resource: "tools/check_downstream_consumer.py"
    title: "Wheel metadata and forbidden adapter dependency verifier"
---

# Development & Verification Workflow

<!-- truth: start -->
- **Environment Setup**: `make install` (`uv sync --all-groups --all-extras`) installs all optional extras (`argon2`, `mfa`, `oauth`, `passkeys`) and dev/lint/doc dependency groups.[^makefile-gates]
- **Focused TDD Inner Loop**:
  - Pure unit tests (no Litestar app or HTTP client): `uv run pytest src/tests/unit/test_<topic>.py -q`[^pyproject-test]
  - End-to-end ASGI/HTTP/WebSocket integration tests: `uv run pytest src/tests/integration/test_<topic>.py -q`[^pyproject-test]
  - Runnable examples: `make examples` (`uv run pytest src/tests/examples`)[^makefile-gates]
- **Static Quality Gate (`make lint`)**:
  - `make prek` (`uvx prek run` across working-tree files: `tools/hooks/no_future_annotations.py`, `ruff-check`, `ruff-format`, `ensure-dunder-all`, `slotscheck`, `codespell`)
  - `make type-check` (`uv run mypy` and `uv run pyright` at `pythonVersion = "3.10"`, `typeCheckingMode = "strict"`)
  - `make slotscheck` (`uv run slotscheck src/litestar_security/`)
  - `make import-boundaries` (`uv run python tools/check_import_boundaries.py` for `R4` and `R5`)
  - `make zizmor` (`uvx zizmor .github/workflows`)[^makefile-gates][^pyproject-test][^boundary-tool]
- **Coverage & Release Gates (`make coverage` / `make check-all`)**:
  - Global threshold: `>=95%` branch+line coverage across `src/litestar_security`.[^makefile-gates][^pyproject-test]
  - Core security gate: `100%` branch coverage (`--cov-fail-under=100`) on `authentication.py`, `guards.py`, `context.py`, `providers/jwt/*`, `providers/oauth/_transactions.py`, `accounts/_refresh.py`, and `websocket/_connect_tokens.py`.[^makefile-gates]
  - Full gate: `make check-all` runs `lint`, `test-all`, `coverage`, `docs`, `docs-linkcheck`, `downstream-check` (`tools/check_downstream_consumer.py`), and `build`.[^makefile-gates][^downstream-tool]
- **Flow Continuity**: Task worksheets (`.agents/bundles/specs/<flow_id>/tasks/` or `chapters/<ch_id>/tasks/`) and owning `spec.md` checklists are the sole authority for task state and commits, requiring one declared `verification_strategy` and testing through real public seams in canonical module test files.[^makefile-gates]
<!-- truth: end -->

## Red-Green-Refactor & Direct Markdown Execution Loop

1. **Choose the right test tier first**: Place pure algorithm, codec, verifier, and service contract tests in `src/tests/unit/` without instantiating `Litestar` or `AsyncTestClient`. Place route-compiled middleware, controller, OpenAPI, cookie/CSRF, and WebSocket lifecycle tests in `src/tests/integration/`.[^pyproject-test]
2. **Drive time deterministically**: Inject `FakeClock` into services, verifiers, caches, and `WebSocketConnectTokenService` instead of calling `time.sleep` or `anyio.sleep` for TTL/expiry tests.
3. **Run targeted checks before full gates**: Execute the targeted pytest file, then run `uv run ruff check`, `uv run mypy`, `uv run pyright`, `uv run slotscheck src/litestar_security/`, and `uv run python tools/check_import_boundaries.py`.[^makefile-gates][^boundary-tool]
4. **Follow Flow worksheet discipline**: Resolve `.agents/setup-state.json`, verify the 5-check preflight (`dependencies_closed`, `worksheet_complete`, `verification_strategy_declared`, `plan_identity_matches`, `target_symbols_exist`), commit atomically per task with GPG signing, and keep `specs/**`, `knowledge/**`, and `.agents/skills/**` synchronized in present tense via `/flow:learn`.

## References

[^makefile-gates]: `Makefile` — Makefile verification and quality gate targets
[^pyproject-test]: `pyproject.toml` — Pytest, coverage, ruff, mypy, and pyright tool settings
[^boundary-tool]: `tools/check_import_boundaries.py` — Import boundary and lazy test-kit verifier
[^downstream-tool]: `tools/check_downstream_consumer.py` — Wheel metadata and forbidden adapter dependency verifier
