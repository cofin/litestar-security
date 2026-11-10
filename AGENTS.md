# litestar-security Agent Context

Unified, storage-agnostic authentication, authorization, provider verification, account lifecycle, and WebSocket security framework for Litestar (`v0.7.1`).

## Knowledge & Skill Routing

- **Root OKF v0.2 Bundle Index**: [`.agents/bundles/index.md`](.agents/bundles/index.md)
- **Product Context**: [Product Definition](.agents/bundles/product/product.md) | [Product Guidelines](.agents/bundles/product/product-guidelines.md) | [Tech Stack](.agents/bundles/product/tech-stack.md)
- **Verification & TDD Workflow**: [`.agents/bundles/knowledge/workflow.md`](.agents/bundles/knowledge/workflow.md)
- **Institutional Knowledge**: [`.agents/bundles/knowledge/index.md`](.agents/bundles/knowledge/index.md) (`architecture/`, `patterns/`, `domains/`, `testing/`, `gotchas/`, `decisions/`)
- **Project-Local Skills & Checklists**: [`.agents/skills/index.md`](.agents/skills/index.md) (`runtime-and-policy`, `providers`, `accounts`, `websocket-and-testing` and paired `review-*` skills)
- **Project-Local Subagents**: `.agents/agents/{runtime-and-policy,providers,accounts,websocket-and-testing}-{specialist,reviewer}.md`

## Core Verification Commands

- **Install**: `make install` (`uv sync --all-groups --all-extras`)
- **Focused Unit Tests**: `uv run pytest src/tests/unit/test_<module>.py -q`
- **Focused Integration Tests**: `uv run pytest src/tests/integration/test_<module>.py -q`
- **Static & Boundary Gates (`make lint`)**: `uvx prek run --all-files`, `uv run mypy`, `uv run pyright`, `uv run slotscheck src/litestar_security/`, `uv run python tools/check_import_boundaries.py`, `uvx zizmor .github/workflows`
- **Full Suite & Coverage Gate**: `make check-all` (`>=95%` overall coverage + `100%` branch coverage on `CORE_COVERAGE` modules + wheel/downstream boundary check)

## Architectural Non-Negotiables

1. **Never use `from __future__ import annotations`**: Enforced by `tools/hooks/no_future_annotations.py` and Ruff `FA102`; Litestar evaluates route, DI, and DTO annotations at runtime.
2. **Zero runtime storage/adapter dependencies**: Never import ORM, database, cache, or cloud SDK packages in `src/litestar_security/` (`TID251` and `tools/check_downstream_consumer.py`).
3. **Startup sync-port wrapping (`R4`) & isolated test-kit boundary (`R5`)**: Never branch on `inspect.isawaitable` per call (wrap synchronous adapters in `BlockingIntegration` at startup) and never import `litestar_security.testing` from runtime modules (`tools/check_import_boundaries.py`).
4. **Slotted value objects & `WireStruct`**: Use `@dataclass(frozen=True, slots=True)` on domain/evidence/outcome records (`@dataclass(slots=True)` on `SecurityConfig`/compilers) and `WireStruct(msgspec.Struct, frozen=True, forbid_unknown_fields=True)` on HTTP wire schemas.

<!-- project-customization: start -->
## External Actions

Always confirm with the user before taking any external action, including:
- Creating, commenting on, or modifying GitHub issues, pull requests, discussions, or releases.
- Pushing commits, tags, or branches to any remote repository.
- Publishing packages, documentation, or artifacts to any external service.
- Sending messages, webhooks, or API requests to external systems on the user's behalf.

Local read-only inspection, running tests/linters, and editing working-tree files requested by the user do not require extra confirmation unless destructive.

## Test Organization

- **Unit tests (`src/tests/unit/`)**: Test individual functions, classes, and pure logic in isolation using in-memory fakes or mocks. Unit tests must **never** instantiate a `Litestar` app, `TestClient`, or `AsyncTestClient`.
- **Integration tests (`src/tests/integration/`)**: Test end-to-end request/response flows, middleware, guards, controllers, OpenAPI generation, and plugin wiring through a real `Litestar` application and test client.
- **Typing helpers (`src/tests/helpers/typing.py`)**: Put static typing test helpers and type-check assertions in `src/tests/helpers/typing.py`. Do not scatter typing-only check helpers across unit or integration test modules.
- **Fixtures (`conftest.py`)**: Keep fixture scope as narrow as possible:
  - Define fixtures used by a single test module inside that module.
  - Define fixtures shared across multiple modules in a directory in that directory's `conftest.py` (`src/tests/unit/conftest.py` or `src/tests/integration/conftest.py`).
  - Reserve the root `src/tests/conftest.py` strictly for baseline fixtures shared across both unit and integration suites.
<!-- project-customization: end -->
