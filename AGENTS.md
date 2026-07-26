# Agent Instructions

## External actions

Never mutate a hosted repository, issue, pull request, review, discussion,
release, or other public artifact without fresh user permission for that exact
action and repository. Local research and drafts are allowed.

## Test organization

Keep the test suite compact and organized by behavior:

- Put pure contracts, normalization, registry compilation, and evaluator tests
  in `src/tests/unit/`.
- Put Litestar application, middleware, dependency injection, plugin, CLI, and
  request lifecycle tests in `src/tests/integration/`.
- Keep strict static fixtures in `src/tests/typing/`; they are type-checker
  inputs, not pytest suites.
- Never add tests for repository tools, build scripts, documentation, or docs
  examples.

Before creating a test file, extend the closest existing behavioral module.
Create a new file only for a genuinely distinct subsystem that would make the
existing module incoherent. Do not create one test module per class, helper, or
small source file.

Use parametrization for outcome matrices, ownership levels, transports,
principal states, and equivalent error cases. Consolidate repeated fake slots,
authenticators, resolvers, users, backends, and app builders instead of copying
them between modules.

Fixture ownership follows the directory hierarchy:

- `src/tests/conftest.py` contains cross-suite fixtures only.
- `src/tests/unit/conftest.py` contains unit-only fixtures.
- `src/tests/integration/conftest.py` contains integration-only fixtures.

Use session-scoped fixtures for immutable values, compiled registries,
read-only configuration, stable clocks, and reusable factories whenever tests
cannot mutate them. Use function scope for clients, applications, middleware
instances, session stores, mutable scopes, counters, and event logs. Never
share request-local security or session state across tests.

Unit tests must not construct a Litestar app or client. Integration tests should
exercise native Litestar behavior rather than duplicating it with hand-written
framework substitutes.
