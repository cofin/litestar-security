# Bundle Activity Log

Append-only chronological record of OKF v0.2 knowledge synthesis, spec promotion, and repository alignment for `litestar-security`.

## [2026-11-11] synthesize | Completed Codebase Debloat, Dependabot Sync, & OKF/Skills/Agents Alignment (`dcce78d`)

- Enforced repository-wide runtime annotations via `tools/hooks/no_future_annotations.py` (`types: [python]`), synced `ruff` (`v0.17.4`) and `uv run prek`, reconciled `[tool.uv].exclude-newer = "2026-11-02T00:00:00Z"` in `pyproject.toml` (retiring `uv.toml` and `tools/scripts/setup-env.sh`), refreshed `.agents/bundles/index.md` and `.agents/skills/index.md` (`updated: "2026-11-11"`), and removed unused `polyfactory` and `hypothesis` entries from `.agents/bundles/product/tech-stack.md`.
- Synchronized `AGENTS.md`, `workflow.md`, `patterns/immutable-contracts-and-typing.md`, `architecture/{runtime-pipeline,provider-and-store-ports}.md`, `domains/{authentication-and-authorization,accounts-and-federation}.md`, `gotchas/route-compilation-and-csrf.md`, Sphinx `docs/`, `CONTRIBUTING.rst`, and all `.agents/skills/**` and `.agents/agents/*.md` files with consolidated class helpers (`SecurityMiddleware._plan_uses_bearer`, `Argon2PasswordHasher._run_worker`, `RefreshReceiptSealer._receipt_aad`, `SessionBindingConfig._validate_binding_cookie_scope`), `RouteCompiler(..., schemes=...)`, `GitHubOAuthProvider(..., resolver=...)`, `OAuthProviderClient.stream_pinned`, eager `OAuthLocalAuthTransport`, controller `_authorize_step_up`, and shared `providers._internal` / `verify_jwks_jwt` / `accounts._internal` helpers.
- Synchronized `testing/test-organization-and-conformance.md`, testing skills, and subagents with unconditional zero-`Litestar` unit boundaries (`integration/test_cli.py`, `test_dto.py` / `integration/test_wire_casing.py` split, `unit/test_accounts/test_controllers.py`), `local_key_ring`-only `src/tests/unit/conftest.py` (`password_hasher` localized in `test_passwords.py`), docstring-only `src/tests/integration/conftest.py`, AST `anyio` checks in `unit/test_config.py`, retired `factories.py` and `test_fixture_vocabulary.py`, and `@pytest.mark.parametrize` conventions.

## [2026-11-10] setup | Aligned OKF v0.2 Bundle, Skills, & Agents (`v0.7.1` / `398fd57`, Shared Mode)

- Transitioned `.agents/` and `AGENTS.md` to `shared` Git tracking on branch `chore/setup-flow`, updating `.gitignore` and `.git/info/exclude` to ignore only `.agents/scratch/` and `.agents/studio-live-state.json`.
- Removed YAML frontmatter from subdirectory `index.md` catalogs (`product/`, `knowledge/`, `research/`, `specs/`) and updated `.agents/setup-state.json` and `.agents/bundles/index.md` to `v0.7.1`.
- Resynthesized all `product/**`, `knowledge/**`, `.agents/skills/**`, and `.agents/agents/**` files directly against `398fd57` (PR #82/#83): added `<!-- truth: start/end -->` blocks to skills, added `readonly: true` / `commandExecutionPolicy: sandbox` / `NotebookEdit` restrictions to agents, corrected `public()` vs. `exclude()` CSRF/OpenAPI semantics, and documented `_PrefixExcludingBearerSlot`, `_plan_uses_bearer` `additional_security_schemes`, strict `GoogleIAPClaims.spiffe_id`, and eager `accounts` exports with `MissingDependencyError` `_EXTRAS`.

## [2026-11-01] setup | Initialized OKF v0.2 Bundle, Domain Skills, and Subagents

- Synthesized product definition, engineering guidelines, and tech stack from `pyproject.toml` (`v0.6.0` at `c4fb0e1`), `Makefile`, `tools/check_*.py`, and `src/litestar_security/`.
- Populated institutional knowledge chapters across `architecture/`, `patterns/`, `domains/`, `testing/`, `gotchas/`, and `decisions/`.
- Generated project-local domain and review skills (`runtime-and-policy`, `providers`, `accounts`, `websocket-and-testing`) under `.agents/skills/` and paired subagents under `.agents/agents/`.
- Configured `local-only` Stealth Mode in `.agents/setup-state.json` and `.git/info/exclude`.

## [2026-11-01] plan | Authored `issue-remediation-and-provider-enhancements` Spec and Task Worksheets (`t01`–`t04`)

- Triaged all open repository issues ([#75](https://github.com/cofin/litestar-security/issues/75), [#80](https://github.com/cofin/litestar-security/issues/80), [#81](https://github.com/cofin/litestar-security/issues/81)) and pull requests ([#24](https://github.com/cofin/litestar-security/pull/24), [#26](https://github.com/cofin/litestar-security/pull/26), [#63](https://github.com/cofin/litestar-security/pull/63), [#67](https://github.com/cofin/litestar-security/pull/67), [#69](https://github.com/cofin/litestar-security/pull/69), [#70](https://github.com/cofin/litestar-security/pull/70), [#73](https://github.com/cofin/litestar-security/pull/73), [#74](https://github.com/cofin/litestar-security/pull/74), [#77](https://github.com/cofin/litestar-security/pull/77), [#78](https://github.com/cofin/litestar-security/pull/78), [#79](https://github.com/cofin/litestar-security/pull/79), and closed [#56](https://github.com/cofin/litestar-security/pull/56)).
- Created `specs/issue-remediation-and-provider-enhancements/spec.md` and vertical-slice worksheets `t01`–`t04`.

## [2026-11-02] archive | Archived `issue-remediation-and-provider-enhancements` (`v0.7.0` / [PR #82](https://github.com/cofin/litestar-security/pull/82))

- Promoted institutional knowledge from `issue-remediation-and-provider-enhancements` (`t01`–`t04`, merged at `73731dc`) into OKF v0.2 product, architecture, domain, testing, gotcha, and decision chapters (including [ADR-003](./knowledge/decisions/adr-003-centralized-optional-extra-shims.md)) and removed the completed active spec workspace.

## [2026-11-02] synthesize | Synced Knowledge, Skills, and Follow-up Contract Hardening (`v0.7.0`)

- Updated `AGENTS.md`, `.agents/bundles/**`, and `.agents/skills/{accounts,review-accounts,providers,review-providers}/**` for `v0.7.0`: centralized optional-extra shims (`litestar_security.typing` / `_typing.py`) with instantiation-only adapter gating, `APIKeyConfig(accept_authorization_bearer=True)` + `AuthenticationRegistry._coordinate_bearer_slots` + `additional_security_schemes` OpenAPI/RFC 9728 projection, `GoogleIAPClaims` SPIFFE and service-account helpers, and Python 3.10/3.11 compatibility gotchas.
