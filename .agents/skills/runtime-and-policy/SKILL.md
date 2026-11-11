---
name: runtime-and-policy
description: Use when editing SecurityPlugin, SecurityConfig, AuthenticationPolicy, RouteCompiler, guards, SecurityContext, WireDTO, or headers. Not for OAuth, accounts, or WebSocket tokens.
---

# Runtime, Policy, Guards, & Wire DTO Engineering

Domain skill for `src/litestar_security/{__init__,_lazy,_typing,typing,_docs,_internal,plugin,config,authentication,guards,context,_openapi,schema,_dto,headers,controllers,workers,_cli}.py`.

## Canonical Modules & Seams

- **Package & Typing Facade**: `src/litestar_security/__init__.py` + `_lazy.py` (lazy `_OAUTH_EXPORTS` from `litestar_security.providers`), `src/litestar_security/{_typing,typing}.py` (`OptionalDependencyFlag`, `MissingDependencyError` `_EXTRAS`, shims).
- **Composition & Lifecycle**: `src/litestar_security/plugin.py::SecurityPlugin`, `src/litestar_security/config.py::{SecurityConfig,RaisedErrorSchema,ExternalCSRF}`.
- **Route Policy, Controllers, & OpenAPI Compilation**: `src/litestar_security/authentication.py::{AuthenticationPolicy,public,exclude,required,optional,any_of,all_of,at_least,mechanism}`, `src/litestar_security/controllers.py::{PublicController,SecureController}`, `src/litestar_security/_openapi.py::{RouteCompiler,PolicyCompiler,OpenAPISchemeSet}`, `src/litestar_security/_docs.py::{RouteDocs,ROUTE_TAGS}`, `src/litestar_security/_internal.py::{RUNTIME_PLAN_OPT_KEY,GENERATED_ROUTE_OPT_KEY}`.
- **Request Evaluation & Context**: `src/litestar_security/authentication.py::{AuthenticationRegistry,_PrefixExcludingBearerSlot,SecurityMiddlewareWrapper,SecurityMiddleware,_AuthenticationEvaluator,CredentialSlot,CredentialVerifier,IdentityResolver,AuthorizationResolver}`, `src/litestar_security/context.py::{Principal,SecurityContext,AuthenticationEvidence,AuthorizationSnapshot,CredentialRestrictions,ResourcePermission,resolve_authorization}`.
- **Predicate Guards**: `src/litestar_security/guards.py::{AuthorizationPredicate,AssuranceRequirement,AssuranceTrait,AuthorizationDecision,requires_authenticated,requires_role,requires_scope,requires_capability,requires_tenant,requires_tenant_role,requires_assurance,requires_all_of,requires_any_of,requires_one_of,requires_at_least}`.
- **Wire Contracts, Headers, Workers, & CLI**: `src/litestar_security/schema.py::{WireStruct,WirePolicy,RouteError,ProblemDetail}`, `src/litestar_security/_dto.py::{WireDTO,WireBackend,WireUnionDTO,WireUnionBackend,wire_dto,union_wire_dto,wire_struct,MAX_NESTED_DEPTH}`, `src/litestar_security/headers.py::{SecurityHeadersConfig,ContentSecurityPolicy,CSPMode,csp_nonce,configure_security_headers}`, `src/litestar_security/workers.py::{BlockingIntegration,BlockingCallRunner,WorkerLimits}`, `src/litestar_security/_cli.py::security_group`.

## Non-Negotiable Rules

<!-- truth: start -->
1. **No `from __future__ import annotations` Repository-Wide**: Keep Litestar route, DI, and DTO types imported at module scope (`tools/hooks/no_future_annotations.py` on `types: [python]` and Ruff `FA102`) and centralize optional-extra shims in `_typing.py` (`typing.py`).
2. **Startup Route Compilation**: Compile `opt["auth"]` (`AUTH_POLICY_OPT_KEY`), `csrf_required`, and OpenAPI security into `opt["litestar_security_plan"]`; `SecurityPlugin.on_app_init` compiles `OpenAPISchemeSet` once, prepares `components.security_schemes` via `prepare_openapi_config`, and passes precomputed `schemes` to `RouteCompiler(..., schemes=schemes)`, which sets per-handler `route_handler.security`.
3. **`public()` vs. `exclude()` CSRF & OpenAPI Semantics**:
   - `public()` (`PublicController`) skips credential extraction (`plan.authenticate=False`), emits OpenAPI `[{}]`, keeps anonymous `Principal`/`SecurityContext`, and sets `opt[csrf_exclude_key] = True` unless `csrf_required=True` is set on the HTTP handler.
   - `exclude()` (`opt={exclude_opt_key: True}`, `SecurityConfig(exclude=...)`) sets `plan.bypass_authentication=True` and OpenAPI `[{}]`, and leaves Litestar's native CSRF untouched unless `csrf_required=True` is set.
4. **Restriction Narrowing & Guard Composition**: `resolve_authorization` intersects `CredentialRestrictions(scopes, roles, capabilities, tenant_ids, resources)` with `AuthorizationSnapshot` without mutating `attributes`; `AuthorizationPredicate` composes via `requires_all_of`, `requires_any_of`, `requires_one_of`, and `requires_at_least` (no bitwise operators).
5. **Bearer Coordination & RFC 9728**: `AuthenticationRegistry._coordinate_bearer_slots` wraps non-dataclass `authorization.bearer` slots in `_PrefixExcludingBearerSlot` and updates dataclass `excluded_prefixes`; `SecurityMiddleware._plan_uses_bearer` inspects `additional_security_schemes` for RFC 9728 `WWW-Authenticate` challenges.
6. **Sync Wrapping (`R4`), Testing Isolation (`R5`), Slotted Contracts, & Wire DTOs**: Never call `inspect.isawaitable` (`BlockingIntegration` + `BlockingCallRunner`) or import `litestar_security.testing` in runtime; freeze domain value objects (`@dataclass(frozen=True, slots=True)`) while using `@dataclass(slots=True)` on mutable orchestrators (`SecurityConfig`, `RouteCompiler`, `PolicyCompiler`); bind `cache_key = (*name_key, shape)` before indexing `_transfer_models`.
<!-- truth: end -->

## Verification Commands

```bash
uv run pytest src/tests/unit/test_config.py src/tests/unit/test_dto.py src/tests/unit/test_openapi.py src/tests/unit/test_headers.py src/tests/unit/test_docs.py src/tests/unit/test_authentication_evaluator.py src/tests/unit/test_authentication_registry.py src/tests/unit/test_guards.py src/tests/unit/test_context.py -q
uv run pytest src/tests/integration/test_plugin.py src/tests/integration/test_openapi_document.py src/tests/integration/test_route_exclusion.py src/tests/integration/test_error_responses.py src/tests/integration/test_authentication_composition.py src/tests/integration/test_resource_server.py src/tests/integration/test_wire_casing.py src/tests/integration/test_cli.py src/tests/integration/test_runtime.py -q
uv run ruff check src/litestar_security/ src/tests/
uv run mypy && uv run pyright
uv run slotscheck src/litestar_security/
uv run python tools/check_import_boundaries.py
```

## References

- [Implementation Checklist](./references/checklist.md)
- [False-Positive Suppressions](./references/false-positive-suppressions.md)
- [Runtime Pipeline Knowledge](../../bundles/knowledge/architecture/runtime-pipeline.md)
- [Wire Schemas & DTOs](../../bundles/knowledge/patterns/wire-schemas-and-dtos.md)
- [Immutable Contracts & Typing](../../bundles/knowledge/patterns/immutable-contracts-and-typing.md)
- [Route Compilation & CSRF Gotchas](../../bundles/knowledge/gotchas/route-compilation-and-csrf.md)
