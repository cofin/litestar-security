---
type: Architecture
title: "Runtime Pipeline, Deep Modules, & Dependency Categories"
description: "Startup route compilation, request authentication pipeline, multi-scheme OpenAPI projection, and authorization predicate guards."
status: stable
tags: [architecture, plugin, middleware, authentication, openapi, guards]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-learn
    at: "2026-11-11T20:45:00Z"
    commit: "dcce78d"
sources:
  - id: plugin-py
    resource: "src/litestar_security/plugin.py::SecurityPlugin"
    title: "SecurityPlugin startup registration and route compilation lifecycle"
  - id: config-py
    resource: "src/litestar_security/config.py::SecurityConfig"
    title: "SecurityConfig composition root and validation invariants"
  - id: headers-py
    resource: "src/litestar_security/headers.py::configure_security_headers"
    title: "Native response headers, before_send backfill/CSP hooks, and csp_nonce DI"
  - id: auth-py
    resource: "src/litestar_security/authentication.py::AuthenticationRegistry"
    title: "AuthenticationRegistry, AuthenticationMechanism, SecurityMiddleware, and _AuthenticationEvaluator"
  - id: openapi-py
    resource: "src/litestar_security/_openapi.py::RouteCompiler"
    title: "RouteCompiler, PolicyCompiler, and OpenAPISchemeSet multi-scheme projection"
  - id: guards-py
    resource: "src/litestar_security/guards.py::AuthorizationPredicate"
    title: "AuthorizationPredicate composable route guards"
  - id: cli-py
    resource: "src/litestar_security/_cli.py::routes_command"
    title: "Litestar security routes CLI inspection over compiled plans and inherited guards"
  - id: jwks-httpx
    resource: "src/litestar_security/providers/jwks/_httpx.py::HttpxJWKSFetcher"
    title: "Bounded JWKS HTTP fetcher with public-IP DNS guard"
  - id: oauth-client
    resource: "src/litestar_security/providers/oauth/_provider.py::OAuthProviderClient"
    title: "Fixed-endpoint OAuth HTTP client with pinned public-IP DNS resolution"
  - id: providers-internal
    resource: "src/litestar_security/providers/_internal.py::resolve_public_addresses"
    title: "Shared public-IP DNS resolution and bounded HTTP body reading primitives"
---

# Runtime Pipeline, Deep Modules, & Dependency Categories

<!-- truth: start -->
- **Composition Root (`SecurityPlugin` + `SecurityConfig`)**: `SecurityPlugin._providers` registers `principal`, `security_context`, `current_user`, and `websocket_connect_tokens`. `SecurityPlugin.on_app_init` installs `SecurityMiddlewareWrapper`, configures `configure_security_headers` via `response_headers`, `before_send` hooks, and `csp_nonce` DI (no headers middleware), validates `app_config.csrf_config` / `external_csrf`, mounts local/MFA/OAuth/RFC 9728/local-JWKS handlers, compiles `OpenAPISchemeSet` once to inject `components.security_schemes` via `prepare_openapi_config(openapi_config, schemes)`, and passes precomputed `schemes=schemes` into `RouteCompiler(..., schemes=schemes)`.[^plugin-py][^config-py][^headers-py][^openapi-py]
- **Compile-Time Route Plan & OpenAPI (`RouteCompiler` + `OpenAPISchemeSet`)**: `RouteCompiler(..., schemes=...)` runs `RouteCompiler._resolve_route_policy` and `RouteCompiler._resolve_effective_policy` over `opt["auth"]` (`AUTH_POLICY_OPT_KEY`), `opt[exclude_opt_key]`, `opt["csrf_required"]`, and `SecurityConfig.exclude` to emit a `SecurityRuntimePlan` into `opt["litestar_security_plan"]` (`RUNTIME_PLAN_OPT_KEY`) and assign per-handler `route_handler.security` (expanding `additional_security_schemes`). `RouteCompiler` inspects handlers (not guards); `litestar security routes` inspects compiled plans and inherited guards.[^openapi-py][^cli-py]
- **Bearer Prefix Coordination (`AuthenticationRegistry._coordinate_bearer_slots`)**: When `APIKeyConfig(accept_authorization_bearer=True)` coexists with `authorization.bearer`, `AuthenticationRegistry` sets `coexists_with_bearer_slot=True` on `_APIKeyCredentialSlot` and sets `excluded_prefixes` on dataclass bearer slots or wraps custom bearer slots in `_PrefixExcludingBearerSlot`.[^auth-py]
- **Request Pipeline (`SecurityMiddleware` -> `_AuthenticationEvaluator`)**: Initializes `scope["user"]` (`Principal`) and `scope["auth"]` (`SecurityContext`), never touching `scope["state"]`; resolves `SecurityRuntimePlan`; evaluates `CredentialSlot.extract` -> `CredentialVerifier.authenticate` -> `IdentityResolver.resolve(claims)` -> `AuthorizationResolver.resolve(principal)` -> `resolve_authorization`; attaches `resource_metadata` in `SecurityMiddleware._advertise_resource_metadata` via `SecurityMiddleware._plan_uses_bearer` (checking `additional_security_schemes`).[^auth-py]
- **Predicate Guards (`AuthorizationPredicate`)**: Route guards in `guards.py` evaluate against `scope["user"]` and `scope["auth"]` (`_AssurancePredicate` enforces `AssuranceRequirement`), composing through `requires_all_of`, `requires_any_of`, `requires_one_of`, and `requires_at_least` (`_CompositePredicate`) with no bitwise operators, `Not`, or `describe()`.[^guards-py]
<!-- truth: end -->

## Dependency Category Classification

| Dependency / Collaborator | Category | Testing & Runtime Treatment |
| :--- | :--- | :--- |
| `Litestar`, `msgspec`, `PyJWT`, `cryptography`, `anyio` | **In-Process Pure / Framework** | Use real instances directly in unit and integration tests.[^plugin-py][^auth-py] |
| Consumer Ports (`AccountLookup`, `LocalAccountCapabilities`, `SessionRegistry`, `NativeSessionStore`, `RefreshTokenFamilyStore`, `RateLimiter`, `APIKeyStore`, `OAuthTransactionStore`, `OAuthAccountStore`, `WebSocketConnectTokenStore`) | **State / Storage Port** | Ship `@runtime_checkable` `Protocol` ports (plus `StoreRateLimiter`); test against `InMemorySecurityBackend` and `assert_security_backend_conformance`.[^config-py] |
| Outbound JWKS / OAuth / OIDC Endpoints (`httpx.AsyncClient`) | **True External Service** | Inject `httpx.MockTransport`, `FakeOAuthHTTPTransport`, or `FakeOAuthProvider` in tests; enforce HTTPS, public-IP DNS pinning, and bounded response reads via `OAuthProviderClient.stream_pinned` / `OAuthProviderClient._pinned_endpoint` (shared with `GitHubOAuthProvider(..., resolver=...)`) and `HttpxJWKSFetcher._guard_host` / `HttpxJWKSFetcher.fetch` (delegating to `providers._internal.resolve_public_addresses` and `providers._internal.read_bounded_body`).[^jwks-httpx][^oauth-client][^providers-internal] |
| Wall Clock (`clock: Callable[[], datetime]`) | **Nondeterministic Time Source** | Inject `FakeClock` via `clock=` parameters on service, verifier, provider, `WebSocketSecurityConfig`, and `requires_assurance` constructors (`SecurityConfig` takes no `clock`).[^guards-py] |

## References

[^plugin-py]: `src/litestar_security/plugin.py::SecurityPlugin` — `SecurityPlugin` startup registration and route compilation lifecycle
[^config-py]: `src/litestar_security/config.py::SecurityConfig` — `SecurityConfig` composition root and validation invariants
[^headers-py]: `src/litestar_security/headers.py::configure_security_headers` — Native response headers, `before_send` backfill/CSP hooks, and `csp_nonce` DI
[^auth-py]: `src/litestar_security/authentication.py::AuthenticationRegistry` — `AuthenticationRegistry`, `SecurityMiddleware`, and `_AuthenticationEvaluator`
[^openapi-py]: `src/litestar_security/_openapi.py::RouteCompiler` — `RouteCompiler`, `PolicyCompiler`, and `OpenAPISchemeSet` projection
[^guards-py]: `src/litestar_security/guards.py::AuthorizationPredicate` — `AuthorizationPredicate` composable route guards
[^cli-py]: `src/litestar_security/_cli.py::routes_command` — Litestar `security routes` CLI inspection over compiled plans and inherited guards
[^jwks-httpx]: `src/litestar_security/providers/jwks/_httpx.py::HttpxJWKSFetcher` — Bounded JWKS HTTP fetcher with public-IP DNS guard
[^oauth-client]: `src/litestar_security/providers/oauth/_provider.py::OAuthProviderClient` — Fixed-endpoint OAuth HTTP client with pinned public-IP DNS resolution
[^providers-internal]: `src/litestar_security/providers/_internal.py::resolve_public_addresses` — Shared public-IP DNS resolution and bounded HTTP body reading primitives
