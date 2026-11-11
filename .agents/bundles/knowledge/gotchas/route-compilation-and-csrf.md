---
type: Gotcha
title: "Route Compilation, CSRF, Slot Ownership, & Cross-Python Gotchas"
description: "Runtime and type-checking traps around public() vs exclude() CSRF handling, bearer slot coordination, __Host- cookies, and Python 3.10/3.11 quirks."
status: stable
tags: [gotchas, csrf, openapi, bearer, route-compiler, api-key, typing]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-learn
    at: "2026-11-11T20:45:00Z"
    commit: "dcce78d"
sources:
  - id: plugin-csrf
    resource: "src/litestar_security/plugin.py::SecurityPlugin"
    title: "CSRF validation, exclusion warning lifespan, and RouteCompiler wiring"
  - id: openapi-compiler
    resource: "src/litestar_security/_openapi.py::RouteCompiler"
    title: "RouteCompiler, PolicyCompiler, CSRF enforcement, and _OPENAPI_HANDLER_MODULES"
  - id: auth-coord
    resource: "src/litestar_security/authentication.py::AuthenticationRegistry"
    title: "AuthenticationRegistry._coordinate_bearer_slots, _PrefixExcludingBearerSlot, and MappingProxyType defaults"
  - id: composite-bearer
    resource: "src/litestar_security/providers/jwt/_bearer.py::CompositeBearerConfig"
    title: "CompositeBearerConfig and _BearerCredentialSlot single-slot JWT ownership"
  - id: api-key-runtime
    resource: "src/litestar_security/providers/api_key/_runtime.py::build_api_key_runtime"
    title: "_APIKeyCredentialSlot header and opt-in Authorization Bearer extraction"
  - id: sessions-cookie
    resource: "src/litestar_security/accounts/_sessions.py::SessionBindingConfig"
    title: "SessionBindingConfig __Host- cookie scope validation"
  - id: oauth-cookie
    resource: "src/litestar_security/providers/oauth/_transactions.py::oauth_binding_cookie"
    title: "OAUTH_BINDING_COOKIE_NAME __Host- cookie enforcement"
  - id: dto-cache-key
    resource: "src/litestar_security/_dto.py::WireBackend"
    title: "Python 3.10 AST-compatible cache_key binding in WireBackend.transfer_model_for"
---

# Route Compilation, CSRF, Slot Ownership, & Cross-Python Gotchas

<!-- truth: start -->
- **`public()` vs. `exclude()` CSRF, OpenAPI, & Middleware Semantics**:
  - `public()`, `exclude()`, and `PublicController` are module-level policy helpers and controller bases (`authentication.py`, `controllers.py`).
  - `public()` sets `plan.authenticate=False`, emits OpenAPI `security=[{}]`, keeps anonymous `Principal`/`SecurityContext` in `SecurityMiddleware`, and sets `route_handler.opt[csrf_exclude_key] = True` unless `csrf_required=True` (`CSRF_REQUIRED_OPT_KEY`) is explicitly set on the HTTP handler (required on cookie-establishing public routes such as session login).
  - `exclude()` (`opt={exclude_opt_key: True}` or `SecurityConfig(exclude=...)`) sets `plan.authenticate=False, plan.bypass_authentication=True`, emits OpenAPI `security=[{}]`, leaves Litestar's native CSRF middleware untouched unless `csrf_required=True` is set, initializes anonymous HTTP `scope["user"]`/`scope["auth"]`, bypasses `_handle_websocket` on WebSocket, and still inherits cumulative parent Litestar `guards=[...]`.[^plugin-csrf][^openapi-compiler][^auth-coord]
- **`CompositeBearerConfig` vs. `APIKeyConfig(accept_authorization_bearer=True)`**: Multiple JWT/OIDC/service-token verifiers share `"authorization.bearer"` through `CompositeBearerConfig` (`extend_composite_bearer`). `APIKeyConfig(accept_authorization_bearer=True)` retains `"api-key"` (`header_name != "Authorization"`), sets `additional_security_schemes={"APIKeyBearer": ...}` (inspected by `SecurityMiddleware._plan_uses_bearer` for RFC 9728 challenges), and `AuthenticationRegistry._coordinate_bearer_slots` sets `coexists_with_bearer_slot=True` and updates `excluded_prefixes` or wraps custom `"authorization.bearer"` slots in `_PrefixExcludingBearerSlot`.[^auth-coord][^composite-bearer][^api-key-runtime]
- **Python 3.10 `mypy` Starred Subscript & Python 3.11+ `MappingProxyType` Traps**: Bind `cache_key = (*name_key, shape)` before indexing `cls._transfer_models[cache_key]` so `mypy` (`ast-serialize`) under Python 3.10 never flags PEP 646 syntax; declare `MappingProxyType` dataclass defaults with `field(default_factory=lambda: MappingProxyType({}))` (such as on `AuthenticationMechanism.additional_security_schemes`) so Python 3.11+ does not raise `ValueError`.[^auth-coord][^dto-cache-key]
- **Diagnostics, Precomputed Schemes, & Built-In OpenAPI Routes**: `SecurityPlugin.on_app_init` passes precomputed schemes to `RouteCompiler(..., schemes=schemes)`, where `RouteCompiler._resolve_route_policy` and `RouteCompiler._resolve_effective_policy` resolve hierarchical `auth` and `exclude_from_auth` layers (rejecting same-layer declaration of both). `SecurityPlugin._configure_exclusion_report` and `RouteCompiler._report_customized_response_class` emit `LitestarWarning` (no custom warning class), while `RouteCompiler._is_openapi_handler` identifies Litestar schema handlers via `_OPENAPI_HANDLER_MODULES` (`OpenAPIPlugin`, `OpenAPIController`, `OpenAPIRenderPlugin`), never by URL path.[^plugin-csrf][^openapi-compiler]
<!-- truth: end -->

## Cookie `__Host-` Prefix Invariants

`SessionBindingConfig._validate_binding_cookie_scope` (`accounts/_sessions.py`) enforces `(secure=True, path="/", domain=None)` when `cookie_name` starts with `"__Host-"`, and `OAUTH_BINDING_COOKIE_NAME` (`__Host-litestar-security-oauth` in `providers/oauth/_transactions.py`) enforces the same attributes in `oauth_binding_cookie`. Tests over plain `http://testserver.local` must use `https://testserver.local` or configure `SessionBindingConfig(..., cookie_name="...", secure=False, allow_insecure=True)` (also checked by `SecurityPlugin._validate_local_session_backend`).[^plugin-csrf][^sessions-cookie][^oauth-cookie]

## References

[^plugin-csrf]: `src/litestar_security/plugin.py::SecurityPlugin` — CSRF validation, exclusion warning lifespan, and `RouteCompiler` wiring
[^openapi-compiler]: `src/litestar_security/_openapi.py::RouteCompiler` — `RouteCompiler`, `PolicyCompiler`, CSRF enforcement, and `_OPENAPI_HANDLER_MODULES`
[^auth-coord]: `src/litestar_security/authentication.py::AuthenticationRegistry` — `AuthenticationRegistry._coordinate_bearer_slots`, `_PrefixExcludingBearerSlot`, and `MappingProxyType` defaults
[^composite-bearer]: `src/litestar_security/providers/jwt/_bearer.py::CompositeBearerConfig` — `CompositeBearerConfig` and `_BearerCredentialSlot` single-slot JWT ownership
[^api-key-runtime]: `src/litestar_security/providers/api_key/_runtime.py::build_api_key_runtime` — `_APIKeyCredentialSlot` header and opt-in `Authorization: Bearer` extraction
[^sessions-cookie]: `src/litestar_security/accounts/_sessions.py::SessionBindingConfig` — `SessionBindingConfig` `__Host-` cookie scope validation
[^oauth-cookie]: `src/litestar_security/providers/oauth/_transactions.py::oauth_binding_cookie` — `OAUTH_BINDING_COOKIE_NAME` `__Host-` cookie enforcement
[^dto-cache-key]: `src/litestar_security/_dto.py::WireBackend` — Python 3.10 AST-compatible `cache_key` binding in `WireBackend.transfer_model_for`
