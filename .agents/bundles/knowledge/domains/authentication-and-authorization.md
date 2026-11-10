---
type: Domain
title: "Authentication, Authorization, & Evidence Domain Model"
description: "Ubiquitous glossary and invariants for CredentialSlot, AuthenticationRegistry, GoogleIAPClaims, Principal, SecurityContext, and AuthorizationSnapshot."
status: stable
tags: [domains, authentication, authorization, context, principal, evidence, iap, api-key]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-setup
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: auth-domain
    resource: "src/litestar_security/authentication.py::AuthenticationRegistry"
    title: "CredentialSlot, CredentialVerifier, IdentityResolver, AuthorizationResolver, and policy helpers"
  - id: context-domain
    resource: "src/litestar_security/context.py::resolve_authorization"
    title: "Principal, SecurityContext, AuthenticationEvidence, AuthorizationSnapshot, and resolve_authorization"
  - id: guards-domain
    resource: "src/litestar_security/guards.py::AuthorizationPredicate"
    title: "AuthorizationPredicate, AssuranceRequirement, and requires_* guard constructors"
  - id: controllers-domain
    resource: "src/litestar_security/controllers.py::SecureController"
    title: "PublicController and SecureController typed auth attributes"
  - id: api-key-slot
    resource: "src/litestar_security/providers/api_key/_runtime.py::build_api_key_runtime"
    title: "APIKeyConfig header and opt-in Authorization Bearer extraction with dual OpenAPI scheme projection"
  - id: iap-claims
    resource: "src/litestar_security/providers/iap/_iap.py::GoogleIAPClaims"
    title: "GoogleIAPClaims human, service-account, and SPIFFE workload identity classification"
---

# Authentication, Authorization, & Evidence Domain Model

<!-- truth: start -->
- **`CredentialSlot` & Bearer Prefix Coordination**: Each physical slot (`"session"`, `"authorization.bearer"`, `"api-key"`, `"google-iap"`) has at most one owning `AuthenticationMechanism`. When `APIKeyConfig(accept_authorization_bearer=True)` coexists with `"authorization.bearer"`, `AuthenticationRegistry._coordinate_bearer_slots` sets `coexists_with_bearer_slot=True` on `_APIKeyCredentialSlot` and updates `excluded_prefixes` on dataclass bearer slots or wraps custom `"authorization.bearer"` slots in `_PrefixExcludingBearerSlot`; `_plan_uses_bearer` checks both `security_scheme` and `additional_security_schemes` (`APIKey` + `APIKeyBearer`) for RFC 9728 `WWW-Authenticate` challenges.[^auth-domain][^api-key-slot]
- **`CredentialVerifier` -> `IdentityResolver` -> `AuthorizationResolver`**:
  1. `CredentialVerifier.authenticate(credential, connection)` validates cryptographic/store integrity and yields `Authenticated(claims, evidence, grants, restrictions)`.
  2. `IdentityResolver.resolve(claims)` maps verified claims to an authenticated `Principal` or returns `InvalidCredentials` / `VerificationUnavailable`.
  3. `AuthorizationResolver.resolve(principal)` loads the base `AuthorizationSnapshot(scopes, roles, capabilities, tenant_roles, tenant_ids, resources, attributes)`.[^auth-domain][^context-domain]
- **`GoogleIAPClaims` Human vs. Machine Classification**: `GoogleIAPClaims` exposes `normalized_subject`, `spiffe_id` (requires `external_identity is None`, rejects `?`, `#`, control/whitespace chars, leading/trailing dots in authority, and empty/`.`/`..` path segments including trailing slashes), `is_service_account` (requires `external_identity is None`, `hosted_domain is None`, and exact `gserviceaccount.com` or `.gserviceaccount.com` email domain), `is_agent_identity`, and `is_machine_principal`.[^iap-claims]
- **Effective Authorization Intersection (`resolve_authorization`)**: `CredentialRestrictions(scopes, roles, capabilities, tenant_ids, resources)` only narrow — and never widen — `AuthorizationSnapshot`, leaving `attributes` application-authoritative.[^context-domain]
- **`AuthenticationEvidence` & Route Guards**: `AuthenticationEvidence(mechanism, slot, authenticated_at, expires_at, methods, traits, acr, amr)` carries assurance facts (`purpose:<name>` in `traits`) verified by `requires_assurance(...)`. Route policies compose via `public()`, `exclude()`, `required()`, `optional()`, `any_of()`, `all_of()`, `at_least()`, and `mechanism()` (or `PublicController` / `SecureController`), while `guards.py` predicates compose via `requires_all_of`, `requires_any_of`, `requires_one_of`, and `requires_at_least`.[^auth-domain][^context-domain][^guards-domain][^controllers-domain]
<!-- truth: end -->

## Core Domain Glossary

| Term | Canonical Symbol | Responsibility |
| :--- | :--- | :--- |
| **Principal** | `litestar_security.context::Principal` | Identity envelope (`id`, `display_name`, `user`) exposing `is_authenticated`, `has_user`, and `require_user()`.[^context-domain] |
| **Security Context** | `litestar_security.context::SecurityContext` | Request-bound aggregate combining `session`, `evidence`, `authorization`, `restrictions`, and `expires_at`.[^context-domain] |
| **Authentication Policy** | `litestar_security.authentication::AuthenticationPolicy` | Closed expression built via `public()`, `exclude()`, `required()`, `optional()`, `any_of()`, `all_of()`, `at_least()`, and `mechanism()`.[^auth-domain] |
| **Authorization Predicate** | `litestar_security.guards::AuthorizationPredicate` | Native guard callable composed via `requires_all_of`, `requires_any_of`, `requires_one_of`, and `requires_at_least` inspecting `scope["user"]` and `scope["auth"]`.[^guards-domain] |

## References

[^auth-domain]: `src/litestar_security/authentication.py::AuthenticationRegistry` — `CredentialSlot`, `CredentialVerifier`, `IdentityResolver`, `AuthorizationResolver`, and policy helpers
[^context-domain]: `src/litestar_security/context.py::resolve_authorization` — `Principal`, `SecurityContext`, `AuthenticationEvidence`, `AuthorizationSnapshot`, and `resolve_authorization`
[^guards-domain]: `src/litestar_security/guards.py::AuthorizationPredicate` — `AuthorizationPredicate`, `AssuranceRequirement`, and `requires_*` guard constructors
[^controllers-domain]: `src/litestar_security/controllers.py::SecureController` — `PublicController` and `SecureController` typed `auth` attributes
[^api-key-slot]: `src/litestar_security/providers/api_key/_runtime.py::build_api_key_runtime` — `APIKeyConfig` header and opt-in `Authorization: Bearer` extraction with dual OpenAPI scheme projection
[^iap-claims]: `src/litestar_security/providers/iap/_iap.py::GoogleIAPClaims` — `GoogleIAPClaims` human, service-account, and SPIFFE workload identity classification
