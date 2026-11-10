---
type: Decision
title: "ADR-002: Compile-Time Route Plans, Startup Sync Bridging, & Msgspec Wire DTOs"
description: "Architectural decision to compile route policies and OpenAPI schemes at startup, wrap sync ports via BlockingIntegration, and standardize on WireStruct/WireDTO."
status: stable
tags: [decisions, adr, route-compiler, openapi, dto, workers]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-setup
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: adr2-openapi
    resource: "src/litestar_security/_openapi.py::RouteCompiler"
    title: "RouteCompiler startup route plan compilation and OpenAPI projection"
  - id: adr2-workers
    resource: "src/litestar_security/workers.py::BlockingCallRunner"
    title: "BlockingIntegration and BlockingCallRunner startup sync-to-async adapter"
  - id: adr2-dto
    resource: "src/litestar_security/_dto.py::WireDTO"
    title: "WireDTO, WireBackend, WireUnionDTO, and WireUnionBackend msgspec projection"
  - id: adr2-boundaries
    resource: "tools/check_import_boundaries.py"
    title: "R4 static gate forbidding runtime inspect.isawaitable branching"
---

# ADR-002: Compile-Time Route Plans, Startup Sync Bridging, & Msgspec Wire DTOs

<!-- truth: start -->
- **Status**: Accepted (`v0.7.1`).[^adr2-openapi]
- **Context**: Per-request route policy parsing, OpenAPI security introspection, `inspect.isawaitable` branching on store calls, and ad-hoc dict or non-msgspec serialization add hot-path latency and allow configuration errors (unknown mechanisms, conflicting bearer slots, dead exclusion regexes, contradictory CSRF metadata) to hide until production traffic hits a route.[^adr2-openapi][^adr2-workers]
- **Decision**:
  1. Compile every route's `AuthenticationPolicy` (`opt["auth"]`), `csrf_required` overrides, and OpenAPI `security` requirements once at startup via `RouteCompiler` (`_openapi.py`) into `opt["litestar_security_plan"]` (`RUNTIME_PLAN_OPT_KEY`).[^adr2-openapi]
  2. Forbid per-call `inspect.isawaitable` branches (`R4`); require synchronous ports to be wrapped at startup in `BlockingIntegration` and executed through `BlockingCallRunner` (`workers.py`).[^adr2-workers][^adr2-boundaries]
  3. Standardize HTTP wire schemas on `WireStruct(msgspec.Struct, frozen=True, forbid_unknown_fields=True)` and `wire_dto` / `union_wire_dto` (`WireDTO`, `WireBackend`, `WireUnionDTO`, `WireUnionBackend` in `_dto.py`, with fixed `MAX_NESTED_DEPTH = 4`).[^adr2-dto]
- **Consequences**:
  - **Positive**: Startup fails fast with `litestar.exceptions.ImproperlyConfiguredException` on invalid mechanism references, slot collisions, or invalid CSRF metadata; request middleware performs a constant-time compiled plan lookup; `litestar security routes` prints the compiled route posture and inherited guards deterministically without serving traffic.[^adr2-openapi]
  - **Trade-off**: Route policies cannot be mutated dynamically after `RouteCompiler` finalizes the route plan, and wire schemas must be `WireStruct` subclasses with runtime-resolvable type annotations.[^adr2-openapi][^adr2-dto]
<!-- truth: end -->

## References

[^adr2-openapi]: `src/litestar_security/_openapi.py::RouteCompiler` — `RouteCompiler` startup route plan compilation and OpenAPI projection
[^adr2-workers]: `src/litestar_security/workers.py::BlockingCallRunner` — `BlockingIntegration` and `BlockingCallRunner` startup sync-to-async adapter
[^adr2-dto]: `src/litestar_security/_dto.py::WireDTO` — `WireDTO`, `WireBackend`, `WireUnionDTO`, and `WireUnionBackend` msgspec projection
[^adr2-boundaries]: `tools/check_import_boundaries.py` — `R4` static gate forbidding runtime `inspect.isawaitable` branching
