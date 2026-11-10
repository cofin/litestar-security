---
type: Pattern
title: "Wire Schemas, Msgspec DTOs, & Error Envelopes"
description: "WireStruct, WirePolicy, WireDTO, WireBackend, union_wire_dto, and raised error envelopes (RouteError, ProblemDetail, RaisedErrorSchema)."
status: stable
tags: [patterns, dto, msgspec, wire, openapi, schema]
generated:
  by: flow/0.26.0
  at: "2026-11-02T01:45:00Z"
verified:
  - by: agent:flow-setup
    at: "2026-11-10T22:45:00Z"
    commit: "398fd57"
sources:
  - id: schema-py
    resource: "src/litestar_security/schema.py::WireStruct"
    title: "WireStruct, WirePolicy, RouteError, and ProblemDetail"
  - id: dto-py
    resource: "src/litestar_security/_dto.py::WireBackend"
    title: "WireDTO, WireBackend, WireUnionDTO, and union_wire_dto"
  - id: plugin-py
    resource: "src/litestar_security/plugin.py::SecurityPlugin"
    title: "ProblemDetailsPlugin detection and RaisedErrorSchema propagation"
  - id: config-py
    resource: "src/litestar_security/config.py::RaisedErrorSchema"
    title: "SecurityConfig wire_rename, wire_forbid_unknown_fields, and raised_error_schema"
  - id: local-schemas
    resource: "src/litestar_security/accounts/schemas/_local.py::LocalAccount"
    title: "Account wire schemas and OperationMessage"
---

# Wire Schemas, Msgspec DTOs, & Error Envelopes

<!-- truth: start -->
- **Base Wire Type (`WireStruct`)**: HTTP request/response payloads subclass `WireStruct(msgspec.Struct, frozen=True, forbid_unknown_fields=True)` from `src/litestar_security/schema.py`, restating `frozen=True` on subclasses for static type checkers and opting out of application casing (`__wire_casing__ = False`) only on specification-defined or Litestar-rendered payloads.[^schema-py][^local-schemas]
- **Declarative Convention (`WirePolicy` + `WireDTO` + `WireBackend`)**: `WirePolicy(rename=None, forbid_unknown_fields=True)` (`schema.py`) pairs with `wire_dto(schema, policy)` and `WireBackend` (`_dto.py`) to share one OpenAPI component key per `(model_type, policy, shape)` and preserve `omit_defaults`, while `MAX_NESTED_DEPTH = 4` is fixed in `_dto.py` so nested leaves are never dropped. `WireDTO.__init_subclass__` isolates `_dto_backends` per narrowed DTO class.[^schema-py][^dto-py]
- **Response-Only Union DTOs (`WireUnionDTO` + `union_wire_dto`)**: `union_wire_dto(union, policy)` builds a `WireUnionDTO` backed by `WireUnionBackend`, which holds one `WireBackend` per renameable `WireStruct` arm and dispatches via `isinstance` during response encoding. Request-body unions are rejected with `ImproperlyConfiguredException`.[^dto-py]
- **Raised Error Envelopes (`RouteError`, `ProblemDetail`, & `RaisedErrorSchema`)**: Raised denials (`400`, `401`, `429`, `503`, OAuth `409`) serialize by default as `RouteError(status_code, detail, extra)`. `SecurityPlugin._converts_to_problem_details` auto-detects `ProblemDetailsPlugin` when `enable_for_all_http_exceptions=True` and restates generated OpenAPI denial specs to `ProblemDetail(status, title, detail, extra)` (`application/problem+json`), while custom exception handlers configure `SecurityConfig.raised_error_schema` (`RaisedErrorSchema`).[^schema-py][^plugin-py][^config-py]
- **Python 3.10 Composite Cache Key Indexing**: Bind composite tuple keys to a local variable (`cache_key = (*name_key, shape)`) before indexing `cls._transfer_models[cache_key]` so `mypy` (`--python-version 3.10` / `ast-serialize`) does not parse starred unpacking inside subscript brackets as PEP 646 syntax.[^dto-py]
<!-- truth: end -->

## Usage Pattern

```python
from litestar import post
from litestar_security._dto import wire_dto
from litestar_security.schema import WirePolicy, WireStruct


class AccountView(WireStruct, frozen=True):
    account_id: str
    display_name: str | None = None


camel_dto = wire_dto(AccountView, WirePolicy(rename="camel"))


@post("/accounts", dto=camel_dto, return_dto=camel_dto)
async def update_account(data: AccountView) -> AccountView:
    return data
```

## Anti-Patterns

- Never use `@dataclass` or Pydantic `BaseModel` for HTTP wire request/response schemas; subclass `WireStruct(frozen=True)`.[^schema-py]
- Never call `json.dumps` or `json.loads` across controller or provider hot paths when `msgspec.json` or `WireDTO` handles the boundary.[^dto-py]

## References

[^schema-py]: `src/litestar_security/schema.py::WireStruct` — `WireStruct`, `WirePolicy`, `RouteError`, and `ProblemDetail`
[^dto-py]: `src/litestar_security/_dto.py::WireBackend` — `WireDTO`, `WireBackend`, `WireUnionDTO`, and `union_wire_dto`
[^plugin-py]: `src/litestar_security/plugin.py::SecurityPlugin` — `ProblemDetailsPlugin` detection and `RaisedErrorSchema` propagation
[^config-py]: `src/litestar_security/config.py::RaisedErrorSchema` — `SecurityConfig` wire and raised-error configuration
[^local-schemas]: `src/litestar_security/accounts/schemas/_local.py::LocalAccount` — Account wire schemas and `OperationMessage`
