"""Unit tests for the DTO types that spell generated bodies in one convention."""

from collections.abc import Iterator
from importlib import import_module
from typing import Annotated, Any, cast, get_args, get_type_hints

import pytest
from litestar.dto import DTOConfig
from litestar.exceptions import ImproperlyConfiguredException
from litestar.typing import FieldDefinition

from litestar_security._dto import (
    MAX_NESTED_DEPTH,
    WireBackend,
    WireDTO,
    WireUnionBackend,
    union_wire_dto,
    wire_dto,
    wire_struct,
)
from litestar_security.accounts import LocalAccount, LocalCredentials, LocalSession
from litestar_security.schema import WirePolicy, WireStruct

SNAKE = WirePolicy()
CAMEL = WirePolicy(rename="camel")


def _nesting_depth(schema: type[Any], seen: frozenset[type[Any]] = frozenset()) -> int:
    """Return how many struct layers sit below one generated schema."""
    if schema in seen:
        return 0
    nested = [
        _nesting_depth(found, seen | {schema}) + 1
        for hint in get_type_hints(schema).values()
        for found in _wire_structs(hint)
    ]
    return max(nested, default=0)


def _wire_structs(annotation: Any) -> Iterator[type[Any]]:
    if isinstance(annotation, type) and issubclass(annotation, WireStruct):
        yield annotation
        return
    for argument in get_args(annotation):
        yield from _wire_structs(argument)


def _generated_schemas() -> Iterator[type[Any]]:
    pending = [WireStruct]
    while pending:
        schema = pending.pop()
        pending.extend(schema.__subclasses__())
        if schema is not WireStruct:
            yield schema


def test_wire_dto_returns_one_class_per_schema_and_policy() -> None:
    assert wire_dto(LocalAccount, SNAKE) is wire_dto(LocalAccount, WirePolicy())
    assert wire_dto(LocalAccount, CAMEL) is not wire_dto(LocalAccount, SNAKE)
    assert wire_dto(LocalSession, SNAKE) is not wire_dto(LocalAccount, SNAKE)


def test_narrowed_wire_dto_classes_do_not_share_a_backend_registry() -> None:
    snake = wire_dto(LocalAccount, SNAKE)
    camel = wire_dto(LocalAccount, CAMEL)

    assert snake._dto_backends is not camel._dto_backends  # noqa: SLF001 - the registry is the point of the test


def test_the_configured_nesting_depth_covers_every_generated_schema() -> None:
    import_module("litestar_security.accounts")
    import_module("litestar_security.providers.oauth")

    deepest = max((_nesting_depth(schema), schema.__name__) for schema in _generated_schemas())

    assert deepest[0] >= 1, "no generated schema nests, so this guard is watching nothing"
    assert deepest[0] <= MAX_NESTED_DEPTH


def test_wire_struct_caches_transfer_model_and_matches_backend_registry() -> None:
    documented = wire_struct(LocalCredentials, CAMEL)

    assert wire_struct(LocalCredentials, CAMEL) is documented
    assert WireBackend.transfer_model_for(LocalCredentials, wire_dto(LocalCredentials, CAMEL).config) is documented


def test_wire_union_backend_rejects_raw_request_body_decoding() -> None:
    union = LocalAccount | LocalCredentials
    backend = WireUnionBackend(
        dto_factory=union_wire_dto(union, SNAKE),
        field_definition=FieldDefinition.from_annotation(union),
        handler_id="union::request",
        is_data_field=True,
        model_type=union,
        wrapper_attribute_name=None,
    )

    with pytest.raises(ImproperlyConfiguredException, match="cannot be narrowed to a union"):
        backend.populate_data_from_raw(b"{}", cast("Any", object()))


def test_one_schema_cannot_publish_two_wire_shapes_under_one_policy() -> None:
    def narrowed(exclude: set[str]) -> Any:
        config = DTOConfig(exclude=exclude, max_nested_depth=MAX_NESTED_DEPTH)
        return WireDTO[Annotated[LocalSession, config]]

    def backend(dto: Any) -> WireBackend:
        return WireBackend(
            dto_factory=dto,
            field_definition=FieldDefinition.from_annotation(LocalSession),
            model_type=LocalSession,
            handler_id=f"shape::{sorted(dto.config.exclude)}",
            is_data_field=False,
            wrapper_attribute_name=None,
        )

    backend(narrowed(set()))

    with pytest.raises(ImproperlyConfiguredException, match="two different wire shapes"):
        backend(narrowed({"current"}))
