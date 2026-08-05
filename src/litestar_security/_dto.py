"""Spell every generated route body in one convention, in both directions.

Litestar's DTO layer converts on the way in and on the way out and reports the
converted shape to OpenAPI, so one policy on :class:`SecurityConfig` reaches the
wire, the document, and therefore a generated client. It is always installed,
because the measured cost is around twenty microseconds against an Argon2
verification measured in milliseconds, and one code path is easier to reason
about than two.

Two things the stock DTO layer does not do, and this module supplies:

* **Stable component keys.** Litestar names a transfer struct after the handler
  that produced it, so ``LocalCredentials`` reaches the document as
  ``LoginLocalCredentialsRequestBody`` even with no rename strategy at all. A
  component key is a generated client's type name, so every transfer struct is
  named after the model it mirrors instead - nested models included - and one
  struct is shared by every handler naming the same model, because several
  structs claiming one qualified name make the schema registry refuse to build
  the document.
* **Unions.** Four generated handlers return one of two bodies, and a DTO
  cannot narrow to a union. :class:`WireUnionBackend` holds one ordinary
  backend per struct arm and composes them.

Reaching into ``litestar.dto._backend`` and ``litestar.dto._codegen_backend``
is confined to this module. Both hold classes that are documented extension
points in every respect except their module name, and keeping the imports in
one file is what makes them one deletion when they are exported.
"""

from collections.abc import Collection
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar, Union, cast, get_args

import msgspec
from litestar import Response
from litestar.dto import DTOConfig, MsgspecDTO
from litestar.dto._backend import DTOBackend, build_annotation_for_backend
from litestar.dto._codegen_backend import DTOCodegenBackend
from litestar.exceptions import ImproperlyConfiguredException
from litestar.typing import FieldDefinition

from litestar_security.schema import WirePolicy, WireStruct

if TYPE_CHECKING:
    from collections.abc import Set as AbstractSet

    from litestar.connection import ASGIConnection
    from litestar.dto import AbstractDTO
    from litestar.dto._types import TransferDTOFieldDefinition

__all__ = (
    "MAX_NESTED_DEPTH",
    "WireBackend",
    "WireDTO",
    "WireUnionBackend",
    "WireUnionDTO",
    "union_wire_dto",
    "wire_dto",
    "wire_struct",
)

T = TypeVar("T", bound="msgspec.Struct | Collection[msgspec.Struct]")

MAX_NESTED_DEPTH = 4
"""How deep a generated schema may nest before its leaves are dropped.

``DTOConfig.max_nested_depth`` defaults to ``1`` and exceeding it does not
raise: the field is silently dropped from the OpenAPI schema *and* from the
wire. That failure is invisible, so the limit is set here rather than defaulted,
with room above the deepest generated schema. It is not an application setting -
it describes this library's own schemas, and the only thing an application could
achieve by lowering it is losing data.
"""


def wire_dto(schema: "type[WireStruct]", policy: WirePolicy) -> "type[WireDTO[Any]]":
    """Build the DTO wrapper that spells one schema in an application's convention.

    Args:
        schema: The generated-route schema the handler sends or receives.
        policy: How that schema is spelled on the wire.

    Returns:
        One DTO class per schema and policy. The same class is returned for
        every later call, because a handler references a schema several times
        and each subscription would otherwise define a new class.
    """
    key = (schema, policy)
    cached = _DTO_TYPES.get(key)
    if cached is None:
        cached = _DTO_TYPES[key] = cast("type[WireDTO[Any]]", cast("Any", WireDTO)[_annotated(schema, policy)])
    return cached


def union_wire_dto(union: Any, policy: WirePolicy) -> "type[WireUnionDTO[Any]]":
    """Build the DTO wrapper for a handler that returns one of several bodies.

    Args:
        union: The union of the bodies the handler may return.
        policy: How the schemas in it are spelled on the wire.

    Returns:
        One DTO class per union and policy.
    """
    key = (union, policy)
    cached = _UNION_DTO_TYPES.get(key)
    if cached is None:
        cached = _UNION_DTO_TYPES[key] = cast(
            "type[WireUnionDTO[Any]]", cast("Any", WireUnionDTO)[_annotated(union, policy)]
        )
    return cached


def wire_struct(schema: "type[WireStruct]", policy: WirePolicy) -> "type[msgspec.Struct]":
    """Return the renamed struct one schema reaches the wire as.

    A response specification names its schema directly, and a specification
    describing the un-renamed schema while the handler emits the renamed one is
    the drift this module exists to prevent. Naming this struct instead makes
    the documented body and the emitted body one component.

    Args:
        schema: The generated-route schema the specification documents.
        policy: How that schema is spelled on the wire.

    Returns:
        The same struct the handler's own DTO transfers through.
    """
    dto = wire_dto(schema, policy)
    cached = WireBackend.transfer_model_for(schema, dto.config)
    if cached is not None:
        return cached
    # Response specifications are built before any handler is registered, so the
    # struct has to exist by then. Building the backend here puts the identical
    # object in the cache the handler will later hit.
    return WireBackend(
        dto_factory=dto,
        field_definition=FieldDefinition.from_annotation(schema),
        model_type=schema,
        handler_id=f"{schema.__module__}.{schema.__qualname__}",
        is_data_field=False,
        wrapper_attribute_name=None,
    ).transfer_model_type


class WireBackend(DTOCodegenBackend):
    """A DTO backend that names transfer structs after the models they mirror.

    Litestar builds ``{handler}{Model}{RequestBody|ResponseBody}`` and mangles
    nested names further, which renames every published component key even when
    no rename strategy is configured. Two overrides fix that: the name a
    transfer struct is created with, and a cache that makes one model yield one
    struct across every handler that names it.

    The cache lives for the life of the process, like the DTO classes
    themselves. Sharing it across applications is deliberate: it is what makes
    two applications with the same policy publish the same component keys.
    """

    __slots__ = ("_models",)

    _transfer_models: ClassVar[dict[tuple[Any, ...], "type[msgspec.Struct]"]] = {}
    _transfer_shapes: ClassVar[dict[tuple[Any, ...], tuple[Any, ...]]] = {}

    @classmethod
    def transfer_model_for(cls, model_type: Any, config: DTOConfig) -> "type[msgspec.Struct] | None":
        """Return the struct already built for one model under one configuration.

        Args:
            model_type: The schema to look up.
            config: The DTO configuration carrying the wire policy.

        Returns:
            The cached struct, or ``None`` when nothing has built it yet.
        """
        name_key = (model_type, _policy_key(config))
        shape = cls._transfer_shapes.get(name_key)
        return None if shape is None else cls._transfer_models[(*name_key, shape)]

    def parse_model(
        self,
        model_type: Any,
        exclude: "AbstractSet[str]",
        include: "AbstractSet[str]",
        rename_fields: dict[str, str],
        nested_depth: int = 0,
    ) -> "tuple[TransferDTOFieldDefinition, ...]":
        """Reduce one model to its transfer fields, remembering which model they came from.

        Litestar hands the returned tuple straight to
        :meth:`create_transfer_model_type` without the model beside it, so its
        identity is how a nested struct recovers the model it mirrors.

        Args:
            model_type: The model being reduced.
            exclude: Field names to leave out.
            include: Field names to restrict to.
            rename_fields: Per-field serialization names.
            nested_depth: How deep this model sits below the root.

        Returns:
            The transfer field definitions for the model.
        """
        field_definitions = super().parse_model(
            model_type=model_type,
            exclude=exclude,
            include=include,
            rename_fields=rename_fields,
            nested_depth=nested_depth,
        )
        self._model_of_fields[id(field_definitions)] = (field_definitions, model_type)
        return field_definitions

    def create_transfer_model_type(
        self, model_name: str, field_definitions: "tuple[TransferDTOFieldDefinition, ...]"
    ) -> "type[msgspec.Struct]":
        """Return one struct per model and policy, named after the model.

        Args:
            model_name: The name Litestar would have used, kept only when the
                model behind the fields cannot be recovered.
            field_definitions: The transfer fields the struct is built from.

        Returns:
            The transfer struct, shared with every other handler naming the same
            model under the same policy.

        Raises:
            ImproperlyConfiguredException: If one model needs two different
                transfer shapes under one policy, which one component key cannot
                serve.
        """
        entry = self._model_of_fields.get(id(field_definitions))
        model_type = entry[1] if entry is not None and entry[0] is field_definitions else self.model_type
        name_key = (model_type, _policy_key(cast("DTOConfig", cast("Any", self).dto_factory.config)))
        shape = tuple(
            (field.name, field.is_excluded, field.is_partial, field.serialization_name) for field in field_definitions
        )
        previous = self._transfer_shapes.get(name_key)
        if previous is not None and previous != shape:
            message = (
                f"Generated schema {model_type.__name__} needs two different wire shapes under one policy, "
                "and one OpenAPI component cannot describe both"
            )
            raise ImproperlyConfiguredException(detail=message)
        cached = self._transfer_models.get((*name_key, shape))
        if cached is not None:
            return cached
        struct = _mirroring_defaults(
            super().create_transfer_model_type(model_name=model_type.__name__, field_definitions=field_definitions),
            model_type,
        )
        self._transfer_shapes[name_key] = shape
        self._transfer_models[(*name_key, shape)] = struct
        return struct

    def _create_transfer_model_name(self, model_name: str) -> str:
        """Return the name unchanged.

        :meth:`create_transfer_model_type` has already decided it, and Litestar's
        own answer would prefix the handler and suffix the direction. Bypassing
        it also bypasses the process-global set of seen names it maintains,
        which makes component keys depend on how many applications the process
        built before this one.

        Args:
            model_name: The name already decided.

        Returns:
            The same name.
        """
        return model_name

    @property
    def _model_of_fields(self) -> "dict[int, tuple[Any, Any]]":
        # parse_model runs inside super().__init__, before a subclass gets to
        # initialize anything of its own.
        store = getattr(self, "_models", None)
        if store is None:
            store = {}
            object.__setattr__(self, "_models", store)
        return cast("dict[int, tuple[Any, Any]]", store)


class WireUnionBackend(DTOBackend):
    """A backend holding one ordinary backend per struct arm of a union.

    :class:`DTOBackend` assumes a single struct from its first statement
    onwards - it reduces ``model_type`` to fields and names a transfer struct
    after ``model_type.__name__``, and a union has neither - so this replaces
    the constructor rather than extending it.

    An arm whose member names belong to a specification passes through
    untouched, as does an arm that is not a struct at all.
    """

    __slots__ = ("arm_backends",)

    def __init__(  # noqa: PLR0913 - the signature Litestar constructs a backend with
        self,
        dto_factory: "type[AbstractDTO[Any]]",
        field_definition: FieldDefinition,
        handler_id: str,
        is_data_field: bool,
        model_type: Any,
        wrapper_attribute_name: str | None,
    ) -> None:
        """Compose one backend per struct arm.

        Args:
            dto_factory: The DTO class installing this backend.
            field_definition: The parsed annotation the union was found in.
            handler_id: The handler the backend belongs to.
            is_data_field: Whether this describes a request body.
            model_type: The union itself.
            wrapper_attribute_name: The attribute holding the union when it is
                wrapped in a generic, such as a response.
        """
        self.dto_factory = dto_factory  # type: ignore[misc]  # replaces the constructor rather than extending it
        self.field_definition = field_definition  # type: ignore[misc]  # same
        self.is_data_field = is_data_field  # type: ignore[misc]  # same
        self.handler_id = handler_id  # type: ignore[misc]  # same
        self.model_type = model_type  # type: ignore[misc]  # same
        self.wrapper_attribute_name = wrapper_attribute_name  # type: ignore[misc]  # same
        self.attribute_accessor = dto_factory.attribute_accessor
        self.dto_data_type = None
        self.parsed_field_definitions = ()
        self.arm_backends: dict[Any, WireBackend] = {}
        annotation: Any = field_definition.annotation
        transfer_arms: list[Any] = []
        for arm in get_args(model_type):
            if not _renames(arm):
                transfer_arms.append(arm)
                continue
            backend = WireBackend(
                dto_factory=dto_factory,
                field_definition=FieldDefinition.from_annotation(arm),
                handler_id=f"{handler_id}::{arm.__name__}",
                is_data_field=is_data_field,
                model_type=arm,
                wrapper_attribute_name=None,
            )
            self.arm_backends[arm] = backend
            transfer_arms.append(backend.transfer_model_type)
            annotation = build_annotation_for_backend(
                arm, FieldDefinition.from_annotation(annotation), backend.transfer_model_type
            )
        self.transfer_model_type = Union[tuple(transfer_arms)]  # type: ignore[assignment]  # a union of arms, not one struct
        self.annotation = annotation

    def encode_data(self, data: Any) -> Any:
        """Transfer whichever arm the handler actually returned.

        Args:
            data: The value the handler returned.

        Returns:
            The value with its renameable arm transferred, or unchanged when no
            arm applies to it.
        """
        value: Any = data
        if self.wrapper_attribute_name is not None:
            wrapped = self.attribute_accessor(value, self.wrapper_attribute_name)
            if (backend := self._backend_for(wrapped)) is not None:
                setattr(value, self.wrapper_attribute_name, _encoded(backend, wrapped))
            return value
        if (backend := self._backend_for(value)) is not None:
            return _encoded(backend, value)
        if not isinstance(value, Response):
            return value
        # An arm spelled `Response[X]`: the policy applies to the body it
        # carries, not to the response carrying it.
        response = cast("Any", value)
        content: Any = response.content
        if (inner := self._backend_for(content)) is not None:
            response.content = _encoded(inner, content)
        return response

    def populate_data_from_raw(self, raw: bytes, asgi_connection: "ASGIConnection[Any, Any, Any, Any]") -> Any:
        """Reject a request body narrowed to a union.

        Args:
            raw: The raw request body.
            asgi_connection: The connection carrying it.

        Raises:
            ImproperlyConfiguredException: Always. No generated handler accepts
                one of several request bodies, and which arm a body decodes to
                would be ambiguous if one did.
        """
        del raw, asgi_connection
        message = "A generated request body cannot be narrowed to a union of schemas"
        raise ImproperlyConfiguredException(detail=message)

    def _backend_for(self, value: Any) -> "WireBackend | None":
        return next((backend for arm, backend in self.arm_backends.items() if isinstance(value, arm)), None)


class WireDTO(MsgspecDTO[T]):
    """A msgspec DTO installing :class:`WireBackend`."""

    @classmethod
    def create_for_field_definition(
        cls, field_definition: FieldDefinition, handler_id: str, backend_cls: "type[DTOBackend] | None" = None
    ) -> None:
        """Create this handler's backend, defaulting to the wire backend.

        Args:
            field_definition: The parsed annotation the DTO applies to.
            handler_id: The handler the backend belongs to.
            backend_cls: An explicit backend class, which Litestar never passes.
        """
        super().create_for_field_definition(
            field_definition=field_definition, handler_id=handler_id, backend_cls=backend_cls or WireBackend
        )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Give every narrowed DTO class its own backend registry.

        ``AbstractDTO._dto_backends`` is one dictionary shared by every DTO in
        the process, keyed only by handler identity. Two applications
        configuring different casing can produce the same handler identity, and
        the second would then decode through the first's backend. A registry per
        narrowed class makes a collision only ever match a backend that already
        agrees.

        Args:
            **kwargs: Class creation keywords, passed through.
        """
        super().__init_subclass__(**kwargs)
        cls._dto_backends = {}


class WireUnionDTO(WireDTO[T]):
    """A wire DTO for a handler that returns one of several bodies."""

    def __class_getitem__(cls, annotation: Any) -> "type[WireUnionDTO[T]]":
        """Narrow this DTO to a union, which the base class refuses.

        Args:
            annotation: The union, optionally annotated with a configuration.

        Returns:
            A DTO class narrowed to that union.
        """
        field_definition = FieldDefinition.from_annotation(annotation)
        config = cls.get_dto_config_from_annotated_type(field_definition) or DTOConfig()
        return cast(
            "type[WireUnionDTO[T]]",
            type(
                f"{cls.__name__}[{annotation}]", (cls,), {"config": config, "model_type": field_definition.annotation}
            ),
        )

    @classmethod
    def is_supported_model_type_field(cls, field_definition: FieldDefinition) -> bool:
        """Report that this DTO applies to the handler's return annotation.

        Args:
            field_definition: The parsed return annotation.

        Returns:
            ``True``. This DTO is only ever installed on the handler whose union
            it was built from.
        """
        del field_definition
        return True

    @classmethod
    def create_for_field_definition(
        cls, field_definition: FieldDefinition, handler_id: str, backend_cls: "type[DTOBackend] | None" = None
    ) -> None:
        """Create one union backend for this handler.

        Args:
            field_definition: The parsed annotation the DTO applies to.
            handler_id: The handler the backend belongs to.
            backend_cls: An explicit backend class, which Litestar never passes.

        Raises:
            ImproperlyConfiguredException: If the union describes a request
                body, which no generated handler accepts.
        """
        del backend_cls
        if field_definition.name == "data":
            message = "A generated request body cannot be narrowed to a union of schemas"
            raise ImproperlyConfiguredException(detail=message)
        backends = cls._dto_backends.setdefault(handler_id, {})
        if "return_backend" in backends:
            return
        inner, wrapper_attribute_name = cls._unwrap(field_definition)
        backends["return_backend"] = WireUnionBackend(
            dto_factory=cls,
            field_definition=inner,
            handler_id=handler_id,
            is_data_field=False,
            model_type=cls.model_type,
            wrapper_attribute_name=wrapper_attribute_name,
        )

    @classmethod
    def _unwrap(cls, field_definition: FieldDefinition) -> tuple[FieldDefinition, str | None]:
        resolved = cls.resolve_model_type(field_definition=field_definition)
        if resolved.annotation is cls.model_type or resolved.origin is None:
            return field_definition, None
        for candidate in resolved.inner_types:
            if cls.resolve_model_type(candidate).annotation != cls.model_type:
                continue
            for attribute, attribute_type in cls.get_model_type_hints(resolved.origin).items():
                if attribute_type.is_type_var or any(inner.is_type_var for inner in attribute_type.inner_types):
                    return candidate, attribute
            return candidate, None
        return field_definition, None


_DTO_TYPES: "dict[tuple[Any, WirePolicy], type[WireDTO[Any]]]" = {}
_UNION_DTO_TYPES: "dict[tuple[Any, WirePolicy], type[WireUnionDTO[Any]]]" = {}


def _annotated(annotation: Any, policy: WirePolicy) -> Any:
    from typing import Annotated  # noqa: PLC0415 - subscripting Annotated needs the runtime name

    return Annotated[
        annotation,
        DTOConfig(
            rename_strategy=policy.rename,
            forbid_unknown_fields=policy.forbid_unknown_fields,
            max_nested_depth=MAX_NESTED_DEPTH,
        ),
    ]


def _encoded(backend: "WireBackend", value: Any) -> Any:
    """Transfer one value through a backend without inheriting Litestar's open return type."""
    return cast(
        "Any",
        backend.encode_data(value),  # pyright: ignore[reportUnknownMemberType] - Litestar's encodable alias is unparameterized
    )


def _mirroring_defaults(struct: "type[msgspec.Struct]", model_type: Any) -> "type[msgspec.Struct]":
    """Carry the model's ``omit_defaults`` onto the struct that replaces it on the wire.

    Litestar builds every transfer struct with the same fixed configuration, so a
    schema promising that a response carries only the members its operation
    resolved would start sending explicit nulls for the rest. That promise is
    part of the body, not of the schema, so nothing in the document would show
    it had been broken.

    Args:
        struct: The transfer struct just built.
        model_type: The schema it mirrors.

    Returns:
        The struct, or a restatement of it that omits defaults the way the model
        does.
    """
    config = getattr(model_type, "__struct_config__", None)
    if config is None or config.omit_defaults == struct.__struct_config__.omit_defaults:
        return struct
    return cast("type[msgspec.Struct]", type(struct.__name__, (struct,), {}, omit_defaults=config.omit_defaults))


def _policy_key(config: DTOConfig) -> tuple[Any, ...]:
    return (config.rename_strategy, config.forbid_unknown_fields, config.max_nested_depth)


def _renames(annotation: Any) -> bool:
    return isinstance(annotation, type) and issubclass(annotation, WireStruct) and annotation.__wire_casing__
