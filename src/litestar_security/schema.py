"""Wire-schema conventions for generated route bodies.

Every request and response schema on the generated ``/auth`` route tree shares
one casing convention and one unknown-field policy through :class:`WireStruct`.
Applications defining their own schemas alongside the generated routes may
inherit the same base so a single convention holds across the whole tree.

:class:`RouteError` lives here rather than beside either route family's own
schemas because both need it and neither owns it: ``providers/oauth/`` does not
import from ``accounts/``, and the body it describes is Litestar's rather than
this library's.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, cast

import msgspec
from litestar.exceptions import ImproperlyConfiguredException

if TYPE_CHECKING:
    from litestar.dto.types import RenameStrategy

__all__ = ("ProblemDetail", "RouteError", "WirePolicy", "WireStruct")

RENAME_STRATEGIES: frozenset[str] = frozenset({"lower", "upper", "camel", "pascal", "kebab"})
"""The named casing strategies :class:`WirePolicy` accepts by name."""


@dataclass(frozen=True, slots=True)
class WirePolicy:
    """How generated request and response bodies are spelled on the wire.

    One value carries both halves of the convention, and it is hashable, so the
    generated routers a feature configuration caches stay one router per policy
    rather than one router that a second application can find already built for
    a casing it did not ask for.
    """

    rename: "RenameStrategy | None" = None
    """The casing strategy, or ``None`` for the field names as Python spells them."""
    forbid_unknown_fields: bool = True
    """Whether an unrecognized member is a decoding error rather than ignored."""

    def __post_init__(self) -> None:
        """Reject a strategy no schema could be built with.

        Raises:
            ImproperlyConfiguredException: If the strategy is neither one of the
                named strategies nor a callable, or the unknown-field policy is
                not boolean.
        """
        rename: object = self.rename
        if rename is not None and not callable(rename) and rename not in RENAME_STRATEGIES:
            named = ", ".join(sorted(RENAME_STRATEGIES))
            message = f"Wire rename strategy must be callable or one of: {named}"
            raise ImproperlyConfiguredException(detail=message)
        forbid_unknown_fields = cast("object", self.forbid_unknown_fields)
        if forbid_unknown_fields.__class__ is not bool:
            message = "Wire unknown-field policy must be boolean"
            raise ImproperlyConfiguredException(detail=message)


class WireStruct(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Base for every generated-route wire schema, and the default it is spelled in.

    Field names reach the wire exactly as they are spelled in Python, and an
    unrecognized member is a decoding error rather than a silently discarded
    key. Rejecting the unknown member is what keeps a stale or misspelled
    optional field from resolving to its default and producing a wrong but
    successful request.

    That is the default rather than a fixed policy. An application chooses the
    convention through ``SecurityConfig.wire_rename`` and
    ``wire_forbid_unknown_fields``, and the generated routes carry the choice
    into the request body, the response body, and the OpenAPI schema together.
    A schema declares what it is called here; the configuration decides how it
    is spelled.

    Subclasses restate ``frozen=True``::

        class LocalCredentials(WireStruct, frozen=True):
            '''Password credentials accepted by generated login handlers.'''

    That keyword is redundant at runtime, because msgspec inherits the struct
    configuration, and required by the type checkers, which read immutability
    from the class keywords rather than from the base. Keeping the base frozen
    anyway means a subclass that omits the keyword is still immutable in fact,
    which is the safer direction for the mistake to fall.

    Strictness applies to decoding, so it constrains request schemas only;
    response schemas inherit it inertly. A schema that must tolerate members it
    does not model - a specification-defined body whose sender may legitimately
    add them - overrides the policy for itself and records why::

        class BackchannelLogout(WireStruct, frozen=True, forbid_unknown_fields=False):
            '''The specification permits unrecognized members.'''

    Prefer that per-schema override to relaxing this base: it keeps the safe
    default intact and leaves the reason beside the schema that needs it.
    """

    __wire_casing__: ClassVar[bool] = True
    """Whether the application's configured casing applies to this schema.

    A schema whose member names belong to a specification, or to a sender other
    than this library, sets this ``False`` and records why beside itself. Its
    members then reach the wire and the document exactly as they are spelled
    here whatever an application configures.
    """


class RouteError(WireStruct, frozen=True, forbid_unknown_fields=False):
    """The body a generated route sends when it *raises* rather than returns.

    A denial - 400, 401, 429, 503, and the OAuth 409 - reaches the wire through
    Litestar's exception handling, not through the handler's return value, so
    the body is ``ExceptionResponseContent``: the status repeated inside the
    payload, a human-readable ``detail``, and ``extra`` when the raised
    exception carries structured context. A request-validation failure always
    carries one, as a list of ``{message, key, source}`` entries, so ``extra``
    is a member clients see in practice rather than a theoretical one.

    Distinguish this from :class:`~litestar_security.accounts.OperationMessage`,
    which is the body a handler *returns* - the 200 confirmations and the 409
    conflict. The two are separate schemas because the distinction that decides
    the shape is raised-versus-returned, not error-versus-success.

    Unknown members are tolerated here, against the base policy, because the
    sender is Litestar: an application handler may add its own members and a
    future Litestar may too, and neither is a reason for a client of this
    library to fail decoding.
    """

    __wire_casing__: ClassVar[bool] = False
    """Litestar's exception handling renders this body, so its members are its own."""

    status_code: int
    """The HTTP status, repeated in the body by Litestar's exception handling."""
    detail: str
    """A human-readable explanation that never names an account."""
    extra: dict[str, Any] | list[Any] | None = None
    """Structured context the raised exception carried, when it carried any."""


class ProblemDetail(WireStruct, frozen=True, forbid_unknown_fields=False):
    """The body a denial takes when the application converts every HTTP exception.

    An application installing Litestar's problem-details plugin with
    ``enable_for_all_http_exceptions=True`` replaces :class:`RouteError` on
    every raised status, and the response is served as
    ``application/problem+json``.

    These are the members Litestar's conversion actually emits, which is not
    the RFC 9457 five-member shape: the raised ``detail`` is moved onto
    ``title`` and ``detail`` falls back to the HTTP reason phrase, while
    ``type`` and ``instance`` are never produced. Unknown members are tolerated
    both because RFC 9457 permits extension members and because the sender is
    Litestar rather than this library.
    """

    __wire_casing__: ClassVar[bool] = False
    """Litestar's problem-details conversion renders this body, so its members are its own."""

    status: int
    """The HTTP status, repeated in the body."""
    title: str
    """The raised explanation, which the conversion moves here from ``detail``."""
    detail: str
    """The HTTP reason phrase, which the conversion leaves as the default."""
    extra: dict[str, Any] | list[Any] | None = None
    """Structured context the raised exception carried, carried through unchanged."""
