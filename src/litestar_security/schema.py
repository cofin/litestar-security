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

from typing import Any

import msgspec

__all__ = ("RouteError", "WireStruct")


class WireStruct(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    """Base for every generated-route wire schema: snake_case, strict fields.

    Field names reach the wire exactly as they are spelled in Python, and an
    unrecognized member is a decoding error rather than a silently discarded
    key. Rejecting the unknown member is what keeps a stale or misspelled
    optional field from resolving to its default and producing a wrong but
    successful request.

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


class RouteError(WireStruct, frozen=True, forbid_unknown_fields=False):
    """The body a generated route sends when it *raises* rather than returns.

    A denial - 400, 401, 429, 503, and the OAuth 409 - reaches the wire through
    Litestar's exception handling, not through the handler's return value, so
    the body is ``ExceptionResponseContent``: the status repeated inside the
    payload, a human-readable ``detail``, and ``extra`` when the raised
    exception carries structured context. A request-validation failure always
    carries one, as a list of ``{message, key, source}`` entries, so ``extra``
    is a member clients see in practice rather than a theoretical one.

    Distinguish this from :class:`~litestar_security.accounts.RouteStatus`,
    which is the body a handler *returns* - the 200 confirmations and the 409
    conflict. The two are separate schemas because the distinction that decides
    the shape is raised-versus-returned, not error-versus-success.

    Unknown members are tolerated here, against the base policy, because the
    sender is Litestar: an application handler may add its own members and a
    future Litestar may too, and neither is a reason for a client of this
    library to fail decoding.
    """

    status_code: int
    """The HTTP status, repeated in the body by Litestar's exception handling."""
    detail: str
    """A human-readable explanation that never names an account."""
    extra: dict[str, Any] | list[Any] | None = None
    """Structured context the raised exception carried, when it carried any."""
