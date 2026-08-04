"""Wire-schema conventions for generated route bodies.

Every request and response schema on the generated ``/auth`` route tree shares
one casing convention and one unknown-field policy through :class:`WireStruct`.
Applications defining their own schemas alongside the generated routes may
inherit the same base so a single convention holds across the whole tree.
"""

import msgspec

__all__ = ("WireStruct",)


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
