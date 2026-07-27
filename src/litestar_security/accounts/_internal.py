"""Shared primitives used by every local-account module.

These are pure helpers with no store, hasher, or transport dependency, so each
account module can share one implementation instead of duplicating identifier
normalization, clock handling, and event construction.

The byte and character widths below describe the on-the-wire shape of session
and refresh credentials. Issuing and verifying code lives in separate modules,
so the widths are defined once here to keep the two sides from drifting apart.
"""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import Error as BinasciiError
from datetime import datetime, timezone
from typing import cast
from uuid import uuid4

__all__ = (
    "DIGEST_BYTES",
    "LOOKUP_BYTES",
    "MINIMUM_PEPPER_BYTES",
    "SECRET_BYTES",
    "SECRET_CHARACTERS",
    "SESSION_ID_BYTES",
    "aware_utc_time",
    "decode_random",
    "decode_random_unbounded",
    "encode_random",
    "new_event_id",
    "strict_context_text",
    "strict_text",
    "utc_now",
    "valid_identifier",
    "valid_security_epoch",
)


LOOKUP_BYTES = 16
SECRET_BYTES = 32
SECRET_CHARACTERS = 43
DIGEST_BYTES = 32
SESSION_ID_BYTES = 32
MINIMUM_PEPPER_BYTES = 32

_MAXIMUM_SECURITY_EPOCH = 9_223_372_036_854_775_807
_MAXIMUM_CONTEXT_TEXT_BYTES = 512
_ASCII_CONTROL_LIMIT = 32


def strict_text(value: object) -> bool:
    return isinstance(value, str) and value.__class__ is str and bool(value.strip())


def strict_context_text(value: object) -> bool:
    return (
        strict_text(value)
        and cast("str", value) == cast("str", value).strip()
        and len(cast("str", value).encode("utf-8")) <= _MAXIMUM_CONTEXT_TEXT_BYTES
        and all(ord(character) >= _ASCII_CONTROL_LIMIT for character in cast("str", value))
    )


def valid_security_epoch(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAXIMUM_SECURITY_EPOCH


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_event_id() -> str:
    return uuid4().hex


def aware_utc_time(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError
    return value.astimezone(timezone.utc)


def encode_random(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_random(value: str, expected_bytes: int) -> bytes | None:
    try:
        decoded = urlsafe_b64decode(f"{value}{'=' * (-len(value) % 4)}".encode("ascii"))
    except (BinasciiError, UnicodeEncodeError, ValueError):
        return None
    return decoded if len(decoded) == expected_bytes and encode_random(decoded) == value else None


def decode_random_unbounded(value: str) -> bytes:
    decoded = urlsafe_b64decode(f"{value}{'=' * (-len(value) % 4)}".encode("ascii"))
    if encode_random(decoded) != value:
        raise ValueError
    return decoded


def valid_identifier(value: object, *, prefix: str | None = None) -> bool:
    if not strict_text(value):
        return False
    text = cast("str", value)
    if prefix is not None and not text.startswith(prefix):
        return False
    encoded = text[len(prefix) :] if prefix is not None else text
    expected_bytes = LOOKUP_BYTES if prefix is not None else SESSION_ID_BYTES
    return decode_random(encoded, expected_bytes) is not None
