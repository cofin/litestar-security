"""JSON, base64url, and strict-text primitives shared by every JWT module.

Nothing here knows about keys, claims, or transport. Segment decoding is bounded
and total so that a malformed token is rejected by shape before any signature or
claim logic runs.
"""

import base64
import binascii
import json
import re
import unicodedata
from datetime import datetime, timezone
from types import MappingProxyType
from typing import NoReturn, cast

from litestar_security.providers._internal import (
    JSONValue,
    raise_config,
    reject_non_finite,
    unique_object,
    validate_depth,
)

_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def raise_value(message: str) -> NoReturn:
    raise ValueError(message)


def reject() -> NoReturn:
    raise ValueError


def is_strict_identifier(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and unicodedata.normalize("NFC", value) == value
        and all(not unicodedata.category(character).startswith("C") for character in value)
    )


def is_scope_token(value: str) -> bool:
    return bool(value) and all(
        character == "!" or "#" <= character <= "[" or "]" <= character <= "~" for character in value
    )


def strict_identifier(value: str) -> str:
    if not is_strict_identifier(value):
        raise_config("JWT identifiers must be non-empty normalized strings without controls or surrounding whitespace")
    return value


def decode_base64url(segment: str) -> bytes:
    if not _BASE64URL_PATTERN.fullmatch(segment):
        raise ValueError
    padding = "=" * (-len(segment) % 4)
    try:
        decoded = base64.b64decode(f"{segment}{padding}", altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
        raise ValueError
    return decoded


def freeze_json(value: JSONValue) -> JSONValue:
    if isinstance(value, dict):
        return cast("JSONValue", MappingProxyType({key: freeze_json(item) for key, item in value.items()}))
    if isinstance(value, list):
        return cast("JSONValue", tuple(freeze_json(item) for item in value))
    return value


def decode_json_segment(segment: str, *, maximum_json_depth: int) -> dict[str, JSONValue]:
    raw = decode_base64url(segment)
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_non_finite)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError from exc
    if not isinstance(value, dict):
        raise TypeError
    decoded = cast("dict[str, JSONValue]", value)
    validate_depth(decoded, maximum=maximum_json_depth)
    return decoded


def aware_utc(value: datetime) -> datetime:
    timestamp_value: object = value
    if (
        not isinstance(timestamp_value, datetime)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
        or timestamp_value.tzinfo is None
        or timestamp_value.utcoffset() is None
    ):
        raise_value("Access-token timestamps must be timezone-aware")
    return timestamp_value.astimezone(timezone.utc)


def strict_identifier_value(value: str) -> str:
    identifier: object = value
    if (
        not isinstance(identifier, str)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
        or not is_strict_identifier(identifier)
    ):
        raise_value("Access-token identifiers must be non-empty normalized strings")
    return identifier


def strict_scope_value(value: str) -> str:
    scope: object = value
    if (
        not isinstance(scope, str)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
        or not is_scope_token(scope)
    ):
        raise_value("Access-token scope values must be OAuth scope tokens")
    return scope


def strict_key_id(value: str) -> str:
    key_id: object = value
    if (
        not isinstance(key_id, str)  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
        or not is_strict_identifier(key_id)
    ):
        raise_config("Local key id must be a non-empty normalized string")
    return key_id
