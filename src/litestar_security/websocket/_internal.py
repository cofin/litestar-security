"""Primitives shared by every WebSocket transport-policy module.

Nothing here depends on another module in the package, so each of them may
import these freely.
"""

from datetime import datetime, timedelta, timezone
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from string import hexdigits
from typing import TYPE_CHECKING, NoReturn, cast
from urllib.parse import urlsplit

from litestar.exceptions import ImproperlyConfiguredException, WebSocketException

if TYPE_CHECKING:
    from collections.abc import Iterable


__all__ = ()

DEFAULT_UNAUTHENTICATED_CLOSE = 4401
DEFAULT_UNAUTHORIZED_CLOSE = 4403
DEFAULT_UNAVAILABLE_CLOSE = 1013
_ASCII_CONTROL_LIMIT = 32
RESERVED_QUERY_PARAMETERS = frozenset({"access_token", "authorization", "bearer", "jwt", "token"})
_HTTP_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAXIMUM_HOST_LENGTH = 253
_MAXIMUM_HOST_LABEL_LENGTH = 63


def strict_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.__class__ is str
        and bool(value)
        and value == value.strip()
        and all(ord(character) >= _ASCII_CONTROL_LIMIT for character in value)
    )


def aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        message = "WebSocket connect token timestamp must be timezone-aware"
        raise ValueError(message)
    return value.astimezone(timezone.utc)


def duration(value: object, name: str) -> timedelta:
    if not isinstance(value, timedelta) or value.__class__ is not timedelta:
        configuration_error(f"WebSocket {name} must be positive")
    duration = value
    if duration <= timedelta(0):
        configuration_error(f"WebSocket {name} must be positive")
    return duration


def normalize_allowed_origins(value: object) -> frozenset[str]:
    if isinstance(value, str):
        configuration_error("WebSocket allowed origins must be a collection")
    try:
        origins = tuple(cast("Iterable[object]", value))
    except TypeError:
        configuration_error("WebSocket allowed origins must be a collection")
    if any(origin.__class__ is not str for origin in origins):
        configuration_error("WebSocket allowed origins must contain text")
    canonical = tuple(canonical_origin(cast("str", origin), configuration=True) for origin in origins)
    if len(canonical) != len(set(canonical)):
        configuration_error("WebSocket allowed origins contain a duplicate")
    return frozenset(canonical)


def invalid_origin(*, configuration: bool, close_code: int) -> NoReturn:
    if configuration:
        configuration_error("WebSocket allowed origins must be canonical HTTP(S) origins")
    raise WebSocketException(code=close_code, detail="WebSocket Origin is not trusted")


def configuration_error(detail: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=detail)


def transport_error(code: int, detail: str) -> NoReturn:
    raise WebSocketException(code=code, detail=detail)


def canonical_origin(value: str, *, configuration: bool, invalid_close_code: int = DEFAULT_UNAUTHORIZED_CLOSE) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeError, ValueError):
        return invalid_origin(configuration=configuration, close_code=invalid_close_code)
    if (
        not value.isascii()
        or parsed.scheme not in _HTTP_DEFAULT_PORTS
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.hostname.endswith(".")
        or "*" in parsed.hostname
        or "%" in parsed.hostname
    ):
        return invalid_origin(configuration=configuration, close_code=invalid_close_code)
    hostname = canonical_hostname(parsed.hostname)
    if hostname is None:
        return invalid_origin(configuration=configuration, close_code=invalid_close_code)
    serialized_host = f"[{hostname}]" if ":" in hostname else hostname
    serialized_port = "" if port is None or port == _HTTP_DEFAULT_PORTS[parsed.scheme] else f":{port}"
    canonical = f"{parsed.scheme}://{serialized_host}{serialized_port}"
    if canonical != value:
        return invalid_origin(configuration=configuration, close_code=invalid_close_code)
    return canonical


def valid_percent_encoding(value: str) -> bool:
    index = 0
    while (index := value.find("%", index)) >= 0:
        if index + 2 >= len(value) or value[index + 1] not in hexdigits or value[index + 2] not in hexdigits:
            return False
        index += 3
    return True


def canonical_hostname(value: str) -> str | None:
    if ":" in value:
        return IPv6Address(value).compressed
    try:
        return str(IPv4Address(value))
    except AddressValueError:
        pass
    labels = value.split(".")
    if (
        len(value) > _MAXIMUM_HOST_LENGTH
        or all(label.isdigit() for label in labels)
        or any(
            not label
            or len(label) > _MAXIMUM_HOST_LABEL_LENGTH
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        )
    ):
        return None
    return value
