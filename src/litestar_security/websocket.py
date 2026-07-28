"""WebSocket-specific transport policy.

Content Security Policy ``connect-src`` is complementary browser hardening. It
does not replace exact server-side Origin validation or credential policy.
"""

from dataclasses import dataclass, field
from datetime import timedelta
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from string import hexdigits
from typing import TYPE_CHECKING, Any, NoReturn, cast
from urllib.parse import parse_qsl, urlsplit

from litestar.exceptions import ImproperlyConfiguredException, WebSocketException

if TYPE_CHECKING:
    from collections.abc import Iterable

    from litestar.connection import ASGIConnection
    from litestar.types import Send

__all__ = ("WebSocketCloseCodes", "WebSocketHandshake", "WebSocketSecurityConfig", "extract_websocket_handshake")

_DEFAULT_UNAUTHENTICATED_CLOSE = 4401
_DEFAULT_UNAUTHORIZED_CLOSE = 4403
_DEFAULT_UNAVAILABLE_CLOSE = 1013
_MAXIMUM_TICKET_TTL = timedelta(minutes=2)
_RESERVED_QUERY_PARAMETERS = frozenset({"access_token", "authorization", "bearer", "jwt", "token"})
_HTTP_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAXIMUM_HOST_LENGTH = 253
_MAXIMUM_HOST_LABEL_LENGTH = 63
_PRIVATE_CLOSE_CODE_MINIMUM = 4000
_PRIVATE_CLOSE_CODE_MAXIMUM = 4999


@dataclass(frozen=True, slots=True)
class WebSocketCloseCodes:
    """Map stable security outcomes to WebSocket close codes."""

    unauthenticated: int = _DEFAULT_UNAUTHENTICATED_CLOSE
    unauthorized: int = _DEFAULT_UNAUTHORIZED_CLOSE
    verification_unavailable: int = _DEFAULT_UNAVAILABLE_CLOSE


@dataclass(frozen=True, slots=True)
class WebSocketSecurityConfig:
    """Configure WebSocket transport validation and optional lifetime hooks."""

    allowed_origins: frozenset[str] = frozenset()
    ticket_store: object | None = field(default=None, repr=False)
    ticket_ttl: timedelta = timedelta(seconds=30)
    maximum_ticket_ttl: timedelta = _MAXIMUM_TICKET_TTL
    ticket_query_parameter: str = "ticket"
    refresh_interval: timedelta | None = None
    snapshot_refresher: object | None = field(default=None, repr=False)
    revocation_source: object | None = field(default=None, repr=False)
    close_codes: WebSocketCloseCodes = WebSocketCloseCodes()

    def __post_init__(self) -> None:
        """Validate and freeze security-sensitive transport settings."""
        object.__setattr__(self, "allowed_origins", _normalize_allowed_origins(self.allowed_origins))
        _validate_ticket_settings(self)
        _validate_refresh_settings(self)
        _validate_close_codes(self.close_codes)


@dataclass(frozen=True, slots=True)
class WebSocketHandshake:
    """Describe credential transports presented by one WebSocket handshake."""

    origin: str | None
    uses_cookie_credentials: bool
    uses_authorization_header: bool
    ticket: str | None = field(repr=False)


async def close_websocket(send: "Send", *, code: int, reason: str) -> None:
    """Send one sanitized WebSocket close event.

    Args:
        send: The routed WebSocket send callable.
        code: A validated WebSocket close code.
        reason: A stable machine-readable reason.

    Returns:
        None.
    """
    await send({"type": "websocket.close", "code": code, "reason": reason})


def extract_websocket_handshake(
    connection: "ASGIConnection[Any, Any, Any, Any]", *, config: WebSocketSecurityConfig, uses_cookie_credentials: bool
) -> WebSocketHandshake:
    """Extract and validate one WebSocket handshake without verifying credentials.

    The caller derives ``uses_cookie_credentials`` from the existing common
    credential-slot extraction. Reusable header and cookie credentials remain
    owned by those common parsers; this function only applies WebSocket Origin
    and URL constraints.

    Args:
        connection: The incoming Litestar WebSocket connection.
        config: Validated WebSocket security configuration.
        uses_cookie_credentials: Whether a common credential slot found a
            cookie- or session-backed credential.

    Returns:
        A redacted description of the presented WebSocket transports.

    Raises:
        WebSocketException: If Origin policy fails or a reusable URL credential
            is presented.
    """
    headers = connection.scope["headers"]
    query_string = connection.scope["query_string"]
    origin_values: list[bytes] = []
    uses_authorization_header = False
    for name, value in headers:
        normalized_name = name.lower()
        if normalized_name == b"origin":
            origin_values.append(value)
        elif normalized_name == b"authorization":
            uses_authorization_header = True
    origin = _validated_request_origin(tuple(origin_values), config=config, required=uses_cookie_credentials)
    ticket = _extract_ticket(query_string, config=config)
    return WebSocketHandshake(
        origin=origin,
        uses_cookie_credentials=uses_cookie_credentials,
        uses_authorization_header=uses_authorization_header,
        ticket=ticket,
    )


def _canonical_origin(value: str, *, configuration: bool, invalid_close_code: int = _DEFAULT_UNAUTHORIZED_CLOSE) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeError, ValueError):
        return _invalid_origin(configuration=configuration, close_code=invalid_close_code)
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
        return _invalid_origin(configuration=configuration, close_code=invalid_close_code)
    hostname = _canonical_hostname(parsed.hostname)
    if hostname is None:
        return _invalid_origin(configuration=configuration, close_code=invalid_close_code)
    serialized_host = f"[{hostname}]" if ":" in hostname else hostname
    serialized_port = "" if port is None or port == _HTTP_DEFAULT_PORTS[parsed.scheme] else f":{port}"
    canonical = f"{parsed.scheme}://{serialized_host}{serialized_port}"
    if canonical != value:
        return _invalid_origin(configuration=configuration, close_code=invalid_close_code)
    return canonical


def _validated_request_origin(
    values: tuple[bytes, ...], *, config: WebSocketSecurityConfig, required: bool
) -> str | None:
    if not values:
        if required:
            _transport_error(config.close_codes.unauthorized, "WebSocket Origin is required")
        return None
    if len(values) != 1:
        _transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    try:
        value = values[0].decode("ascii")
    except (AttributeError, UnicodeDecodeError):
        _transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    origin = _canonical_origin(value, configuration=False, invalid_close_code=config.close_codes.unauthorized)
    if origin not in config.allowed_origins:
        _transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    return origin


def _extract_ticket(query_string: bytes, *, config: WebSocketSecurityConfig) -> str | None:
    if not query_string:
        return None
    try:
        encoded = query_string.decode("ascii")
        parameters = parse_qsl(encoded, keep_blank_values=True, encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        _transport_error(config.close_codes.unauthenticated, "WebSocket query credentials are invalid")
    if not _valid_percent_encoding(encoded):
        _transport_error(config.close_codes.unauthenticated, "WebSocket query credentials are invalid")
    tickets: list[str] = []
    for name, value in parameters:
        if name.casefold() in _RESERVED_QUERY_PARAMETERS:
            _transport_error(config.close_codes.unauthenticated, "Reusable URL credentials are forbidden")
        if name == config.ticket_query_parameter:
            tickets.append(value)
    if len(tickets) > 1 or (tickets and not tickets[0]):
        _transport_error(config.close_codes.unauthenticated, "WebSocket ticket is invalid")
    return tickets[0] if tickets else None


def _valid_percent_encoding(value: str) -> bool:
    index = 0
    while (index := value.find("%", index)) >= 0:
        if index + 2 >= len(value) or value[index + 1] not in hexdigits or value[index + 2] not in hexdigits:
            return False
        index += 3
    return True


def _canonical_hostname(value: str) -> str | None:
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


def _duration(value: object, name: str) -> timedelta:
    if not isinstance(value, timedelta) or value.__class__ is not timedelta:
        _configuration_error(f"WebSocket {name} must be positive")
    duration = value
    if duration <= timedelta(0):
        _configuration_error(f"WebSocket {name} must be positive")
    return duration


def _normalize_allowed_origins(value: object) -> frozenset[str]:
    if isinstance(value, str):
        _configuration_error("WebSocket allowed origins must be a collection")
    try:
        origins = tuple(cast("Iterable[object]", value))
    except TypeError:
        _configuration_error("WebSocket allowed origins must be a collection")
    if any(origin.__class__ is not str for origin in origins):
        _configuration_error("WebSocket allowed origins must contain text")
    canonical = tuple(_canonical_origin(cast("str", origin), configuration=True) for origin in origins)
    if len(canonical) != len(set(canonical)):
        _configuration_error("WebSocket allowed origins contain a duplicate")
    return frozenset(canonical)


def _validate_ticket_settings(config: WebSocketSecurityConfig) -> None:
    maximum_ticket_ttl = _duration(config.maximum_ticket_ttl, "maximum ticket TTL")
    if maximum_ticket_ttl > _MAXIMUM_TICKET_TTL:
        _configuration_error("WebSocket maximum ticket TTL cannot exceed two minutes")
    ticket_ttl = _duration(config.ticket_ttl, "ticket TTL")
    if ticket_ttl > maximum_ticket_ttl:
        _configuration_error("WebSocket ticket TTL cannot exceed its configured maximum")

    query_name_value = cast("object", config.ticket_query_parameter)
    if not isinstance(query_name_value, str) or query_name_value.__class__ is not str:
        _configuration_error("WebSocket ticket query parameter must be text")
    query_name = query_name_value
    if (
        not query_name
        or query_name != query_name.strip()
        or not query_name.isascii()
        or any(character in query_name for character in "&#=;")
    ):
        _configuration_error("WebSocket ticket query parameter must be a non-empty safe name")
    if query_name.casefold() in _RESERVED_QUERY_PARAMETERS:
        _configuration_error("WebSocket ticket query parameter uses a reserved credential name")


def _validate_refresh_settings(config: WebSocketSecurityConfig) -> None:
    if config.refresh_interval is not None:
        _duration(config.refresh_interval, "refresh interval")
        if config.snapshot_refresher is None:
            _configuration_error("WebSocket refresh interval requires a snapshot refresher")


def _validate_close_codes(value: object) -> None:
    if not isinstance(value, WebSocketCloseCodes) or value.__class__ is not WebSocketCloseCodes:
        _configuration_error("WebSocket close codes must use WebSocketCloseCodes")
    codes = value
    values = (codes.unauthenticated, codes.unauthorized, codes.verification_unavailable)
    if (
        any(code.__class__ is not int for code in values)
        or not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.unauthenticated <= _PRIVATE_CLOSE_CODE_MAXIMUM
        or not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.unauthorized <= _PRIVATE_CLOSE_CODE_MAXIMUM
        or (
            codes.verification_unavailable != _DEFAULT_UNAVAILABLE_CLOSE
            and not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.verification_unavailable <= _PRIVATE_CLOSE_CODE_MAXIMUM
        )
        or len(set(values)) != len(values)
        or codes.unauthenticated == _DEFAULT_UNAUTHORIZED_CLOSE
        or codes.unauthorized == _DEFAULT_UNAUTHENTICATED_CLOSE
        or codes.verification_unavailable in {_DEFAULT_UNAUTHENTICATED_CLOSE, _DEFAULT_UNAUTHORIZED_CLOSE}
    ):
        _configuration_error("WebSocket close code assignments are invalid")


def _invalid_origin(*, configuration: bool, close_code: int) -> NoReturn:
    if configuration:
        _configuration_error("WebSocket allowed origins must be canonical HTTP(S) origins")
    raise WebSocketException(code=close_code, detail="WebSocket Origin is not trusted")


def _configuration_error(detail: str) -> NoReturn:
    raise ImproperlyConfiguredException(detail=detail)


def _transport_error(code: int, detail: str) -> NoReturn:
    raise WebSocketException(code=code, detail=detail)
