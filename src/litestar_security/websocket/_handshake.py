"""Read the credential transports one WebSocket handshake presents."""

from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection

from litestar_security.websocket._bindings import WebSocketHandshake
from litestar_security.websocket._config import WebSocketSecurityConfig
from litestar_security.websocket._internal import (
    RESERVED_QUERY_PARAMETERS,
    canonical_origin,
    transport_error,
    valid_percent_encoding,
)

__all__ = ("extract_websocket_handshake",)


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
    connect_token = _extract_connect_token(query_string, config=config)
    return WebSocketHandshake(
        origin=origin,
        uses_cookie_credentials=uses_cookie_credentials,
        uses_authorization_header=uses_authorization_header,
        connect_token=connect_token,
    )


def _validated_request_origin(
    values: tuple[bytes, ...], *, config: WebSocketSecurityConfig, required: bool
) -> str | None:
    if not values:
        if required:
            transport_error(config.close_codes.unauthorized, "WebSocket Origin is required")
        return None
    if len(values) != 1:
        transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    try:
        value = values[0].decode("ascii")
    except (AttributeError, UnicodeDecodeError):
        transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    origin = canonical_origin(value, configuration=False, invalid_close_code=config.close_codes.unauthorized)
    if origin not in config.allowed_origins:
        transport_error(config.close_codes.unauthorized, "WebSocket Origin is not trusted")
    return origin


def _extract_connect_token(query_string: bytes, *, config: WebSocketSecurityConfig) -> str | None:
    if not query_string:
        return None
    try:
        encoded = query_string.decode("ascii")
        parameters = parse_qsl(encoded, keep_blank_values=True, encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        transport_error(config.close_codes.unauthenticated, "WebSocket query credentials are invalid")
    if not valid_percent_encoding(encoded):
        transport_error(config.close_codes.unauthenticated, "WebSocket query credentials are invalid")
    connect_tokens: list[str] = []
    for name, value in parameters:
        if name.casefold() in RESERVED_QUERY_PARAMETERS:
            transport_error(config.close_codes.unauthenticated, "Reusable URL credentials are forbidden")
        if name == config.connect_token_query_parameter:
            connect_tokens.append(value)
    if len(connect_tokens) > 1 or (connect_tokens and not connect_tokens[0]):
        transport_error(config.close_codes.unauthenticated, "WebSocket connect token is invalid")
    return connect_tokens[0] if connect_tokens else None
