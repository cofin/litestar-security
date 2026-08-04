"""Transport policy an application declares for its WebSocket routes."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from anyio import sleep

from litestar_security.websocket._bindings import AuthorizationSnapshotRefresher, WebSocketRevocationSource
from litestar_security.websocket._connect_tokens import MAXIMUM_CONNECT_TOKEN_TTL, WebSocketConnectTokenStore
from litestar_security.websocket._internal import (
    DEFAULT_UNAUTHENTICATED_CLOSE,
    DEFAULT_UNAUTHORIZED_CLOSE,
    DEFAULT_UNAVAILABLE_CLOSE,
    RESERVED_QUERY_PARAMETERS,
    configuration_error,
    duration,
    normalize_allowed_origins,
)

__all__ = ("WebSocketCloseCodes", "WebSocketSecurityConfig")

_PRIVATE_CLOSE_CODE_MINIMUM = 4000
_PRIVATE_CLOSE_CODE_MAXIMUM = 4999


@dataclass(frozen=True, slots=True)
class WebSocketCloseCodes:
    """Map stable security outcomes to WebSocket close codes."""

    unauthenticated: int = DEFAULT_UNAUTHENTICATED_CLOSE
    unauthorized: int = DEFAULT_UNAUTHORIZED_CLOSE
    verification_unavailable: int = DEFAULT_UNAVAILABLE_CLOSE


@dataclass(frozen=True, slots=True)
class WebSocketSecurityConfig:
    """Configure WebSocket transport validation and optional lifetime hooks."""

    allowed_origins: frozenset[str] = frozenset()
    connect_token_store: "WebSocketConnectTokenStore | None" = field(default=None, repr=False)
    connect_token_ttl: timedelta = timedelta(seconds=30)
    maximum_connect_token_ttl: timedelta = MAXIMUM_CONNECT_TOKEN_TTL
    connect_token_query_parameter: str = "connect_token"  # noqa: S105 - a query parameter name, not a secret
    current_security_epoch: "Callable[[str], Awaitable[int | None]] | None" = field(
        default=None, repr=False, compare=False
    )
    refresh_interval: timedelta | None = None
    snapshot_refresher: "AuthorizationSnapshotRefresher[Any] | None" = field(default=None, repr=False)
    revocation_source: "WebSocketRevocationSource | None" = field(default=None, repr=False)
    close_codes: WebSocketCloseCodes = WebSocketCloseCodes()
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc), repr=False, compare=False)
    sleeper: Callable[[float], Awaitable[None]] = field(default=sleep, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate and freeze security-sensitive transport settings."""
        object.__setattr__(self, "allowed_origins", normalize_allowed_origins(self.allowed_origins))
        _validate_connect_token_settings(self)
        _validate_refresh_settings(self)
        _validate_close_codes(self.close_codes)
        if not callable(self.clock) or not callable(self.sleeper):
            configuration_error("WebSocket clock and sleeper must be callable")


def _validate_connect_token_settings(config: WebSocketSecurityConfig) -> None:
    connect_token_store = cast("object | None", config.connect_token_store)
    if connect_token_store is not None and not isinstance(connect_token_store, WebSocketConnectTokenStore):
        configuration_error("WebSocket connect token store must implement atomic create and consume")
    if config.current_security_epoch is not None and not callable(config.current_security_epoch):
        configuration_error("WebSocket current security epoch must be an async callback")
    maximum_connect_token_ttl = duration(config.maximum_connect_token_ttl, "maximum connect token TTL")
    if maximum_connect_token_ttl > MAXIMUM_CONNECT_TOKEN_TTL:
        configuration_error("WebSocket maximum connect token TTL cannot exceed two minutes")
    connect_token_ttl = duration(config.connect_token_ttl, "connect token TTL")
    if connect_token_ttl > maximum_connect_token_ttl:
        configuration_error("WebSocket connect token TTL cannot exceed its configured maximum")

    query_name_value = cast("object", config.connect_token_query_parameter)
    if not isinstance(query_name_value, str) or query_name_value.__class__ is not str:
        configuration_error("WebSocket connect token query parameter must be text")
    query_name = query_name_value
    if (
        not query_name
        or query_name != query_name.strip()
        or not query_name.isascii()
        or any(character in query_name for character in "&#=;")
    ):
        configuration_error("WebSocket connect token query parameter must be a non-empty safe name")
    if query_name.casefold() in RESERVED_QUERY_PARAMETERS:
        configuration_error("WebSocket connect token query parameter uses a reserved credential name")


def _validate_refresh_settings(config: WebSocketSecurityConfig) -> None:
    refresher = cast("object | None", config.snapshot_refresher)
    revocation_source = cast("object | None", config.revocation_source)
    if refresher is not None and not isinstance(refresher, AuthorizationSnapshotRefresher):
        configuration_error("WebSocket snapshot refresher must define refresh")
    if revocation_source is not None and not isinstance(revocation_source, WebSocketRevocationSource):
        configuration_error("WebSocket revocation source must define wait")
    if config.refresh_interval is not None:
        duration(config.refresh_interval, "refresh interval")
        if refresher is None:
            configuration_error("WebSocket refresh interval requires a snapshot refresher")


def _validate_close_codes(value: object) -> None:
    if not isinstance(value, WebSocketCloseCodes) or value.__class__ is not WebSocketCloseCodes:
        configuration_error("WebSocket close codes must use WebSocketCloseCodes")
    codes = value
    values = (codes.unauthenticated, codes.unauthorized, codes.verification_unavailable)
    if (
        any(code.__class__ is not int for code in values)
        or not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.unauthenticated <= _PRIVATE_CLOSE_CODE_MAXIMUM
        or not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.unauthorized <= _PRIVATE_CLOSE_CODE_MAXIMUM
        or (
            codes.verification_unavailable != DEFAULT_UNAVAILABLE_CLOSE
            and not _PRIVATE_CLOSE_CODE_MINIMUM <= codes.verification_unavailable <= _PRIVATE_CLOSE_CODE_MAXIMUM
        )
        or len(set(values)) != len(values)
        or codes.unauthenticated == DEFAULT_UNAUTHORIZED_CLOSE
        or codes.unauthorized == DEFAULT_UNAUTHENTICATED_CLOSE
        or codes.verification_unavailable in {DEFAULT_UNAUTHENTICATED_CLOSE, DEFAULT_UNAUTHORIZED_CLOSE}
    ):
        configuration_error("WebSocket close code assignments are invalid")
