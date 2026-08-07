"""Unit tests for WebSocket handshake transport policy."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.websocket import WebSocketCloseCodes, WebSocketSecurityConfig

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


def _connection(*, headers: tuple[tuple[bytes, bytes], ...] = (), query_string: bytes = b"") -> SimpleNamespace:
    return SimpleNamespace(scope={"headers": list(headers), "query_string": query_string})


@pytest.mark.parametrize(
    "origin",
    ["https://trusted.example", "http://trusted.example:8080", "https://127.0.0.1:8443", "https://[2001:db8::1]:8443"],
)
def test_websocket_config_accepts_only_canonical_serialized_origins(origin: str) -> None:
    config = WebSocketSecurityConfig(allowed_origins=frozenset({origin}))

    assert config.allowed_origins == frozenset({origin})


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "https://*.trusted.example",
        "https://user@trusted.example",
        "https://trusted.example/path",
        "https://trusted.example?query=value",
        "https://trusted.example#fragment",
        "null",
        "ftp://trusted.example",
        "HTTPS://trusted.example",
        "https://TRUSTED.example",
        "https://trusted.example:443",
        "http://trusted.example:80",
        "https://trusted.example/",
        "https://trusted.example.",
        "https://trusted..example",
        "https://-trusted.example",
        "https://trusted_.example",
        "https://not an origin",
        "https://trusted.example:invalid",
        "not an origin",
    ],
)
def test_websocket_config_rejects_noncanonical_or_unsafe_origins(origin: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="canonical HTTP"):
        WebSocketSecurityConfig(allowed_origins=frozenset({origin}))


def test_websocket_config_rejects_duplicate_canonical_origins() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="duplicate"):
        WebSocketSecurityConfig(allowed_origins=["https://trusted.example", "https://trusted.example"])


@pytest.mark.parametrize("allowed_origins", ["https://trusted.example", 1, [object()]])
def test_websocket_config_rejects_malformed_origin_collections(allowed_origins: object) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="allowed origins"):
        WebSocketSecurityConfig(allowed_origins=allowed_origins)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"connect_token_ttl": 30}, "connect token TTL"),
        ({"connect_token_ttl": timedelta(0)}, "connect token TTL"),
        ({"connect_token_ttl": timedelta(minutes=3)}, "connect token TTL"),
        ({"maximum_connect_token_ttl": timedelta(0)}, "maximum connect token TTL"),
        ({"maximum_connect_token_ttl": timedelta(minutes=2, microseconds=1)}, "maximum connect token TTL"),
        ({"connect_token_query_parameter": ""}, "query parameter"),
        ({"connect_token_query_parameter": object()}, "query parameter"),
        ({"connect_token_query_parameter": " token "}, "query parameter"),
        ({"connect_token_query_parameter": "tick&et"}, "query parameter"),
        ({"connect_token_query_parameter": "access_token"}, "reserved"),
        ({"connect_token_query_parameter": "ToKeN"}, "reserved"),
        ({"refresh_interval": timedelta(0)}, "refresh interval"),
        ({"refresh_interval": timedelta(seconds=1)}, "snapshot refresher"),
        ({"connect_token_store": object()}, "connect token store"),
        ({"snapshot_refresher": object()}, "snapshot refresher"),
        ({"revocation_source": object()}, "revocation source"),
        ({"current_security_epoch": object()}, "current security epoch"),
    ],
)
def test_websocket_config_rejects_invalid_lifetime_and_query_settings(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        WebSocketSecurityConfig(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "close_codes",
    [
        WebSocketCloseCodes(unauthenticated=1008),
        WebSocketCloseCodes(unauthenticated=1013),
        WebSocketCloseCodes(unauthorized=5000),
        WebSocketCloseCodes(unauthorized=1013),
        WebSocketCloseCodes(verification_unavailable=1001),
        WebSocketCloseCodes(unauthenticated=4501, verification_unavailable=4401),
        WebSocketCloseCodes(unauthorized=4503, verification_unavailable=4403),
        WebSocketCloseCodes(unauthenticated=4403),
        WebSocketCloseCodes(unauthorized=4401),
        WebSocketCloseCodes(unauthenticated=4500, unauthorized=4500),
    ],
)
def test_websocket_config_rejects_invalid_or_swapped_close_codes(close_codes: WebSocketCloseCodes) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="close code"):
        WebSocketSecurityConfig(close_codes=close_codes)


def test_websocket_config_rejects_wrong_close_code_object() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="close codes"):
        WebSocketSecurityConfig(close_codes=object())  # type: ignore[arg-type]


def test_websocket_refresh_interval_accepts_an_explicit_refresher() -> None:
    class Refresher:
        async def refresh(self, **_kwargs: object) -> object:
            return object()

    refresher = Refresher()

    config = WebSocketSecurityConfig(refresh_interval=timedelta(seconds=1), snapshot_refresher=refresher)

    assert config.snapshot_refresher is refresher
