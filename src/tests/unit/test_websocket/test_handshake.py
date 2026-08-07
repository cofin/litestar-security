"""Unit tests for WebSocket handshake transport policy."""

from collections.abc import Iterator
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from litestar.exceptions import WebSocketException

from litestar_security.websocket import (
    WebSocketCloseCodes,
    WebSocketHandshake,
    WebSocketSecurityConfig,
    extract_websocket_handshake,
)

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


def _connection(*, headers: tuple[tuple[bytes, bytes], ...] = (), query_string: bytes = b"") -> SimpleNamespace:
    return SimpleNamespace(scope={"headers": list(headers), "query_string": query_string})


@pytest.mark.parametrize("uses_cookie_credentials", [True, False])
def test_exact_allowed_origin_is_preserved_for_cookie_and_header_transports(
    uses_cookie_credentials: bool,  # noqa: FBT001 - parametrized transport-state matrix
) -> None:
    config = WebSocketSecurityConfig(allowed_origins=frozenset({"https://trusted.example"}))
    headers = [(b"origin", b"https://trusted.example")]
    if not uses_cookie_credentials:
        headers.append((b"authorization", b"Bearer secret"))

    handshake = extract_websocket_handshake(
        _connection(headers=tuple(headers)), config=config, uses_cookie_credentials=uses_cookie_credentials
    )

    assert handshake == WebSocketHandshake(
        origin="https://trusted.example",
        uses_cookie_credentials=uses_cookie_credentials,
        uses_authorization_header=not uses_cookie_credentials,
        connect_token=None,
    )


@pytest.mark.parametrize(
    "headers",
    [
        (),
        ((b"origin", b"https://wrong.example"),),
        ((b"origin", b"https://trusted.example.attacker.test"),),
        ((b"origin", b"null"),),
        ((b"origin", b"https://trusted.example"), (b"Origin", b"https://trusted.example")),
        ((b"origin", b"HTTPS://trusted.example"),),
        ((b"origin", b"https://trusted.example:443"),),
        ((b"origin", b"\xff"),),
    ],
)
def test_cookie_credentials_require_one_exact_trusted_origin(headers: tuple[tuple[bytes, bytes], ...]) -> None:
    config = WebSocketSecurityConfig(allowed_origins=frozenset({"https://trusted.example"}))

    with pytest.raises(WebSocketException) as captured:
        extract_websocket_handshake(_connection(headers=headers), config=config, uses_cookie_credentials=True)

    assert captured.value.code == 4403


def test_non_browser_authorization_header_does_not_require_origin() -> None:
    handshake = extract_websocket_handshake(
        _connection(headers=((b"authorization", b"Bearer secret"), (b"x-request-id", b"request-1"))),
        config=WebSocketSecurityConfig(),
        uses_cookie_credentials=False,
    )

    assert handshake.uses_authorization_header is True
    assert handshake.origin is None


@pytest.mark.parametrize(
    "origin", ["https://wrong.example", "https://trusted.example.attacker.test", "null", "HTTPS://trusted.example"]
)
def test_present_origin_is_validated_for_header_authenticated_clients(origin: str) -> None:
    config = WebSocketSecurityConfig(allowed_origins=frozenset({"https://trusted.example"}))

    with pytest.raises(WebSocketException) as captured:
        extract_websocket_handshake(
            _connection(headers=((b"authorization", b"Bearer secret"), (b"origin", origin.encode("ascii")))),
            config=config,
            uses_cookie_credentials=False,
        )

    assert captured.value.code == 4403


def test_origin_denial_uses_the_configured_authorization_close_code() -> None:
    config = WebSocketSecurityConfig(
        allowed_origins=frozenset({"https://trusted.example"}),
        close_codes=WebSocketCloseCodes(unauthenticated=4501, unauthorized=4503),
    )

    with pytest.raises(WebSocketException) as captured:
        extract_websocket_handshake(
            _connection(headers=((b"origin", b"https://malformed..example"),)),
            config=config,
            uses_cookie_credentials=True,
        )

    assert captured.value.code == 4503


@pytest.mark.parametrize("parameter", ["access_token", "token", "bearer", "authorization", "jwt", "ToKeN"])
def test_reusable_bearer_query_parameters_are_rejected_without_exposing_values(parameter: str) -> None:
    sensitive_value = "do-not-log-or-repr"

    with pytest.raises(WebSocketException) as captured:
        extract_websocket_handshake(
            _connection(query_string=f"{parameter}={sensitive_value}".encode()),
            config=WebSocketSecurityConfig(),
            uses_cookie_credentials=False,
        )

    assert captured.value.code == 4401
    assert sensitive_value not in repr(captured.value)


def test_connect_token_is_the_only_credential_like_query_value_and_is_redacted() -> None:
    sensitive_value = "one-time-connect token-secret"
    handshake = extract_websocket_handshake(
        _connection(query_string=f"filter=active&connect_token={sensitive_value}".encode()),
        config=WebSocketSecurityConfig(),
        uses_cookie_credentials=False,
    )

    assert handshake.connect_token == sensitive_value
    assert sensitive_value not in repr(handshake)


@pytest.mark.parametrize(
    "query_string",
    [
        b"connect_token=first&connect_token=second",
        b"connect_token=",
        b"connect_token=%FF",
        b"connect_token=%ZZ",
        b"%74oken=secret",
    ],
)
def test_malformed_duplicate_or_encoded_bearer_query_values_are_rejected(query_string: bytes) -> None:
    with pytest.raises(WebSocketException) as captured:
        extract_websocket_handshake(
            _connection(query_string=query_string), config=WebSocketSecurityConfig(), uses_cookie_credentials=False
        )

    assert captured.value.code == 4401


def test_handshake_parses_raw_headers_and_query_once() -> None:
    class OneIterationHeaders:
        iterations = 0

        def __iter__(self) -> Iterator[tuple[bytes, bytes]]:
            self.iterations += 1
            if self.iterations > 1:
                message = "headers were parsed more than once"
                raise AssertionError(message)
            return iter([(b"origin", b"https://trusted.example")])

    class OneReadScope(dict[str, object]):
        reads: dict[str, int]
        header_values: OneIterationHeaders

        def __init__(self) -> None:
            self.header_values = OneIterationHeaders()
            super().__init__(headers=self.header_values, query_string=b"connect_token=secret")
            self.reads = {"headers": 0, "query_string": 0}

        def __getitem__(self, key: str) -> object:
            self.reads[key] += 1
            return super().__getitem__(key)

    scope = OneReadScope()
    connection = SimpleNamespace(scope=scope)

    handshake = extract_websocket_handshake(
        connection,
        config=WebSocketSecurityConfig(allowed_origins=frozenset({"https://trusted.example"})),
        uses_cookie_credentials=True,
    )

    assert handshake.connect_token == "secret"  # noqa: S105 - the fixture value under assertion
    assert scope.reads == {"headers": 1, "query_string": 1}
    assert scope.header_values.iterations == 1


def test_close_codes_can_be_customized_without_swapping_meanings() -> None:
    codes = WebSocketCloseCodes(unauthenticated=4501, unauthorized=4503, verification_unavailable=1013)

    assert replace(WebSocketSecurityConfig(), close_codes=codes).close_codes is codes
