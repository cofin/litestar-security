"""Unit tests for WebSocket handshake transport policy."""

from collections.abc import Iterator
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import anyio
import pytest
from litestar.exceptions import ImproperlyConfiguredException, WebSocketException

from litestar_security.context import CredentialRestrictions, NullSessionHandle, Principal, SecurityContext
from litestar_security.websocket import (
    InMemoryWebSocketTicketStore,
    IssuedWebSocketTicket,
    WebSocketCloseCodes,
    WebSocketHandshake,
    WebSocketSecurityConfig,
    WebSocketTicketService,
    extract_websocket_handshake,
)

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
        ({"ticket_ttl": 30}, "ticket TTL"),
        ({"ticket_ttl": timedelta(0)}, "ticket TTL"),
        ({"ticket_ttl": timedelta(minutes=3)}, "ticket TTL"),
        ({"maximum_ticket_ttl": timedelta(0)}, "maximum ticket TTL"),
        ({"maximum_ticket_ttl": timedelta(minutes=2, microseconds=1)}, "maximum ticket TTL"),
        ({"ticket_query_parameter": ""}, "query parameter"),
        ({"ticket_query_parameter": object()}, "query parameter"),
        ({"ticket_query_parameter": " token "}, "query parameter"),
        ({"ticket_query_parameter": "access_token"}, "reserved"),
        ({"ticket_query_parameter": "ToKeN"}, "reserved"),
        ({"refresh_interval": timedelta(0)}, "refresh interval"),
        ({"refresh_interval": timedelta(seconds=1)}, "snapshot refresher"),
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
    refresher = object()

    config = WebSocketSecurityConfig(refresh_interval=timedelta(seconds=1), snapshot_refresher=refresher)

    assert config.snapshot_refresher is refresher


def test_websocket_configuration_values_are_frozen_and_slotted() -> None:
    config = WebSocketSecurityConfig()
    handshake = WebSocketHandshake(
        origin=None, uses_cookie_credentials=False, uses_authorization_header=False, ticket=None
    )

    with pytest.raises(FrozenInstanceError):
        config.ticket_query_parameter = "other"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        handshake.origin = "https://trusted.example"  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        handshake.extra = True  # type: ignore[attr-defined]


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
        ticket=None,
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


def test_ticket_is_the_only_credential_like_query_value_and_is_redacted() -> None:
    sensitive_value = "one-time-ticket-secret"
    handshake = extract_websocket_handshake(
        _connection(query_string=f"filter=active&ticket={sensitive_value}".encode()),
        config=WebSocketSecurityConfig(),
        uses_cookie_credentials=False,
    )

    assert handshake.ticket == sensitive_value
    assert sensitive_value not in repr(handshake)


@pytest.mark.parametrize(
    "query_string", [b"ticket=first&ticket=second", b"ticket=", b"ticket=%FF", b"ticket=%ZZ", b"%74oken=secret"]
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
            super().__init__(headers=self.header_values, query_string=b"ticket=secret")
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

    assert handshake.ticket == "secret"
    assert scope.reads == {"headers": 1, "query_string": 1}
    assert scope.header_values.iterations == 1


def test_close_codes_can_be_customized_without_swapping_meanings() -> None:
    codes = WebSocketCloseCodes(unauthenticated=4501, unauthorized=4503, verification_unavailable=1013)

    assert replace(WebSocketSecurityConfig(), close_codes=codes).close_codes is codes


@pytest.mark.anyio
async def test_websocket_ticket_is_digest_only_one_time_and_exactly_bound() -> None:
    store = InMemoryWebSocketTicketStore()
    service = WebSocketTicketService(
        store=store,
        ttl=timedelta(seconds=30),
        clock=lambda: _NOW,
        entropy=lambda length: b"i" * length if length == 16 else b"s" * length,
    )
    restrictions = CredentialRestrictions(scopes=frozenset({"reports:read"}))

    issued = await service.issue(
        principal=Principal(id="subject-1"),
        context=SecurityContext(session=NullSessionHandle()),
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
        restrictions=restrictions,
    )

    assert isinstance(issued, IssuedWebSocketTicket)
    assert issued.value not in repr(issued)
    assert all(issued.value.encode() not in repr(record).encode() for record in store.records)
    consumed = await service.consume(
        issued.value, route_name="reports.socket", origin="https://trusted.example", policy_fingerprint="f" * 64
    )
    replay = await service.consume(
        issued.value, route_name="reports.socket", origin="https://trusted.example", policy_fingerprint="f" * 64
    )

    assert consumed is not None
    assert consumed.subject_id == "subject-1"
    assert consumed.restrictions == restrictions
    assert replay is None


@pytest.mark.anyio
async def test_websocket_ticket_is_consumed_before_later_binding_failure() -> None:
    service = WebSocketTicketService(
        store=InMemoryWebSocketTicketStore(),
        clock=lambda: _NOW,
        entropy=lambda length: b"i" * length if length == 16 else b"s" * length,
    )
    issued = await service.issue(
        principal=Principal(id="subject-1"),
        context=SecurityContext(session=NullSessionHandle()),
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
    )

    mismatch = await service.consume(
        issued.value, route_name="other.socket", origin="https://trusted.example", policy_fingerprint="f" * 64
    )
    retry = await service.consume(
        issued.value, route_name="reports.socket", origin="https://trusted.example", policy_fingerprint="f" * 64
    )

    assert mismatch is None
    assert retry is None


@pytest.mark.anyio
async def test_websocket_ticket_atomic_double_consume_has_one_winner() -> None:
    async def consume(service: WebSocketTicketService, value: str, results: list[object]) -> None:
        results.append(
            await service.consume(
                value, route_name="reports.socket", origin="https://trusted.example", policy_fingerprint="f" * 64
            )
        )

    for _ in range(100):
        service = WebSocketTicketService(
            store=InMemoryWebSocketTicketStore(),
            clock=lambda: _NOW,
            entropy=lambda length: b"i" * length if length == 16 else b"s" * length,
        )
        issued = await service.issue(
            principal=Principal(id="subject-1"),
            context=SecurityContext(session=NullSessionHandle()),
            route_name="reports.socket",
            origin="https://trusted.example",
            policy_fingerprint="f" * 64,
        )
        results: list[object] = []

        async with anyio.create_task_group() as task_group:
            task_group.start_soon(consume, service, issued.value, results)
            task_group.start_soon(consume, service, issued.value, results)

        assert sum(result is not None for result in results) == 1


@pytest.mark.anyio
async def test_websocket_ticket_expiry_boundary_is_exclusive_and_deletes_record() -> None:
    current = [_NOW]
    store = InMemoryWebSocketTicketStore()
    service = WebSocketTicketService(
        store=store,
        ttl=timedelta(seconds=30),
        clock=lambda: current[0],
        entropy=lambda length: b"i" * length if length == 16 else b"s" * length,
    )
    issued = await service.issue(
        principal=Principal(id="subject-1"),
        context=SecurityContext(session=NullSessionHandle()),
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
    )
    current[0] = issued.expires_at

    consumed = await service.consume(
        issued.value, route_name="reports.socket", origin="https://trusted.example", policy_fingerprint="f" * 64
    )

    assert consumed is None
    assert store.records == ()
