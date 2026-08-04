"""Unit tests for WebSocket handshake transport policy."""

from collections.abc import Awaitable, Callable, Iterator
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import anyio
import anyio.lowlevel
import pytest
from litestar.enums import HttpMethod
from litestar.exceptions import (
    ImproperlyConfiguredException,
    PermissionDeniedException,
    ServiceUnavailableException,
    WebSocketException,
)
from litestar.handlers import WebsocketRouteHandler
from litestar.handlers.http_handlers import HTTPRouteHandler

import litestar_security.websocket as websocket_module
import litestar_security.websocket._connect_tokens as connect_tokens_module
from litestar_security._internal import RUNTIME_PLAN_OPT_KEY
from litestar_security.authentication import SecurityRuntimePlan
from litestar_security.context import CredentialRestrictions, NullSessionHandle, Principal, SecurityContext
from litestar_security.testing import InMemoryWebSocketRevocationSource
from litestar_security.websocket import (
    InMemoryWebSocketConnectTokenStore,
    IssuedWebSocketConnectToken,
    WebSocketBinding,
    WebSocketCloseCodes,
    WebSocketCloseCoordinator,
    WebSocketConnectTokenIssuer,
    WebSocketConnectTokenRecord,
    WebSocketConnectTokenService,
    WebSocketHandshake,
    WebSocketSecurityConfig,
    extract_websocket_handshake,
    issue_websocket_connect_token,
    supervise_websocket_lifetime,
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


def test_websocket_configuration_values_are_frozen_and_slotted() -> None:
    config = WebSocketSecurityConfig()
    handshake = WebSocketHandshake(
        origin=None, uses_cookie_credentials=False, uses_authorization_header=False, connect_token=None
    )

    with pytest.raises(FrozenInstanceError):
        config.connect_token_query_parameter = "other"  # type: ignore[misc]  # noqa: S105 - a parameter name
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


@pytest.mark.parametrize("field_name", ["clock", "sleeper"])
def test_websocket_config_rejects_non_callable_runtime_hooks(field_name: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="clock and sleeper"):
        WebSocketSecurityConfig(**{field_name: None})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"connection_id": ""}, "binding"),
        ({"subject_id": " subject"}, "binding"),
        ({"route_name": "\n"}, "binding"),
        ({"credential_ids": frozenset({""})}, "binding"),
        ({"session_id": ""}, "binding"),
    ],
)
def test_websocket_binding_validates_and_freezes_identifiers(kwargs: dict[str, object], match: str) -> None:
    values = {
        "connection_id": "connection-1",
        "subject_id": "subject-1",
        "credential_ids": {"bearer:authorization"},  # type: ignore[dict-item]
        "session_id": "session-1",
        "route_name": "reports.socket",
        **kwargs,
    }
    if kwargs:
        with pytest.raises(ValueError, match=match):
            WebSocketBinding(**values)  # type: ignore[arg-type]
    else:  # pragma: no cover - parametrization always supplies one invalid field
        assert WebSocketBinding(**values).credential_ids == frozenset({"bearer:authorization"})  # type: ignore[arg-type]

    binding = WebSocketBinding(
        connection_id="connection-1",
        subject_id="subject-1",
        credential_ids={"bearer:authorization"},  # type: ignore[arg-type]
        session_id=None,
        route_name="reports.socket",
    )
    assert binding.credential_ids == frozenset({"bearer:authorization"})


@pytest.mark.anyio
async def test_in_memory_websocket_revocation_source_releases_only_the_matching_binding() -> None:
    source = InMemoryWebSocketRevocationSource()
    first = WebSocketBinding(
        connection_id="connection-1",
        subject_id="subject-1",
        credential_ids=frozenset({"bearer:authorization"}),
        session_id="session-1",
        route_name="reports.socket",
    )
    second = replace(first, connection_id="connection-2")
    released: list[WebSocketBinding] = []

    async def wait_for_revocation(binding: WebSocketBinding) -> None:
        await source.wait(binding)
        released.append(binding)

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(wait_for_revocation, first)
        task_group.start_soon(wait_for_revocation, second)
        await anyio.lowlevel.checkpoint()
        assert released == []

        source.revoke(first)
        await anyio.lowlevel.checkpoint()

        assert released == [first]
        task_group.cancel_scope.cancel()


def _connect_token_record(**changes: object) -> WebSocketConnectTokenRecord:
    values = {
        "connect_token_id": "aWlpaWlpaWlpaWlpaWlpaQ",
        "digest": b"d" * 32,
        "subject_id": "subject-1",
        "security_epoch": 7,
        "route_name": "reports.socket",
        "origin": "https://trusted.example",
        "restrictions": CredentialRestrictions(),
        "policy_fingerprint": "f" * 64,
        "issued_at": _NOW,
        "expires_at": _NOW + timedelta(seconds=30),
        **changes,
    }
    return WebSocketConnectTokenRecord(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changes",
    [
        {"connect_token_id": "bad"},
        {"digest": bytearray(32)},
        {"digest": b"short"},
        {"subject_id": ""},
        {"security_epoch": -1},
        {"security_epoch": True},
        {"route_name": ""},
        {"restrictions": object()},
        {"policy_fingerprint": ""},
        {"expires_at": _NOW},
        {"expires_at": _NOW + timedelta(minutes=3)},
    ],
)
def test_websocket_connect_token_record_rejects_invalid_storage_values(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="record is invalid"):
        _connect_token_record(**changes)


def test_issued_websocket_connect_token_rejects_invalid_value_and_naive_expiry() -> None:
    with pytest.raises(ValueError, match="Issued WebSocket connect token"):
        IssuedWebSocketConnectToken(value="invalid", expires_at=_NOW)
    with pytest.raises(ValueError, match="timezone-aware"):
        _connect_token_record(issued_at=_NOW.replace(tzinfo=None))


@pytest.mark.anyio
async def test_websocket_connect_token_store_rejects_duplicate_and_digest_mismatch() -> None:
    store = InMemoryWebSocketConnectTokenStore()
    record = _connect_token_record()
    await store.create(record)
    with pytest.raises(ValueError, match="already exists"):
        await store.create(record)
    assert await store.consume(connect_token_id=record.connect_token_id, digest=b"x" * 32, now=_NOW) is None
    assert store.records == (record,)


@pytest.mark.parametrize(
    "kwargs", [{"store": object()}, {"ttl": 30}, {"ttl": timedelta(0)}, {"clock": None}, {"entropy": None}]
)
def test_websocket_connect_token_service_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    values = {"store": InMemoryWebSocketConnectTokenStore(), **kwargs}
    with pytest.raises(ImproperlyConfiguredException, match="service configuration"):
        WebSocketConnectTokenService(**values)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_websocket_connect_token_service_rejects_anonymous_invalid_and_unavailable_inputs() -> None:
    service = WebSocketConnectTokenService(store=InMemoryWebSocketConnectTokenStore(), clock=lambda: _NOW)
    issue_kwargs = {
        "route_name": "reports.socket",
        "origin": "https://trusted.example",
        "policy_fingerprint": "f" * 64,
        "security_epoch": 7,
    }
    with pytest.raises(ValueError, match="authenticated"):
        await service.issue(
            principal=Principal(id=None), context=SecurityContext(session=NullSessionHandle()), **issue_kwargs
        )
    with pytest.raises(ValueError, match="authenticated"):
        await service.issue(
            principal=Principal(id="subject-1"),
            context=object(),  # type: ignore[arg-type]
            **issue_kwargs,
        )
    assert (
        await service.consume(
            object(),
            route_name="reports.socket",
            origin="https://trusted.example",
            policy_fingerprint="f" * 64,
            current_security_epoch=_epoch(7),
        )
        is None
    )

    class BrokenStore:
        async def create(self, record: WebSocketConnectTokenRecord) -> None:
            del record

        async def consume(self, **kwargs: object) -> None:
            del kwargs
            raise RuntimeError

    broken = WebSocketConnectTokenService(store=BrokenStore(), clock=lambda: _NOW)
    with pytest.raises(websocket_module.WebSocketConnectTokenUnavailableError):
        await broken.consume(
            "wsct.aWlpaWlpaWlpaWlpaWlpaQ.c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M",
            route_name="reports.socket",
            origin="https://trusted.example",
            policy_fingerprint="f" * 64,
            current_security_epoch=_epoch(7),
        )


@pytest.mark.anyio
@pytest.mark.parametrize("entropy", [lambda _length: b"bad", lambda _length: object()])
async def test_websocket_connect_token_service_rejects_invalid_entropy(entropy: object) -> None:
    service = WebSocketConnectTokenService(
        store=InMemoryWebSocketConnectTokenStore(),
        clock=lambda: _NOW,
        entropy=entropy,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="entropy is unavailable"):
        await service.issue(
            principal=Principal(id="subject-1"),
            context=SecurityContext(session=NullSessionHandle()),
            route_name="reports.socket",
            origin="https://trusted.example",
            policy_fingerprint="f" * 64,
            security_epoch=7,
        )


@pytest.mark.anyio
async def test_websocket_connect_token_service_sanitizes_entropy_failure() -> None:
    def unavailable(_length: int) -> bytes:
        raise RuntimeError

    service = WebSocketConnectTokenService(
        store=InMemoryWebSocketConnectTokenStore(), clock=lambda: _NOW, entropy=unavailable
    )
    with pytest.raises(ValueError, match="entropy is unavailable"):
        await service.issue(
            principal=Principal(id="subject-1"),
            context=SecurityContext(session=NullSessionHandle()),
            route_name="reports.socket",
            origin="https://trusted.example",
            policy_fingerprint="f" * 64,
            security_epoch=7,
        )


@pytest.mark.anyio
async def test_issue_websocket_connect_token_helper_issues_bound_connect_token() -> None:
    issued = await issue_websocket_connect_token(
        principal=Principal(id="subject-1"),
        context=SecurityContext(session=NullSessionHandle()),
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
        security_epoch=7,
        restrictions=CredentialRestrictions(),
        store=InMemoryWebSocketConnectTokenStore(),
        clock=lambda: _NOW,
    )
    assert issued.expires_at == _NOW + timedelta(seconds=30)


@pytest.mark.parametrize("value", [b"bytes", "wrong.parts", "bad." + "a" * 22 + "." + "b" * 43])
def test_issued_connect_token_rejects_noncanonical_proofs(value: object) -> None:
    with pytest.raises(ValueError, match="Issued WebSocket connect token"):
        IssuedWebSocketConnectToken(value=value, expires_at=_NOW)  # type: ignore[arg-type]


def test_private_connect_token_encoding_defenses_reject_invalid_values() -> None:
    with pytest.raises(ValueError, match="entropy"):
        connect_tokens_module._encode_connect_token_segment(bytearray(16))  # type: ignore[attr-defined,arg-type]  # noqa: SLF001
    assert (
        connect_tokens_module._decode_connect_token_segment(  # type: ignore[attr-defined]  # noqa: SLF001
            "a" * 21, expected_bytes=16, expected_characters=22
        )
        is None
    )


def test_websocket_policy_fingerprint_is_stable_for_default_shape() -> None:
    plan = SimpleNamespace(
        authenticate=True,
        required=True,
        allow_anonymous=False,
        participant_names=frozenset({"bearer"}),
        alternatives=((SimpleNamespace(name="bearer", scopes=("reports:read",)),),),
    )
    assert websocket_module.websocket_policy_fingerprint(plan) == websocket_module.websocket_policy_fingerprint(plan)


def test_websocket_policy_fingerprint_uses_canonical_versioned_json_primitives() -> None:
    left = SimpleNamespace(
        authenticate=True,
        required=True,
        allow_anonymous=False,
        participant_names=frozenset({"cookie", "bearer"}),
        alternatives=((SimpleNamespace(name="bearer", scopes=("reports:read",)),),),
    )
    right = SimpleNamespace(
        authenticate=True,
        required=True,
        allow_anonymous=False,
        participant_names=frozenset({"bearer", "cookie"}),
        alternatives=((SimpleNamespace(name="bearer", scopes=("reports:read",)),),),
    )

    assert websocket_module.websocket_policy_fingerprint(left) == websocket_module.websocket_policy_fingerprint(right)
    with pytest.raises(ValueError, match="policy fingerprint"):
        websocket_module.websocket_policy_fingerprint(
            SimpleNamespace(
                authenticate=1,
                required=True,
                allow_anonymous=False,
                participant_names=frozenset({"bearer"}),
                alternatives=(),
            )
        )


@pytest.mark.parametrize(
    "plan",
    [
        SimpleNamespace(
            authenticate=True, required=True, allow_anonymous=False, participant_names=("bearer",), alternatives=()
        ),
        SimpleNamespace(
            authenticate=True, required=True, allow_anonymous=False, participant_names=frozenset({""}), alternatives=()
        ),
        SimpleNamespace(
            authenticate=True,
            required=True,
            allow_anonymous=False,
            participant_names=frozenset({"bearer"}),
            alternatives=[],
        ),
        SimpleNamespace(
            authenticate=True,
            required=True,
            allow_anonymous=False,
            participant_names=frozenset({"bearer"}),
            alternatives=([],),
        ),
        SimpleNamespace(
            authenticate=True,
            required=True,
            allow_anonymous=False,
            participant_names=frozenset({"bearer"}),
            alternatives=((SimpleNamespace(name="bearer", scopes=["reports:read"]),),),
        ),
        SimpleNamespace(
            authenticate=True,
            required=True,
            allow_anonymous=False,
            participant_names=frozenset({"bearer"}),
            alternatives=((SimpleNamespace(name="", scopes=()),),),
        ),
    ],
)
def test_websocket_policy_fingerprint_rejects_malformed_plan_shapes(plan: object) -> None:
    with pytest.raises(ValueError, match="policy fingerprint"):
        websocket_module.websocket_policy_fingerprint(plan)


def test_websocket_policy_fingerprint_accepts_an_absent_participant_set() -> None:
    plan = SimpleNamespace(
        authenticate=False, required=False, allow_anonymous=True, participant_names=None, alternatives=()
    )

    assert len(websocket_module.websocket_policy_fingerprint(plan)) == 64


@pytest.mark.anyio
async def test_connect_token_issuer_mints_by_route_name_and_rejects_invalid_targets() -> None:
    class App:
        handlers: dict[str, object]

        def get_handler_index_by_name(self, name: str) -> object | None:
            return self.handlers.get(name)

    plan = SecurityRuntimePlan(required=True, participant_names=frozenset({"bearer"}))
    websocket_handler = WebsocketRouteHandler(name="reports.socket", opt={RUNTIME_PLAN_OPT_KEY: plan})
    http_handler = HTTPRouteHandler(name="reports.http", http_method=HttpMethod.GET)
    missing_plan_handler = WebsocketRouteHandler(name="reports.missing-plan")
    mismatch_handler = WebsocketRouteHandler(name="reports.mismatch", opt={RUNTIME_PLAN_OPT_KEY: object()})
    wrong_name_handler = WebsocketRouteHandler(name="reports.actual", opt={RUNTIME_PLAN_OPT_KEY: plan})
    app = App()
    app.handlers = {
        "reports.socket": {"handler": websocket_handler},
        "reports.http": {"handler": http_handler},
        "reports.missing-plan": {"handler": missing_plan_handler},
        "reports.mismatch": {"handler": mismatch_handler},
        "reports.alias": {"handler": wrong_name_handler},
    }
    store = InMemoryWebSocketConnectTokenStore()
    issuer = WebSocketConnectTokenIssuer(app=app, store=store, clock=lambda: _NOW)  # type: ignore[arg-type]
    principal = Principal(id="subject-1")
    context = SecurityContext(session=NullSessionHandle())
    origin = "https://trusted.example"

    with pytest.raises(ImproperlyConfiguredException, match="does not resolve"):
        await issuer.issue("missing", principal=principal, context=context, origin=origin, security_epoch=7)
    with pytest.raises(ImproperlyConfiguredException, match="does not resolve"):
        await issuer.issue("reports.http", principal=principal, context=context, origin=origin, security_epoch=7)
    with pytest.raises(ImproperlyConfiguredException, match="has no compiled"):
        await issuer.issue(
            "reports.missing-plan", principal=principal, context=context, origin=origin, security_epoch=7
        )
    with pytest.raises(ImproperlyConfiguredException, match="has an invalid"):
        await issuer.issue("reports.mismatch", principal=principal, context=context, origin=origin, security_epoch=7)
    with pytest.raises(ImproperlyConfiguredException, match="does not match"):
        await issuer.issue("reports.alias", principal=principal, context=context, origin=origin, security_epoch=7)

    issued = await issuer.issue("reports.socket", principal=principal, context=context, origin=origin, security_epoch=7)
    consumed = await WebSocketConnectTokenService(store=store, clock=lambda: _NOW).consume(
        issued.value,
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint=websocket_module.websocket_policy_fingerprint(plan),
        current_security_epoch=_epoch(7),
    )

    assert consumed is not None
    assert consumed.subject_id == "subject-1"


@pytest.mark.anyio
async def test_close_websocket_sends_sanitized_event() -> None:
    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    await websocket_module.close_websocket(send, code=4401, reason="authentication_required")  # type: ignore[arg-type]
    assert messages == [{"type": "websocket.close", "code": 4401, "reason": "authentication_required"}]


@pytest.mark.anyio
async def test_websocket_connect_token_is_digest_only_one_time_and_exactly_bound() -> None:
    store = InMemoryWebSocketConnectTokenStore()
    service = WebSocketConnectTokenService(
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
        security_epoch=7,
        restrictions=restrictions,
    )

    assert isinstance(issued, IssuedWebSocketConnectToken)
    assert issued.value not in repr(issued)
    assert all(issued.value.encode() not in repr(record).encode() for record in store.records)
    consumed = await service.consume(
        issued.value,
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
        current_security_epoch=_epoch(7),
    )
    replay = await service.consume(
        issued.value,
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
        current_security_epoch=_epoch(7),
    )

    assert consumed is not None
    assert consumed.subject_id == "subject-1"
    assert consumed.security_epoch == 7
    assert consumed.restrictions == restrictions
    assert replay is None


def _epoch(value: object) -> Callable[[str], Awaitable[object]]:
    async def current_security_epoch(_subject_id: str) -> object:
        if isinstance(value, Exception):
            raise value
        return value

    return current_security_epoch


@pytest.mark.anyio
@pytest.mark.parametrize("current", [None, True, -1, RuntimeError("offline")])
async def test_websocket_connect_token_epoch_verification_fails_unavailable_after_atomic_consume(
    current: object,
) -> None:
    store = InMemoryWebSocketConnectTokenStore()
    service = WebSocketConnectTokenService(store=store, clock=lambda: _NOW)
    issued = await service.issue(
        principal=Principal(id="subject-1"),
        context=SecurityContext(session=NullSessionHandle()),
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
        security_epoch=7,
    )

    with pytest.raises(websocket_module.WebSocketConnectTokenUnavailableError):
        await service.consume(
            issued.value,
            route_name="reports.socket",
            origin="https://trusted.example",
            policy_fingerprint="f" * 64,
            current_security_epoch=_epoch(current),
        )
    assert store.records == ()


@pytest.mark.anyio
async def test_websocket_connect_token_epoch_mismatch_is_unauthorized_after_atomic_consume() -> None:
    store = InMemoryWebSocketConnectTokenStore()
    service = WebSocketConnectTokenService(store=store, clock=lambda: _NOW)
    issued = await service.issue(
        principal=Principal(id="subject-1"),
        context=SecurityContext(session=NullSessionHandle()),
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
        security_epoch=7,
    )

    assert (
        await service.consume(
            issued.value,
            route_name="reports.socket",
            origin="https://trusted.example",
            policy_fingerprint="f" * 64,
            current_security_epoch=_epoch(8),
        )
        is None
    )
    assert store.records == ()


@pytest.mark.anyio
async def test_websocket_connect_token_is_consumed_before_later_binding_failure() -> None:
    service = WebSocketConnectTokenService(
        store=InMemoryWebSocketConnectTokenStore(),
        clock=lambda: _NOW,
        entropy=lambda length: b"i" * length if length == 16 else b"s" * length,
    )
    issued = await service.issue(
        principal=Principal(id="subject-1"),
        context=SecurityContext(session=NullSessionHandle()),
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
        security_epoch=7,
    )

    mismatch = await service.consume(
        issued.value,
        route_name="other.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
        current_security_epoch=_epoch(7),
    )
    retry = await service.consume(
        issued.value,
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
        current_security_epoch=_epoch(7),
    )

    assert mismatch is None
    assert retry is None


@pytest.mark.anyio
async def test_websocket_connect_token_atomic_double_consume_has_one_winner() -> None:
    async def consume(service: WebSocketConnectTokenService, value: str, results: list[object]) -> None:
        results.append(
            await service.consume(
                value,
                route_name="reports.socket",
                origin="https://trusted.example",
                policy_fingerprint="f" * 64,
                current_security_epoch=_epoch(7),
            )
        )

    for _ in range(100):
        service = WebSocketConnectTokenService(
            store=InMemoryWebSocketConnectTokenStore(),
            clock=lambda: _NOW,
            entropy=lambda length: b"i" * length if length == 16 else b"s" * length,
        )
        issued = await service.issue(
            principal=Principal(id="subject-1"),
            context=SecurityContext(session=NullSessionHandle()),
            route_name="reports.socket",
            origin="https://trusted.example",
            policy_fingerprint="f" * 64,
            security_epoch=7,
        )
        results: list[object] = []

        async with anyio.create_task_group() as task_group:
            task_group.start_soon(consume, service, issued.value, results)
            task_group.start_soon(consume, service, issued.value, results)

        assert sum(result is not None for result in results) == 1


@pytest.mark.anyio
async def test_websocket_connect_token_expiry_boundary_is_exclusive_and_deletes_record() -> None:
    current = [_NOW]
    store = InMemoryWebSocketConnectTokenStore()
    service = WebSocketConnectTokenService(
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
        security_epoch=7,
    )
    current[0] = issued.expires_at

    consumed = await service.consume(
        issued.value,
        route_name="reports.socket",
        origin="https://trusted.example",
        policy_fingerprint="f" * 64,
        current_security_epoch=_epoch(7),
    )

    assert consumed is None
    assert store.records == ()


@pytest.mark.anyio
async def test_websocket_expiry_closes_once_and_cancels_idle_handler() -> None:
    messages: list[dict[str, object]] = []
    handler_cleaned = anyio.Event()

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        try:
            await anyio.sleep_forever()
        finally:
            handler_cleaned.set()

    async def expire_immediately(_delay: float) -> None:
        return None

    coordinator = WebSocketCloseCoordinator(send)  # type: ignore[arg-type]
    await supervise_websocket_lifetime(
        handler,
        expires_at=_NOW + timedelta(minutes=1),
        coordinator=coordinator,
        unauthenticated_close_code=4401,
        clock=lambda: _NOW,
        sleeper=expire_immediately,
    )

    assert messages == [{"type": "websocket.close", "code": 4401, "reason": "credential_expired"}]
    assert handler_cleaned.is_set()
    assert coordinator.state == "closed"


@pytest.mark.anyio
async def test_websocket_handler_return_cancels_expiry_task_without_close() -> None:
    messages: list[dict[str, object]] = []
    sleeper_cleaned = anyio.Event()

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        return None

    async def wait_forever(_delay: float) -> None:
        try:
            await anyio.sleep_forever()
        finally:
            sleeper_cleaned.set()

    await supervise_websocket_lifetime(
        handler,
        expires_at=_NOW + timedelta(minutes=1),
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        clock=lambda: _NOW,
        sleeper=wait_forever,
    )

    assert messages == []
    assert sleeper_cleaned.is_set()


@pytest.mark.anyio
async def test_websocket_simultaneous_terminal_causes_emit_one_close() -> None:
    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    coordinator = WebSocketCloseCoordinator(send)  # type: ignore[arg-type]

    async def close(reason: str) -> None:
        await coordinator.close(code=4401, reason=reason)

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(close, "credential_expired")
        task_group.start_soon(close, "credential_revoked")

    assert len(messages) == 1
    assert messages[0]["reason"] in {"credential_expired", "credential_revoked"}


@pytest.mark.anyio
async def test_websocket_coordinator_ignores_events_after_close_and_duplicate_accept() -> None:
    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    coordinator = WebSocketCloseCoordinator(send)  # type: ignore[arg-type]
    await coordinator.send({"type": "websocket.accept"})  # type: ignore[arg-type]
    await coordinator.send({"type": "websocket.accept"})  # type: ignore[arg-type]
    await coordinator.send({"type": "websocket.send", "text": "open"})  # type: ignore[arg-type]
    await coordinator.send({"type": "websocket.close", "code": 4401})  # type: ignore[arg-type]
    await coordinator.send({"type": "websocket.send", "text": "late"})  # type: ignore[arg-type]

    assert messages == [
        {"type": "websocket.accept"},
        {"type": "websocket.send", "text": "open"},
        {"type": "websocket.close", "code": 4401},
    ]


@pytest.mark.anyio
async def test_websocket_supervisor_default_path_creates_no_tasks() -> None:
    called = False

    async def handler() -> None:
        nonlocal called
        called = True

    async def send(_message: dict[str, object]) -> None:
        return None

    await supervise_websocket_lifetime(
        handler,
        expires_at=None,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
    )

    assert called


@pytest.mark.anyio
async def test_websocket_already_expired_closes_without_starting_handler() -> None:
    messages: list[dict[str, object]] = []
    handler_called = False

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        nonlocal handler_called
        handler_called = True

    await supervise_websocket_lifetime(
        handler,
        expires_at=_NOW,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        clock=lambda: _NOW,
    )

    assert messages == [{"type": "websocket.close", "code": 4401, "reason": "credential_expired"}]
    assert handler_called is False


@pytest.mark.anyio
async def test_websocket_revocation_event_closes_and_cancels_handler() -> None:
    messages: list[dict[str, object]] = []
    cleaned = anyio.Event()

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        try:
            await anyio.sleep_forever()
        finally:
            cleaned.set()

    async def revoked() -> None:
        return None

    await supervise_websocket_lifetime(
        handler,
        expires_at=None,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        revocation_wait=revoked,
    )

    assert messages == [{"type": "websocket.close", "code": 4401, "reason": "credential_revoked"}]
    assert cleaned.is_set()


@pytest.mark.anyio
async def test_websocket_revocation_outage_closes_as_unavailable() -> None:
    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        await anyio.sleep_forever()

    async def unavailable() -> None:
        raise RuntimeError

    await supervise_websocket_lifetime(
        handler,
        expires_at=None,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        revocation_wait=unavailable,
    )

    assert messages == [{"type": "websocket.close", "code": 1013, "reason": "verification_unavailable"}]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("error", "code", "reason"),
    [
        (PermissionDeniedException(), 4403, "authorization_denied"),
        (ServiceUnavailableException(), 1013, "verification_unavailable"),
        (RuntimeError(), 1013, "verification_unavailable"),
    ],
)
async def test_websocket_refresh_failure_has_stable_close(error: Exception, code: int, reason: str) -> None:
    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        await anyio.sleep_forever()

    async def refresh() -> None:
        raise error

    async def refresh_now(_delay: float) -> None:
        return None

    await supervise_websocket_lifetime(
        handler,
        expires_at=None,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        revocation_wait=None,
        refresh=refresh,
        refresh_interval=timedelta(seconds=1),
        sleeper=refresh_now,
    )

    assert messages == [{"type": "websocket.close", "code": code, "reason": reason}]


@pytest.mark.anyio
async def test_websocket_refresh_completes_short_resource_scope_and_preserves_access() -> None:
    messages: list[dict[str, object]] = []
    refreshed = anyio.Event()
    resource_open = False
    sleep_calls = 0

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def handler() -> None:
        await refreshed.wait()

    async def refresh() -> None:
        nonlocal resource_open
        resource_open = True
        try:
            await anyio.lowlevel.checkpoint()
        finally:
            resource_open = False
        refreshed.set()

    async def interval(_delay: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls > 1:
            await anyio.sleep_forever()

    await supervise_websocket_lifetime(
        handler,
        expires_at=None,
        coordinator=WebSocketCloseCoordinator(send),  # type: ignore[arg-type]
        unauthenticated_close_code=4401,
        refresh=refresh,
        refresh_interval=timedelta(seconds=1),
        sleeper=interval,
    )

    assert messages == []
    assert refreshed.is_set()
    assert resource_open is False
