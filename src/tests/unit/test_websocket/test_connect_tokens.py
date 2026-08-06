"""Unit tests for WebSocket handshake transport policy."""

from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import anyio
import anyio.lowlevel
import pytest
from litestar.enums import HttpMethod
from litestar.exceptions import ImproperlyConfiguredException
from litestar.handlers import WebsocketRouteHandler
from litestar.handlers.http_handlers import HTTPRouteHandler

import litestar_security.websocket as websocket_module
import litestar_security.websocket._connect_tokens as connect_tokens_module
from litestar_security._internal import RUNTIME_PLAN_OPT_KEY
from litestar_security.authentication import SecurityRuntimePlan
from litestar_security.context import CredentialRestrictions, NullSessionHandle, Principal, SecurityContext
from litestar_security.websocket import (
    InMemoryWebSocketConnectTokenStore,
    IssuedWebSocketConnectToken,
    WebSocketConnectTokenIssuer,
    WebSocketConnectTokenRecord,
    WebSocketConnectTokenService,
    issue_websocket_connect_token,
)

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


def _connection(*, headers: tuple[tuple[bytes, bytes], ...] = (), query_string: bytes = b"") -> SimpleNamespace:
    return SimpleNamespace(scope={"headers": list(headers), "query_string": query_string})


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


async def test_close_websocket_sends_sanitized_event() -> None:
    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    await websocket_module.close_websocket(send, code=4401, reason="authentication_required")  # type: ignore[arg-type]
    assert messages == [{"type": "websocket.close", "code": 4401, "reason": "authentication_required"}]


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
