from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast

import pytest
from litestar import Litestar, Request, Response, get
from litestar.enums import ScopeType
from litestar.exceptions import NotAuthorizedException, ServiceUnavailableException
from litestar.middleware import DefineMiddleware
from litestar.middleware._internal.exceptions import ExceptionHandlerMiddleware
from litestar.middleware.session.base import BaseSessionBackend, SessionMiddleware
from litestar.status_codes import HTTP_401_UNAUTHORIZED, HTTP_503_SERVICE_UNAVAILABLE
from litestar.testing import AsyncTestClient

from litestar_security import authentication
from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationRegistry,
    InvalidCredentials,
    OwnedSessionBackend,
    PresentedCredential,
    SecurityMiddleware,
    SecurityMiddlewareWrapper,
    SecurityRuntimeConfig,
    SecurityRuntimePlan,
    VerificationUnavailable,
)
from litestar_security.context import AuthenticationEvidence, Principal, SecurityContext

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar.connection import ASGIConnection
    from litestar.types import ASGIApp, Message, Receive, Scope, Send

_NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)


class _Slot:
    name = "authorization.bearer"

    def __init__(self, extraction: object, events: list[str] | None = None) -> None:
        self.extraction = extraction
        self.events = events
        self.calls = 0

    def extract(self, _connection: object) -> object:
        self.calls += 1
        if self.events is not None:
            self.events.append("extract")
        return self.extraction


class _Authenticator:
    name = "bearer"
    slot = "authorization.bearer"
    participates_by_default = True

    def __init__(self, outcome: object, *, mutate_session: bool = False) -> None:
        self.outcome = outcome
        self.mutate_session = mutate_session
        self.calls = 0

    async def authenticate(self, _credential: str, connection: ASGIConnection) -> object:
        self.calls += 1
        if self.mutate_session:
            assert "session" in connection.scope
            connection.scope["session"]["failure_seen"] = True
        return self.outcome


class _Resolver:
    async def resolve(self, claims: str) -> Principal[object]:
        return Principal(id=claims)


@dataclass
class _SessionConfig:
    exclude: str | list[str] | None = None
    exclude_opt_key: str = "skip_session"
    scopes: set[ScopeType] = field(default_factory=lambda: {ScopeType.HTTP, ScopeType.WEBSOCKET})


class _MemorySessionBackend(BaseSessionBackend[Any]):
    def __init__(self) -> None:
        super().__init__(_SessionConfig())
        self.stored: dict[str, object] = {}

    def get_session_id(self, _connection: ASGIConnection) -> None:
        return None

    async def store_in_message(self, scope_session: object, _message: Message, _connection: ASGIConnection) -> None:
        self.stored = dict(cast("dict[str, object]", scope_session))

    async def load_from_connection(self, _connection: ASGIConnection) -> dict[str, Any]:
        return dict(self.stored)


def _runtime(
    outcome: object | None = None,
    *,
    extraction: object | None = None,
    mutate_session: bool = False,
    owned_session_backend: OwnedSessionBackend | None = None,
    plan_lookup: Callable[[Scope], SecurityRuntimePlan] | None = None,
) -> tuple[SecurityRuntimeConfig[object], _Slot | None, _Authenticator | None]:
    if outcome is None:
        return (
            SecurityRuntimeConfig(
                registry=AuthenticationRegistry(), owned_session_backend=owned_session_backend, plan_lookup=plan_lookup
            ),
            None,
            None,
        )
    slot = _Slot(extraction if extraction is not None else PresentedCredential("token"))
    authenticator = _Authenticator(outcome, mutate_session=mutate_session)
    registry = AuthenticationRegistry(
        slots=[slot],  # type: ignore[list-item]
        mechanisms=[
            AuthenticationMechanism(
                authenticator=authenticator,  # type: ignore[arg-type]
                resolver=_Resolver(),
            )
        ],
    )
    return (
        SecurityRuntimeConfig(registry=registry, owned_session_backend=owned_session_backend, plan_lookup=plan_lookup),
        slot,
        authenticator,
    )


def _scope(scope_type: str = "http", *, method: str = "GET", route_handler: object | None = None) -> Scope:
    return cast(
        "Scope",
        {
            "type": scope_type,
            "asgi": {"spec_version": "2.0", "version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "root_path": "",
            "headers": [],
            "client": ("test", 50000),
            "server": ("testserver", 80),
            "route_handler": route_handler or _RouteHandler(),
        },
    )


async def _receive() -> Message:
    return {"type": "http.request", "body": b"", "more_body": False}


async def _send(_message: Message) -> None:
    return None


@dataclass
class _RouteHandler:
    opt: dict[str, object] | None = None
    fn: Callable[..., object] | None = None

    def __post_init__(self) -> None:
        self.opt = self.opt or {}
        self.fn = self.fn or (lambda: None)


@pytest.mark.anyio
@pytest.mark.parametrize("scope_type", ["http", "websocket"])
async def test_anonymous_http_and_websocket_always_receive_typed_scope(scope_type: str) -> None:
    observed: list[Scope] = []
    config, _, _ = _runtime()

    async def app(scope: Scope, _receive: Receive, _send: Send) -> None:
        observed.append(scope)

    await SecurityMiddleware(app=app, config=config)(_scope(scope_type), _receive, _send)

    assert isinstance(observed[0]["user"], Principal)
    assert not observed[0]["user"].is_authenticated
    assert isinstance(observed[0]["auth"], SecurityContext)


@pytest.mark.anyio
@pytest.mark.parametrize("scope_type", ["http", "websocket"])
async def test_authenticated_http_and_websocket_replace_anonymous_scope(scope_type: str) -> None:
    observed: list[Scope] = []
    success = Authenticated(
        claims="user-1",
        evidence=AuthenticationEvidence(mechanism="bearer", slot="authorization.bearer", authenticated_at=_NOW),
    )
    config, slot, authenticator = _runtime(success)

    async def app(scope: Scope, _receive: Receive, _send: Send) -> None:
        observed.append(scope)

    await SecurityMiddleware(app=app, config=config)(_scope(scope_type), _receive, _send)

    assert observed[0]["user"].id == "user-1"
    assert observed[0]["auth"].evidence[0].mechanism == "bearer"
    assert slot is not None
    assert slot.calls == 1
    assert authenticator is not None
    assert authenticator.calls == 1


@pytest.mark.anyio
async def test_explicit_bypass_initializes_scope_without_extracting() -> None:
    observed: list[Scope] = []
    config, slot, _ = _runtime(InvalidCredentials())
    route_handler = _RouteHandler(opt={"litestar_security_plan": SecurityRuntimePlan(authenticate=False)})

    async def app(scope: Scope, _receive: Receive, _send: Send) -> None:
        observed.append(scope)

    await SecurityMiddleware(app=app, config=config)(_scope(route_handler=route_handler), _receive, _send)

    assert isinstance(observed[0]["user"], Principal)
    assert isinstance(observed[0]["auth"], SecurityContext)
    assert slot is not None
    assert slot.calls == 0


@pytest.mark.anyio
async def test_generated_options_initializes_scope_without_extracting() -> None:
    observed: list[Scope] = []
    config, slot, _ = _runtime(InvalidCredentials())

    def options_handler() -> None:
        return None

    options_handler.__module__ = "litestar.routes.http"
    route_handler = _RouteHandler(fn=options_handler)

    async def app(scope: Scope, _receive: Receive, _send: Send) -> None:
        observed.append(scope)

    await SecurityMiddleware(app=app, config=config)(
        _scope(method="OPTIONS", route_handler=route_handler), _receive, _send
    )

    assert isinstance(observed[0]["user"], Principal)
    assert isinstance(observed[0]["auth"], SecurityContext)
    assert slot is not None
    assert slot.calls == 0


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("outcome", "status_code", "exception_name"),
    [
        (InvalidCredentials(), HTTP_401_UNAUTHORIZED, "NotAuthorizedException"),
        (VerificationUnavailable(), HTTP_503_SERVICE_UNAVAILABLE, "ServiceUnavailableException"),
    ],
)
async def test_native_exception_dispatch_and_hooks_observe_anonymous_scope(
    outcome: object, status_code: int, exception_name: str
) -> None:
    hook_observations: list[tuple[object, object]] = []
    config, _, _ = _runtime(outcome)

    @get("/")
    async def handler() -> dict[str, bool]:
        return {"unreachable": True}

    async def after_exception(_exc: Exception, scope: Scope) -> None:
        hook_observations.append((scope["user"], scope["auth"]))

    def exception_handler(request: Request, exc: Exception) -> Response[dict[str, object]]:
        return Response(
            content={
                "handled": type(exc).__name__,
                "anonymous": not request.user.is_authenticated,
                "typed_context": isinstance(request.auth, SecurityContext),
            },
            status_code=status_code,
        )

    app = Litestar(
        route_handlers=[handler],
        middleware=[DefineMiddleware(SecurityMiddlewareWrapper, config=config)],
        after_exception=[after_exception],
        exception_handlers={NotAuthorizedException: exception_handler, ServiceUnavailableException: exception_handler},
    )

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/")

    assert response.status_code == status_code
    assert response.json() == {"handled": exception_name, "anonymous": True, "typed_context": True}
    assert isinstance(hook_observations[0][0], Principal)
    assert isinstance(hook_observations[0][1], SecurityContext)


@pytest.mark.anyio
async def test_owned_native_session_loads_before_security_and_persists_through_401() -> None:
    backend = _MemorySessionBackend()
    owned_session = OwnedSessionBackend(
        middleware=DefineMiddleware(SessionMiddleware, backend=backend), backend=backend
    )
    config, _, _ = _runtime(
        InvalidCredentials(),
        mutate_session=True,
        owned_session_backend=owned_session,
        plan_lookup=lambda scope: (
            SecurityRuntimePlan(authenticate=False)
            if scope["path"] == "/session"
            else SecurityRuntimePlan(authenticate=True, required=True, participant_names=frozenset({"bearer"}))
        ),
    )

    @get("/protected")
    async def protected() -> None:
        return None

    @get("/session")
    async def session_value(request: Request) -> dict[str, object]:
        return {"failure_seen": request.session.get("failure_seen")}

    app = Litestar(
        route_handlers=[protected, session_value],
        middleware=[DefineMiddleware(SecurityMiddlewareWrapper, config=config)],
    )

    async with AsyncTestClient(app=app) as client:
        denied = await client.get("/protected")
        persisted = await client.get("/session")

    assert denied.status_code == HTTP_401_UNAUTHORIZED
    assert persisted.json() == {"failure_seen": True}


@pytest.mark.anyio
async def test_wrapper_runtime_order_and_native_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    builds = 0

    class _ExceptionProbe:
        def __init__(self, app: ASGIApp, debug: object) -> None:
            nonlocal builds
            del debug
            builds += 1
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            events.append("inner_exception_boundary")
            await self.app(scope, receive, send)

    class _SessionProbe:
        def __init__(self, app: ASGIApp, backend: object) -> None:
            del backend
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            events.append("session")
            scope["session"] = {}
            await self.app(scope, receive, send)

    async def route(_scope: Scope, _receive: Receive, _send: Send) -> None:
        events.append("route")

    async def csrf(scope: Scope, receive: Receive, send: Send) -> None:
        events.append("csrf")
        await route(scope, receive, send)

    monkeypatch.setattr(authentication, "ExceptionHandlerMiddleware", _ExceptionProbe)
    session_middleware = DefineMiddleware(_SessionProbe, backend=object())
    config, _, _ = _runtime(
        owned_session_backend=OwnedSessionBackend(
            middleware=session_middleware, backend=session_middleware.kwargs["backend"]
        ),
        plan_lookup=lambda _scope: events.append("security") or SecurityRuntimePlan(authenticate=False),
    )
    wrapper = SecurityMiddlewareWrapper(app=csrf, config=config)

    await wrapper(_scope(), _receive, _send)
    await wrapper(_scope(), _receive, _send)

    assert events == [
        "session",
        "inner_exception_boundary",
        "security",
        "csrf",
        "route",
        "session",
        "inner_exception_boundary",
        "security",
        "csrf",
        "route",
    ]
    assert builds == 1
    assert authentication._NATIVE_EXCEPTION_HANDLER is ExceptionHandlerMiddleware  # noqa: SLF001
