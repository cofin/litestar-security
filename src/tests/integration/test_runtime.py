"""Integration tests for Litestar security middleware and dependency injection."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, ClassVar, cast

import pytest
from litestar import Controller, Litestar, Request, Response, Router, WebSocket, get, websocket
from litestar.config.app import AppConfig
from litestar.enums import ScopeType
from litestar.exceptions import NotAuthorizedException, ServiceUnavailableException
from litestar.middleware import DefineMiddleware
from litestar.middleware._internal.exceptions import ExceptionHandlerMiddleware
from litestar.middleware.session.base import BaseSessionBackend, SessionMiddleware
from litestar.status_codes import HTTP_401_UNAUTHORIZED, HTTP_503_SERVICE_UNAVAILABLE
from litestar.testing import AsyncTestClient, TestClient

from litestar_security import SecurityConfig, SecurityPlugin, authentication
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
    public,
    security,
)
from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    NullSessionHandle,
    Principal,
    SecurityContext,
)
from litestar_security.guards import requires_scope

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar.connection import ASGIConnection
    from litestar.types import ASGIApp, Message, Receive, Scope, Send

    from litestar_security.plugin import CurrentUser, PrincipalDependency, SecurityContextDependency

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


@dataclass(frozen=True)
class _DependencyUser:
    name: str


class _DependencySlot:
    name = "test"

    def extract(self, _connection: ASGIConnection[Any, Any, Any, Any]) -> PresentedCredential[str]:
        return PresentedCredential("credential")


class _DependencyAuthenticator:
    name = "test"
    slot = "test"
    participates_by_default = True

    async def authenticate(
        self, _credential: str, _connection: ASGIConnection[Any, Any, Any, Any]
    ) -> Authenticated[str]:
        return Authenticated(
            claims="subject",
            evidence=AuthenticationEvidence(mechanism=self.name, slot=self.slot, authenticated_at=_NOW),
        )


class _DependencyResolver:
    def __init__(self, principal: Principal[_DependencyUser]) -> None:
        self.principal = principal

    async def resolve(self, _claims: str) -> Principal[_DependencyUser]:
        return self.principal


def _identity_plugin(principal: Principal[_DependencyUser]) -> SecurityPlugin[_DependencyUser]:
    return SecurityPlugin(
        SecurityConfig(
            slots=(_DependencySlot(),),
            mechanisms=(
                AuthenticationMechanism(
                    authenticator=_DependencyAuthenticator(), resolver=_DependencyResolver(principal)
                ),
            ),
        )
    )


def test_dependency_providers_are_non_threaded_and_request_local(empty_security_config: SecurityConfig[object]) -> None:
    app_config = SecurityPlugin(empty_security_config).on_app_init(AppConfig())

    for provider in app_config.dependencies.values():
        assert provider.sync_to_thread is False
        assert provider.use_cache is False


def test_anonymous_dependency_injection_is_typed() -> None:
    @get("/")
    async def handler(
        principal: PrincipalDependency[_DependencyUser], security_context: SecurityContextDependency
    ) -> dict[str, bool]:
        return {
            "anonymous": not principal.is_authenticated,
            "typed_context": isinstance(security_context, SecurityContext),
        }

    with TestClient(Litestar(route_handlers=[handler], plugins=[SecurityPlugin()])) as client:
        response = client.get("/")

    assert response.json() == {"anonymous": True, "typed_context": True}


def test_native_guard_layers_remain_cumulative_for_http_and_websocket_with_child_policy() -> None:
    events: list[str] = []

    def probe(name: str) -> Callable[[ASGIConnection, object], None]:
        def guard(_connection: ASGIConnection, _handler: object) -> None:
            events.append(name)

        return guard

    class GuardedController(Controller):
        path = "/guarded"
        guards: ClassVar = [probe("controller")]

        @get("/http", guards=[probe("handler")], opt=security(public()))
        async def http_handler(self) -> dict[str, bool]:
            return {"ok": True}

        @websocket("/ws", guards=[probe("handler")], opt=security(public()))
        async def websocket_handler(self, socket: WebSocket) -> None:
            await socket.accept()
            await socket.send_text("ok")
            await socket.close()

    app = Litestar(
        route_handlers=[Router(path="/api", route_handlers=[GuardedController], guards=[probe("router")])],
        guards=[probe("app")],
        plugins=[SecurityPlugin()],
    )

    with TestClient(app) as client:
        response = client.get("/api/guarded/http")
        http_events = tuple(events)
        events.clear()
        with client.websocket_connect("/api/guarded/ws") as socket:
            websocket_message = socket.receive_text()
        websocket_events = tuple(events)

    assert response.status_code == 200
    assert websocket_message == "ok"
    assert http_events == websocket_events == ("app", "router", "controller", "handler")


@pytest.mark.parametrize("connection_type", [Request, WebSocket])
def test_authorization_guard_has_identical_http_and_websocket_decisions(connection_type: object) -> None:
    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message: Message) -> None:
        return None

    scope = _scope("http" if connection_type is Request else "websocket")
    scope["user"] = Principal[object](id="user-1")
    scope["auth"] = SecurityContext(
        session=NullSessionHandle(), authorization=AuthorizationSnapshot(scopes={"reports:read"})
    )
    connection = connection_type(scope=scope, receive=receive, send=send)  # type: ignore[operator]

    requires_scope("reports:read")(connection, _RouteHandler())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("principal", "expected_principal", "expected_user_status", "expected_user"),
    [
        (
            Principal(id="user-1", user=_DependencyUser(name="Ada")),
            {"id": "user-1", "has_user": True, "evidence": "test"},
            200,
            "Ada",
        ),
        (Principal(id="service-1"), {"id": "service-1", "has_user": False, "evidence": "test"}, 401, None),
    ],
)
def test_authenticated_dependency_injection_for_user_and_service_principals(
    principal: Principal[_DependencyUser],
    expected_principal: dict[str, object],
    expected_user_status: int,
    expected_user: str | None,
) -> None:
    @get("/principal")
    async def principal_handler(
        principal: PrincipalDependency[_DependencyUser], security_context: SecurityContextDependency
    ) -> dict[str, object]:
        return {"id": principal.id, "has_user": principal.has_user, "evidence": security_context.evidence[0].mechanism}

    @get("/user")
    async def user_handler(current_user: CurrentUser[_DependencyUser]) -> str:
        return current_user.name

    with TestClient(
        Litestar(route_handlers=[principal_handler, user_handler], plugins=[_identity_plugin(principal)])
    ) as client:
        principal_response = client.get("/principal")
        user_response = client.get("/user")

    assert principal_response.json() == expected_principal
    assert user_response.status_code == expected_user_status
    if expected_user is not None:
        assert user_response.text == expected_user
