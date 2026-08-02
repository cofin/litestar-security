"""Integration tests for Litestar security middleware and dependency injection."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, ClassVar, cast

import anyio
import jwt
import pytest
from litestar import Controller, Litestar, Request, Response, Router, WebSocket, get, post, websocket
from litestar.config.app import AppConfig
from litestar.config.csrf import CSRFConfig
from litestar.di import NamedDependency, Provide
from litestar.enums import ScopeType
from litestar.exceptions import (
    NotAuthorizedException,
    PermissionDeniedException,
    ServiceUnavailableException,
    WebSocketDisconnect,
)
from litestar.middleware import DefineMiddleware
from litestar.middleware._internal.exceptions import ExceptionHandlerMiddleware
from litestar.middleware.session.base import BaseSessionBackend, SessionMiddleware
from litestar.middleware.session.client_side import CookieBackendConfig
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.params import FromPath  # noqa: TC002 - Litestar resolves handler annotations at runtime
from litestar.status_codes import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_503_SERVICE_UNAVAILABLE
from litestar.stores.memory import MemoryStore
from litestar.testing import AsyncTestClient, TestClient

from litestar_security import SecurityConfig, SecurityPlugin, authentication
from litestar_security.accounts import (
    ConsumeResult,
    ConsumeStatus,
    CreateRefreshFamilyCommand,
    CreateSessionCommand,
    LocalAccount,
    LocalAuth,
    LocalAuthSecrets,
    NotificationCommand,
    PasswordChangeResult,
    PasswordChangeStatus,
    PasswordCredentialState,
    PasswordResetResult,
    PasswordResetStatus,
    PasswordVerificationResult,
    PasswordVerificationStatus,
    PurposeTokenCodec,
    RefreshFamilyContext,
    RefreshReceiptKey,
    RefreshReceiptSealer,
    RefreshRotationStatus,
    RefreshTokenCodec,
    RefreshTokenProof,
    RegistrationPolicy,
    RegistrationResult,
    RegistrationStatus,
    RotateRefreshCommand,
    RotateRefreshResult,
    SessionBindingConfig,
    SessionRecord,
    TokenIssue,
    TokenPurpose,
)
from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationRegistry,
    InvalidCredentials,
    NoCredentials,
    OwnedSessionBackend,
    PresentedCredential,
    SecurityMiddleware,
    SecurityMiddlewareWrapper,
    SecurityRuntimeConfig,
    SecurityRuntimePlan,
    VerificationUnavailable,
    public,
    required,
)
from litestar_security.config import ExternalCSRF
from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    CredentialRestrictions,
    NullSessionHandle,
    Principal,
    SecurityContext,
    SessionPersistenceUnavailableError,
)
from litestar_security.guards import requires_scope
from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JWTClaims,
    JWTValidationConfig,
    JWTVerifier,
    LocalKeyRing,
    PyJWTVerifier,
    SigningKey,
)
from litestar_security.websocket import (
    InMemoryWebSocketTicketStore,
    WebSocketSecurityConfig,
    WebSocketTicketRecord,
    WebSocketTicketService,
    websocket_policy_fingerprint,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from litestar.connection import ASGIConnection
    from litestar.types import ASGIApp, Message, Receive, Scope, Send

    from litestar_security.plugin import CurrentUser

_NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)


def _local_auth_secrets(*, refresh: bool = False) -> LocalAuthSecrets:
    return LocalAuthSecrets(
        purpose_tokens=PurposeTokenCodec(pepper=b"p" * 32),
        refresh_codec=RefreshTokenCodec(pepper=b"q" * 32) if refresh else None,
        refresh_receipts=(
            RefreshReceiptSealer(active_key=RefreshReceiptKey("test-key", b"r" * 32)) if refresh else None
        ),
    )


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


class _JWTResolver:
    async def resolve(self, claims: JWTClaims) -> Principal[object]:
        return Principal(id=claims.subject)


@dataclass(frozen=True)
class _UnavailableJWTVerifier:
    config: JWTValidationConfig

    async def verify(self, _token: str, *, now: datetime) -> VerificationUnavailable:
        del now
        return VerificationUnavailable()


@dataclass
class _SessionConfig:
    exclude: str | list[str] | None = None
    exclude_opt_key: str = "skip_session"
    scopes: set[ScopeType] = field(default_factory=lambda: {ScopeType.HTTP, ScopeType.WEBSOCKET})


class _MemorySessionBackend(BaseSessionBackend[Any]):
    def __init__(self) -> None:
        super().__init__(_SessionConfig())
        self.stored: dict[str, object] = {}
        self.store_calls = 0

    def get_session_id(self, _connection: ASGIConnection) -> None:
        return None

    async def store_in_message(self, scope_session: object, _message: Message, _connection: ASGIConnection) -> None:
        self.store_calls += 1
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


@dataclass
class _WebSocketRouteHandler(_RouteHandler):
    handler_name: str = "socket"
    guards_present: bool = False
    authorization_error: Exception | None = None
    authorization_calls: int = 0

    def resolve_guards(self) -> tuple[object, ...]:
        return (object(),) if self.guards_present else ()

    async def authorize_connection(self, *, connection: object) -> None:
        del connection
        self.authorization_calls += 1
        if self.authorization_error is not None:
            raise self.authorization_error


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
        principal: NamedDependency[Principal[_DependencyUser]], security_context: NamedDependency[SecurityContext]
    ) -> dict[str, bool]:
        return {
            "anonymous": not principal.is_authenticated,
            "typed_context": isinstance(security_context, SecurityContext),
        }

    with TestClient(Litestar(route_handlers=[handler], plugins=[SecurityPlugin()])) as client:
        response = client.get("/")

    assert response.json() == {"anonymous": True, "typed_context": True}


def test_composite_bearer_runs_through_the_complete_litestar_runtime() -> None:
    issuer = "https://runtime.example"
    audience = "runtime-api"
    now = datetime.now(timezone.utc)
    verification_config = JWTValidationConfig(
        issuer=issuer, audiences=frozenset({audience}), algorithms=frozenset({"HS256"})
    )
    signing_key = bytes(range(32))
    claims = {
        "iss": issuer,
        "sub": "runtime-user",
        "aud": audience,
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "iat": int(now.timestamp()),
        "nbf": int((now - timedelta(seconds=1)).timestamp()),
        "client_id": "runtime-client",
        "jti": "runtime-token",
    }
    token = jwt.encode(claims, signing_key, algorithm="HS256", headers={"typ": "at+jwt"})
    wrong_key_token = jwt.encode(claims, bytes(range(1, 33)), algorithm="HS256", headers={"typ": "at+jwt"})

    def build_app(verifier: JWTVerifier[JWTClaims]) -> Litestar:
        physical_slot, mechanism_value = CompositeBearerConfig(
            mechanism_name="bearer",
            slots=(
                BearerTokenSlot(
                    name="runtime",
                    selector=BearerSlotSelector(issuers=frozenset({issuer}), audiences=frozenset({audience})),
                    verifier=verifier,
                ),
            ),
        ).build(_JWTResolver())

        @get("/")
        async def handler(request: Request) -> dict[str, object]:
            return {
                "id": request.user.id,
                "mechanism": request.auth.evidence[0].mechanism,
                "slot": request.auth.evidence[0].slot,
            }

        return Litestar(
            route_handlers=[handler],
            openapi_config=None,
            plugins=[
                SecurityPlugin(
                    SecurityConfig(slots=(physical_slot,), mechanisms=(mechanism_value,))  # type: ignore[arg-type]
                )
            ],
        )

    verifier = PyJWTVerifier(config=verification_config, key=signing_key, require_key_id=False)
    with TestClient(build_app(verifier)) as client:
        authenticated = client.get("/", headers={"Authorization": f"Bearer {token}"})
        invalid = client.get("/", headers={"Authorization": f"Bearer {wrong_key_token}"})

    with TestClient(build_app(_UnavailableJWTVerifier(verification_config))) as client:
        unavailable = client.get("/", headers={"Authorization": f"Bearer {token}"})

    assert authenticated.status_code == 200
    assert authenticated.json() == {"id": "runtime-user", "mechanism": "bearer", "slot": "runtime"}
    assert invalid.status_code == HTTP_401_UNAUTHORIZED
    assert unavailable.status_code == HTTP_503_SERVICE_UNAVAILABLE


def _native_local_accounts() -> tuple[SimpleNamespace, LocalAccount[object]]:  # noqa: C901
    account = LocalAccount(
        account_id="account-1",
        normalized_identifier="user@example.com",
        display_name="User",
        active=True,
        verified=True,
        security_epoch=1,
        user=object(),
    )
    records: dict[str, SessionRecord] = {}
    state = SimpleNamespace(epoch=1, fail_epoch=False, fail_lookup=False, touches=0)

    async def create(command: CreateSessionCommand, **_kwargs: object) -> SessionRecord:
        record = SessionRecord(
            session_id=command.session_id,
            binding_id=command.binding_id,
            binding_digest=command.binding_digest,
            account_id=command.account_id,
            security_epoch=command.security_epoch,
            created_at=command.created_at,
            last_seen_at=command.created_at,
            expires_at=command.expires_at,
            display_metadata=command.display_metadata,
        )
        records[record.session_id] = record
        return record

    async def get_session(session_id: str) -> SessionRecord | None:
        return records.get(session_id)

    async def get_account(account_id: str) -> LocalAccount[object] | None:
        if state.fail_lookup:
            raise OSError
        return account if account_id == account.account_id else None

    async def current_epoch(account_id: str) -> int | None:
        if state.fail_epoch:
            raise OSError
        return cast("int", state.epoch) if account_id == account.account_id else None

    async def list_for_account(account_id: str) -> list[SessionRecord]:
        return [record for record in records.values() if record.account_id == account_id]

    async def touch(session_id: str, **kwargs: object) -> SessionRecord | None:
        record = records.get(session_id)
        if record is None:
            return None
        state.touches += 1
        touched = SessionRecord(
            session_id=record.session_id,
            binding_id=record.binding_id,
            binding_digest=record.binding_digest,
            account_id=record.account_id,
            security_epoch=record.security_epoch,
            created_at=record.created_at,
            last_seen_at=cast("datetime", kwargs["now"]),
            expires_at=record.expires_at,
            display_metadata=record.display_metadata,
        )
        records[session_id] = touched
        return touched

    async def revoke_session_for_account(account_id: str, session_id: str, **_kwargs: object) -> bool:
        record = records.get(session_id)
        if record is None or record.account_id != account_id:
            return False
        del records[session_id]
        return True

    async def revoke_sessions_for_account(account_id: str, **_kwargs: object) -> int:
        matches = tuple(key for key, record in records.items() if record.account_id == account_id)
        for key in matches:
            del records[key]
        return len(matches)

    async def revoke_other_sessions(account_id: str, session_id: str, **_kwargs: object) -> int:
        matches = tuple(key for key, record in records.items() if record.account_id == account_id and key != session_id)
        for key in matches:
            del records[key]
        return len(matches)

    async def rebind(prior_session_id: str, command: CreateSessionCommand, **kwargs: object) -> SessionRecord | None:
        if prior_session_id not in records:
            return None
        del records[prior_session_id]
        return await create(command, **kwargs)

    async def unused(*_args: object, **_kwargs: object) -> None:
        return None

    return (
        SimpleNamespace(
            compare_and_replace_password=unused,
            consume_and_reset=unused,
            consume_and_verify=unused,
            create=create,
            create_family=unused,
            current_epoch=current_epoch,
            find_for_login=unused,
            get=get_session,
            get_by_id=get_account,
            get_password_state=unused,
            issue=unused,
            list_for_account=list_for_account,
            prepare_rotation=unused,
            rebind=rebind,
            register_login_method=unused,
            replace_password_and_bump_epoch=unused,
            revoke_family=unused,
            revoke_for_account=unused,
            revoke_token=unused,
            revoke_token_for_account=unused,
            revoke_login_method=unused,
            revoke_other_sessions=revoke_other_sessions,
            revoke_session_for_account=revoke_session_for_account,
            revoke_sessions_for_account=revoke_sessions_for_account,
            state=state,
            touch=touch,
            rotate=unused,
        ),
        account,
    )


@dataclass(frozen=True, slots=True)
class _RoutePasswordHasher:
    async def hash(self, password: str) -> str:
        return f"test-hash:{password}"

    async def verify(self, encoded_hash: str | None, password: str) -> PasswordVerificationResult:
        return PasswordVerificationResult(
            PasswordVerificationStatus.VERIFIED
            if encoded_hash == f"test-hash:{password}"
            else PasswordVerificationStatus.INVALID
        )


@dataclass(slots=True)
class _RouteRefreshState:
    token_id: str
    token_digest: bytes
    account_id: str
    family_id: str
    security_epoch: int
    token_expires_at: datetime
    family_expires_at: datetime
    scopes: frozenset[str]
    revoked: bool = False


@dataclass(slots=True)
class _GeneratedRouteAccounts:
    account: LocalAccount[object] | None = None
    password_hash: str | None = None
    sessions: dict[str, SessionRecord] = field(default_factory=dict)
    purpose_tokens: dict[str, TokenIssue] = field(default_factory=dict)
    refresh_tokens: dict[str, _RouteRefreshState] = field(default_factory=dict)
    verification_token: str | None = None
    recovery_token: str | None = None

    async def find_for_login(self, normalized_identifier: str) -> LocalAccount[object] | None:
        if self.account is None or self.account.normalized_identifier != normalized_identifier:
            return None
        return self.account

    async def get_by_id(self, account_id: str) -> LocalAccount[object] | None:
        return self.account if self.account is not None and self.account.account_id == account_id else None

    async def current_epoch(self, account_id: str) -> int | None:
        account = await self.get_by_id(account_id)
        return account.security_epoch if account is not None else None

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        account = await self.get_by_id(account_id)
        if account is None or self.password_hash is None:
            return None
        return PasswordCredentialState(password_hash=self.password_hash, security_epoch=account.security_epoch)

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, **_kwargs: object
    ) -> bool:
        if await self.get_by_id(account_id) is None or self.password_hash != expected_hash:
            return False
        self.password_hash = password_hash
        return True

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, **_kwargs: object
    ) -> PasswordChangeResult:
        account = await self.get_by_id(account_id)
        if account is None or account.security_epoch != expected_epoch:
            return PasswordChangeResult(PasswordChangeStatus.CONFLICT)
        self.password_hash = password_hash
        self.account = replace(account, security_epoch=expected_epoch + 1)
        return PasswordChangeResult(PasswordChangeStatus.CHANGED, expected_epoch + 1)

    async def register(
        self, command: object, password_hash: str, *, verification: object | None, **_kwargs: object
    ) -> RegistrationResult[object]:
        if self.account is not None:
            return RegistrationResult(RegistrationStatus.DUPLICATE)
        self.account = LocalAccount(
            account_id="account-1",
            normalized_identifier=cast("Any", command).normalized_identifier,
            display_name=cast("Any", command).display_name,
            active=True,
            verified=verification is None,
            security_epoch=1,
            user=object(),
        )
        self.password_hash = password_hash
        if verification is not None:
            issue, notification = cast("Any", verification).bind(self.account.account_id)
            await self.issue(issue, notification)
        return RegistrationResult(RegistrationStatus.CREATED, self.account)

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, **_kwargs: object) -> None:
        self.purpose_tokens[issue.token_id] = issue
        if issue.purpose is TokenPurpose.VERIFICATION:
            self.verification_token = notification.token
        elif issue.purpose is TokenPurpose.RECOVERY:
            self.recovery_token = notification.token

    async def consume_and_verify(self, token_id: str, digest: bytes, **_kwargs: object) -> ConsumeResult:
        issue = self.purpose_tokens.pop(token_id, None)
        if issue is None or issue.digest != digest or self.account is None:
            return ConsumeResult(ConsumeStatus.INVALID)
        self.account = replace(self.account, verified=True)
        return ConsumeResult(ConsumeStatus.CONSUMED, self.account.account_id, self.account.security_epoch)

    async def consume_and_reset(
        self, token_id: str, digest: bytes, new_password_hash: str, **_kwargs: object
    ) -> PasswordResetResult:
        issue = self.purpose_tokens.pop(token_id, None)
        if issue is None or issue.digest != digest or self.account is None:
            return PasswordResetResult(PasswordResetStatus.INVALID)
        self.password_hash = new_password_hash
        self.account = replace(self.account, security_epoch=self.account.security_epoch + 1)
        return PasswordResetResult(PasswordResetStatus.RESET, self.account.account_id, self.account.security_epoch)

    async def register_login_method(self, *_args: object, **_kwargs: object) -> None:
        return None

    async def revoke_login_method(self, *_args: object, **_kwargs: object) -> object:
        return object()

    async def create(self, command: CreateSessionCommand, **_kwargs: object) -> SessionRecord:
        record = SessionRecord(
            session_id=command.session_id,
            binding_id=command.binding_id,
            binding_digest=command.binding_digest,
            account_id=command.account_id,
            security_epoch=command.security_epoch,
            created_at=command.created_at,
            last_seen_at=command.created_at,
            expires_at=command.expires_at,
            display_metadata=command.display_metadata,
        )
        self.sessions[record.session_id] = record
        return record

    async def get(self, session_id: str) -> SessionRecord | None:
        return self.sessions.get(session_id)

    async def list_for_account(self, account_id: str) -> list[SessionRecord]:
        return [record for record in self.sessions.values() if record.account_id == account_id]

    async def touch(self, session_id: str, *, now: datetime) -> SessionRecord | None:
        record = self.sessions.get(session_id)
        if record is None:
            return None
        touched = replace(record, last_seen_at=now)
        self.sessions[session_id] = touched
        return touched

    async def revoke_session_for_account(self, account_id: str, session_id: str, **_kwargs: object) -> bool:
        record = self.sessions.get(session_id)
        if record is None or record.account_id != account_id:
            return False
        del self.sessions[session_id]
        return True

    async def revoke_sessions_for_account(self, account_id: str, **_kwargs: object) -> int:
        matches = tuple(key for key, record in self.sessions.items() if record.account_id == account_id)
        for key in matches:
            del self.sessions[key]
        return len(matches)

    async def revoke_other_sessions(self, account_id: str, session_id: str, **_kwargs: object) -> int:
        matches = tuple(
            key for key, record in self.sessions.items() if record.account_id == account_id and key != session_id
        )
        for key in matches:
            del self.sessions[key]
        return len(matches)

    async def rebind(
        self, prior_session_id: str, command: CreateSessionCommand, **kwargs: object
    ) -> SessionRecord | None:
        if prior_session_id not in self.sessions:
            return None
        del self.sessions[prior_session_id]
        return await self.create(command, **kwargs)

    async def create_family(self, command: CreateRefreshFamilyCommand, **_kwargs: object) -> bool:
        self.refresh_tokens[command.token_id] = _RouteRefreshState(
            token_id=command.token_id,
            token_digest=command.token_digest,
            account_id=command.account_id,
            family_id=command.family_id,
            security_epoch=command.security_epoch,
            token_expires_at=command.token_expires_at,
            family_expires_at=command.family_expires_at,
            scopes=command.scopes,
        )
        return True

    async def prepare_rotation(
        self, proof: RefreshTokenProof, _idempotency_digest: bytes | None, **_kwargs: object
    ) -> RefreshFamilyContext:
        state = self.refresh_tokens[proof.token_id]
        assert state.token_digest == proof.digest
        assert not state.revoked
        return RefreshFamilyContext(
            account_id=state.account_id,
            family_id=state.family_id,
            security_epoch=state.security_epoch,
            token_expires_at=state.token_expires_at,
            family_expires_at=state.family_expires_at,
            scopes=state.scopes,
        )

    async def rotate(self, command: RotateRefreshCommand, **_kwargs: object) -> RotateRefreshResult:
        current = self.refresh_tokens.pop(command.token_id)
        assert current.token_digest == command.token_digest
        assert not current.revoked
        self.refresh_tokens[command.successor_id] = _RouteRefreshState(
            token_id=command.successor_id,
            token_digest=command.successor_digest,
            account_id=command.account_id,
            family_id=command.family_id,
            security_epoch=command.security_epoch,
            token_expires_at=command.successor_expires_at,
            family_expires_at=command.family_expires_at,
            scopes=command.scopes,
        )
        return RotateRefreshResult(RefreshRotationStatus.ROTATED, command.sealed_receipt)

    async def revoke_family(self, family_id: str, **_kwargs: object) -> bool:
        matches = [state for state in self.refresh_tokens.values() if state.family_id == family_id]
        for state in matches:
            state.revoked = True
        return bool(matches)

    async def revoke_token(self, token_id: str, token_digest: bytes, **_kwargs: object) -> bool:
        state = self.refresh_tokens.get(token_id)
        if state is None or state.token_digest != token_digest:
            return False
        state.revoked = True
        return True

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, **_kwargs: object
    ) -> bool:
        state = self.refresh_tokens.get(token_id)
        if state is None or state.account_id != account_id or state.token_digest != token_digest:
            return False
        state.revoked = True
        return True

    async def revoke_for_account(self, account_id: str, **_kwargs: object) -> int:
        matches = [state for state in self.refresh_tokens.values() if state.account_id == account_id]
        for state in matches:
            state.revoked = True
        return len(matches)


@pytest.mark.anyio
async def test_local_access_token_runtime_enforces_scope_account_and_epoch(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    accounts, account = _native_local_accounts()
    private_key, _public_key = jwt_key_material["EdDSA"]
    local_auth = LocalAuth.tokens(
        accounts=cast("Any", accounts),
        secrets=_local_auth_secrets(refresh=True),
        key_ring=LocalKeyRing(
            issuer="https://local.example",
            active_signing_key=SigningKey(key_id="local-active", algorithm="EdDSA", private_key=private_key),
        ),
        token_audience="local-api",  # noqa: S106 - public JWT audience
    )
    issuer = local_auth.access_token_issuer
    assert issuer is not None
    issued = await issuer.issue(account, scopes=frozenset({"reports:read"}), now=datetime.now(timezone.utc))
    assert not isinstance(issued, (InvalidCredentials, VerificationUnavailable))
    bearer_slot = local_auth.bearer_slot
    assert bearer_slot is not None
    invalid_verification = await bearer_slot.verifier.verify("malformed", now=datetime.now(timezone.utc))
    assert isinstance(invalid_verification, InvalidCredentials)

    @get("/", auth=required("bearer"), guards=[requires_scope("reports:read")])
    async def handler(request: Request) -> dict[str, object]:
        return {
            "id": request.user.id,
            "slot": request.auth.evidence[0].slot,
            "scopes": sorted(request.auth.authorization.scopes),
        }

    app = Litestar(
        route_handlers=[handler], openapi_config=None, plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth))]
    )
    headers = {"Authorization": f"Bearer {issued.access_token}"}
    async with AsyncTestClient(app=app) as client:
        authenticated = await client.get("/", headers=headers)
        malformed = await client.get("/", headers={"Authorization": "Bearer malformed"})
        accounts.state.epoch = 2
        invalidated = await client.get("/", headers=headers)
        accounts.state.epoch = 1
        accounts.state.fail_epoch = True
        unavailable = await client.get("/", headers=headers)

    assert authenticated.status_code == 200
    assert authenticated.json() == {"id": "account-1", "slot": "local", "scopes": ["reports:read"]}
    assert malformed.status_code == HTTP_401_UNAUTHORIZED
    assert invalidated.status_code == HTTP_401_UNAUTHORIZED
    assert unavailable.status_code == HTTP_503_SERVICE_UNAVAILABLE


@pytest.mark.parametrize("backend_kind", ["client", "server"])
def test_real_native_session_backends_preserve_anonymous_state_and_resist_fixation(  # noqa: PLR0915
    backend_kind: str,
) -> None:
    accounts, account = _native_local_accounts()
    binding = SessionBindingConfig(
        pepper=b"p" * 32, cookie_name="binding", secure=False, allow_insecure=True, max_age=600
    )
    local_auth = LocalAuth.session(accounts=cast("Any", accounts), secrets=_local_auth_secrets(), binding=binding)
    external_csrf = ExternalCSRF("runtime", lambda _method, _path, _policy: True)
    current_time = [datetime(2026, 7, 27, tzinfo=timezone.utc)]
    session_auth = cast("Any", local_auth.session_auth)
    session_auth.clock = lambda: current_time[0]
    session_config = (
        CookieBackendConfig(
            secret=bytes(range(16)),
            key="native-session",
            max_age=600,
            scopes={ScopeType.HTTP, ScopeType.WEBSOCKET},
            secure=False,
        )
        if backend_kind == "client"
        else ServerSideSessionConfig(
            key="native-session",
            max_age=600,
            scopes={ScopeType.HTTP, ScopeType.WEBSOCKET},
            secure=False,
            store="sessions",
        )
    )

    @get("/anonymous", auth=public())
    async def anonymous_handler(request: Request) -> dict[str, int]:
        visits = cast("int", request.session.get("visits", 0)) + 1
        request.session["visits"] = visits
        return {"visits": visits}

    @get("/me", auth=required("session"))
    async def current_handler(request: Request) -> dict[str, str]:
        return {"id": request.user.id}

    @get("/login", auth=public())
    async def login_handler(request: Request) -> dict[str, str]:
        result = await session_auth.establish(request, account)
        assert not isinstance(result, VerificationUnavailable)
        return {"session_id": result.session_id}

    @post("/logout", auth=required("session"))
    async def logout_handler(request: Request) -> dict[str, bool]:
        return {"revoked": bool(await session_auth.logout(request))}

    @post("/revoke/{session_id:str}", auth=required("session"))
    async def revoke_handler(request: Request, session_id: FromPath[str]) -> dict[str, bool]:
        return {"revoked": bool(await session_auth.revoke_session(request, request.user.id, session_id))}

    @websocket("/ws", auth=required("session"))
    async def websocket_handler(socket: WebSocket) -> None:
        await socket.accept()
        await socket.send_json({"id": socket.user.id})
        await socket.close()

    app = Litestar(
        route_handlers=[
            anonymous_handler,
            current_handler,
            login_handler,
            logout_handler,
            revoke_handler,
            websocket_handler,
        ],
        middleware=[session_config.middleware],
        openapi_config=None,
        stores={"sessions": MemoryStore()},
        plugins=[
            SecurityPlugin(
                SecurityConfig(
                    external_csrf=external_csrf,
                    local_auth=local_auth,
                    websocket=WebSocketSecurityConfig(
                        allowed_origins=frozenset({"http://testserver.local"}), clock=lambda: current_time[0]
                    ),
                )
            )
        ],
    )

    with TestClient(app) as client:
        assert client.get("/anonymous").json() == {"visits": 1}
        assert client.get("/anonymous").json() == {"visits": 2}
        fixed_native = client.cookies.get("native-session")
        assert fixed_native is not None
        assert client.cookies.get("binding") is None

        first_login = client.get("/login")
        assert first_login.status_code == 200
        first_native = client.cookies.get("native-session")
        first_binding = client.cookies.get("binding")
        assert first_native is not None
        assert first_binding is not None
        cookie_headers = first_login.headers.get_list("set-cookie")
        assert any(header.startswith("native-session=") for header in cookie_headers)
        assert any(header.startswith("binding=") for header in cookie_headers)
        assert sum(header.count(first_binding) for header in cookie_headers) == 1
        assert client.get("/me").json() == {"id": "account-1"}
        with client.websocket_connect("/ws", headers={"Origin": "http://testserver.local"}) as socket:
            assert socket.receive_json() == {"id": "account-1"}
        assert accounts.state.touches == 0
        current_time[0] += timedelta(minutes=5)
        assert client.get("/me").status_code == 200
        assert client.get("/me").status_code == 200
        assert accounts.state.touches == 1

        assert client.post("/logout").json() == {"revoked": True}
        assert client.cookies.get("binding") is None
        assert client.get("/me").status_code == HTTP_401_UNAUTHORIZED

        assert client.get("/login").status_code == 200
        accounts.state.epoch = 2
        assert client.get("/me").status_code == HTTP_401_UNAUTHORIZED
        accounts.state.epoch = 1

        revoke_login = client.get("/login")
        assert client.post(f"/revoke/{revoke_login.json()['session_id']}").json() == {"revoked": True}
        assert client.cookies.get("binding") is None
        assert client.get("/me").status_code == HTTP_401_UNAUTHORIZED

        expiry_login = client.get("/login")
        assert expiry_login.status_code == 200
        current_time[0] += timedelta(minutes=10)
        assert client.get("/me").status_code == HTTP_401_UNAUTHORIZED
        current_time[0] += timedelta(seconds=1)

        assert client.get("/login").status_code == 200
        replay_native = client.cookies.get("native-session")
        replay_binding = client.cookies.get("binding")
        assert replay_native is not None
        assert replay_binding is not None
        assert client.get("/login").status_code == 200
        assert client.cookies.get("binding") != replay_binding

        client.cookies.clear()
        client.cookies.set("native-session", replay_native)
        client.cookies.set("binding", replay_binding)
        assert client.get("/me").status_code == HTTP_401_UNAUTHORIZED

        client.cookies.clear()
        client.cookies.set("native-session", fixed_native)
        assert client.get("/me").status_code == HTTP_401_UNAUTHORIZED


def test_generated_session_routes_complete_local_account_lifecycle() -> None:
    accounts = _GeneratedRouteAccounts()
    csrf = CSRFConfig(secret="s" * 32)
    binding = SessionBindingConfig(
        pepper=b"b" * 32, cookie_name="binding", secure=False, allow_insecure=True, max_age=600
    )
    local_auth = LocalAuth.session(
        accounts=accounts,
        secrets=_local_auth_secrets(),
        binding=binding,
        password_hasher=_RoutePasswordHasher(),
        registration=RegistrationPolicy.public(),
    )
    session_config = CookieBackendConfig(
        secret=bytes(range(16)),
        key="native-session",
        max_age=600,
        scopes={ScopeType.HTTP, ScopeType.WEBSOCKET},
        secure=False,
    )

    @get("/csrf", auth=public(), csrf_required=True)
    async def csrf_seed() -> None:
        return None

    app = Litestar(
        route_handlers=[csrf_seed],
        csrf_config=csrf,
        middleware=[session_config.middleware],
        openapi_config=None,
        plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth))],
    )
    initial_password = "initial password 123"  # noqa: S105
    changed_password = "changed password 123"  # noqa: S105
    recovered_password = "recovered password 123"  # noqa: S105

    with TestClient(app) as client:
        assert client.get("/csrf").status_code == 200
        csrf_headers = {csrf.header_name: cast("str", client.cookies.get(csrf.cookie_name))}
        registration = client.post(
            "/auth/register",
            json={"identifier": "user@example.com", "password": initial_password, "display_name": "User"},
        )
        assert registration.status_code == 202, registration.text
        assert accounts.verification_token is not None
        assert client.post("/auth/verification/confirm", json={"token": accounts.verification_token}).status_code == 200

        login = client.post(
            "/auth/login", json={"identifier": "user@example.com", "password": initial_password}, headers=csrf_headers
        )
        assert login.status_code == 200
        assert login.json() == {"account_id": "account-1", "display_name": "User"}
        sessions = client.get("/auth/sessions")
        assert sessions.status_code == 200, sessions.text
        assert sessions.json()["sessions"][0]["current"] is True

        change = client.post(
            "/auth/password/change",
            json={"current_password": initial_password, "password": changed_password},
            headers=csrf_headers,
        )
        assert change.status_code == 200
        assert client.get("/auth/sessions").status_code == 200
        assert client.post("/auth/password/recovery", json={"identifier": "user@example.com"}).status_code == 202
        assert accounts.recovery_token is not None
        assert (
            client.post(
                "/auth/password/reset", json={"token": accounts.recovery_token, "password": recovered_password}
            ).status_code
            == 200
        )
        assert client.get("/auth/sessions").status_code == HTTP_401_UNAUTHORIZED

        assert (
            client.post(
                "/auth/login",
                json={"identifier": "user@example.com", "password": recovered_password},
                headers=csrf_headers,
            ).status_code
            == 200
        )
        logout = client.post("/auth/logout", headers=csrf_headers)
        assert logout.status_code == 200
        assert client.get("/auth/sessions").status_code == HTTP_401_UNAUTHORIZED


def test_generated_token_routes_register_verify_login_refresh_and_revoke(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    accounts = _GeneratedRouteAccounts()
    private_key, _public_key = jwt_key_material["EdDSA"]
    local_auth = LocalAuth.tokens(
        accounts=accounts,
        secrets=_local_auth_secrets(refresh=True),
        key_ring=LocalKeyRing(
            issuer="https://local.example",
            active_signing_key=SigningKey(key_id="local-active", algorithm="EdDSA", private_key=private_key),
        ),
        token_audience="local-api",  # noqa: S106 - public JWT audience
        password_hasher=_RoutePasswordHasher(),
        registration=RegistrationPolicy.public(),
    )
    app = Litestar(
        route_handlers=[], openapi_config=None, plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth))]
    )
    password = "initial password 123"  # noqa: S105

    with TestClient(app) as client:
        assert (
            client.post("/auth/register", json={"identifier": "user@example.com", "password": password}).status_code
            == 202
        )
        assert accounts.verification_token is not None
        assert client.post("/auth/verification/confirm", json={"token": accounts.verification_token}).status_code == 200

        login = client.post("/auth/token", json={"identifier": "user@example.com", "password": password})
        assert login.status_code == 200
        assert login.headers["cache-control"] == "no-store"
        first = login.json()
        rotated = client.post(
            "/auth/token/refresh",
            json={"token": first["refresh_token"]},
            headers={"Idempotency-Key": "aWlpaWlpaWlpaWlpaWlpaQ"},
        )
        assert rotated.status_code == 200
        assert rotated.headers["pragma"] == "no-cache"
        second = rotated.json()
        revoke = client.post(
            "/auth/token/revoke",
            json={"token": second["refresh_token"]},
            headers={"Authorization": f"Bearer {second['access_token']}"},
        )

    assert revoke.status_code == 200
    assert revoke.json() == {"detail": "Token revoked."}
    assert any(state.revoked for state in accounts.refresh_tokens.values())


def test_generated_token_routes_reject_unknown_and_camel_case_body_members(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    accounts = _GeneratedRouteAccounts()
    private_key, _public_key = jwt_key_material["EdDSA"]
    local_auth = LocalAuth.tokens(
        accounts=accounts,
        secrets=_local_auth_secrets(refresh=True),
        key_ring=LocalKeyRing(
            issuer="https://local.example",
            active_signing_key=SigningKey(key_id="local-active", algorithm="EdDSA", private_key=private_key),
        ),
        token_audience="local-api",  # noqa: S106 - public JWT audience
        password_hasher=_RoutePasswordHasher(),
        registration=RegistrationPolicy.public(),
    )
    app = Litestar(
        route_handlers=[], openapi_config=None, plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth))]
    )
    password = "initial password 123"  # noqa: S105

    with TestClient(app) as client:
        unknown_member = client.post(
            "/auth/register", json={"identifier": "user@example.com", "password": password, "role": "admin"}
        )
        # A camelCase spelling of an optional field must not resolve to its default,
        # which would register the account with no display name.
        stale_casing = client.post(
            "/auth/register", json={"identifier": "user@example.com", "password": password, "displayName": "User"}
        )
        assert client.post("/auth/register", json={"identifier": "user@example.com", "password": password}).status_code
        assert accounts.verification_token is not None
        confirm = client.post("/auth/verification/confirm", json={"token": accounts.verification_token, "extra": 1})
        credentials = client.post(
            "/auth/token", json={"identifier": "user@example.com", "password": password, "remember": True}
        )

    assert unknown_member.status_code == HTTP_400_BAD_REQUEST, unknown_member.text
    assert stale_casing.status_code == HTTP_400_BAD_REQUEST, stale_casing.text
    assert confirm.status_code == HTTP_400_BAD_REQUEST, confirm.text
    assert credentials.status_code == HTTP_400_BAD_REQUEST, credentials.text


def test_native_guard_layers_remain_cumulative_for_http_and_websocket_with_child_policy() -> None:
    events: list[str] = []

    def probe(name: str) -> Callable[[ASGIConnection, object], None]:
        def guard(_connection: ASGIConnection, _handler: object) -> None:
            events.append(name)

        return guard

    class GuardedController(Controller):
        path = "/guarded"
        guards: ClassVar = [probe("controller")]

        @get("/http", guards=[probe("handler")], auth=public())
        async def http_handler(self) -> dict[str, bool]:
            return {"ok": True}

        @websocket("/ws", guards=[probe("handler")], auth=public())
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
    scope["user"] = Principal(id="user-1")
    scope["auth"] = SecurityContext(
        session=NullSessionHandle(), authorization=AuthorizationSnapshot(scopes={"reports:read"})
    )
    connection = connection_type(scope=scope, receive=receive, send=send)  # type: ignore[operator]

    requires_scope("reports:read")(connection, _RouteHandler())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("extraction", "outcome", "expected_code", "expected_reason"),
    [
        (NoCredentials(), NoCredentials(), 4401, "authentication_required"),
        (InvalidCredentials(), NoCredentials(), 4401, "authentication_required"),
        (PresentedCredential("credential"), VerificationUnavailable(), 1013, "verification_unavailable"),
    ],
)
def test_websocket_authentication_denial_closes_before_accept_handler_and_di(
    extraction: object, outcome: object, expected_code: int, expected_reason: str
) -> None:
    events: list[str] = []
    slot = _Slot(extraction)
    authenticator = _Authenticator(outcome)

    async def provide_resource() -> str:
        events.append("dependency")
        return "resource"

    @websocket("/ws")
    async def handler(socket: WebSocket, resource: NamedDependency[str]) -> None:
        events.append(resource)
        await socket.accept()

    app = Litestar(
        route_handlers=[handler],
        dependencies={"resource": Provide(provide_resource)},
        openapi_config=None,
        plugins=[
            SecurityPlugin(
                SecurityConfig(
                    slots=(slot,),  # type: ignore[arg-type]
                    mechanisms=(
                        AuthenticationMechanism(
                            authenticator=authenticator,  # type: ignore[arg-type]
                            resolver=_Resolver(),
                        ),
                    ),
                    websocket=WebSocketSecurityConfig(),
                )
            )
        ],
    )

    with TestClient(app) as client, pytest.raises(WebSocketDisconnect) as captured, client.websocket_connect("/ws"):
        pass

    assert captured.value.code == expected_code
    assert captured.value.detail == expected_reason
    assert events == []


def test_websocket_native_guard_denial_closes_before_handler_and_di() -> None:
    events: list[str] = []

    async def provide_resource() -> str:
        events.append("dependency")
        return "resource"

    @websocket("/ws", guards=[requires_scope("reports:write")])
    async def handler(socket: WebSocket, resource: NamedDependency[str]) -> None:
        events.append(resource)
        await socket.accept()

    app = Litestar(
        route_handlers=[handler],
        dependencies={"resource": Provide(provide_resource)},
        openapi_config=None,
        plugins=[
            SecurityPlugin(
                SecurityConfig(
                    slots=(_DependencySlot(),),
                    mechanisms=(
                        AuthenticationMechanism(
                            authenticator=_DependencyAuthenticator(),
                            resolver=_DependencyResolver(Principal(id="subject")),
                        ),
                    ),
                    websocket=WebSocketSecurityConfig(),
                )
            )
        ],
    )

    with TestClient(app) as client, pytest.raises(WebSocketDisconnect) as captured, client.websocket_connect("/ws"):
        pass

    assert captured.value.code == 4403
    assert captured.value.detail == "authorization_denied"
    assert events == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("scope_changes", "websocket_config", "expected_code", "expected_reason"),
    [
        (
            {"headers": [(b"origin", b"https://wrong.example")]},
            WebSocketSecurityConfig(allowed_origins=frozenset({"https://trusted.example"})),
            4403,
            "origin_denied",
        ),
        (
            {"headers": [(b"origin", b"https://trusted.example")], "query_string": b"ticket=not-configured"},
            WebSocketSecurityConfig(allowed_origins=frozenset({"https://trusted.example"})),
            4401,
            "authentication_required",
        ),
    ],
)
async def test_websocket_transport_failures_are_mapped_before_application(
    scope_changes: dict[str, object],
    websocket_config: WebSocketSecurityConfig,
    expected_code: int,
    expected_reason: str,
) -> None:
    messages: list[Message] = []
    app_called = False

    async def app(_scope: Scope, _receive: Receive, _send: Send) -> None:
        nonlocal app_called
        app_called = True

    async def send(message: Message) -> None:
        messages.append(message)

    runtime, _, _ = _runtime()
    runtime = replace(runtime, websocket=websocket_config)
    scope = _scope("websocket", route_handler=_WebSocketRouteHandler())
    scope.update(cast("dict[str, Any]", scope_changes))
    await SecurityMiddleware(app=app, config=runtime)(scope, _receive, send)

    assert messages == [{"type": "websocket.close", "code": expected_code, "reason": expected_reason}]
    assert app_called is False


@pytest.mark.anyio
async def test_websocket_revocation_hook_receives_secret_free_session_binding() -> None:
    observed: list[object] = []
    success = Authenticated(
        claims="subject-1",
        evidence=AuthenticationEvidence(mechanism="bearer", slot="authorization.bearer", authenticated_at=_NOW),
    )

    class RevocationSource:
        async def wait(self, binding: object) -> None:
            observed.append(binding)

    runtime, _, _ = _runtime(success)
    runtime = replace(runtime, websocket=WebSocketSecurityConfig(revocation_source=RevocationSource()))

    async def app(_scope: Scope, _receive: Receive, _send: Send) -> None:
        await anyio.sleep_forever()

    messages: list[Message] = []

    async def send(message: Message) -> None:
        messages.append(message)

    scope = _scope("websocket", route_handler=_WebSocketRouteHandler())
    scope["session"] = {"_litestar_security": {"session_id": "session-1"}}
    await SecurityMiddleware(app=app, config=runtime)(scope, _receive, send)

    binding = observed[0]
    assert binding.subject_id == "subject-1"
    assert binding.session_id == "session-1"
    assert binding.credential_ids == frozenset({"bearer:authorization.bearer"})
    assert messages == [{"type": "websocket.close", "code": 4401, "reason": "credential_revoked"}]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("snapshot", "expected_message", "guards_present"),
    [
        (AuthorizationSnapshot(scopes={"reports:read"}), None, True),
        (AuthorizationSnapshot(scopes={"reports:read"}), None, False),
        (object(), {"type": "websocket.close", "code": 1013, "reason": "verification_unavailable"}, True),
    ],
)
async def test_websocket_authorization_refresh_replaces_snapshot_and_rechecks_guards(
    snapshot: object,
    expected_message: dict[str, object] | None,
    guards_present: bool,  # noqa: FBT001 - parametrized guard-state matrix
) -> None:
    refreshed = anyio.Event()
    sleep_calls = 0
    success = Authenticated(
        claims="subject-1",
        evidence=AuthenticationEvidence(mechanism="bearer", slot="authorization.bearer", authenticated_at=_NOW),
    )

    class Refresher:
        async def refresh(self, **_kwargs: object) -> object:
            refreshed.set()
            return snapshot

    async def sleeper(_delay: float) -> None:
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls > 1:
            await anyio.sleep_forever()

    runtime, _, _ = _runtime(success)
    runtime = replace(
        runtime,
        websocket=WebSocketSecurityConfig(
            refresh_interval=timedelta(seconds=1), snapshot_refresher=Refresher(), sleeper=sleeper
        ),
    )
    route_handler = _WebSocketRouteHandler(guards_present=guards_present)
    observed_scope: list[Scope] = []

    async def app(scope: Scope, _receive: Receive, _send: Send) -> None:
        observed_scope.append(scope)
        await refreshed.wait()
        if expected_message is not None:
            await anyio.sleep_forever()

    messages: list[Message] = []

    async def send(message: Message) -> None:
        messages.append(message)

    await SecurityMiddleware(app=app, config=runtime)(_scope("websocket", route_handler=route_handler), _receive, send)

    assert messages == ([] if expected_message is None else [expected_message])
    if expected_message is None:
        assert observed_scope[0]["auth"].authorization == snapshot
        assert route_handler.authorization_calls == int(guards_present)


@pytest.mark.anyio
@pytest.mark.parametrize("error", [NotAuthorizedException(), PermissionDeniedException()])
async def test_websocket_handler_authorization_exceptions_map_to_4403(error: Exception) -> None:
    async def app(_scope: Scope, _receive: Receive, _send: Send) -> None:
        raise error

    messages: list[Message] = []

    async def send(message: Message) -> None:
        messages.append(message)

    runtime, _, _ = _runtime()
    await SecurityMiddleware(app=app, config=runtime)(
        _scope("websocket", route_handler=_WebSocketRouteHandler()), _receive, send
    )

    assert messages == [{"type": "websocket.close", "code": 4403, "reason": "authorization_denied"}]


def _runtime_ticket_record() -> WebSocketTicketRecord:
    return WebSocketTicketRecord(
        ticket_id="aWlpaWlpaWlpaWlpaWlpaQ",
        digest=b"d" * 32,
        subject_id="subject-1",
        route_name="socket",
        origin="https://trusted.example",
        restrictions=CredentialRestrictions(scopes=frozenset({"reports:read"})),
        policy_fingerprint="f" * 64,
        issued_at=_NOW,
        expires_at=_NOW + timedelta(seconds=30),
    )


@pytest.mark.anyio
async def test_websocket_ticket_merge_requires_the_same_authenticated_subject() -> None:
    runtime, _, _ = _runtime()

    async def app(_scope: Scope, _receive: Receive, _send: Send) -> None:
        return None

    middleware = SecurityMiddleware(app=app, config=runtime)
    context = SecurityContext(
        session=NullSessionHandle(), authorization=AuthorizationSnapshot(scopes={"reports:read", "reports:write"})
    )
    principal, merged = await middleware._merge_ticket(  # noqa: SLF001 - exercises the ticket/runtime merge boundary
        _runtime_ticket_record(), principal=Principal(id="subject-1"), context=context, session=context.session
    )

    assert principal.id == "subject-1"
    assert merged.authorization.scopes == frozenset({"reports:read"})
    with pytest.raises(NotAuthorizedException):
        await middleware._merge_ticket(  # noqa: SLF001 - exercises the ticket/runtime merge boundary
            _runtime_ticket_record(), principal=Principal(id="other-subject"), context=context, session=context.session
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("resolution", "expected_error"),
    [
        (AuthorizationSnapshot(scopes={"reports:read", "reports:write"}), None),
        (VerificationUnavailable(), ServiceUnavailableException),
        (InvalidCredentials(), NotAuthorizedException),
    ],
)
async def test_anonymous_websocket_ticket_uses_authorization_resolver(
    resolution: object, expected_error: type[Exception] | None
) -> None:
    class Resolver:
        async def resolve(self, _principal: Principal[object]) -> object:
            return resolution

    runtime = SecurityRuntimeConfig(registry=AuthenticationRegistry(authorization_resolver=Resolver()))

    async def app(_scope: Scope, _receive: Receive, _send: Send) -> None:
        return None

    middleware = SecurityMiddleware(app=app, config=runtime)
    context = SecurityContext(session=NullSessionHandle())
    if expected_error is not None:
        with pytest.raises(expected_error):
            await middleware._merge_ticket(  # noqa: SLF001 - exercises the ticket/runtime merge boundary
                _runtime_ticket_record(), principal=Principal(id=None), context=context, session=context.session
            )
        return

    principal, merged = await middleware._merge_ticket(  # noqa: SLF001 - exercises the ticket/runtime merge boundary
        _runtime_ticket_record(), principal=Principal(id=None), context=context, session=context.session
    )
    assert principal.id == "subject-1"
    assert merged.authorization.scopes == frozenset({"reports:read"})


@pytest.mark.anyio
async def test_public_websocket_and_http_install_the_same_anonymous_context_with_async_client() -> None:
    observed: list[tuple[Principal[object], SecurityContext]] = []

    @get("/http", auth=public())
    async def http_handler(request: Request) -> dict[str, bool]:
        observed.append((request.user, request.auth))
        return {"anonymous": not request.user.is_authenticated}

    @websocket("/ws", auth=public())
    async def websocket_handler(socket: WebSocket) -> None:
        observed.append((socket.user, socket.auth))
        await socket.accept()
        await socket.send_json({"anonymous": not socket.user.is_authenticated})
        await socket.close()

    app = Litestar(
        route_handlers=[http_handler, websocket_handler],
        plugins=[SecurityPlugin(SecurityConfig(websocket=WebSocketSecurityConfig()))],
    )
    async with AsyncTestClient(app=app) as client:
        assert (await client.get("/http")).json() == {"anonymous": True}
        session = await client.websocket_connect("/ws")
        with session as socket:
            assert socket.receive_json() == {"anonymous": True}

    assert len(observed) == 2
    assert all(
        isinstance(principal, Principal) and isinstance(context, SecurityContext) for principal, context in observed
    )


def test_websocket_native_session_is_read_only_and_never_persisted() -> None:
    backend = _MemorySessionBackend()
    backend.stored = {"existing": "value"}

    @websocket("/ws", auth=public())
    async def websocket_handler(socket: WebSocket) -> None:
        assert socket.auth.session.is_available
        assert not socket.auth.session.can_persist
        assert socket.auth.session.get("existing") == "value"
        for mutation in (
            lambda: socket.auth.session.set("new", "value"),
            lambda: socket.auth.session.pop("existing"),
            socket.auth.session.clear,
        ):
            with pytest.raises(SessionPersistenceUnavailableError, match="cannot persist"):
                mutation()
        await socket.accept()
        await socket.send_json({"existing": socket.auth.session.get("existing")})
        await socket.close()

    app = Litestar(
        route_handlers=[websocket_handler],
        middleware=[DefineMiddleware(SessionMiddleware, backend=backend)],
        openapi_config=None,
        plugins=[
            SecurityPlugin(
                SecurityConfig(
                    websocket=WebSocketSecurityConfig(allowed_origins=frozenset({"http://testserver.local"}))
                )
            )
        ],
    )
    with TestClient(app) as client, client.websocket_connect("/ws") as socket:
        assert socket.receive_json() == {"existing": "value"}

    assert backend.stored == {"existing": "value"}
    assert backend.store_calls == 0


def test_websocket_message_loop_performs_security_work_once() -> None:
    slot = _Slot(PresentedCredential("subject"))
    authenticator = _Authenticator(
        Authenticated(
            claims="subject",
            evidence=AuthenticationEvidence(
                mechanism="bearer", slot="authorization.bearer", authenticated_at=datetime.now(timezone.utc)
            ),
        )
    )

    class CountingResolver:
        def __init__(self) -> None:
            self.calls = 0

        async def resolve(self, claims: str) -> Principal[object]:
            self.calls += 1
            return Principal(id=claims)

    resolver = CountingResolver()

    @websocket("/ws")
    async def websocket_handler(socket: WebSocket) -> None:
        await socket.accept()
        for _ in range(2):
            await socket.send_text(await socket.receive_text())
        await socket.close()

    app = Litestar(
        route_handlers=[websocket_handler],
        openapi_config=None,
        plugins=[
            SecurityPlugin(
                SecurityConfig(
                    slots=(slot,),  # type: ignore[arg-type]
                    mechanisms=(
                        AuthenticationMechanism(authenticator=authenticator, resolver=resolver),  # type: ignore[arg-type]
                    ),
                    websocket=WebSocketSecurityConfig(),
                )
            )
        ],
    )
    with TestClient(app) as client, client.websocket_connect("/ws") as socket:
        for value in ("first", "second"):
            socket.send_text(value)
            assert socket.receive_text() == value

    assert (slot.calls, authenticator.calls, resolver.calls) == (1, 1, 1)


@pytest.mark.anyio
async def test_matching_one_time_ticket_authenticates_cross_origin_websocket_once() -> None:
    store = InMemoryWebSocketTicketStore()
    slot = _Slot(NoCredentials())
    authenticator = _Authenticator(NoCredentials())

    @websocket("/ws", name="reports.socket")
    async def handler(socket: WebSocket) -> None:
        await socket.accept()
        await socket.send_json({
            "subject": socket.user.id,
            "mechanisms": [evidence.mechanism for evidence in socket.auth.evidence],
        })
        await socket.close()

    app = Litestar(
        route_handlers=[handler],
        openapi_config=None,
        plugins=[
            SecurityPlugin(
                SecurityConfig(
                    slots=(slot,),  # type: ignore[arg-type]
                    mechanisms=(
                        AuthenticationMechanism(
                            authenticator=authenticator,  # type: ignore[arg-type]
                            resolver=_Resolver(),
                        ),
                    ),
                    websocket=WebSocketSecurityConfig(
                        allowed_origins=frozenset({"https://browser.example"}), ticket_store=store
                    ),
                )
            )
        ],
    )
    now = datetime.now(timezone.utc)
    service = WebSocketTicketService(store=store, clock=lambda: now)
    compiled_handler = next(
        route.route_handler
        for route in app.routes
        if getattr(route, "path", None) == "/ws"  # type: ignore[attr-defined]
    )
    plan = compiled_handler.opt["litestar_security_plan"]

    issued = await service.issue(
        principal=Principal(id="subject-1"),
        context=SecurityContext(session=NullSessionHandle()),
        route_name="reports.socket",
        origin="https://browser.example",
        policy_fingerprint=websocket_policy_fingerprint(plan),
    )
    async with AsyncTestClient(app=app) as client:
        session = await client.websocket_connect(
            f"/ws?ticket={issued.value}", headers={"Origin": "https://browser.example"}
        )
        with session as socket:
            message = socket.receive_json()
        replay_session = await client.websocket_connect(
            f"/ws?ticket={issued.value}", headers={"Origin": "https://browser.example"}
        )
        with pytest.raises(WebSocketDisconnect) as replay, replay_session:
            pass

    assert message == {"subject": "subject-1", "mechanisms": ["websocket-ticket"]}
    assert replay.value.code == 4401


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
        principal: NamedDependency[Principal[_DependencyUser]], security_context: NamedDependency[SecurityContext]
    ) -> dict[str, object]:
        return {"id": principal.id, "has_user": principal.has_user, "evidence": security_context.evidence[0].mechanism}

    @get("/user")
    async def user_handler(current_user: CurrentUser[_DependencyUser]) -> str:
        return current_user.name

    with TestClient(
        Litestar(
            route_handlers=[principal_handler, user_handler], openapi_config=None, plugins=[_identity_plugin(principal)]
        )
    ) as client:
        principal_response = client.get("/principal")
        user_response = client.get("/user")

    assert principal_response.json() == expected_principal
    assert user_response.status_code == expected_user_status
    if expected_user is not None:
        assert user_response.text == expected_user
