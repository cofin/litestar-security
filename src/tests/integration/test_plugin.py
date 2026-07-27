"""Integration tests for plugin ownership, session wiring, and CLI behavior."""

from __future__ import annotations

import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from importlib.metadata import entry_points
from secrets import token_hex
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, ClassVar, Literal, cast

import anyio.lowlevel
import click
import pytest
from click.testing import CliRunner
from litestar import Controller, Litestar, Router, WebSocket, asgi, get, post, route, websocket
from litestar.config.app import AppConfig
from litestar.config.csrf import CSRFConfig
from litestar.di import Provide
from litestar.enums import HttpMethod, ScopeType
from litestar.exceptions import ImproperlyConfiguredException
from litestar.middleware import DefineMiddleware
from litestar.middleware.session.base import SessionMiddleware
from litestar.middleware.session.client_side import CookieBackendConfig
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.openapi import OpenAPIConfig
from litestar.openapi.controller import OpenAPIController
from litestar.openapi.plugins import JsonRenderPlugin
from litestar.openapi.spec import Components, OpenAPIResponse, SecurityScheme
from litestar.plugins import CLIPlugin, CLIPluginProtocol, InitPlugin, ReceiveRoutePlugin
from litestar.routes import ASGIRoute, BaseRoute, HTTPRoute, WebSocketRoute
from litestar.testing import TestClient

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security._cli import register, security_group
from litestar_security.accounts import (
    LifecycleAccepted,
    LocalAuth,
    RegistrationPolicy,
    SessionBindingConfig,
    SessionSummary,
)
from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationPolicy,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    SecurityMiddlewareWrapper,
    SecurityRuntimePlan,
    VerificationUnavailable,
    all_of,
    any_of,
    at_least,
    mechanism,
    optional,
    public,
    required,
    security,
)
from litestar_security.config import ExternalCSRF
from litestar_security.context import AuthenticationEvidence, Principal, SecurityContext
from litestar_security.plugin import CurrentUser, PrincipalDependency, SecurityContextDependency
from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JWTValidationConfig,
    LocalJWKSConfig,
    LocalKeyRing,
    SigningKey,
    VerificationKey,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar.middleware.session.base import BaseSessionBackend
    from litestar.types import Receive, Scope, Send


class _CompilerSlot:
    def __init__(self, name: str) -> None:
        self.name = name

    def extract(self, connection: Any) -> object:
        value = connection.headers.get(f"x-auth-{self.name.removeprefix('slot-')}")
        if value is None:
            return NoCredentials()
        if value != "valid":
            return InvalidCredentials()
        return PresentedCredential("user")


class _CompilerAuthenticator:
    participates_by_default = True

    def __init__(self, name: str, slot: str) -> None:
        self.name = name
        self.slot = slot

    async def authenticate(self, credential: object, _connection: object) -> Authenticated[str]:
        return Authenticated(
            claims=cast("str", credential),
            evidence=AuthenticationEvidence(
                mechanism=self.name, slot=self.slot, authenticated_at=datetime(2026, 7, 26, tzinfo=timezone.utc)
            ),
        )


class _CompilerResolver:
    async def resolve(self, claims: str) -> Principal[object]:
        return Principal(id=claims)


def _compiler_config(  # noqa: PLR0913
    *,
    openapi_policy: AuthenticationPolicy | None = None,
    names: tuple[str, ...] = ("a", "b"),
    scheme_names: dict[str, str] | None = None,
    scheme_types: dict[str, Literal["apiKey", "http", "mutualTLS", "oauth2", "openIdConnect"]] | None = None,
    max_openapi_combinations: int = 32,
    session_names: frozenset[str] = frozenset(),
    csrf_config: CSRFConfig | None = None,
    external_csrf: ExternalCSRF | None = None,
) -> SecurityConfig[object]:
    slots = tuple(_CompilerSlot(name=f"slot-{name}") for name in names)
    mechanisms = tuple(
        AuthenticationMechanism(
            authenticator=_CompilerAuthenticator(name=name, slot=f"slot-{name}"),  # type: ignore[arg-type]
            resolver=_CompilerResolver(),
            scheme_name=(scheme_names or {}).get(name, name),
            security_scheme=SecurityScheme(
                type=(scheme_types or {}).get(name, "http"),
                scheme="bearer" if (scheme_types or {}).get(name, "http") == "http" else None,
                open_id_connect_url=(
                    "https://issuer.example/.well-known/openid-configuration"
                    if (scheme_types or {}).get(name) == "openIdConnect"
                    else None
                ),
            ),
            session_capable=name in session_names,
        )
        for name in names
    )
    return SecurityConfig(
        slots=slots,  # type: ignore[arg-type]
        mechanisms=mechanisms,
        openapi_policy=openapi_policy,
        max_openapi_combinations=max_openapi_combinations,
        csrf_config=csrf_config,
        external_csrf=external_csrf,
    )


def _http_plan(app: Litestar, path: str, method: str = "GET") -> SecurityRuntimePlan:
    route_value = next(
        route_value for route_value in app.routes if isinstance(route_value, HTTPRoute) and route_value.path == path
    )
    return cast("SecurityRuntimePlan", route_value.route_handler_map[method][0].opt["litestar_security_plan"])


def _operation_security(app: Litestar, path: str) -> list[dict[str, list[str]]] | None:
    operation = app.openapi_schema.paths[path].get
    assert operation is not None
    return cast("list[dict[str, list[str]]] | None", operation.security)


def _local_session_accounts() -> Any:
    capability_names = (
        "compare_and_replace_password",
        "consume_and_reset",
        "consume_and_verify",
        "create",
        "current_epoch",
        "find_for_login",
        "get",
        "get_by_id",
        "get_password_state",
        "issue",
        "list_for_account",
        "rebind",
        "register_login_method",
        "replace_password_and_bump_epoch",
        "revoke",
        "revoke_login_method",
        "revoke_other_sessions",
        "revoke_session_for_account",
        "revoke_sessions_for_account",
        "touch",
    )
    return SimpleNamespace(**{name: lambda *_args, **_kwargs: None for name in capability_names})


def _native_session_backend(  # noqa: PLR0913
    kind: Literal["client", "server"],
    *,
    key: str = "native-session",
    max_age: int = 600,
    scopes: set[ScopeType] | None = None,
    secure: bool = True,
    httponly: bool = True,
) -> tuple[BaseSessionBackend[Any], DefineMiddleware]:
    configured_scopes = scopes if scopes is not None else {ScopeType.HTTP, ScopeType.WEBSOCKET}
    if kind == "client":
        config = CookieBackendConfig(
            secret=bytes(range(16)),
            key=key,
            max_age=max_age,
            scopes=configured_scopes,
            secure=secure,
            httponly=httponly,
        )
    else:
        config = ServerSideSessionConfig(
            key=key, max_age=max_age, scopes=configured_scopes, secure=secure, httponly=httponly
        )
    middleware = config.middleware
    return cast("BaseSessionBackend[Any]", middleware.kwargs["backend"]), middleware


def _local_session_auth(*, csrf: CSRFConfig | ExternalCSRF, binding: SessionBindingConfig | None = None) -> Any:
    return LocalAuth.session(
        accounts=cast("Any", _local_session_accounts()),
        csrf=csrf,
        binding=binding or SessionBindingConfig(pepper=b"binding-pepper-for-plugin-tests!", max_age=600),
    )


def test_plugin_constructs_default_config() -> None:
    plugin = SecurityPlugin()

    assert isinstance(plugin.config, SecurityConfig)


def test_plugin_preserves_supplied_config_by_identity() -> None:
    config = SecurityConfig()

    assert SecurityPlugin(config).config is config


def test_plugin_publishes_canonical_public_local_jwks(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    ed_private, _ed_public = jwt_key_material["EdDSA"]
    _es_private, es_public = jwt_key_material["ES256"]
    generated = SigningKey(key_id="z-active", algorithm="EdDSA", private_key=ed_private)
    supplied_jwk = {
        **dict(cast("Mapping[str, object]", generated.public_jwk)),
        "internal_path": "/run/secrets/signing.pem",
        "x5c": ["untrusted-certificate"],
        "x5u": "https://untrusted.example/certificate",
    }
    ring = LocalKeyRing(
        issuer="https://issuer.example",
        active_signing_key=SigningKey(
            key_id="z-active", algorithm="EdDSA", private_key=ed_private, public_jwk=cast("Any", supplied_jwk)
        ),
        verification_keys=(VerificationKey(key_id="a-retained", algorithm="ES256", key=es_public),),
    )
    jwks = LocalJWKSConfig(key_set=ring.verification_key_set)
    security_config = _compiler_config()
    security_config.local_jwks = jwks
    app = Litestar(
        route_handlers=[],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(security_config)],
    )

    with TestClient(app) as client:
        response = client.get("/auth/.well-known/jwks.json")
        conditional_responses = tuple(
            client.get("/auth/.well-known/jwks.json", headers={"If-None-Match": value})
            for value in (
                response.headers["etag"],
                f"W/{response.headers['etag']}",
                f'"other", {response.headers["etag"]}',
                "*",
            )
        )
        modified = client.get("/auth/.well-known/jwks.json", headers={"If-None-Match": '"other"'})

    assert response.status_code == 200
    assert response.content == jwks.canonical_bytes
    assert response.json()["keys"] == sorted(response.json()["keys"], key=lambda key: key["kid"])
    assert response.headers["cache-control"] == "public, max-age=300"
    assert response.headers["content-type"] == "application/jwk-set+json"
    assert response.headers["etag"] == jwks.etag
    assert modified.status_code == 200
    for not_modified in conditional_responses:
        assert not_modified.status_code == 304
        assert not not_modified.content
        assert not_modified.headers["cache-control"] == response.headers["cache-control"]
        assert not_modified.headers["etag"] == response.headers["etag"]
    assert _http_plan(app, "/auth/.well-known/jwks.json") == SecurityRuntimePlan(
        authenticate=False, csrf_required=False
    )
    assert _operation_security(app, "/auth/.well-known/jwks.json") == [{}]
    assert not {
        "d",
        "dp",
        "dq",
        "internal_path",
        "k",
        "oth",
        "p",
        "q",
        "qi",
        "x5c",
        "x5t",
        "x5t#S256",
        "x5u",
    }.intersection(key_name for key in response.json()["keys"] for key_name in key)
    assert ed_private not in response.content
    operation = app.openapi_schema.paths["/auth/.well-known/jwks.json"].get
    assert operation is not None
    assert operation.responses is not None
    success = operation.responses["200"]
    not_modified_schema = operation.responses["304"]
    assert success.content is not None
    assert tuple(success.content) == ("application/jwk-set+json",)
    assert success.headers is not None
    assert {"Cache-Control", "ETag"}.issubset(success.headers)
    assert not_modified_schema.content is None


def test_local_jwks_rotation_replaces_cached_representation(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    ed_private, _ed_public = jwt_key_material["EdDSA"]
    es_private, _es_public = jwt_key_material["ES256"]
    old_ring = LocalKeyRing(
        issuer="https://issuer.example",
        active_signing_key=SigningKey(key_id="old", algorithm="EdDSA", private_key=ed_private),
    )
    new_ring = LocalKeyRing(
        issuer="https://issuer.example",
        active_signing_key=SigningKey(key_id="new", algorithm="ES256", private_key=es_private),
        verification_keys=(old_ring.active_signing_key.as_verification_key(),),
    )
    old = LocalJWKSConfig(key_set=old_ring.verification_key_set, route_prefix="/identity/", cache_max_age=0)
    rotated = LocalJWKSConfig(key_set=new_ring.verification_key_set, route_prefix="/identity", cache_max_age=60)

    def fetch(config: LocalJWKSConfig) -> Any:
        app = Litestar(
            route_handlers=[], openapi_config=None, plugins=[SecurityPlugin(SecurityConfig(local_jwks=config))]
        )
        with TestClient(app) as client:
            return client.get("/identity/.well-known/jwks.json")

    old_response = fetch(old)
    rotated_response = fetch(rotated)

    assert old.path == rotated.path == "/identity/.well-known/jwks.json"
    assert old.etag != rotated.etag
    assert old.canonical_bytes != rotated.canonical_bytes
    assert old_response.content == old.canonical_bytes
    assert old_response.headers["cache-control"] == "public, max-age=0"
    assert rotated_response.content == rotated.canonical_bytes
    assert rotated_response.headers["cache-control"] == "public, max-age=60"
    assert [key["kid"] for key in rotated.document["keys"]] == ["new", "old"]


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("hmac-only", "asymmetric"),
        ("negative-max-age", "cache_max_age"),
        ("excessive-max-age", "cache_max_age"),
        ("boolean-max-age", "cache_max_age"),
        ("relative-prefix", "route_prefix"),
        ("root-prefix", "route_prefix"),
        ("parameter-prefix", "route_prefix"),
        ("dot-prefix", "route_prefix"),
    ],
)
def test_local_jwks_rejects_unsafe_publication_configuration(
    case: str, match: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    private_key, _public_key = jwt_key_material["EdDSA"]
    signing_key = SigningKey(key_id="active", algorithm="EdDSA", private_key=private_key)
    key_set = LocalKeyRing(issuer="https://issuer.example", active_signing_key=signing_key).verification_key_set
    if case == "hmac-only":
        secret, _ = jwt_key_material["HS256"]
        key_set = LocalKeyRing(
            issuer="https://issuer.example",
            active_signing_key=SigningKey(key_id="hmac", algorithm="HS256", private_key=secret),
        ).verification_key_set

    invalid_options: dict[str, Any] = {
        "negative-max-age": {"cache_max_age": -1},
        "excessive-max-age": {"cache_max_age": 86_401},
        "boolean-max-age": {"cache_max_age": bool(1)},
        "relative-prefix": {"route_prefix": "auth"},
        "root-prefix": {"route_prefix": "/"},
        "parameter-prefix": {"route_prefix": "/auth/{tenant}"},
        "dot-prefix": {"route_prefix": "/auth/../identity"},
    }.get(case, {})

    with pytest.raises(ImproperlyConfiguredException, match=match):
        LocalJWKSConfig(key_set=key_set, **invalid_options)


def test_config_freezes_authentication_collections() -> None:
    slots: list[Any] = []
    mechanisms: list[Any] = []

    config = SecurityConfig(slots=slots, mechanisms=mechanisms)

    assert config.slots == ()
    assert config.mechanisms == ()
    slots.append(object())
    mechanisms.append(object())
    assert config.slots == ()
    assert config.mechanisms == ()


def test_plugin_is_an_init_and_cli_plugin() -> None:
    plugin = SecurityPlugin()
    app = Litestar(plugins=[plugin])

    assert isinstance(plugin, InitPlugin)
    assert isinstance(plugin, CLIPlugin)
    assert isinstance(plugin, CLIPluginProtocol)
    assert any(registered is plugin for registered in app.plugins.cli)


def test_plugin_receives_routes_and_attaches_public_runtime_plan() -> None:
    @get("/", **security(public()))
    async def handler() -> None:
        return None

    plugin = SecurityPlugin()
    app = Litestar(route_handlers=[handler], openapi_config=None, plugins=[plugin])
    route = next(route for route in app.routes if isinstance(route, HTTPRoute))
    route_handler = route.route_handler_map["GET"][0]

    assert isinstance(plugin, ReceiveRoutePlugin)
    assert route_handler.opt["litestar_security_plan"] == SecurityRuntimePlan(authenticate=False, csrf_required=False)


def test_route_policy_uses_native_nearest_owner_inheritance() -> None:
    @get("/application")
    async def application_handler() -> None:
        return None

    @get("/owned")
    async def router_handler() -> None:
        return None

    class PolicyController(Controller):
        path = "/controller"
        opt: ClassVar = security(required("b"))

        @get("/owned")
        async def owned(self) -> None:
            return None

        @get("/handler", **security(required("a")))
        async def handler_override(self) -> None:
            return None

    csrf_config = CSRFConfig(secret=token_hex())
    app = Litestar(
        route_handlers=[
            application_handler,
            Router(path="/router", route_handlers=[router_handler], opt=security(required("b"))),
            PolicyController,
        ],
        opt=security(required("a")),
        csrf_config=csrf_config,
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(_compiler_config(session_names=frozenset({"b"})))],
    )

    expected_by_path = {"/application": "a", "/router/owned": "b", "/controller/owned": "b", "/controller/handler": "a"}
    with TestClient(app) as client:
        for path, mechanism_name in expected_by_path.items():
            plan = _http_plan(app, path)
            route_value = next(
                route_value
                for route_value in app.routes
                if isinstance(route_value, HTTPRoute) and route_value.path == path
            )
            route_opt = route_value.route_handler_map["GET"][0].opt
            assert plan.participant_names == frozenset({mechanism_name})
            assert plan.csrf_required is (mechanism_name == "b")
            assert plan.csrf_enforcement == ("native" if mechanism_name == "b" else None)
            assert route_opt.get(csrf_config.exclude_from_csrf_key) is (None if mechanism_name == "b" else True)
            assert _operation_security(app, path) == [{mechanism_name: []}]
            assert client.get(path, headers={f"x-auth-{mechanism_name}": "valid"}).status_code == 200
            assert client.get(path).status_code == 401


def test_http_methods_and_options_receive_distinct_compiled_plans() -> None:
    @get("/resource", opt=security(public()))
    async def read_resource() -> None:
        return None

    @post("/resource", opt=security(required("b"), csrf_required=True))
    async def write_resource() -> None:
        return None

    app = Litestar(
        route_handlers=[read_resource, write_resource],
        csrf_config=CSRFConfig(secret=token_hex()),
        openapi_config=None,
        plugins=[SecurityPlugin(_compiler_config())],
    )

    assert not _http_plan(app, "/resource", "GET").authenticate
    assert _http_plan(app, "/resource", "POST").participant_names == frozenset({"b"})
    assert _http_plan(app, "/resource", "POST").csrf_required is True
    assert not _http_plan(app, "/resource", "OPTIONS").authenticate
    assert _http_plan(app, "/resource", "OPTIONS").csrf_required is False


def test_websocket_compiles_runtime_only_and_explicit_asgi_policy_fails() -> None:
    @websocket("/socket", opt=security(required("b")))
    async def socket_handler(socket: WebSocket) -> None:
        del socket

    app = Litestar(route_handlers=[socket_handler], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])
    socket_route = next(route_value for route_value in app.routes if isinstance(route_value, WebSocketRoute))

    assert socket_route.route_handler.opt["litestar_security_plan"].participant_names == frozenset({"b"})
    assert not hasattr(socket_route.route_handler, "security")

    @asgi("/mount", opt=security(public()), copy_scope=True)
    async def mounted_app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive, send

    with pytest.raises(ImproperlyConfiguredException, match=r"Raw ASGI.*asgi /mount"):
        Litestar(route_handlers=[mounted_app], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])

    @websocket("/anonymous")
    async def anonymous_socket(socket: WebSocket) -> None:
        del socket

    anonymous_app = Litestar(route_handlers=[anonymous_socket], openapi_config=None, plugins=[SecurityPlugin()])
    anonymous_route = next(
        route_value for route_value in anonymous_app.routes if isinstance(route_value, WebSocketRoute)
    )

    assert not anonymous_route.route_handler.opt["litestar_security_plan"].authenticate


def test_asgi_default_dynamic_registration_and_receive_route_are_idempotent() -> None:
    @asgi("/mount", copy_scope=True)
    async def mounted_app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive, send

    plugin = SecurityPlugin(_compiler_config())
    app = Litestar(route_handlers=[mounted_app], openapi_config=None, plugins=[plugin])
    mount_route = next(route_value for route_value in app.routes if isinstance(route_value, ASGIRoute))
    mount_plan = mount_route.route_handler.opt["litestar_security_plan"]

    @get("/dynamic", opt=security(required("b")))
    async def dynamic_handler() -> None:
        return None

    app.register(dynamic_handler)
    dynamic_plan = _http_plan(app, "/dynamic")
    dynamic_route = next(
        route_value
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path == "/dynamic"
    )
    plugin.receive_route(dynamic_route)

    assert mount_plan.participant_names == frozenset({"a", "b"})
    assert dynamic_plan.participant_names == frozenset({"b"})
    assert _http_plan(app, "/dynamic") is dynamic_plan


def test_generated_and_explicit_options_are_distinguished() -> None:
    @post("/generated", opt=security(public(), csrf_required=True))
    async def generated() -> None:
        return None

    @route("/explicit", http_method=HttpMethod.OPTIONS, opt=security(required("b")))
    async def explicit() -> None:
        return None

    app = Litestar(
        route_handlers=[generated, explicit],
        csrf_config=CSRFConfig(secret=token_hex()),
        openapi_config=None,
        plugins=[SecurityPlugin(_compiler_config())],
    )

    assert not _http_plan(app, "/generated", "OPTIONS").authenticate
    assert _http_plan(app, "/generated", "OPTIONS").csrf_required is False
    assert _http_plan(app, "/explicit", "OPTIONS").participant_names == frozenset({"b"})


@pytest.mark.parametrize(
    ("openapi_config", "plugin_policy", "expected_path", "expected_participants"),
    [
        (OpenAPIConfig(title="Test", version="1.0"), None, "/schema/openapi.json", None),
        (
            OpenAPIConfig(title="Test", version="1.0", path="/docs"),
            required("b"),
            "/docs/openapi.json",
            frozenset({"b"}),
        ),
        (
            OpenAPIConfig(
                title="Test",
                version="1.0",
                openapi_router=Router(path="/reference", route_handlers=[], opt=security(required("a"))),
                render_plugins=[JsonRenderPlugin()],
            ),
            required("b"),
            "/reference/openapi.json",
            frozenset({"a"}),
        ),
    ],
)
def test_openapi_routes_use_default_configured_and_custom_router_policy(
    openapi_config: OpenAPIConfig,
    plugin_policy: AuthenticationPolicy | None,
    expected_path: str,
    expected_participants: frozenset[str] | None,
) -> None:
    @get("/application")
    async def application_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[application_handler],
        opt=security(required("a")),
        openapi_config=openapi_config,
        plugins=[SecurityPlugin(_compiler_config(openapi_policy=plugin_policy))],
    )
    plan = _http_plan(app, expected_path)

    assert plan.participant_names == expected_participants
    assert plan.authenticate is (expected_participants is not None)


@pytest.mark.parametrize(
    ("policy", "expected", "accepted", "rejected"),
    [
        (public(), [{}], (frozenset(), frozenset({"a"})), ()),
        (required("a"), [{"a": []}], (frozenset({"a"}),), (frozenset(), frozenset({"b"}))),
        (any_of("a", "b"), [{"a": []}, {"b": []}], (frozenset({"a"}), frozenset({"b"})), (frozenset(),)),
        (all_of("a", "b"), [{"a": [], "b": []}], (frozenset({"a", "b"}),), (frozenset({"a"}), frozenset({"b"}))),
        (optional(required("a")), [{}, {"a": []}], (frozenset(), frozenset({"a"})), (frozenset({"b"}),)),
        (
            at_least(2, "a", "b", "c"),
            [{"a": [], "b": []}, {"a": [], "c": []}, {"b": [], "c": []}],
            (frozenset({"a", "b"}), frozenset({"a", "c"}), frozenset({"b", "c"})),
            (frozenset({"a"}),),
        ),
        (
            required(mechanism("oidc", "reports:read")),
            [{"oidc": ["reports:read"]}],
            (frozenset({"oidc"}),),
            (frozenset(),),
        ),
    ],
)
def test_native_openapi_projection_matches_runtime_policy(
    policy: AuthenticationPolicy,
    expected: list[dict[str, list[str]]],
    accepted: tuple[frozenset[str], ...],
    rejected: tuple[frozenset[str], ...],
) -> None:
    @get("/resource", opt=security(policy))
    async def handler() -> None:
        return None

    config = _compiler_config(names=("a", "b", "c", "oidc"), scheme_types={"oidc": "openIdConnect"})
    app = Litestar(
        route_handlers=[handler],
        openapi_config=OpenAPIConfig(title="Test", version="1.0", render_plugins=[JsonRenderPlugin()]),
        plugins=[SecurityPlugin(config)],
    )
    route_handler = next(
        route_value.route_handler_map["GET"][0]
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path == "/resource"
    )

    assert route_handler.resolve_security() == expected
    assert _operation_security(app, "/resource") == expected
    assert [
        tuple((requirement.name, requirement.scopes) for requirement in alternative)
        for alternative in _http_plan(app, "/resource").alternatives
    ] == [
        tuple((name, tuple(scopes)) for name, scopes in alternative.items()) for alternative in expected if alternative
    ]
    with TestClient(app) as client:
        for names in accepted:
            response = client.get("/resource", headers={f"x-auth-{name}": "valid" for name in names})
            assert response.status_code == 200
        for names in rejected:
            response = client.get("/resource", headers={f"x-auth-{name}": "valid" for name in names})
            assert response.status_code == 401


def test_openapi_scope_and_combination_limits_fail_with_route_context() -> None:
    @get("/scoped", opt=security(required(mechanism("a", "read"))))
    async def scoped_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"a.*scopes.*GET /scoped"):
        Litestar(
            route_handlers=[scoped_handler],
            openapi_config=OpenAPIConfig(title="Test", version="1.0"),
            plugins=[SecurityPlugin(_compiler_config(names=("a",)))],
        )

    names = tuple(f"m{index}" for index in range(9))

    @get("/threshold", opt=security(at_least(2, *names)))
    async def threshold_handler() -> None:
        return None

    with pytest.raises(
        ImproperlyConfiguredException, match=r"at_least\(2\).*9 participants.*36.*cap 32.*GET /threshold"
    ):
        Litestar(
            route_handlers=[threshold_handler],
            openapi_config=OpenAPIConfig(title="Test", version="1.0"),
            plugins=[SecurityPlugin(_compiler_config(names=names))],
        )

    @get("/threshold", opt=security(at_least(2, *names)))
    async def threshold_success() -> None:
        return None

    app = Litestar(
        route_handlers=[threshold_success],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(_compiler_config(names=names, max_openapi_combinations=36))],
    )

    assert len(cast("list[object]", _operation_security(app, "/threshold"))) == 36


def test_account_dto_annotations_resolve_during_native_openapi_generation() -> None:
    @get("/sessions")
    async def session_handler() -> SessionSummary:
        raise NotImplementedError

    app = Litestar(route_handlers=[session_handler], openapi_config=OpenAPIConfig(title="Test", version="1.0"))

    assert app.openapi_schema.components is not None
    assert app.openapi_schema.components.schemas is not None
    assert "SessionSummary" in app.openapi_schema.components.schemas


def test_disabled_registration_adds_no_route_and_lifecycle_response_uses_native_202_schema(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    capabilities = SimpleNamespace(**{
        name: lambda: None
        for name in (
            "compare_and_replace_password",
            "consume_and_reset",
            "consume_and_verify",
            "current_epoch",
            "find_for_login",
            "get_by_id",
            "get_password_state",
            "issue",
            "register_login_method",
            "replace_password_and_bump_epoch",
            "revoke_family",
            "revoke_for_account",
            "revoke_login_method",
            "rotate",
        )
    })
    private_key, _public_key = jwt_key_material["EdDSA"]
    local_auth = LocalAuth.tokens(
        accounts=cast("Any", capabilities),
        key_ring=LocalKeyRing(
            issuer="https://issuer.example",
            active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=private_key),
        ),
        token_audience="local-client",  # noqa: S106 - public JWT audience
        registration=RegistrationPolicy.disabled(),
    )
    disabled = Litestar(
        route_handlers=[],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth))],
    )

    assert cast("SecurityPlugin[object]", disabled.plugins.init[0]).config.local_auth is local_auth
    assert "/auth/register" not in disabled.openapi_schema.paths
    assert all(
        not isinstance(route_value, HTTPRoute) or route_value.path != "/auth/register"
        for route_value in disabled.routes
    )

    @post("/lifecycle", status_code=202)
    async def lifecycle_handler() -> LifecycleAccepted:
        return LifecycleAccepted()

    app = Litestar(
        route_handlers=[lifecycle_handler],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin()],
    )

    with TestClient(app) as client:
        response = client.post("/lifecycle")
    operation = app.openapi_schema.paths["/lifecycle"].post
    assert operation is not None
    assert response.status_code == 202
    assert response.json() == {"detail": "If eligible, the request will be processed."}
    assert "202" in operation.responses
    assert app.openapi_schema.components is not None
    assert app.openapi_schema.components.schemas is not None
    assert "LifecycleAccepted" in app.openapi_schema.components.schemas

    with pytest.raises(ImproperlyConfiguredException, match="must be a LocalAuthConfig"):
        SecurityPlugin(SecurityConfig(local_auth=cast("Any", object()))).on_app_init(AppConfig())


def test_openapi_component_contribution_preserves_callers_and_validates_duplicates() -> None:
    scheme = SecurityScheme(type="http", scheme="bearer")
    caller_components = Components(
        responses={"Existing": OpenAPIResponse(description="Existing response")},
        security_schemes={"foreign": SecurityScheme(type="mutualTLS"), "shared": scheme},
    )
    original_value = deepcopy(caller_components)
    openapi_config = OpenAPIConfig(
        title="Test", version="1.0", components=caller_components, render_plugins=[JsonRenderPlugin()]
    )
    app = Litestar(
        route_handlers=[],
        openapi_config=openapi_config,
        plugins=[SecurityPlugin(_compiler_config(scheme_names={"a": "shared", "b": "shared"}))],
    )

    assert openapi_config.components is caller_components
    assert caller_components == original_value
    assert app.openapi_schema.components is not None
    assert app.openapi_schema.components.responses == {"Existing": OpenAPIResponse(description="Existing response")}
    assert app.openapi_schema.components.security_schemes == {
        "foreign": SecurityScheme(type="mutualTLS"),
        "shared": scheme,
    }

    with pytest.raises(ImproperlyConfiguredException, match=r"Conflicting.*shared"):
        Litestar(
            route_handlers=[],
            openapi_config=OpenAPIConfig(
                title="Test",
                version="1.0",
                components=Components(
                    security_schemes={
                        "shared": SecurityScheme(type="apiKey", name="X-Key", security_scheme_in="header")
                    }
                ),
            ),
            plugins=[SecurityPlugin(_compiler_config(names=("a",), scheme_names={"a": "shared"}))],
        )

    with pytest.raises(ImproperlyConfiguredException, match=r"Conflicting.*shared"):
        Litestar(
            route_handlers=[],
            openapi_config=OpenAPIConfig(title="Test", version="1.0"),
            plugins=[
                SecurityPlugin(
                    _compiler_config(scheme_names={"a": "shared", "b": "shared"}, scheme_types={"b": "openIdConnect"})
                )
            ],
        )


def test_composite_bearer_contributes_one_native_openapi_scheme() -> None:
    class _Verifier:
        config = JWTValidationConfig(
            issuer="https://issuer.example", audiences=frozenset({"api"}), algorithms=frozenset({"RS256"})
        )

        async def verify(self, _token: str, *, now: datetime) -> InvalidCredentials:
            del now
            return InvalidCredentials()

    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="oidc",
                selector=BearerSlotSelector(
                    issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"api"})
                ),
                verifier=_Verifier(),
            ),
        ),
    )
    slot, bearer_mechanism = composite.build(_CompilerResolver())  # type: ignore[arg-type]

    @get("/bearer", opt=security(required("bearer")))
    async def bearer_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[bearer_handler],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(SecurityConfig(slots=(slot,), mechanisms=(bearer_mechanism,)))],
    )

    assert app.openapi_schema.components is not None
    assert app.openapi_schema.components.security_schemes == {
        "bearer": SecurityScheme(type="http", scheme="bearer", bearer_format="JWT")
    }
    assert _operation_security(app, "/bearer") == [{"bearer": []}]


def test_openapi_rejects_conflicting_shared_scheme_scopes_and_dynamic_native_security() -> None:
    @get("/scopes", opt=security(all_of(mechanism("a", "one"), mechanism("b", "two"))))
    async def scoped_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"conflicting scopes.*GET /scopes"):
        Litestar(
            route_handlers=[scoped_handler],
            openapi_config=OpenAPIConfig(title="Test", version="1.0"),
            plugins=[
                SecurityPlugin(
                    _compiler_config(
                        scheme_names={"a": "shared", "b": "shared"},
                        scheme_types={"a": "openIdConnect", "b": "openIdConnect"},
                    )
                )
            ],
        )

    plugin = SecurityPlugin()
    app = Litestar(route_handlers=[], openapi_config=OpenAPIConfig(title="Test", version="1.0"), plugins=[plugin])

    @get("/dynamic-native", security=[{"native": []}])
    async def dynamic_native() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"Competing.*GET /dynamic-native"):
        app.register(dynamic_native)


@pytest.mark.parametrize("owner", ["application", "openapi", "router", "controller", "handler"])
def test_competing_native_security_declarations_fail(owner: str) -> None:
    native_security = [{"native": []}]

    @get("/", security=native_security if owner == "handler" else None)
    async def handler() -> None:
        return None

    route_handlers: list[Any]
    if owner == "router":
        route_handlers = [Router(path="/router", route_handlers=[handler], security=native_security)]
    elif owner == "controller":

        class NativeController(Controller):
            path = "/controller"
            security: ClassVar = native_security

            @get("/")
            async def owned(self) -> None:
                return None

        route_handlers = [NativeController]
    else:
        route_handlers = [handler]

    openapi_config = OpenAPIConfig(
        title="Test", version="1.0", security=native_security if owner == "openapi" else None
    )
    kwargs = {"security": native_security} if owner == "application" else {}

    with pytest.raises(ImproperlyConfiguredException, match="competing"):
        Litestar(route_handlers=route_handlers, openapi_config=openapi_config, plugins=[SecurityPlugin()], **kwargs)


def test_memoized_native_security_is_replaced_and_openapi_disabled_needs_no_scheme() -> None:
    class MemoizeSecurity(ReceiveRoutePlugin):
        def receive_route(self, route_value: BaseRoute) -> None:
            if isinstance(route_value, HTTPRoute):
                for route_handler in route_value.route_handlers:
                    route_handler.resolve_security()

    @get("/memoized", opt=security(required("a")))
    async def memoized_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[memoized_handler],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[MemoizeSecurity(), SecurityPlugin(_compiler_config(names=("a",)))],
    )

    assert _operation_security(app, "/memoized") == [{"a": []}]

    slot = _CompilerSlot("slot-a")
    mechanism_without_schema = AuthenticationMechanism(
        authenticator=_CompilerAuthenticator("a", "slot-a"),  # type: ignore[arg-type]
        resolver=_CompilerResolver(),
    )
    runtime_config = SecurityConfig(
        slots=(slot,),  # type: ignore[arg-type]
        mechanisms=(mechanism_without_schema,),
    )

    with pytest.raises(ImproperlyConfiguredException, match="a has no native OpenAPI security scheme"):
        Litestar(route_handlers=[], plugins=[SecurityPlugin(runtime_config)])

    @get("/memoized", opt=security(required("a")))
    async def runtime_handler() -> None:
        return None

    runtime_only = Litestar(
        route_handlers=[runtime_handler], openapi_config=None, plugins=[SecurityPlugin(runtime_config)]
    )

    assert _http_plan(runtime_only, "/memoized").participant_names == frozenset({"a"})


@pytest.mark.parametrize("csrf_owner", ["application", "plugin"])
def test_session_capable_routes_require_and_derive_declared_csrf_enforcement(
    csrf_owner: Literal["application", "plugin"],
) -> None:
    @post("/session", opt=security(required("session")))
    async def session_handler() -> None:
        return None

    config = _compiler_config(names=("session",), session_names=frozenset({"session"}))
    with pytest.raises(ImproperlyConfiguredException, match=r"requires native CSRF.*POST /session"):
        Litestar(route_handlers=[session_handler], plugins=[SecurityPlugin(config)])

    @get("/session", opt=security(required("session")))
    async def read_session() -> None:
        return None

    @post("/hybrid", opt=security(any_of("session", "bearer")))
    async def hybrid_handler() -> None:
        return None

    @post("/bearer", opt=security(required("bearer"), csrf_required=False))
    async def bearer_handler() -> None:
        return None

    csrf_config = CSRFConfig(secret=token_hex())
    security_plugin = SecurityPlugin(
        _compiler_config(
            names=("session", "bearer"),
            session_names=frozenset({"session"}),
            csrf_config=csrf_config if csrf_owner == "plugin" else None,
        )
    )
    app = Litestar(
        route_handlers=[read_session, session_handler, hybrid_handler, bearer_handler],
        csrf_config=csrf_config if csrf_owner == "application" else None,
        plugins=[security_plugin],
    )
    session_plan = _http_plan(app, "/session", "POST")
    session_route = next(
        route_value
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path == "/session"
    )

    assert session_plan.csrf_required is True
    assert session_plan.csrf_enforcement == "native"
    assert session_plan.participant_names == frozenset({"session"})
    assert csrf_config.exclude_from_csrf_key not in session_route.route_handler_map["POST"][0].opt
    assert _http_plan(app, "/hybrid", "POST").csrf_required is True
    assert _http_plan(app, "/hybrid", "POST").participant_names == frozenset({"session", "bearer"})
    assert _http_plan(app, "/bearer", "POST").csrf_required is False
    assert _http_plan(app, "/bearer", "POST").csrf_enforcement is None
    bearer_route = next(
        route_value
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path == "/bearer"
    )
    assert bearer_route.route_handler_map["POST"][0].opt[csrf_config.exclude_from_csrf_key] is True
    assert session_route.route_handler_map["OPTIONS"][0].opt[csrf_config.exclude_from_csrf_key] is True
    assert app.openapi_schema.paths["/session"].post.security == [{"session": []}]
    assert app.openapi_schema.paths["/hybrid"].post.security == [{"session": []}, {"bearer": []}]
    assert app.openapi_schema.paths["/bearer"].post.security == [{"bearer": []}]

    with TestClient(app) as client:
        auth_headers = {"x-auth-session": "valid"}
        assert client.post("/session", headers=auth_headers).status_code == 403
        assert client.post("/bearer", headers={"x-auth-bearer": "valid"}).status_code == 201
        assert client.post("/hybrid", headers={"x-auth-bearer": "valid"}).status_code == 403
        assert client.get("/session", headers=auth_headers).status_code == 200
        token = client.cookies[csrf_config.cookie_name]
        assert client.post("/session", headers={**auth_headers, csrf_config.header_name: "wrong"}).status_code == 403
        assert client.post("/session", headers={**auth_headers, csrf_config.header_name: token}).status_code == 201
        assert (
            client.post("/hybrid", headers={"x-auth-bearer": "valid", csrf_config.header_name: token}).status_code
            == 201
        )

    bearer_route.route_handler_map["POST"][0].opt["litestar_security_csrf"] = False
    with pytest.raises(ImproperlyConfiguredException, match=r"Conflicting compiled native CSRF.*POST /bearer"):
        security_plugin.receive_route(bearer_route)
    bearer_route.route_handler_map["POST"][0].opt["litestar_security_csrf"] = True
    bearer_route.route_handler_map["POST"][0].opt[csrf_config.exclude_from_csrf_key] = False
    with pytest.raises(ImproperlyConfiguredException, match=r"Conflicting compiled native CSRF.*POST /bearer"):
        security_plugin.receive_route(bearer_route)
    session_route.route_handler_map["POST"][0].opt[csrf_config.exclude_from_csrf_key] = True
    with pytest.raises(ImproperlyConfiguredException, match=r"Conflicting compiled native CSRF.*POST /session"):
        security_plugin.receive_route(session_route)


def test_csrf_config_ownership_and_false_override_are_strict() -> None:
    configured_secret = token_hex()
    configured = CSRFConfig(secret=configured_secret)
    app_config = AppConfig(csrf_config=CSRFConfig(secret=configured_secret))

    result = SecurityPlugin(SecurityConfig(csrf_config=configured)).on_app_init(app_config)

    assert result.csrf_config is configured

    with pytest.raises(ImproperlyConfiguredException, match="unequal native Litestar CSRF"):
        SecurityPlugin(SecurityConfig(csrf_config=configured)).on_app_init(
            AppConfig(csrf_config=CSRFConfig(secret=token_hex()))
        )
    external = ExternalCSRF(name="edge", validate=lambda _path, _method, _policy: True)
    with pytest.raises(ImproperlyConfiguredException, match="native and external CSRF"):
        SecurityPlugin(SecurityConfig(external_csrf=external)).on_app_init(AppConfig(csrf_config=configured))

    @post("/unsafe", opt=security(required("session"), csrf_required=False))
    async def unsafe_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"session-capable mechanism session.*POST /unsafe"):
        Litestar(
            route_handlers=[unsafe_handler],
            csrf_config=configured,
            plugins=[SecurityPlugin(_compiler_config(names=("session",), session_names=frozenset({"session"})))],
        )


@pytest.mark.parametrize(
    ("csrf_config", "match"),
    [
        (CSRFConfig(secret=token_hex(), exclude="/unsafe"), "route policy"),
        (CSRFConfig(secret=token_hex(), safe_methods={"GET", "POST"}), "unsafe HTTP methods"),
        (CSRFConfig(secret=token_hex(), safe_methods={"GET", "HEAD"}), "GET, HEAD, and OPTIONS"),
        (CSRFConfig(secret=token_hex(), exclude_from_csrf_key=" "), "opt key"),
        (CSRFConfig(secret=token_hex(), exclude_from_csrf_key="litestar_security_policy"), "reserved"),
        (CSRFConfig(secret=token_hex(), exclude_from_csrf_key="litestar_security_plan"), "reserved"),
        (CSRFConfig(secret=token_hex(), exclude_from_csrf_key="litestar_security_csrf"), "reserved"),
    ],
    ids=[
        "path-exclusion",
        "unsafe-safe-method",
        "missing-safe-method",
        "blank-opt-key",
        "policy-opt-key",
        "plan-opt-key",
        "csrf-opt-key",
    ],
)
def test_native_csrf_rejects_competing_bypass_configuration(csrf_config: CSRFConfig, match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        SecurityPlugin(SecurityConfig(csrf_config=csrf_config)).on_app_init(AppConfig())


def test_native_csrf_rejects_invalid_runtime_configuration_shapes() -> None:
    invalid_safe_methods = CSRFConfig(secret=token_hex())
    invalid_safe_methods.safe_methods = cast("Any", None)
    with pytest.raises(ImproperlyConfiguredException, match="safe methods"):
        SecurityPlugin(SecurityConfig(csrf_config=invalid_safe_methods)).on_app_init(AppConfig())

    app_config = AppConfig()
    app_config.csrf_config = cast("Any", object())
    with pytest.raises(ImproperlyConfiguredException, match="Litestar CSRFConfig"):
        SecurityPlugin().on_app_init(app_config)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"csrf_config": object()}, "Litestar CSRFConfig"),
        ({"external_csrf": object()}, "ExternalCSRF assertion"),
        (
            {
                "csrf_config": CSRFConfig(secret=token_hex()),
                "external_csrf": ExternalCSRF("edge", lambda _path, _method, _policy: True),
            },
            "native and external CSRF",
        ),
    ],
    ids=["invalid-native", "invalid-external", "mixed-ownership"],
)
def test_security_config_rejects_invalid_csrf_ownership(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        SecurityConfig(**cast("Any", kwargs))


def test_external_csrf_validates_required_routes_and_installs_no_native_middleware() -> None:
    calls: list[tuple[str, str, AuthenticationPolicy]] = []

    def validate(path: str, method: str, policy: AuthenticationPolicy) -> bool:
        calls.append((path, method, policy))
        return True

    external = ExternalCSRF(name="edge", validate=validate)

    @post("/session", opt=security(required("session")))
    async def session_handler() -> None:
        return None

    @post("/login", opt=security(public(), csrf_required=True))
    async def login_handler() -> None:
        return None

    @post("/public", opt=security(public()))
    async def public_handler() -> None:
        return None

    external_plugin = SecurityPlugin(
        _compiler_config(names=("session",), session_names=frozenset({"session"}), external_csrf=external)
    )
    app = Litestar(route_handlers=[session_handler, login_handler, public_handler], plugins=[external_plugin])

    assert app.csrf_config is None
    assert {(path, method) for path, method, _ in calls} == {("/session", "POST"), ("/login", "POST")}
    assert _http_plan(app, "/session", "POST").csrf_enforcement == "edge"
    assert _http_plan(app, "/login", "POST").csrf_enforcement == "edge"
    assert _http_plan(app, "/public", "POST").csrf_enforcement is None
    public_route = next(
        route_value
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path == "/public"
    )
    assert "exclude_from_csrf" not in public_route.route_handler_map["POST"][0].opt
    session_route = next(
        route_value
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path == "/session"
    )
    external_plugin.receive_route(session_route)
    assert {(path, method) for path, method, _ in calls} == {("/session", "POST"), ("/login", "POST")}

    rejecting = ExternalCSRF(name="rejecting-edge", validate=lambda _path, _method, _policy: False)

    @post("/rejected", opt=security(public(), csrf_required=True))
    async def rejected_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"rejecting-edge.*POST.*POST /rejected"):
        Litestar(route_handlers=[rejected_handler], plugins=[SecurityPlugin(_compiler_config(external_csrf=rejecting))])

    truthy = ExternalCSRF(name="truthy-edge", validate=cast("Any", lambda _path, _method, _policy: 1))
    with pytest.raises(ImproperlyConfiguredException, match=r"truthy-edge.*POST.*POST /rejected"):
        Litestar(route_handlers=[rejected_handler], plugins=[SecurityPlugin(_compiler_config(external_csrf=truthy))])

    async def rejected_async() -> bool:
        return False

    returning_coroutine = ExternalCSRF(
        name="async-edge", validate=cast("Any", lambda _path, _method, _policy: rejected_async())
    )
    with pytest.raises(ImproperlyConfiguredException, match=r"async-edge.*POST.*POST /rejected"):
        Litestar(
            route_handlers=[rejected_handler],
            plugins=[SecurityPlugin(_compiler_config(external_csrf=returning_coroutine))],
        )


@pytest.mark.parametrize("manual_exclusion", [False, None])
def test_native_csrf_rejects_manual_exclusion_and_uses_litestar_cookie_header_flow(manual_exclusion: Any) -> None:
    csrf_config = CSRFConfig(secret=token_hex())

    @post("/manual", opt={**security(public()), csrf_config.exclude_from_csrf_key: manual_exclusion})
    async def manual_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"manual native CSRF.*POST /manual"):
        Litestar(route_handlers=[manual_handler], csrf_config=csrf_config, plugins=[SecurityPlugin()])

    @get("/login", opt=security(public(), csrf_required=True))
    async def login_form() -> str:
        return "form"

    @post("/login", opt=security(public(), csrf_required=True))
    async def login_submit() -> str:
        return "ok"

    with TestClient(
        Litestar(route_handlers=[login_form, login_submit], csrf_config=csrf_config, plugins=[SecurityPlugin()])
    ) as client:
        assert client.app.openapi_schema.paths["/login"].post.security == [{}]
        form_response = client.get("/login")
        token = client.cookies[csrf_config.cookie_name]
        missing_response = client.post("/login")
        mismatch_response = client.post("/login", headers={csrf_config.header_name: "wrong"})
        success_response = client.post("/login", headers={csrf_config.header_name: token})

    assert form_response.status_code == 200
    assert missing_response.status_code == 403
    assert mismatch_response.status_code == 403
    assert success_response.status_code == 201
    assert success_response.text == "ok"


def test_route_compiler_errors_include_method_and_path() -> None:
    @get("/missing", opt=security(required("missing")))
    async def handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"GET /missing"):
        Litestar(route_handlers=[handler], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])


def test_route_compiler_rejects_invalid_metadata_and_conflicting_private_plan() -> None:
    @get("/invalid", opt={"litestar_security_policy": object()})
    async def invalid_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"Invalid.*GET /invalid"):
        Litestar(route_handlers=[invalid_handler], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])

    @get("/conflict", opt=security(public()))
    async def conflict_handler() -> None:
        return None

    plugin = SecurityPlugin(_compiler_config())
    app = Litestar(route_handlers=[conflict_handler], openapi_config=None, plugins=[plugin])
    conflict_route = next(route_value for route_value in app.routes if isinstance(route_value, HTTPRoute))
    conflict_route.route_handler_map["GET"][0].opt["litestar_security_plan"] = SecurityRuntimePlan(
        authenticate=True, required=True
    )

    with pytest.raises(ImproperlyConfiguredException, match=r"Conflicting.*GET /conflict"):
        plugin.receive_route(conflict_route)


def test_openapi_controller_and_invalid_custom_router_metadata_use_native_ownership() -> None:
    class TestOpenAPIController(OpenAPIController):
        path = "/legacy-docs"

    with pytest.warns(DeprecationWarning, match="openapi_controller"):
        openapi_config = OpenAPIConfig(
            title="Test", version="1.0", openapi_controller=TestOpenAPIController, render_plugins=[]
        )
    app = Litestar(route_handlers=[], openapi_config=openapi_config, plugins=[SecurityPlugin(_compiler_config())])

    assert not _http_plan(app, "/legacy-docs/openapi.json").authenticate

    invalid_router = Router(path="/reference", route_handlers=[], opt={"litestar_security_policy": object()})
    invalid_config = OpenAPIConfig(
        title="Test", version="1.0", openapi_router=invalid_router, render_plugins=[JsonRenderPlugin()]
    )

    with pytest.raises(ImproperlyConfiguredException, match=r"Invalid.*GET /reference"):
        Litestar(route_handlers=[], openapi_config=invalid_config, plugins=[SecurityPlugin(_compiler_config())])


def test_receive_route_before_application_initialization_fails() -> None:
    @get("/")
    async def handler() -> None:
        return None

    route_value = HTTPRoute(path="/", route_handlers=[handler])

    with pytest.raises(ImproperlyConfiguredException, match="before application initialization"):
        SecurityPlugin().receive_route(route_value)


def test_plugin_traverses_constructed_controller_ownership_without_collisions() -> None:
    class TestController(Controller):
        path = "/"

        @get("/")
        async def route(self) -> None:
            return None

    router = Router(path="/api", route_handlers=[TestController])

    app_config = SecurityPlugin().on_app_init(AppConfig(route_handlers=[router]))

    assert set(app_config.dependencies) == {"current_user", "principal", "security_context"}


def test_plugin_traverses_direct_controller_and_leaves_unknown_handlers_to_litestar() -> None:
    class TestController(Controller):
        path = "/"

        @get("/")
        async def route(self) -> None:
            return None

    app_config = SecurityPlugin().on_app_init(AppConfig(route_handlers=[TestController, cast("Any", object())]))

    assert set(app_config.dependencies) == {"current_user", "principal", "security_context"}


def test_plugin_registers_runtime_contract_idempotently() -> None:
    plugin = SecurityPlugin()
    app_config = AppConfig()

    assert plugin.on_app_init(app_config) is app_config
    providers = dict(app_config.dependencies)
    middleware = list(app_config.middleware)
    namespace = dict(app_config.signature_namespace)

    assert set(providers) == {"current_user", "principal", "security_context"}
    assert len(middleware) == 1
    assert isinstance(middleware[0], DefineMiddleware)
    assert middleware[0].middleware is SecurityMiddlewareWrapper
    assert namespace == {
        "CurrentUser": CurrentUser,
        "Principal": Principal,
        "PrincipalDependency": PrincipalDependency,
        "SecurityContext": SecurityContext,
        "SecurityContextDependency": SecurityContextDependency,
    }

    assert plugin.on_app_init(app_config) is app_config
    assert app_config.dependencies == providers
    assert app_config.middleware == middleware
    assert app_config.signature_namespace == namespace


@pytest.mark.parametrize("reserved_name", ["principal", "security_context", "current_user"])
@pytest.mark.parametrize("owner", ["application", "router", "controller", "handler"])
def test_plugin_rejects_reserved_dependency_collisions(reserved_name: str, owner: str) -> None:
    provider = Provide(object, sync_to_thread=False, use_cache=False)

    @get("/")
    async def handler() -> None:
        return None

    if owner == "application":
        app_config = AppConfig(dependencies={reserved_name: provider}, route_handlers=[handler])
    elif owner == "router":
        app_config = AppConfig(
            route_handlers=[Router(path="/", route_handlers=[handler], dependencies={reserved_name: provider})]
        )
    elif owner == "controller":

        class TestController(Controller):
            path = "/"
            dependencies: ClassVar = {reserved_name: provider}

            @get("/")
            async def route(self) -> None:
                return None

        app_config = AppConfig(route_handlers=[TestController])
    else:

        @get("/", dependencies={reserved_name: provider})
        async def owned_handler() -> None:
            return None

        app_config = AppConfig(route_handlers=[owned_handler])

    with pytest.raises(ImproperlyConfiguredException, match=rf"{reserved_name}.*{owner}"):
        SecurityPlugin().on_app_init(app_config)

    if owner == "application":
        assert app_config.dependencies[reserved_name] is provider


def test_exact_plugin_owned_provider_is_accepted_at_lower_layer() -> None:
    plugin = SecurityPlugin()
    first_config = plugin.on_app_init(AppConfig())

    @get("/", dependencies={"principal": first_config.dependencies["principal"]})
    async def handler() -> None:
        return None

    app_config = AppConfig(
        dependencies=dict(first_config.dependencies),
        middleware=list(first_config.middleware),
        route_handlers=[handler],
        signature_namespace=dict(first_config.signature_namespace),
    )

    assert plugin.on_app_init(app_config) is app_config


def test_controller_handler_collision_is_reported_as_handler_owned() -> None:
    provider = Provide(object, sync_to_thread=False, use_cache=False)

    class TestController(Controller):
        path = "/"

        @get("/", dependencies={"principal": provider})
        async def route(self) -> None:
            return None

    with pytest.raises(ImproperlyConfiguredException, match=r"principal.*handler"):
        SecurityPlugin().on_app_init(AppConfig(route_handlers=[TestController]))


def test_local_auth_native_csrf_becomes_the_effective_plugin_config() -> None:
    csrf = CSRFConfig(secret=token_hex())
    backend, _ = _native_session_backend("client")
    local_auth = _local_session_auth(csrf=csrf)

    result = SecurityPlugin(SecurityConfig(local_auth=local_auth, session_backend=backend)).on_app_init(AppConfig())

    assert result.csrf_config is csrf


@pytest.mark.parametrize("owner", ["security", "application"])
def test_local_auth_rejects_conflicting_native_csrf_sources(owner: str) -> None:
    local_csrf = CSRFConfig(secret=token_hex())
    conflicting = CSRFConfig(secret=token_hex())
    backend, _ = _native_session_backend("client")
    config = SecurityConfig(
        local_auth=_local_session_auth(csrf=local_csrf),
        session_backend=backend,
        csrf_config=conflicting if owner == "security" else None,
    )
    app_config = AppConfig(csrf_config=conflicting if owner == "application" else None)

    with pytest.raises(ImproperlyConfiguredException, match="CSRF"):
        SecurityPlugin(config).on_app_init(app_config)


def test_local_auth_rejects_native_and_external_csrf_combination() -> None:
    backend, _ = _native_session_backend("client")
    native = CSRFConfig(secret=token_hex())
    external = ExternalCSRF(name="edge", validate=lambda _path, _method, _policy: True)

    with pytest.raises(ImproperlyConfiguredException, match="cannot be combined"):
        SecurityPlugin(
            SecurityConfig(local_auth=_local_session_auth(csrf=native), session_backend=backend, external_csrf=external)
        ).on_app_init(AppConfig())


def test_local_auth_external_csrf_becomes_route_enforcement_and_rejects_conflicts() -> None:
    calls: list[tuple[str, str, AuthenticationPolicy]] = []

    def validate(path: str, method: str, policy: AuthenticationPolicy) -> bool:
        calls.append((path, method, policy))
        return True

    external = ExternalCSRF(name="local-edge", validate=validate)
    backend, _ = _native_session_backend("client")

    @post("/session", opt=security(required("session")))
    async def session_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[session_handler],
        plugins=[
            SecurityPlugin(SecurityConfig(local_auth=_local_session_auth(csrf=external), session_backend=backend))
        ],
    )

    assert app.csrf_config is None
    assert _http_plan(app, "/session", "POST").csrf_enforcement == "local-edge"
    assert [(path, method) for path, method, _ in calls] == [("/session", "POST")]

    conflicting = ExternalCSRF(name="other-edge", validate=lambda _path, _method, _policy: True)
    with pytest.raises(ImproperlyConfiguredException, match="CSRF"):
        SecurityPlugin(
            SecurityConfig(
                local_auth=_local_session_auth(csrf=external), session_backend=backend, external_csrf=conflicting
            )
        ).on_app_init(AppConfig())
    with pytest.raises(ImproperlyConfiguredException, match="cannot be combined"):
        SecurityPlugin(
            SecurityConfig(
                local_auth=_local_session_auth(csrf=external),
                session_backend=backend,
                csrf_config=CSRFConfig(secret=token_hex()),
            )
        ).on_app_init(AppConfig())


@pytest.mark.parametrize(
    ("native_cookie", "csrf_cookie", "binding_cookie"),
    [("shared", "csrf", "shared"), ("native", "shared", "shared"), ("shared", "shared", "binding")],
    ids=["binding-native", "binding-csrf", "native-csrf"],
)
def test_local_session_cookie_names_must_be_pairwise_distinct(
    native_cookie: str, csrf_cookie: str, binding_cookie: str
) -> None:
    csrf = CSRFConfig(secret=token_hex(), cookie_name=csrf_cookie)
    backend, _ = _native_session_backend("client", key=native_cookie)
    binding = SessionBindingConfig(pepper=b"binding-pepper-for-plugin-tests!", cookie_name=binding_cookie, max_age=600)

    with pytest.raises(ImproperlyConfiguredException, match="cookie names must be distinct"):
        SecurityPlugin(
            SecurityConfig(local_auth=_local_session_auth(csrf=csrf, binding=binding), session_backend=backend)
        ).on_app_init(AppConfig())


@pytest.mark.parametrize(
    (
        "scopes",
        "native_max_age",
        "binding_max_age",
        "native_secure",
        "native_httponly",
        "binding_secure",
        "allow_insecure",
        "match",
    ),
    [
        ({ScopeType.HTTP, ScopeType.WEBSOCKET}, 600, 600, True, True, True, False, None),
        ({ScopeType.HTTP, ScopeType.WEBSOCKET}, 600, 600, False, True, False, True, None),
        ({ScopeType.HTTP}, 600, 600, True, True, True, False, "HTTP and WebSocket"),
        ({ScopeType.WEBSOCKET}, 600, 600, True, True, True, False, "HTTP and WebSocket"),
        ({ScopeType.HTTP, ScopeType.WEBSOCKET}, 600, 1_200, True, True, True, False, "lifetime"),
        ({ScopeType.HTTP, ScopeType.WEBSOCKET}, 600, 600, False, True, True, False, "Secure"),
        ({ScopeType.HTTP, ScopeType.WEBSOCKET}, 600, 600, True, False, True, False, "HttpOnly"),
    ],
    ids=[
        "production",
        "development",
        "http-only",
        "websocket-only",
        "binding-outlives-native",
        "insecure-native",
        "readable-native",
    ],
)
def test_local_session_backend_constraints(  # noqa: PLR0913
    scopes: set[ScopeType],
    native_max_age: int,
    binding_max_age: int,
    *,
    native_secure: bool,
    native_httponly: bool,
    binding_secure: bool,
    allow_insecure: bool,
    match: str | None,
) -> None:
    csrf = CSRFConfig(secret=token_hex())
    backend, _ = _native_session_backend(
        "client", max_age=native_max_age, scopes=scopes, secure=native_secure, httponly=native_httponly
    )
    binding = SessionBindingConfig(
        pepper=b"binding-pepper-for-plugin-tests!",
        cookie_name="__Host-binding" if binding_secure else "binding",
        secure=binding_secure,
        max_age=binding_max_age,
        allow_insecure=allow_insecure,
        touch_interval=timedelta(minutes=5),
    )
    plugin = SecurityPlugin(
        SecurityConfig(local_auth=_local_session_auth(csrf=csrf, binding=binding), session_backend=backend)
    )

    if match is None:
        result = plugin.on_app_init(AppConfig())
        assert result.csrf_config is csrf
    else:
        with pytest.raises(ImproperlyConfiguredException, match=match):
            plugin.on_app_init(AppConfig())


def test_local_session_requires_a_backend_and_secure_samesite_none() -> None:
    csrf = CSRFConfig(secret=token_hex())
    binding = SessionBindingConfig(
        pepper=b"binding-pepper-for-plugin-tests!",
        cookie_name="binding",
        secure=False,
        allow_insecure=True,
        max_age=600,
    )
    local_auth = _local_session_auth(csrf=csrf, binding=binding)

    with pytest.raises(ImproperlyConfiguredException, match="requires one native"):
        SecurityPlugin(SecurityConfig(local_auth=local_auth)).on_app_init(AppConfig())

    config = CookieBackendConfig(
        secret=bytes(range(16)),
        key="native-session",
        max_age=600,
        scopes={ScopeType.HTTP, ScopeType.WEBSOCKET},
        secure=False,
        httponly=True,
        samesite="none",
    )
    backend = cast("BaseSessionBackend[Any]", config.middleware.kwargs["backend"])
    with pytest.raises(ImproperlyConfiguredException, match="SameSite=None"):
        SecurityPlugin(SecurityConfig(local_auth=local_auth, session_backend=backend)).on_app_init(AppConfig())


@pytest.mark.parametrize("backend_kind", ["client", "server"])
@pytest.mark.parametrize("ownership", ["owned", "existing"])
def test_local_session_owned_and_existing_backends_have_registry_and_openapi_parity(
    backend_kind: Literal["client", "server"], ownership: Literal["owned", "existing"]
) -> None:
    csrf = CSRFConfig(secret=token_hex())
    binding = SessionBindingConfig(pepper=b"binding-pepper-for-plugin-tests!", max_age=600)
    local_auth = _local_session_auth(csrf=csrf, binding=binding)
    backend, native_middleware = _native_session_backend(backend_kind)
    config = SecurityConfig(local_auth=local_auth, session_backend=backend if ownership == "owned" else None)

    @get("/session", opt=security(required("session")))
    async def session_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[session_handler],
        middleware=[] if ownership == "owned" else [native_middleware],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(config)],
    )
    security_middleware = next(
        item
        for item in app.middleware
        if isinstance(item, DefineMiddleware) and item.middleware is SecurityMiddlewareWrapper
    )
    runtime = security_middleware.kwargs["config"]
    registry = runtime.registry
    session_mechanism = registry.get_mechanism("session")
    native_middleware_count = sum(
        isinstance(item, DefineMiddleware)
        and isinstance(item.middleware, type)
        and issubclass(item.middleware, SessionMiddleware)
        for item in app.middleware
    )

    assert app.csrf_config is csrf
    assert registry.slot_names == ("session",)
    assert registry.mechanism_names == ("session",)
    assert registry.default_mechanism_names == ("session",)
    assert registry.get_slot("session") is local_auth.session_auth
    assert session_mechanism.authenticator is local_auth.session_auth
    assert session_mechanism.resolver is local_auth.session_auth
    assert session_mechanism.session_capable
    assert session_mechanism.scheme_name == "LocalSession"
    assert _http_plan(app, "/session").csrf_enforcement == "native"
    assert _operation_security(app, "/session") == [{"LocalSession": []}]
    assert app.openapi_schema.components is not None
    assert app.openapi_schema.components.security_schemes == {
        "LocalSession": SecurityScheme(
            type="apiKey",
            name=binding.cookie_name,
            security_scheme_in="cookie",
            description="Litestar native session plus independent binding cookie.",
        )
    }
    assert native_middleware_count == (0 if ownership == "owned" else 1)
    assert (runtime.owned_session_backend is not None) is (ownership == "owned")
    if ownership == "owned":
        assert runtime.owned_session_backend.backend is backend
    else:
        assert app.middleware.index(native_middleware) < app.middleware.index(security_middleware)


def test_duplicate_native_sessions_fail_startup() -> None:
    sessions = [
        DefineMiddleware(SessionMiddleware, backend=object()),
        DefineMiddleware(SessionMiddleware, backend=object()),
    ]

    with pytest.raises(ImproperlyConfiguredException, match="multiple native Litestar session"):
        SecurityPlugin().on_app_init(AppConfig(middleware=sessions))


def test_plugin_owned_and_application_session_conflict_fails_startup() -> None:
    session = DefineMiddleware(SessionMiddleware, backend=object())
    config = SecurityConfig(session_backend=cast("BaseSessionBackend[Any]", object()))

    with pytest.raises(ImproperlyConfiguredException, match="both configure native Litestar session"):
        SecurityPlugin(config).on_app_init(AppConfig(middleware=[session]))


def test_foreign_security_wrapper_fails_startup() -> None:
    middleware = DefineMiddleware(SecurityMiddlewareWrapper, config=object())

    with pytest.raises(ImproperlyConfiguredException, match="not owned by this plugin"):
        SecurityPlugin().on_app_init(AppConfig(middleware=[middleware]))


def test_required_default_without_participants_fails_startup() -> None:
    with pytest.raises(
        ImproperlyConfiguredException, match=r"required default authentication plan.*participating mechanism"
    ):
        SecurityPlugin(SecurityConfig(require_default=True)).on_app_init(AppConfig())


@pytest.mark.parametrize(
    ("warmup_failure", "fails", "raises"),
    [("fail_startup", False, False), ("fail_startup", True, True), ("lazy", True, False)],
)
def test_plugin_owns_jwks_warmup_and_shutdown_lifespan(
    warmup_failure: Literal["fail_startup", "lazy"], *, fails: bool, raises: bool
) -> None:
    events: list[str] = []

    class Provider:
        async def select_key(
            self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime
        ) -> InvalidCredentials:
            del issuer, jwks_uri, kid, algorithm, now
            return InvalidCredentials()

        async def warmup(self, *, now: datetime) -> VerificationUnavailable | None:
            assert now.tzinfo is not None
            events.append("warmup")
            return VerificationUnavailable() if fails else None

        async def aclose(self) -> None:
            events.append("close")

    app = Litestar(
        [],
        plugins=[
            SecurityPlugin(
                SecurityConfig(jwks_providers=(cast("Any", Provider()),), jwks_warmup_failure=warmup_failure)
            )
        ],
    )

    if raises:
        with pytest.RaisesGroup(ImproperlyConfiguredException, flatten_subgroups=True), TestClient(app):
            pass
    else:
        with TestClient(app):
            assert events == ["warmup"]
    assert events == ["warmup", "close"]


def test_plugin_validates_and_registers_one_jwks_lifespan() -> None:
    class Provider:
        async def select_key(
            self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime
        ) -> InvalidCredentials:
            del issuer, jwks_uri, kid, algorithm, now
            return InvalidCredentials()

        async def warmup(self, *, now: datetime) -> VerificationUnavailable | None:
            del now
            return None

        async def aclose(self) -> None:
            return None

    plugin = SecurityPlugin(SecurityConfig(jwks_providers=(cast("Any", Provider()),)))
    app_config = AppConfig()

    plugin._configure_jwks_lifespan(app_config)  # noqa: SLF001
    plugin._configure_jwks_lifespan(app_config)  # noqa: SLF001

    assert len(app_config.lifespan) == 1
    with pytest.raises(ImproperlyConfiguredException, match="must implement JWKSProvider"):
        SecurityPlugin(SecurityConfig(jwks_providers=(cast("Any", object()),))).on_app_init(AppConfig())


@pytest.mark.parametrize(
    ("warmup_fails", "expected_error"),
    [(False, "JWKS provider shutdown failed"), (True, "JWKS warmup failed during application startup")],
)
def test_plugin_awaits_all_jwks_closes_and_preserves_primary_failure(
    *, warmup_fails: bool, expected_error: str
) -> None:
    events: list[str] = []

    class Provider:
        def __init__(self, name: str, *, close_fails: bool = False) -> None:
            self.name = name
            self.close_fails = close_fails

        async def select_key(
            self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime
        ) -> InvalidCredentials:
            del issuer, jwks_uri, kid, algorithm, now
            return InvalidCredentials()

        async def warmup(self, *, now: datetime) -> VerificationUnavailable | None:
            del now
            return VerificationUnavailable() if warmup_fails and self.name == "first" else None

        async def aclose(self) -> None:
            await anyio.lowlevel.checkpoint()
            events.append(f"close-{self.name}")
            if self.close_fails:
                msg = "private close detail"
                raise OSError(msg)

    app = Litestar(
        [],
        plugins=[
            SecurityPlugin(
                SecurityConfig(
                    jwks_providers=(cast("Any", Provider("first", close_fails=True)), cast("Any", Provider("second")))
                )
            )
        ],
    )

    with (
        pytest.RaisesGroup(
            ImproperlyConfiguredException, flatten_subgroups=True, check=lambda error: expected_error in repr(error)
        ),
        TestClient(app),
    ):
        pass

    assert events == ["close-first", "close-second"]


def test_importing_plugin_does_not_import_private_cli() -> None:
    existing_module = sys.modules.pop("litestar_security._cli", None)
    try:
        SecurityPlugin()

        assert "litestar_security._cli" not in sys.modules
    finally:
        if existing_module is not None:
            sys.modules["litestar_security._cli"] = existing_module


def _root_group() -> click.Group:
    return click.Group(name="litestar")


def test_cli_entry_point_and_lazy_plugin_registration() -> None:
    entry_point = next(
        candidate for candidate in entry_points(group="litestar.commands") if candidate.name == "security"
    )
    cli = _root_group()

    SecurityPlugin().on_cli_init(cli)

    assert entry_point.load() is security_group
    assert cli.commands["security"] is security_group


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (["security", "--help"], "Litestar Security operations."),
        (["security", "--version"], "litestar-security, version 0.1.0"),
    ],
)
def test_cli_output(arguments: list[str], expected: str) -> None:
    cli = _root_group()
    register(cli)

    result = CliRunner().invoke(cli, arguments)

    assert result.exit_code == 0
    assert expected in result.output


def test_cli_registration_is_idempotent() -> None:
    cli = _root_group()

    register(cli)
    register(cli)
    SecurityPlugin().on_cli_init(cli)

    assert list(cli.commands) == ["security"]
