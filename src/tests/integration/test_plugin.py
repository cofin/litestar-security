"""Integration tests for plugin ownership, session wiring, and CLI behavior."""

from __future__ import annotations

import sys
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from importlib.metadata import entry_points
from secrets import token_hex
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, ClassVar, Literal, cast

import anyio.lowlevel
import click
import pytest
from click.testing import CliRunner
from litestar import Controller, Litestar, Response, Router, WebSocket, asgi, get, post, route, websocket
from litestar.config.app import AppConfig
from litestar.config.csrf import CSRFConfig
from litestar.di import Provide
from litestar.enums import HttpMethod, ScopeType
from litestar.exceptions import (
    ClientException,
    HTTPException,
    ImproperlyConfiguredException,
    ServiceUnavailableException,
    TooManyRequestsException,
)
from litestar.middleware import DefineMiddleware
from litestar.middleware.csrf import generate_csrf_token
from litestar.middleware.session.base import SessionMiddleware
from litestar.middleware.session.client_side import CookieBackendConfig
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.openapi import OpenAPIConfig
from litestar.openapi.controller import OpenAPIController
from litestar.openapi.plugins import JsonRenderPlugin, SwaggerRenderPlugin
from litestar.openapi.spec import Components, OpenAPIResponse, SecurityScheme, Tag
from litestar.plugins import CLIPlugin, CLIPluginProtocol, InitPlugin, ReceiveRoutePlugin
from litestar.routes import ASGIRoute, BaseRoute, HTTPRoute, WebSocketRoute
from litestar.status_codes import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST
from litestar.testing import TestClient

import litestar_security.accounts as accounts_module
from litestar_security import MFAConfig, PasskeyConfig, SecurityConfig, SecurityPlugin, __version__, csp_nonce
from litestar_security._cli import register, security_group
from litestar_security.accounts import (
    LOCAL_AUTH_TAGS,
    LifecycleAccepted,
    LocalAccountResponse,
    LocalAuth,
    LocalAuthSecrets,
    LocalCredentials,
    PasskeySummary,
    PasswordReauthenticationProof,
    ProtectedSecret,
    PurposeTokenCodec,
    RecoveryCodes,
    RefreshReceiptKey,
    RefreshReceiptSealer,
    RefreshTokenCodec,
    RegistrationPolicy,
    RevokeLoginMethodResult,
    RevokeLoginMethodStatus,
    SessionBindingConfig,
    SessionSummary,
    StepUpGrant,
    TOTPEnrollment,
    TOTPMethod,
    TOTPPolicy,
    WebAuthnOptions,
    build_mfa_routes,
)
from litestar_security.accounts._mfa_login import MFARequired
from litestar_security.accounts._records import LocalAccount
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
)
from litestar_security.config import ExternalCSRF
from litestar_security.context import AuthenticationEvidence, Principal, SecurityContext
from litestar_security.headers import ContentSecurityPolicy, SecurityHeadersConfig
from litestar_security.plugin import CurrentUser
from litestar_security.providers.api_key import APIKeyConfig
from litestar_security.providers.iap import GoogleIAPConfig
from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JWTValidationConfig,
    LocalJWKSConfig,
    LocalKeyRing,
    PyJWTVerifier,
    SigningKey,
    VerificationKey,
)
from litestar_security.providers.oidc import ServiceTokenConfig
from litestar_security.websocket import WebSocketSecurityConfig


def test_static_security_headers_use_native_response_headers_without_hook() -> None:
    @get("/", sync_to_thread=False)
    def handler() -> None:
        return None

    plugin = SecurityPlugin[object](
        SecurityConfig[object](
            headers=SecurityHeadersConfig(
                static={"X-Content-Type-Options": "nosniff"},
                csp=ContentSecurityPolicy(directives={"default-src": ("'self'",)}),
            )
        )
    )
    app = Litestar(route_handlers=[handler], plugins=[plugin])

    with TestClient(app) as client:
        response = client.get("/")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == "default-src 'self'"
    assert app.before_send == []


def test_nonce_csp_dependency_matches_fresh_response_header() -> None:
    @get("/", sync_to_thread=False)
    def handler(csp_nonce: csp_nonce) -> str:
        return csp_nonce

    plugin = SecurityPlugin[object](
        SecurityConfig[object](
            headers=SecurityHeadersConfig(
                csp=ContentSecurityPolicy(
                    directives={"default-src": ("'self'",), "script-src": ("'self'",)}, nonce_directives=("script-src",)
                )
            )
        )
    )
    app = Litestar(route_handlers=[handler], plugins=[plugin])

    with TestClient(app) as client:
        first = client.get("/")
        second = client.get("/")

    first_nonce = first.text
    second_nonce = second.text
    assert first_nonce != second_nonce
    assert len(first_nonce) >= 22
    assert f"'nonce-{first_nonce}'" in first.headers["content-security-policy"]
    assert f"'nonce-{second_nonce}'" in second.headers["content-security-policy"]
    assert len(app.before_send) == 1


def test_security_headers_reject_application_ownership_collisions() -> None:
    static_plugin = SecurityPlugin[object](
        SecurityConfig[object](headers=SecurityHeadersConfig(static={"X-Content-Type-Options": "nosniff"}))
    )
    with pytest.raises(ImproperlyConfiguredException, match="Application response header conflicts"):
        static_plugin.on_app_init(AppConfig(response_headers={"X-Content-Type-Options": "unsafe"}))

    matching = static_plugin.on_app_init(AppConfig(response_headers={"X-Content-Type-Options": "nosniff"}))
    assert len(matching.response_headers) == 1

    nonce_plugin = SecurityPlugin[object](
        SecurityConfig[object](
            headers=SecurityHeadersConfig(
                csp=ContentSecurityPolicy(directives={"script-src": ("'self'",)}, nonce_directives=("script-src",))
            )
        )
    )
    with pytest.raises(ImproperlyConfiguredException, match=r"already owns.*csp_nonce"):
        nonce_plugin.on_app_init(
            AppConfig(dependencies={"csp_nonce": Provide(lambda: "application", sync_to_thread=False)})
        )


@pytest.mark.anyio
async def test_nonce_csp_hook_is_idempotent_and_rejects_response_conflicts() -> None:
    plugin = SecurityPlugin[object](
        SecurityConfig[object](
            headers=SecurityHeadersConfig(
                csp=ContentSecurityPolicy(directives={"script-src": ("'self'",)}, nonce_directives=("script-src",))
            )
        )
    )
    app_config = plugin.on_app_init(AppConfig())
    assert plugin.on_app_init(app_config) is app_config
    assert len(app_config.before_send) == 1
    hook = app_config.before_send[0]
    scope = cast("Any", {"type": "http"})

    await hook(cast("Any", {"type": "http.response.body"}), scope)
    message = cast("Any", {"type": "http.response.start", "headers": []})
    await hook(message, scope)
    header = message["headers"][0]
    message["headers"].append(header)
    await hook(message, scope)
    assert message["headers"] == [header]

    message["headers"][0] = (header[0], b"script-src 'none'")
    with pytest.raises(ImproperlyConfiguredException, match="conflicting Content-Security-Policy"):
        await hook(message, scope)


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


class _ProviderStore:
    async def get(self, _key_id: str) -> None:
        return None

    async def create(self, _record: object) -> None:
        return None

    async def rotate(self, **_kwargs: object) -> None:
        return None

    async def revoke(self, **_kwargs: object) -> None:
        return None


class _ProviderJWKS:
    async def select_key(self, *_args: object, **_kwargs: object) -> InvalidCredentials:
        return InvalidCredentials()

    async def warmup(self, *, now: datetime) -> None:
        del now

    async def aclose(self) -> None:
        return None


def test_chapter_seven_provider_configs_register_native_openapi_schemes() -> None:
    resolver = _CompilerResolver()
    jwks = _ProviderJWKS()
    config = SecurityConfig(
        api_key=APIKeyConfig(store=_ProviderStore(), pepper=b"p" * 32, identity_resolver=resolver),
        iap=GoogleIAPConfig(
            audience="/projects/123/global/backendServices/456",
            identity_resolver=resolver,  # type: ignore[arg-type]
            jwks=jwks,
        ),
        service_token=ServiceTokenConfig(
            issuer="https://id.example.com",
            audiences=frozenset({"service-api"}),
            allowed_algorithms=frozenset({"ES256"}),
            jwks=jwks,
            jwks_uri="https://id.example.com/jwks",
        ),
    )

    @get("/protected")
    async def protected() -> None:
        return None

    plugin = SecurityPlugin(config)
    app = Litestar(
        route_handlers=[protected], openapi_config=OpenAPIConfig(title="Test", version="1.0"), plugins=[plugin]
    )
    with TestClient(app) as client:
        response = client.get("/protected")

    assert response.status_code == 401
    assert app.openapi_schema.components is not None
    assert app.openapi_schema.components.security_schemes == {
        "APIKey": SecurityScheme(type="apiKey", name="X-API-Key", security_scheme_in="header"),
        "GoogleIAP": SecurityScheme(
            type="apiKey",
            name="X-Goog-IAP-JWT-Assertion",
            security_scheme_in="header",
            description=(
                "Assertion header injected by Google IAP; normal API clients must not supply this value manually."
            ),
        ),
        "service-jwt": SecurityScheme(type="http", scheme="bearer", bearer_format="JWT"),
    }
    assert app.openapi_schema.paths["/protected"].get.security == [
        {"APIKey": []},
        {"GoogleIAP": []},
        {"service-jwt": []},
    ]
    assert config.jwks_providers == (jwks,)
    reused = AppConfig(openapi_config=None)
    assert plugin.on_app_init(reused) is reused
    assert plugin.on_app_init(reused) is reused
    assert len(reused.lifespan) == 2


def _compiler_config(  # noqa: PLR0913
    *,
    names: tuple[str, ...] = ("a", "b"),
    scheme_names: dict[str, str] | None = None,
    scheme_types: dict[str, Literal["apiKey", "http", "mutualTLS", "oauth2", "openIdConnect"]] | None = None,
    max_openapi_combinations: int = 32,
    session_names: frozenset[str] = frozenset(),
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
        max_openapi_combinations=max_openapi_combinations,
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


def test_generated_mfa_route_bundle_has_exact_paths_policies_and_secret_free_openapi() -> None:
    router = build_mfa_routes(
        step_up=cast("Any", object()),
        epochs=cast("Any", object()),
        mfa=cast("Any", object()),
        passkeys=cast("Any", object()),
    )
    assert set(router.dependencies) == {"mfa_service"}
    app = Litestar(
        route_handlers=[router],
        csrf_config=CSRFConfig(secret=token_hex()),
        openapi_config=OpenAPIConfig(title="MFA", version="1.0"),
        plugins=[SecurityPlugin(_compiler_config(names=("session", "bearer"), session_names=frozenset({"session"})))],
    )

    paths = {
        route_value.path
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path.startswith("/auth/")
    }
    assert paths == {
        "/auth/mfa/recovery-codes",
        "/auth/mfa/totp/enroll",
        "/auth/mfa/totp/verify",
        "/auth/mfa/totp/{method_id:str}/remove",
        "/auth/passkeys",
        "/auth/passkeys/authentication/options",
        "/auth/passkeys/authentication/verify",
        "/auth/passkeys/registration/options",
        "/auth/passkeys/registration/verify",
        "/auth/passkeys/{credential_id:str}/remove",
        "/auth/step-up/{purpose:str}",
    }
    assert router.cache_control is not None
    assert router.cache_control.no_store is True
    schema = repr(app.openapi_schema)
    assert "otpauth://" not in schema
    assert "rc_v1_" not in schema
    assert "private credential" not in schema.lower()


class _RouteMFAService:
    failure: str | None = None

    async def verify_totp(self, account_id: str, method_id: str, code: str) -> object:
        del account_id, method_id, code
        if self.failure == "factor":
            return InvalidCredentials()
        return _route_factor_evidence()

    async def consume_recovery_code(self, account_id: str, code: str) -> object:
        del account_id, code
        if self.failure == "factor":
            return InvalidCredentials()
        return _route_factor_evidence()

    async def begin_totp_enrollment(self, account_id: str, *, label: str) -> object:
        del account_id, label
        if self.failure == "enroll":
            return VerificationUnavailable()
        return TOTPEnrollment(
            enrollment_id="enrollment-1",
            method_id="method-1",
            provisioning_uri="otpauth://totp/Example?secret=SECRET",
            expires_at=datetime(2026, 7, 27, 0, 5, tzinfo=timezone.utc),
        )

    async def activate_totp(self, account_id: str, enrollment_id: str, code: str) -> object:
        del enrollment_id, code
        if self.failure == "activate":
            return InvalidCredentials()
        return TOTPMethod(
            method_id="method-1",
            account_id=account_id,
            protected_secret=ProtectedSecret(ciphertext=b"ciphertext", key_version="v1"),
            policy=TOTPPolicy(),
            last_accepted_counter=1,
            created_at=datetime(2026, 7, 27, tzinfo=timezone.utc),
        )

    async def activate_totp_with_recovery_codes(self, account_id: str, enrollment_id: str, code: str) -> object:
        del account_id, enrollment_id, code
        if self.failure == "activate":
            return InvalidCredentials()
        if self.failure == "recovery":
            return VerificationUnavailable()
        return RecoveryCodes(codes=("rc_v1_00000000000000000000000000000000",))

    async def generate_recovery_codes(self, account_id: str) -> object:
        del account_id
        if self.failure == "recovery":
            return VerificationUnavailable()
        return RecoveryCodes(codes=("rc_v1_00000000000000000000000000000000",))

    async def remove_totp_method(self, account_id: str, method_id: str) -> object:
        del account_id, method_id
        if self.failure == "remove":
            return VerificationUnavailable()
        return RevokeLoginMethodResult(RevokeLoginMethodStatus.REVOKED)


class _RoutePasskeyService:
    failure: str | None = None

    async def verify_authentication(self, account_id: str, *, binding: bytes, response: str) -> object:
        del account_id, binding, response
        if self.failure == "authentication":
            return InvalidCredentials()
        return _route_factor_evidence()

    async def begin_registration(self, account_id: str, *, user_name: str, binding: bytes) -> object:
        del account_id, user_name, binding
        if self.failure == "options":
            return VerificationUnavailable()
        return _route_options()

    async def verify_registration(self, account_id: str, *, binding: bytes, response: str) -> object:
        del account_id, binding, response
        if self.failure == "registration":
            return InvalidCredentials()
        return SimpleNamespace(credential_id=b"credential")

    async def begin_authentication(self, account_id: str, *, binding: bytes) -> object:
        del account_id, binding
        if self.failure == "options":
            return VerificationUnavailable()
        return _route_options()

    async def list_credentials(self, account_id: str) -> object:
        del account_id
        if self.failure == "list":
            return VerificationUnavailable()
        return (
            PasskeySummary(
                credential_id="Y3JlZGVudGlhbA",
                display_name="Laptop",
                backup_eligible=True,
                backup_state=False,
                suspect=False,
                created_at=datetime(2026, 7, 27, tzinfo=timezone.utc),
                last_used_at=None,
            ),
        )

    async def remove_credential(self, account_id: str, credential_id: bytes) -> object:
        del account_id, credential_id
        if self.failure == "remove":
            return VerificationUnavailable()
        return RevokeLoginMethodResult(RevokeLoginMethodStatus.REVOKED)


class _RouteStepUpService:
    failure: str | None = None

    async def issue(self, **kwargs: object) -> object:
        del kwargs
        if self.failure == "issue":
            return InvalidCredentials()
        return StepUpGrant(
            token="step-up-grant",  # noqa: S106 - deterministic opaque fixture token
            purpose="settings",
            expires_at=datetime(2026, 7, 27, 0, 5, tzinfo=timezone.utc),
        )

    async def consume(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        if self.failure == "consume":
            return InvalidCredentials()
        return _route_factor_evidence()


class _RouteEpochs:
    value: object = 1

    async def current_epoch(self, account_id: str) -> int:
        del account_id
        if isinstance(self.value, BaseException):
            raise self.value
        return cast("int", self.value)


class _RouteLocalAuth:
    failure = False

    class PasswordReauthentication:
        failure = False

        async def verify(self, account_id: str, password: str) -> object:
            del password
            if self.failure:
                return InvalidCredentials()
            return PasswordReauthenticationProof(
                account_id=account_id,
                security_epoch=1,
                authenticated_at=datetime(2026, 7, 27, tzinfo=timezone.utc),
                expires_at=datetime(2026, 7, 27, 0, 5, tzinfo=timezone.utc),
            )

    password_reauthentication = PasswordReauthentication()

    async def passkey_login(
        self, request: object, account_id: str, *, transport: str | None, evidence: object
    ) -> object:
        del request, transport, evidence
        if self.failure:
            return InvalidCredentials()
        return LocalAccountResponse(account_id=account_id)


def _route_factor_evidence() -> AuthenticationEvidence:
    return AuthenticationEvidence(
        mechanism="totp",
        slot="mfa",
        authenticated_at=datetime(2026, 7, 27, tzinfo=timezone.utc),
        methods=frozenset({"totp"}),
    )


def _route_options() -> WebAuthnOptions:
    return WebAuthnOptions(
        challenge="challenge",
        json='{"challenge":"challenge"}',
        expires_at=datetime(2026, 7, 27, 0, 5, tzinfo=timezone.utc),
    )


def test_generated_mfa_routes_document_the_status_they_actually_return() -> None:
    router = build_mfa_routes(
        step_up=cast("Any", _RouteStepUpService()),
        epochs=cast("Any", _RouteEpochs()),
        mfa=cast("Any", _RouteMFAService()),
        passkeys=cast("Any", _RoutePasskeyService()),
        local_auth=cast("Any", _RouteLocalAuth()),
    )
    app = Litestar(
        route_handlers=[router],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(_compiler_config(names=("a",)))],
    )
    authenticated = {"x-auth-a": "valid", "authorization": "Bearer transport"}
    calls: tuple[tuple[str, str, dict[str, object]], ...] = (
        ("POST", "/auth/mfa/totp/enroll", {"label": "person@example.com", "step_up_grant": "grant"}),
        ("POST", "/auth/mfa/totp/verify", {"enrollment_id": "enrollment-1", "code": "123456"}),
        ("POST", "/auth/mfa/recovery-codes", {"step_up_grant": "grant"}),
        ("POST", "/auth/passkeys/registration/options", {"user_name": "person@example.com", "step_up_grant": "grant"}),
        ("POST", "/auth/passkeys/registration/verify", {"account_id": "user", "response": "{}"}),
        ("POST", "/auth/passkeys/authentication/options", {"account_id": "user"}),
    )

    observed: dict[str, int] = {}
    with TestClient(app) as client:
        for method, path, payload in calls:
            observed[path] = client.request(method, path, headers=authenticated, json=payload).status_code

    documented = {
        path: next(iter(app.openapi_schema.paths[path].post.responses))
        for _method, path, _payload in calls
        if app.openapi_schema.paths[path].post is not None
    }

    assert observed == {path: int(status) for path, status in documented.items()}


def test_generated_mfa_bodies_are_snake_case_on_the_wire() -> None:
    router = build_mfa_routes(
        step_up=cast("Any", _RouteStepUpService()),
        epochs=cast("Any", _RouteEpochs()),
        mfa=cast("Any", _RouteMFAService()),
        passkeys=cast("Any", _RoutePasskeyService()),
        local_auth=cast("Any", _RouteLocalAuth()),
    )
    app = Litestar(
        route_handlers=[router], openapi_config=None, plugins=[SecurityPlugin(_compiler_config(names=("a",)))]
    )
    authenticated = {"x-auth-a": "valid", "authorization": "Bearer transport"}

    with TestClient(app) as client:
        enrolled = client.post(
            "/auth/mfa/totp/enroll",
            headers=authenticated,
            json={"label": "person@example.com", "step_up_grant": "grant"},
        )
        stepped_up = client.post(
            "/auth/step-up/totp-enroll", headers=authenticated, json={"method": "password", "credential": "secret"}
        )
        options = client.post("/auth/passkeys/authentication/options", json={"account_id": "user"})
        rejected_casing = client.post(
            "/auth/mfa/totp/enroll", headers=authenticated, json={"label": "person@example.com", "stepUpGrant": "grant"}
        )

    assert enrolled.status_code == HTTP_201_CREATED, enrolled.text
    assert {"enrollment_id", "method_id", "provisioning_uri", "expires_at"} <= set(enrolled.json())
    assert stepped_up.status_code == HTTP_200_OK, stepped_up.text
    assert {"grant", "purpose", "expires_at"} <= set(stepped_up.json())
    assert options.status_code == HTTP_200_OK, options.text
    assert {"options", "expires_at", "binding"} <= set(options.json())
    assert rejected_casing.status_code == HTTP_400_BAD_REQUEST, rejected_casing.text


def test_generated_mfa_handlers_delegate_every_success_path_and_shape_safe_responses() -> None:
    local_auth = _RouteLocalAuth()
    router = build_mfa_routes(
        step_up=cast("Any", _RouteStepUpService()),
        epochs=cast("Any", _RouteEpochs()),
        mfa=cast("Any", _RouteMFAService()),
        passkeys=cast("Any", _RoutePasskeyService()),
        local_auth=cast("Any", local_auth),
    )
    app = Litestar(
        route_handlers=[router], openapi_config=None, plugins=[SecurityPlugin(_compiler_config(names=("a",)))]
    )
    authenticated = {"x-auth-a": "valid", "authorization": "Bearer transport"}

    with TestClient(app) as client:
        local_auth.password_reauthentication.failure = True
        assert (
            client.post(
                "/auth/step-up/recovery-codes", headers=authenticated, json={"method": "password", "credential": "bad"}
            ).status_code
            == 401
        )
        local_auth.password_reauthentication.failure = False
        assert (
            client.post(
                "/auth/step-up/recovery-codes", headers=authenticated, json={"method": "passkey", "credential": "{}"}
            ).status_code
            == HTTP_200_OK
        )
        assert (
            client.post(
                "/auth/step-up/totp-enroll", headers=authenticated, json={"method": "password", "credential": "secret"}
            ).status_code
            == HTTP_200_OK
        )
        assert (
            client.post(
                "/auth/step-up/totp-enroll",
                headers=authenticated,
                json={"method": "totp", "credential": "123456", "method_id": "method-1"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/auth/mfa/totp/enroll",
                headers=authenticated,
                json={"label": "person@example.com", "step_up_grant": "grant"},
            ).status_code
            == HTTP_201_CREATED
        )
        assert (
            client.post(
                "/auth/mfa/totp/verify", headers=authenticated, json={"enrollment_id": "enrollment-1", "code": "123456"}
            ).status_code
            == HTTP_200_OK
        )
        assert (
            client.post(
                "/auth/mfa/totp/method-1/remove", headers=authenticated, json={"step_up_grant": "grant"}
            ).status_code
            == HTTP_200_OK
        )
        assert (
            client.post("/auth/mfa/recovery-codes", headers=authenticated, json={"step_up_grant": "grant"}).status_code
            == HTTP_200_OK
        )
        assert (
            client.post(
                "/auth/passkeys/registration/options",
                headers=authenticated,
                json={"user_name": "person@example.com", "step_up_grant": "grant"},
            ).status_code
            == HTTP_200_OK
        )
        assert (
            client.post(
                "/auth/passkeys/registration/verify",
                headers=authenticated,
                json={"account_id": "user", "response": "{}"},
            ).status_code
            == HTTP_201_CREATED
        )
        authentication_options = client.post("/auth/passkeys/authentication/options", json={"account_id": "user"})
        assert authentication_options.status_code == HTTP_200_OK
        assert (
            client.post(
                "/auth/passkeys/authentication/verify",
                json={"account_id": "user", "response": "{}", "transport": "tokens"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/auth/passkeys/authentication/verify",
                json={
                    "account_id": "user",
                    "response": "{}",
                    "binding": authentication_options.json()["binding"],
                    "transport": "tokens",
                },
            ).status_code
            == HTTP_200_OK
        )
        inventory = client.get("/auth/passkeys", headers=authenticated)
        assert inventory.status_code == HTTP_200_OK
        assert "public_key" not in inventory.text
        assert (
            client.post(
                "/auth/passkeys/Y3JlZGVudGlhbA/remove", headers=authenticated, json={"step_up_grant": "grant"}
            ).status_code
            == HTTP_200_OK
        )
        assert all(response.headers["cache-control"] == "no-store" for response in (inventory,))
        assert inventory.headers["pragma"] == "no-cache"


def test_generated_mfa_handlers_sanitize_service_and_binding_failures() -> None:  # noqa: PLR0915 - one route-family failure matrix
    mfa = _RouteMFAService()
    passkeys = _RoutePasskeyService()
    step_up = _RouteStepUpService()
    epochs = _RouteEpochs()
    local_auth = _RouteLocalAuth()
    router = build_mfa_routes(
        step_up=cast("Any", step_up),
        epochs=cast("Any", epochs),
        mfa=cast("Any", mfa),
        passkeys=cast("Any", passkeys),
        local_auth=cast("Any", local_auth),
    )
    app = Litestar(
        route_handlers=[router], openapi_config=None, plugins=[SecurityPlugin(_compiler_config(names=("a",)))]
    )
    headers = {"x-auth-a": "valid", "authorization": "Bearer transport"}

    with TestClient(app) as client:
        assert (
            client.post(
                "/auth/step-up/totp-enroll", headers=headers, json={"method": "unknown", "credential": "x"}
            ).status_code
            == 401
        )
        passkeys.failure = "authentication"
        assert (
            client.post(
                "/auth/step-up/passkey-remove", headers=headers, json={"method": "passkey", "credential": "{}"}
            ).status_code
            == 401
        )
        passkeys.failure = None
        step_up.failure = "issue"
        assert (
            client.post(
                "/auth/step-up/recovery-codes", headers=headers, json={"method": "password", "credential": "x"}
            ).status_code
            == 401
        )
        step_up.failure = None
        epochs.value = False
        assert (
            client.post(
                "/auth/step-up/passkey-register", headers=headers, json={"method": "passkey", "credential": "{}"}
            ).status_code
            == 503
        )
        epochs.value = 1
        step_up.failure = "consume"
        assert (
            client.post(
                "/auth/mfa/totp/enroll", headers=headers, json={"label": "User", "step_up_grant": "bad"}
            ).status_code
            == 401
        )
        step_up.failure = None
        mfa.failure = "enroll"
        assert (
            client.post(
                "/auth/mfa/totp/enroll", headers=headers, json={"label": "User", "step_up_grant": "grant"}
            ).status_code
            == 503
        )
        mfa.failure = "activate"
        assert (
            client.post(
                "/auth/mfa/totp/verify", headers=headers, json={"enrollment_id": "e1", "code": "123456"}
            ).status_code
            == 401
        )
        mfa.failure = "recovery"
        assert (
            client.post(
                "/auth/mfa/totp/verify", headers=headers, json={"enrollment_id": "e1", "code": "123456"}
            ).status_code
            == 503
        )
        assert (
            client.post("/auth/mfa/recovery-codes", headers=headers, json={"step_up_grant": "grant"}).status_code == 503
        )
        mfa.failure = "remove"
        assert (
            client.post("/auth/mfa/totp/m1/remove", headers=headers, json={"step_up_grant": "grant"}).status_code == 503
        )
        mfa.failure = None
        passkeys.failure = "options"
        assert (
            client.post(
                "/auth/passkeys/registration/options",
                headers=headers,
                json={"user_name": "User", "step_up_grant": "grant"},
            ).status_code
            == 503
        )
        passkeys.failure = "registration"
        assert (
            client.post(
                "/auth/passkeys/registration/verify", headers=headers, json={"account_id": "user", "response": "{}"}
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/auth/passkeys/registration/verify", headers=headers, json={"account_id": "other", "response": "{}"}
            ).status_code
            == 401
        )
        passkeys.failure = "options"
        assert client.post("/auth/passkeys/authentication/options", json={"account_id": "user"}).status_code == 503
        passkeys.failure = "authentication"
        assert (
            client.post(
                "/auth/passkeys/authentication/verify",
                json={"account_id": "user", "response": "{}", "binding": "binding"},
            ).status_code
            == 401
        )
        passkeys.failure = None
        local_auth.failure = True
        assert (
            client.post(
                "/auth/passkeys/authentication/verify",
                json={"account_id": "user", "response": "{}", "binding": "binding"},
            ).status_code
            == 401
        )
        local_auth.failure = False
        passkeys.failure = "list"
        assert client.get("/auth/passkeys", headers=headers).status_code == 503
        assert (
            client.post("/auth/passkeys/a/remove", headers=headers, json={"step_up_grant": "grant"}).status_code == 400
        )
        passkeys.failure = "remove"
        assert (
            client.post(
                "/auth/passkeys/Y3JlZGVudGlhbA/remove", headers=headers, json={"step_up_grant": "grant"}
            ).status_code
            == 503
        )
        step_up.failure = "consume"
        for method, path, payload in (
            ("POST", "/auth/mfa/totp/m1/remove", {"step_up_grant": "bad"}),
            ("POST", "/auth/mfa/recovery-codes", {"step_up_grant": "bad"}),
            ("POST", "/auth/passkeys/registration/options", {"user_name": "User", "step_up_grant": "bad"}),
            ("POST", "/auth/passkeys/Y3JlZGVudGlhbA/remove", {"step_up_grant": "bad"}),
        ):
            assert client.request(method, path, headers=headers, json=payload).status_code == 401


@pytest.mark.parametrize(
    "purpose", ["totp-enroll", "totp-remove", "recovery-codes", "passkey-register", "passkey-remove"]
)
def test_generated_step_up_purposes_constrain_factors_deny_by_default(purpose: str) -> None:
    router = build_mfa_routes(
        step_up=cast("Any", _RouteStepUpService()),
        epochs=cast("Any", _RouteEpochs()),
        mfa=cast("Any", _RouteMFAService()),
        passkeys=cast("Any", _RoutePasskeyService()),
        local_auth=cast("Any", _RouteLocalAuth()),
    )
    app = Litestar(
        route_handlers=[router], openapi_config=None, plugins=[SecurityPlugin(_compiler_config(names=("a",)))]
    )
    authenticated = {"x-auth-a": "valid", "authorization": "Bearer transport"}

    with TestClient(app) as client:
        strong = client.post(
            f"/auth/step-up/{purpose}", headers=authenticated, json={"method": "password", "credential": "secret"}
        )
        weak = client.post(
            f"/auth/step-up/{purpose}",
            headers=authenticated,
            json={"method": "totp", "method_id": "m1", "credential": "123456"},
        )
        unknown = client.post(
            "/auth/step-up/settings", headers=authenticated, json={"method": "password", "credential": "secret"}
        )

    assert strong.status_code == HTTP_200_OK, strong.text
    assert weak.status_code == 401
    assert unknown.status_code == 401


def test_generated_mfa_handlers_apply_shared_rate_limit_before_factor_work() -> None:
    class Guard:
        async def check(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            return accounts_module.RateLimited(retry_after=2)

    router = build_mfa_routes(
        step_up=cast("Any", _RouteStepUpService()),
        epochs=cast("Any", _RouteEpochs()),
        mfa=cast("Any", _RouteMFAService()),
        passkeys=cast("Any", _RoutePasskeyService()),
        local_auth=cast("Any", _RouteLocalAuth()),
        rate_limits=cast("Any", Guard()),
        client_key=lambda _request: "client",
    )
    app = Litestar(
        route_handlers=[router], openapi_config=None, plugins=[SecurityPlugin(_compiler_config(names=("a",)))]
    )
    headers = {"x-auth-a": "valid", "authorization": "Bearer transport"}
    requests = (
        ("POST", "/auth/step-up/totp-enroll", {"method": "password", "credential": "x"}, headers),
        ("POST", "/auth/mfa/totp/enroll", {"label": "User", "step_up_grant": "grant"}, headers),
        ("POST", "/auth/mfa/totp/verify", {"enrollment_id": "e1", "code": "123456"}, headers),
        ("POST", "/auth/mfa/totp/m1/remove", {"step_up_grant": "grant"}, headers),
        ("POST", "/auth/mfa/recovery-codes", {"step_up_grant": "grant"}, headers),
        ("POST", "/auth/passkeys/Y3JlZGVudGlhbA/remove", {"step_up_grant": "grant"}, headers),
        ("POST", "/auth/passkeys/registration/options", {"user_name": "User", "step_up_grant": "grant"}, headers),
        ("POST", "/auth/passkeys/registration/verify", {"account_id": "user", "response": "{}"}, headers),
        ("POST", "/auth/passkeys/authentication/options", {"account_id": "user"}, {}),
        ("POST", "/auth/passkeys/authentication/verify", {"account_id": "user", "response": "{}"}, {}),
    )
    with TestClient(app) as client:
        for method, path, payload, request_headers in requests:
            response = client.request(method, path, headers=request_headers, json=payload)
            assert response.status_code == 429
            assert response.headers["retry-after"] == "2"


@pytest.mark.parametrize(
    ("outcome_name", "status", "retry_after"),
    [("unavailable", 503, None), ("rate_limited", 429, "7"), ("invalid", 400, None)],
)
def test_generated_local_route_errors_raise_interceptable_classified_exceptions(
    outcome_name: str, status: int, retry_after: str | None
) -> None:
    outcome: object = {
        "unavailable": VerificationUnavailable(),
        "rate_limited": accounts_module.RateLimited(retry_after=7),
        "invalid": InvalidCredentials(),
    }[outcome_name]

    class Service:
        session_auth = None
        refresh_tokens = None
        registration = None

        async def session_login(self, request: object, data: object) -> object:
            del request, data
            return outcome

    config = SimpleNamespace(
        local_auth_service=Service(),
        mfa_login=None,
        mode=accounts_module.LocalAuthMode.SESSION,
        registration=SimpleNamespace(mode=accounts_module.RegistrationMode.DISABLED),
        route_prefix="/identity",
    )
    intercepted: list[int] = []

    def record(request: Any, exc: HTTPException) -> Response[Any]:
        del request
        intercepted.append(exc.status_code)
        return Response(content={"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    csrf_secret = token_hex()
    app = Litestar(
        route_handlers=[accounts_module.build_local_auth_routes(cast("Any", config))],
        csrf_config=CSRFConfig(secret=csrf_secret),
        openapi_config=None,
        plugins=[SecurityPlugin(_compiler_config(names=("session",), session_names=frozenset({"session"})))],
        exception_handlers={
            ServiceUnavailableException: record,
            TooManyRequestsException: record,
            ClientException: record,
        },
    )

    with TestClient(app) as client:
        csrf_token = generate_csrf_token(csrf_secret)
        client.cookies.set("csrftoken", csrf_token)
        response = client.post(
            "/identity/login",
            json={"identifier": "user@example.com", "password": "secret"},
            headers={"x-csrftoken": csrf_token},
        )

    assert response.status_code == status, response.text
    assert response.headers.get("retry-after") == retry_after
    assert intercepted == [status]


def test_generated_credential_bearing_route_errors_raise_unauthorized() -> None:
    class Service:
        session_auth = None
        refresh_tokens = None
        registration = None

    config = SimpleNamespace(
        local_auth_service=Service(),
        mfa_login=None,
        mode=accounts_module.LocalAuthMode.SESSION,
        registration=SimpleNamespace(mode=accounts_module.RegistrationMode.DISABLED),
        route_prefix="/identity",
    )
    csrf_secret = token_hex()
    app = Litestar(
        route_handlers=[accounts_module.build_local_auth_routes(cast("Any", config))],
        csrf_config=CSRFConfig(secret=csrf_secret),
        openapi_config=None,
        plugins=[SecurityPlugin(_compiler_config(names=("session",), session_names=frozenset({"session"})))],
    )

    with TestClient(app) as client:
        csrf_token = generate_csrf_token(csrf_secret)
        client.cookies.set("csrftoken", csrf_token)
        # An authenticated caller whose service graph cannot resolve sessions is
        # a credential-path denial, not a malformed request.
        revoked = client.request(
            "DELETE", "/identity/sessions/sid", headers={"x-auth-session": "valid", "x-csrftoken": csrf_token}
        )

    assert revoked.status_code == 401, revoked.text


def test_generated_mfa_login_routes_are_conditional_typed_and_transport_bound() -> None:
    """MFA-gated password login exposes only the configured completion transports."""

    class Service:
        session_auth = object()
        refresh_tokens = object()
        registration = None

        def __init__(self) -> None:
            self.completions: list[dict[str, object]] = []

        async def session_login(self, _request: object, _data: object) -> MFARequired:
            return MFARequired(
                challenge="challenge-secret",
                account_id="account-1",
                expires_at=datetime(2026, 7, 26, 12, 5, tzinfo=timezone.utc),
                methods=frozenset({"totp", "recovery-code"}),
            )

        async def token_login(self, request: object, data: object) -> MFARequired:
            return await self.session_login(request, data)

        async def complete_mfa_login(self, _request: object, _challenge: str, **kwargs: object) -> object:
            self.completions.append(kwargs)
            if kwargs["transport"] == "session":
                return LocalAccountResponse(account_id="account-1")
            return InvalidCredentials()

    service = Service()
    config = SimpleNamespace(
        local_auth_service=service,
        mfa_login=object(),
        mode=accounts_module.LocalAuthMode.HYBRID,
        registration=SimpleNamespace(mode=accounts_module.RegistrationMode.DISABLED),
        route_prefix="/identity",
    )
    csrf_secret = token_hex()
    app = Litestar(
        route_handlers=[accounts_module.build_local_auth_routes(cast("Any", config))],
        csrf_config=CSRFConfig(secret=csrf_secret),
        openapi_config=OpenAPIConfig(title="MFA login", version="1.0"),
        plugins=[SecurityPlugin(_compiler_config(names=("session", "bearer"), session_names=frozenset({"session"})))],
    )
    paths = {route_value.path for route_value in app.routes if isinstance(route_value, HTTPRoute)}
    assert {"/identity/login/mfa", "/identity/token/mfa"} <= paths
    route_handlers = {
        route_value.path: route_value.route_handler_map["POST"][0]
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path in {"/identity/login/mfa", "/identity/token/mfa"}
    }
    assert (route_handlers["/identity/login/mfa"].name, route_handlers["/identity/login/mfa"].operation_id) == (
        "local.session.login.mfa",
        "LocalSessionMFALogin",
    )
    assert (route_handlers["/identity/token/mfa"].name, route_handlers["/identity/token/mfa"].operation_id) == (
        "local.token.login.mfa",
        "LocalTokenMFALogin",
    )
    assert _http_plan(app, "/identity/login/mfa", "POST").csrf_required is True
    assert _http_plan(app, "/identity/token/mfa", "POST").csrf_required is False
    session_login = app.openapi_schema.paths["/identity/login"].post
    token_login = app.openapi_schema.paths["/identity/token"].post
    assert session_login is not None
    assert session_login.responses is not None
    assert token_login is not None
    assert token_login.responses is not None
    for responses, success_schema in (
        (session_login.responses, "#/components/schemas/LocalAccountResponse"),
        (token_login.responses, "#/components/schemas/RefreshTokenResponse"),
    ):
        success_content = responses["200"].content
        required_content = responses["403"].content
        assert success_content is not None
        assert required_content is not None
        assert success_content["application/json"].schema is not None
        assert required_content["application/json"].schema is not None
        assert success_content["application/json"].schema.ref == success_schema
        assert required_content["application/json"].schema.ref == "#/components/schemas/LocalMFARequiredResponse"

    with TestClient(app) as client:
        csrf_token = generate_csrf_token(csrf_secret)
        client.cookies.set("csrftoken", csrf_token)
        required = client.post(
            "/identity/login",
            json={"identifier": "person@example.com", "password": "password"},
            headers={"x-csrftoken": csrf_token},
        )
        completed = client.post(
            "/identity/login/mfa",
            json={
                "challenge": "challenge-secret",
                "account_id": "account-1",
                "method": "totp",
                "method_id": "method-1",
                "code": "123456",
            },
            headers={"x-csrftoken": csrf_token},
        )
        token_completed = client.post(
            "/identity/token/mfa",
            json={
                "challenge": "challenge-secret",
                "account_id": "account-1",
                "method": "recovery-code",
                "code": "recovery-secret",
            },
        )

    assert required.status_code == 403
    assert required.headers["cache-control"] == "no-store"
    assert required.headers["pragma"] == "no-cache"
    assert required.json() == {
        "challenge": "challenge-secret",
        "account_id": "account-1",
        "expires_at": "2026-07-26T12:05:00Z",
        "methods": ["recovery-code", "totp"],
        "code": "mfa_required",
        "detail": "Multi-factor authentication is required.",
    }
    assert completed.status_code == 200
    assert token_completed.status_code == 400
    assert service.completions == [
        {
            "account_id": "account-1",
            "method": "totp",
            "method_id": "method-1",
            "code": "123456",
            "transport": "session",
        },
        {
            "account_id": "account-1",
            "method": "recovery-code",
            "method_id": None,
            "code": "recovery-secret",
            "transport": "tokens",
        },
    ]


@pytest.mark.parametrize("mode", ["session", "tokens", "hybrid"])
def test_generated_mfa_completion_routes_follow_local_auth_transport_and_csrf_mode(mode: str) -> None:
    """MFA completion exposes each enabled issuer path and only sessions require native CSRF."""

    class Service:
        session_auth = object() if mode in {"session", "hybrid"} else None
        refresh_tokens = object() if mode in {"tokens", "hybrid"} else None
        registration = None

        def __init__(self) -> None:
            self.transports: list[str] = []

        async def session_login(self, _request: object, _data: object) -> MFARequired:
            return MFARequired(
                challenge="challenge-secret",
                account_id="account-1",
                expires_at=datetime(2026, 7, 26, 12, 5, tzinfo=timezone.utc),
                methods=frozenset({"totp"}),
            )

        async def token_login(self, request: object, data: object) -> MFARequired:
            return await self.session_login(request, data)

        async def complete_mfa_login(self, _request: object, _challenge: str, **kwargs: object) -> object:
            transport = cast("str", kwargs["transport"])
            self.transports.append(transport)
            if transport == "session":
                return LocalAccountResponse(account_id="account-1")
            return accounts_module.RefreshTokenResponse(
                access_token="e30.e30.YQ",  # noqa: S106 - compact public test JWT
                refresh_token="rt_aWlpaWlpaWlpaWlpaWlpaQ.c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M",  # noqa: S106
                expires_in=60,
            )

    service = Service()
    csrf_secret = token_hex()
    session_enabled = mode in {"session", "hybrid"}
    mechanism_names = ("session", "bearer") if mode == "hybrid" else (("session",) if session_enabled else ("bearer",))
    app = Litestar(
        route_handlers=[
            accounts_module.build_local_auth_routes(
                cast(
                    "Any",
                    SimpleNamespace(
                        local_auth_service=service,
                        mfa_login=object(),
                        mode=accounts_module.LocalAuthMode(mode),
                        registration=SimpleNamespace(mode=accounts_module.RegistrationMode.DISABLED),
                        route_prefix="/identity",
                    ),
                )
            )
        ],
        csrf_config=CSRFConfig(secret=csrf_secret) if session_enabled else None,
        openapi_config=None,
        plugins=[
            SecurityPlugin(
                _compiler_config(
                    names=mechanism_names, session_names=frozenset({"session"}) if session_enabled else frozenset()
                )
            )
        ],
    )
    expected = {"/identity/login/mfa" if session_enabled else "/identity/token/mfa"}
    if mode == "hybrid":
        expected.add("/identity/token/mfa")
    completion_paths = {
        route_value.path
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path.endswith("/mfa")
    }
    assert completion_paths == expected

    with TestClient(app) as client:
        if session_enabled:
            blocked = client.post(
                "/identity/login/mfa",
                json={"challenge": "challenge-secret", "account_id": "account-1", "method": "totp", "code": "123456"},
            )
            assert blocked.status_code == 403
            csrf_token = generate_csrf_token(csrf_secret)
            client.cookies.set("csrftoken", csrf_token)
            session_response = client.post(
                "/identity/login/mfa",
                json={"challenge": "challenge-secret", "account_id": "account-1", "method": "totp", "code": "123456"},
                headers={"x-csrftoken": csrf_token},
            )
            assert session_response.status_code == 200
        if mode in {"tokens", "hybrid"}:
            token_response = client.post(
                "/identity/token/mfa",
                json={"challenge": "challenge-secret", "account_id": "account-1", "method": "totp", "code": "123456"},
            )
            assert token_response.status_code == 200

    expected_transports = ([] if not session_enabled else ["session"]) + ([] if mode == "session" else ["tokens"])
    assert service.transports == expected_transports


def test_generated_token_mfa_completion_surfaces_controlled_login_mfa_rate_limit() -> None:
    """The public token completion route preserves the shared LOGIN_MFA retry signal."""

    class Service:
        session_auth = None
        refresh_tokens = object()
        registration = None

        async def complete_mfa_login(self, *_args: object, **_kwargs: object) -> accounts_module.RateLimited:
            return accounts_module.RateLimited(retry_after=7)

    app = Litestar(
        route_handlers=[
            accounts_module.build_local_auth_routes(
                cast(
                    "Any",
                    SimpleNamespace(
                        local_auth_service=Service(),
                        mfa_login=object(),
                        mode=accounts_module.LocalAuthMode.TOKENS,
                        registration=SimpleNamespace(mode=accounts_module.RegistrationMode.DISABLED),
                        route_prefix="/identity",
                    ),
                )
            )
        ],
        openapi_config=None,
        plugins=[SecurityPlugin(_compiler_config(names=("bearer",), session_names=frozenset()))],
    )

    with TestClient(app) as client:
        response = client.post(
            "/identity/token/mfa",
            json={"challenge": "challenge-secret", "account_id": "account-1", "method": "totp", "code": "123456"},
        )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "7"


def _feature_test_ports() -> tuple[object, object, object, object]:
    async def none(*_args: object, **_kwargs: object) -> None:
        return None

    async def false(*_args: object, **_kwargs: object) -> bool:
        return False

    mfa_store = SimpleNamespace(
        create_totp_enrollment=none,
        get_totp_enrollment=none,
        activate_totp=none,
        activate_totp_with_recovery_codes=none,
        get_totp_method=none,
        advance_totp_counter=false,
        replace_recovery_codes=none,
        consume_recovery_code=false,
        register_login_method=none,
        revoke_login_method=none,
        put=none,
        consume=none,
    )
    protector = SimpleNamespace(active_key_version="v1", protect=none, unprotect=none)
    passkey_store = SimpleNamespace(
        add_credential=false,
        get_credential=none,
        record_assertion=none,
        list_credentials=none,
        rename_credential=none,
        register_login_method=none,
        revoke_login_method=none,
    )
    challenge_store = SimpleNamespace(put=none, consume=none)
    return mfa_store, protector, passkey_store, challenge_store


def test_plugin_mfa_route_registration_validates_ownership_and_is_idempotent() -> None:
    mfa_store, protector, passkey_store, challenge_store = _feature_test_ports()
    disabled = MFAConfig(store=mfa_store, secret_protector=protector, register_routes=False)
    app_config = AppConfig()
    SecurityPlugin(SecurityConfig(mfa=disabled))._configure_mfa_routes(app_config)  # noqa: SLF001
    assert app_config.route_handlers == []

    recovery_peppers = (accounts_module.RecoveryCodePepper("v1", b"p" * 32),)
    enabled = MFAConfig(
        store=mfa_store,
        secret_protector=protector,
        recovery_peppers=recovery_peppers,
        login_methods=cast("Any", mfa_store),
    )
    with pytest.raises(ImproperlyConfiguredException, match="local authentication"):
        SecurityPlugin(SecurityConfig(mfa=enabled))._configure_mfa_routes(AppConfig())  # noqa: SLF001

    local_auth = _local_session_auth(binding=SessionBindingConfig(pepper=b"b" * 32, max_age=600))
    no_step_store = SimpleNamespace(**{
        name: getattr(mfa_store, name)
        for name in (
            "create_totp_enrollment",
            "get_totp_enrollment",
            "activate_totp",
            "activate_totp_with_recovery_codes",
            "get_totp_method",
            "advance_totp_counter",
            "replace_recovery_codes",
            "consume_recovery_code",
        )
    })
    without_step = MFAConfig(
        store=no_step_store,
        secret_protector=protector,
        recovery_peppers=recovery_peppers,
        login_methods=cast("Any", mfa_store),
    )
    with pytest.raises(ImproperlyConfiguredException, match="StepUpStore"):
        SecurityPlugin(SecurityConfig(local_auth=local_auth, mfa=without_step))._configure_mfa_routes(  # noqa: SLF001
            AppConfig()
        )

    passkeys = PasskeyConfig(
        store=passkey_store,
        challenge_store=challenge_store,
        rp_id="example.com",
        origins=("https://example.com",),
        login_methods=cast("Any", passkey_store),
        step_up_store=mfa_store,
        route_prefix="/other",
    )
    with pytest.raises(ImproperlyConfiguredException, match="route prefix"):
        SecurityPlugin(SecurityConfig(local_auth=local_auth, mfa=enabled, passkeys=passkeys))._configure_mfa_routes(  # noqa: SLF001 - validates the plugin construction invariant directly
            AppConfig()
        )
    object.__setattr__(enabled, "step_up_service", object())
    with pytest.raises(ImproperlyConfiguredException, match="StepUpService"):
        SecurityPlugin(SecurityConfig(local_auth=local_auth, mfa=enabled))._configure_mfa_routes(  # noqa: SLF001 - validates the plugin construction invariant directly
            AppConfig()
        )
    object.__setattr__(enabled, "step_up_service", accounts_module.StepUpService(cast("Any", mfa_store)))

    passkeys = PasskeyConfig(
        store=passkey_store,
        challenge_store=challenge_store,
        rp_id="example.com",
        origins=("https://example.com",),
        login_methods=cast("Any", passkey_store),
        step_up_store=mfa_store,
    )
    plugin = SecurityPlugin(SecurityConfig(local_auth=local_auth, mfa=enabled, passkeys=passkeys))
    app_config = AppConfig()
    plugin._configure_mfa_routes(app_config)  # noqa: SLF001
    plugin._configure_mfa_routes(app_config)  # noqa: SLF001
    assert len(app_config.route_handlers) == 1


@pytest.mark.anyio
async def test_plugin_binds_login_mfa_before_local_route_caching_and_gates_password_login() -> None:
    """The MFA-login service is installed before generated local routes can cache."""
    mfa_store, protector, _passkey_store, _challenge_store = _feature_test_ports()
    mfa = MFAConfig(
        store=mfa_store,
        secret_protector=protector,
        recovery_peppers=(accounts_module.RecoveryCodePepper("v1", b"p" * 32),),
        login_methods=cast("Any", mfa_store),
        require_at_login=True,
        register_routes=False,
    )
    local_auth = _local_session_auth()
    plugin = SecurityPlugin(SecurityConfig(local_auth=local_auth, mfa=mfa))

    plugin._configure_mfa_login()  # noqa: SLF001 - assert composition order directly

    assert local_auth.mfa_login is not None
    assert local_auth.local_auth_service.mfa_login is local_auth.mfa_login
    assert local_auth.build_route_handlers() == ()

    account = LocalAccount(
        account_id="account-1",
        normalized_identifier="person@example.com",
        display_name="Person",
        active=True,
        verified=True,
        security_epoch=1,
    )

    class PasswordLogin:
        async def authenticate(self, *_args: object, **_kwargs: object) -> LocalAccount[object]:
            return account

    service = replace(local_auth.local_auth_service, password_login=cast("Any", PasswordLogin()))
    outcome = await service.session_login(
        cast("Any", object()),
        LocalCredentials(identifier="person@example.com", password="password"),  # noqa: S106
    )
    assert isinstance(outcome, MFARequired)


def test_plugin_mfa_login_binding_validates_configuration_and_is_idempotent() -> None:
    mfa_store, protector, _passkey_store, _challenge_store = _feature_test_ports()
    peppers = (accounts_module.RecoveryCodePepper("v1", b"p" * 32),)
    mfa = MFAConfig(
        store=mfa_store,
        secret_protector=protector,
        recovery_peppers=peppers,
        login_methods=cast("Any", mfa_store),
        require_at_login=True,
    )
    local_auth = _local_session_auth()
    plugin = SecurityPlugin(SecurityConfig(local_auth=local_auth, mfa=mfa))

    plugin._configure_mfa_login()  # noqa: SLF001 - plugin composition boundary
    bound = local_auth.mfa_login
    plugin._configure_mfa_login()  # noqa: SLF001 - same config is intentionally idempotent
    assert local_auth.mfa_login is bound

    cached_auth = LocalAuth.session(
        accounts=cast("Any", _local_session_accounts()),
        secrets=_local_auth_secrets(),
        binding=SessionBindingConfig(pepper=b"binding-pepper-for-plugin-tests!", max_age=600),
    )
    cached_auth.build_route_handlers()
    with pytest.raises(ImproperlyConfiguredException, match="route handlers"):
        cached_auth.bind_mfa_login(mfa)

    other = MFAConfig(
        store=mfa_store,
        secret_protector=protector,
        recovery_peppers=peppers,
        login_methods=cast("Any", mfa_store),
        require_at_login=True,
    )
    with pytest.raises(ImproperlyConfiguredException, match="already bound"):
        local_auth.bind_mfa_login(other)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"require_at_login": cast("Any", 1)}, "require_at_login must be boolean"),
        ({"require_at_login": True, "login_challenge_store": object()}, "MFALoginChallengeStore"),
        ({"require_at_login": True}, "recovery-code peppers and a login-method store"),
    ],
)
def test_mfa_login_config_requires_a_valid_challenge_store_and_dependencies(
    kwargs: dict[str, object], match: str
) -> None:
    mfa_store, protector, _passkey_store, _challenge_store = _feature_test_ports()
    with pytest.raises(ImproperlyConfiguredException, match=match):
        MFAConfig(store=mfa_store, secret_protector=protector, register_routes=False, **kwargs)  # type: ignore[arg-type]


def test_plugin_mfa_login_allows_explicit_store_override_and_requires_local_auth() -> None:
    mfa_store, protector, _passkey_store, _challenge_store = _feature_test_ports()

    class OverrideStore:
        async def put(self, _challenge: object) -> None:
            return None

        async def consume(self, *_args: object, **_kwargs: object) -> None:
            return None

    override = OverrideStore()
    mfa = MFAConfig(
        store=mfa_store,
        secret_protector=protector,
        login_challenge_store=override,
        recovery_peppers=(accounts_module.RecoveryCodePepper("v1", b"p" * 32),),
        login_methods=cast("Any", mfa_store),
        require_at_login=True,
        register_routes=False,
    )
    assert mfa.login_challenge_store is override

    with pytest.raises(ImproperlyConfiguredException, match="local authentication"):
        SecurityPlugin(SecurityConfig(mfa=mfa))._configure_mfa_login()  # noqa: SLF001


def _local_session_accounts() -> Any:
    capability_names = (
        "compare_and_replace_password",
        "consume_and_reset",
        "consume_and_verify",
        "create",
        "create_family",
        "current_epoch",
        "find_for_login",
        "get",
        "get_by_id",
        "get_password_state",
        "issue",
        "issue_absent",
        "list_for_account",
        "prepare_rotation",
        "rebind",
        "register",
        "register_login_method",
        "replace_password_and_bump_epoch",
        "revoke",
        "revoke_family",
        "revoke_for_account",
        "revoke_login_method",
        "revoke_other_sessions",
        "revoke_session_for_account",
        "revoke_sessions_for_account",
        "revoke_token",
        "revoke_token_for_account",
        "rotate",
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


def _local_session_auth(*, binding: SessionBindingConfig | None = None) -> Any:
    return LocalAuth.session(
        accounts=cast("Any", _local_session_accounts()),
        secrets=_local_auth_secrets(),
        binding=binding or SessionBindingConfig(pepper=b"binding-pepper-for-plugin-tests!", max_age=600),
        register_routes=False,
    )


def _local_auth_secrets(*, refresh: bool = False) -> LocalAuthSecrets:
    return LocalAuthSecrets(
        purpose_tokens=PurposeTokenCodec(pepper=b"p" * 32),
        refresh_codec=RefreshTokenCodec(pepper=b"q" * 32) if refresh else None,
        refresh_receipts=(
            RefreshReceiptSealer(active_key=RefreshReceiptKey("test-key", b"r" * 32)) if refresh else None
        ),
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
    @get("/", auth=public())
    async def handler() -> None:
        return None

    plugin = SecurityPlugin(_compiler_config())
    app = Litestar(
        route_handlers=[handler], openapi_config=OpenAPIConfig(title="Test", version="1.0"), plugins=[plugin]
    )
    route = next(route for route in app.routes if isinstance(route, HTTPRoute))
    route_handler = route.route_handler_map["GET"][0]

    assert isinstance(plugin, ReceiveRoutePlugin)
    assert route_handler.opt["litestar_security_plan"] == SecurityRuntimePlan(authenticate=False, csrf_required=False)
    assert app.openapi_schema.paths["/"].get.security == [{}]


def test_route_policy_uses_native_nearest_owner_inheritance() -> None:
    @get("/application")
    async def application_handler() -> None:
        return None

    @get("/owned")
    async def router_handler() -> None:
        return None

    class PolicyController(Controller):
        path = "/controller"
        opt: ClassVar = {"auth": required("b")}

        @get("/owned")
        async def owned(self) -> None:
            return None

        @get("/handler", auth=required("a"))
        async def handler_override(self) -> None:
            return None

    class AttributeController(Controller):
        path = "/attribute"
        auth = public()

        @get("/ignored")
        async def ignored(self) -> None:
            return None

    csrf_config = CSRFConfig(secret=token_hex())
    app = Litestar(
        route_handlers=[
            application_handler,
            Router(path="/router", route_handlers=[router_handler], opt={"auth": required("b")}),
            PolicyController,
            AttributeController,
        ],
        opt={"auth": required("a")},
        csrf_config=csrf_config,
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(_compiler_config(session_names=frozenset({"b"})))],
    )

    expected_by_path = {
        "/application": "a",
        "/router/owned": "b",
        "/controller/owned": "b",
        "/controller/handler": "a",
        "/attribute/ignored": "a",
    }
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
    @get("/resource", auth=public())
    async def read_resource() -> None:
        return None

    @post("/resource", auth=required("b"), csrf_required=True)
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


def test_websocket_and_asgi_compile_native_auth_runtime_plans() -> None:
    @websocket("/socket", auth=required("b"))
    async def socket_handler(socket: WebSocket) -> None:
        del socket

    app = Litestar(route_handlers=[socket_handler], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])
    socket_route = next(route_value for route_value in app.routes if isinstance(route_value, WebSocketRoute))

    assert socket_route.route_handler.opt["litestar_security_plan"].participant_names == frozenset({"b"})
    assert not hasattr(socket_route.route_handler, "security")

    @asgi("/mount", auth=public(), copy_scope=True)
    async def mounted_app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive, send

    asgi_app = Litestar(route_handlers=[mounted_app], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])
    asgi_route = next(route_value for route_value in asgi_app.routes if isinstance(route_value, ASGIRoute))

    assert not asgi_route.route_handler.opt["litestar_security_plan"].authenticate

    @websocket("/anonymous")
    async def anonymous_socket(socket: WebSocket) -> None:
        del socket

    anonymous_app = Litestar(route_handlers=[anonymous_socket], openapi_config=None, plugins=[SecurityPlugin()])
    anonymous_route = next(
        route_value for route_value in anonymous_app.routes if isinstance(route_value, WebSocketRoute)
    )

    assert not anonymous_route.route_handler.opt["litestar_security_plan"].authenticate


def test_csrf_required_is_rejected_outside_http_routes() -> None:
    @websocket("/socket", auth=public(), csrf_required=True)
    async def socket_handler(socket: WebSocket) -> None:
        del socket

    with pytest.raises(ImproperlyConfiguredException, match=r"only on HTTP routes.*websocket /socket"):
        Litestar(route_handlers=[socket_handler], openapi_config=None, plugins=[SecurityPlugin()])

    @asgi("/mount", auth=public(), csrf_required=True, copy_scope=True)
    async def mounted_app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive, send

    with pytest.raises(ImproperlyConfiguredException, match=r"only on HTTP routes.*asgi /mount"):
        Litestar(route_handlers=[mounted_app], openapi_config=None, plugins=[SecurityPlugin()])


def test_session_capable_websocket_requires_trusted_origin_at_startup() -> None:
    @websocket("/socket", auth=required("session"))
    async def socket_handler(socket: WebSocket) -> None:
        del socket

    config = _compiler_config(names=("session",), session_names=frozenset({"session"}))
    with pytest.raises(ImproperlyConfiguredException, match=r"trusted WebSocket Origin.*websocket /socket"):
        Litestar(route_handlers=[socket_handler], openapi_config=None, plugins=[SecurityPlugin(config)])

    configured = _compiler_config(names=("session",), session_names=frozenset({"session"}))
    configured.websocket = WebSocketSecurityConfig(allowed_origins=frozenset({"https://app.example.com"}))
    app = Litestar(route_handlers=[socket_handler], openapi_config=None, plugins=[SecurityPlugin(configured)])
    socket_route = next(route_value for route_value in app.routes if isinstance(route_value, WebSocketRoute))

    assert socket_route.route_handler.opt["litestar_security_plan"].participant_names == frozenset({"session"})


def test_asgi_default_dynamic_registration_and_receive_route_are_idempotent() -> None:
    @asgi("/mount", copy_scope=True)
    async def mounted_app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive, send

    plugin = SecurityPlugin(_compiler_config())
    app = Litestar(route_handlers=[mounted_app], openapi_config=None, plugins=[plugin])
    mount_route = next(route_value for route_value in app.routes if isinstance(route_value, ASGIRoute))
    mount_plan = mount_route.route_handler.opt["litestar_security_plan"]

    @get("/dynamic", auth=required("b"))
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
    @post("/generated", auth=public(), csrf_required=True)
    async def generated() -> None:
        return None

    @route("/explicit", http_method=HttpMethod.OPTIONS, auth=required("b"))
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
    ("openapi_config", "expected_path", "expected_participants"),
    [
        (OpenAPIConfig(title="Test", version="1.0"), "/schema/openapi.json", None),
        (
            OpenAPIConfig(
                title="Test",
                version="1.0",
                openapi_router=Router(path="/docs", route_handlers=[], opt={"auth": required("b")}),
                render_plugins=[JsonRenderPlugin()],
            ),
            "/docs/openapi.json",
            frozenset({"b"}),
        ),
        (
            OpenAPIConfig(
                title="Test",
                version="1.0",
                openapi_router=Router(path="/reference", route_handlers=[], opt={"auth": required("a")}),
                render_plugins=[JsonRenderPlugin()],
            ),
            "/reference/openapi.json",
            frozenset({"a"}),
        ),
    ],
)
def test_openapi_routes_use_default_configured_and_custom_router_policy(
    openapi_config: OpenAPIConfig, expected_path: str, expected_participants: frozenset[str] | None
) -> None:
    @get("/application")
    async def application_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[application_handler],
        opt={"auth": required("a")},
        openapi_config=openapi_config,
        plugins=[SecurityPlugin(_compiler_config())],
    )
    plan = _http_plan(app, expected_path)

    assert plan.participant_names == expected_participants
    assert plan.authenticate is (expected_participants is not None)


@pytest.mark.parametrize(
    ("openapi_config", "application_path"),
    [
        pytest.param(
            OpenAPIConfig(title="Test", version="1.0", path="/api", render_plugins=[JsonRenderPlugin()]),
            "/api/orders",
            id="openapi_base_path_shadows_the_api",
        ),
        pytest.param(
            OpenAPIConfig(title="Test", version="1.0", path="/", render_plugins=[JsonRenderPlugin()]),
            "/orders",
            id="openapi_base_path_shadows_the_root",
        ),
        pytest.param(
            OpenAPIConfig(title="Test", version="1.0", render_plugins=[JsonRenderPlugin()]),
            "/schema-report",
            id="openapi_base_path_shares_only_a_string_boundary",
        ),
    ],
)
def test_application_route_under_the_openapi_base_path_keeps_its_own_auth(
    openapi_config: OpenAPIConfig, application_path: str
) -> None:
    @get(application_path, opt={"auth": required("a")})
    async def application_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[application_handler],
        openapi_config=openapi_config,
        plugins=[SecurityPlugin(_compiler_config(names=("a",)))],
    )
    plan = _http_plan(app, application_path)

    assert plan.authenticate is True
    assert plan.participant_names == frozenset({"a"})


@pytest.mark.parametrize(
    "schema_path", ["/schema/openapi.json", "/schema/swagger", "/schema/oauth2-redirect.html", "/schema/{path:str}"]
)
def test_every_generated_schema_route_stays_public_whatever_module_defines_it(schema_path: str) -> None:
    app = Litestar(
        route_handlers=[],
        openapi_config=OpenAPIConfig(
            title="Test", version="1.0", render_plugins=[SwaggerRenderPlugin(), JsonRenderPlugin()]
        ),
        plugins=[SecurityPlugin(_compiler_config(names=("a",)))],
    )

    assert _http_plan(app, schema_path).authenticate is False


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
    @get("/resource", auth=policy)
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
    @get("/scoped", auth=required(mechanism("a", "read")))
    async def scoped_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"a.*scopes.*GET /scoped"):
        Litestar(
            route_handlers=[scoped_handler],
            openapi_config=OpenAPIConfig(title="Test", version="1.0"),
            plugins=[SecurityPlugin(_compiler_config(names=("a",)))],
        )

    names = tuple(f"m{index}" for index in range(9))

    @get("/threshold", auth=at_least(2, *names))
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

    @get("/threshold", auth=at_least(2, *names))
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
            "create_family",
            "current_epoch",
            "find_for_login",
            "get_by_id",
            "get_password_state",
            "issue",
            "issue_absent",
            "prepare_rotation",
            "register_login_method",
            "replace_password_and_bump_epoch",
            "revoke_family",
            "revoke_for_account",
            "revoke_login_method",
            "revoke_token",
            "revoke_token_for_account",
            "rotate",
        )
    })
    private_key, _public_key = jwt_key_material["EdDSA"]
    local_auth = LocalAuth.tokens(
        accounts=cast("Any", capabilities),
        secrets=_local_auth_secrets(refresh=True),
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


@pytest.mark.parametrize("registration_mode", ["disabled", "public", "invite"])
@pytest.mark.parametrize("mode", ["session", "tokens", "hybrid"])
def test_generated_local_routes_are_mode_explicit_native_and_admin_free(  # noqa: PLR0915
    mode: str, registration_mode: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    accounts = cast("Any", _local_session_accounts())
    registration = {
        "disabled": RegistrationPolicy.disabled(),
        "public": RegistrationPolicy.public(),
        "invite": RegistrationPolicy.invite_only(),
    }[registration_mode]
    private_key, _public_key = jwt_key_material["EdDSA"]
    config_kwargs: dict[str, object] = {
        "accounts": accounts,
        "secrets": _local_auth_secrets(refresh=mode != "session"),
        "registration": registration,
        "route_prefix": "/identity",
    }
    session_middleware: DefineMiddleware | None = None
    csrf_config: CSRFConfig | None = None
    if mode in {"session", "hybrid"}:
        config_kwargs["binding"] = SessionBindingConfig(pepper=b"b" * 32, max_age=600)
        session_middleware = _native_session_backend("client")[1]
        csrf_config = CSRFConfig(secret=token_hex())
    if mode in {"tokens", "hybrid"}:
        config_kwargs.update(
            key_ring=LocalKeyRing(
                issuer="https://local.example",
                active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=private_key),
            ),
            token_audience="local-client",  # noqa: S106 - public JWT audience
        )
    local_auth = getattr(LocalAuth, mode)(**config_kwargs)
    app = Litestar(
        route_handlers=[],
        csrf_config=csrf_config,
        middleware=[session_middleware] if session_middleware is not None else None,
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth))],
    )

    observed = {
        (method, route_value.path)
        for route_value in app.routes
        if isinstance(route_value, HTTPRoute) and route_value.path.startswith("/identity")
        for method in route_value.route_handler_map
        if method != "OPTIONS"
    }
    expected = {
        ("POST", "/identity/password/recovery"),
        ("POST", "/identity/password/reset"),
        ("POST", "/identity/verification"),
        ("POST", "/identity/verification/confirm"),
    }
    if mode in {"session", "hybrid"}:
        expected.update({
            ("POST", "/identity/login"),
            ("POST", "/identity/logout"),
            ("GET", "/identity/sessions"),
            ("DELETE", "/identity/sessions/{session_id:str}"),
            ("POST", "/identity/password/change"),
        })
    if mode in {"tokens", "hybrid"}:
        expected.update({
            ("POST", "/identity/token"),
            ("POST", "/identity/token/refresh"),
            ("POST", "/identity/token/revoke"),
            ("POST", "/identity/token/password/change" if mode == "hybrid" else "/identity/password/change"),
        })
    if registration_mode != "disabled":
        expected.add(("POST", "/identity/register"))

    assert observed == expected
    assert local_auth.build_route_handlers() is local_auth.build_route_handlers()
    assert not any(word in path for _method, path in observed for word in ("admin", "force", "disable", "other-user"))
    recovery_operation = app.openapi_schema.paths["/identity/password/recovery"].post
    assert recovery_operation is not None
    assert recovery_operation.responses["202"].headers is not None
    assert set(recovery_operation.responses["202"].headers) == {"cache-control", "Pragma"}
    schemas = app.openapi_schema.components.schemas if app.openapi_schema.components is not None else None
    assert schemas is not None
    if registration_mode == "public":
        assert "invitation_token" not in schemas["LocalRegistrationRequest"].properties
    elif registration_mode == "invite":
        invitation_schema = schemas["LocalInvitationRegistrationRequest"]
        assert invitation_schema.required is not None
        assert "invitation_token" in invitation_schema.required
    if mode in {"tokens", "hybrid"}:
        token_operation = app.openapi_schema.paths["/identity/token"].post
        revoke_operation = app.openapi_schema.paths["/identity/token/revoke"].post
        assert token_operation.security == [{}]
        assert set(token_operation.responses) == {"200", "400", "403", "429", "503"}
        assert revoke_operation.security == [{"bearer": []}]
        assert set(revoke_operation.responses) == {"200", "400", "401", "503"}
    if mode in {"session", "hybrid"}:
        login_operation = app.openapi_schema.paths["/identity/login"].post
        logout_operation = app.openapi_schema.paths["/identity/logout"].post
        assert login_operation.security == [{}]
        assert set(login_operation.responses) == {"200", "400", "403", "429", "503"}
        assert logout_operation.security == [{"LocalSession": []}]
        assert set(logout_operation.responses) == {"200", "401", "503"}

    plugin = cast("SecurityPlugin[object]", app.plugins.init[0])
    app_config = AppConfig()
    plugin._configure_local_auth_routes(app_config)  # noqa: SLF001
    plugin._configure_local_auth_routes(app_config)  # noqa: SLF001
    assert app_config.route_handlers == [local_auth.build_route_handlers()[0]]
    plugin._configure_local_auth_rate_limits(app_config)  # noqa: SLF001
    plugin._configure_local_auth_rate_limits(app_config)  # noqa: SLF001
    assert len(app_config.lifespan) == 1
    provider = cast("Provide", local_auth.build_route_handlers()[0].dependencies["local_auth_service"])
    assert provider.dependency() is local_auth.local_auth_service


def test_generated_local_routes_are_grouped_documented_and_uniquely_identified(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    private_key, _public_key = jwt_key_material["EdDSA"]
    local_auth = LocalAuth.hybrid(
        accounts=cast("Any", _local_session_accounts()),
        secrets=_local_auth_secrets(refresh=True),
        binding=SessionBindingConfig(pepper=b"b" * 32, max_age=600),
        key_ring=LocalKeyRing(
            issuer="https://local.example",
            active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=private_key),
        ),
        token_audience="local-client",  # noqa: S106 - public JWT audience
        registration=RegistrationPolicy.public(),
    )
    caller_tag = Tag(name="Local sessions", description="Caller owns this description.")
    app = Litestar(
        route_handlers=[],
        csrf_config=CSRFConfig(secret=token_hex()),
        middleware=[_native_session_backend("client")[1]],
        openapi_config=OpenAPIConfig(title="Test", version="1.0", tags=[caller_tag]),
        plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth))],
    )

    declared = {tag.name: tag for tag in app.openapi_schema.tags or ()}
    assert set(declared) == {tag.name for tag in LOCAL_AUTH_TAGS}
    assert declared["Local sessions"] is caller_tag
    assert all(tag.description for tag in declared.values())

    operations = [
        operation
        for path_item in app.openapi_schema.paths.values()
        for operation in (path_item.get, path_item.post, path_item.delete)
        if operation is not None
    ]
    generated = [operation for operation in operations if (operation.operation_id or "").startswith("Local")]
    assert len(generated) == 14
    assert len({operation.operation_id for operation in generated}) == len(generated)
    assert all(operation.summary and operation.description for operation in generated)
    assert all(len(operation.tags or ()) == 1 for operation in generated)
    assert {tag for operation in generated for tag in operation.tags or ()} == set(declared)

    schemas = app.openapi_schema.components.schemas if app.openapi_schema.components is not None else None
    assert schemas is not None
    documented = ("LocalCredentials", "LocalPasswordChangeRequest", "LocalSessionResponse", "RouteStatusResponse")
    # LocalSessionResponse is only named when the nested annotation resolves, which a
    # quoted reference does not do on Python 3.10.
    assert set(documented) <= set(schemas)
    assert all(all(prop.description for prop in (schemas[name].properties or {}).values()) for name in documented)

    by_id = {operation.operation_id: operation for operation in generated}
    assert by_id["LocalSessionLogin"].tags == ["Local sessions"]
    assert by_id["LocalTokenRefresh"].tags == ["Local tokens"]
    assert by_id["LocalRegister"].tags == ["Local registration"]
    assert by_id["LocalPasswordRecovery"].tags == ["Local passwords"]
    assert by_id["LocalVerificationConfirm"].tags == ["Local verification"]
    assert by_id["LocalPasswordChange"].tags == ["Local passwords"]
    assert by_id["LocalTokenPasswordChange"].tags == ["Local passwords"]


def test_custom_local_controllers_keep_services_without_generated_routes(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    private_key, _public_key = jwt_key_material["EdDSA"]
    local_auth = LocalAuth.tokens(
        accounts=cast("Any", _local_session_accounts()),
        secrets=_local_auth_secrets(refresh=True),
        key_ring=LocalKeyRing(
            issuer="https://local.example",
            active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=private_key),
        ),
        token_audience="local-client",  # noqa: S106 - public JWT audience
        register_routes=False,
    )
    app = Litestar(
        route_handlers=[],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth))],
    )

    assert local_auth.build_route_handlers() == ()
    assert local_auth.local_auth_service.password_login is local_auth.password_login
    assert not any(path.startswith("/auth") for path in app.openapi_schema.paths)


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

    @get("/bearer", auth=required("bearer"))
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
    @get("/scopes", auth=all_of(mechanism("a", "one"), mechanism("b", "two")))
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

    @get("/memoized", auth=required("a"))
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

    @get("/memoized", auth=required("a"))
    async def runtime_handler() -> None:
        return None

    runtime_only = Litestar(
        route_handlers=[runtime_handler], openapi_config=None, plugins=[SecurityPlugin(runtime_config)]
    )

    assert _http_plan(runtime_only, "/memoized").participant_names == frozenset({"a"})


def test_session_capable_routes_require_and_derive_declared_csrf_enforcement() -> None:
    @post("/session", auth=required("session"))
    async def session_handler() -> None:
        return None

    config = _compiler_config(names=("session",), session_names=frozenset({"session"}))
    with pytest.raises(ImproperlyConfiguredException, match=r"requires native CSRF.*POST /session"):
        Litestar(route_handlers=[session_handler], plugins=[SecurityPlugin(config)])

    @get("/session", auth=required("session"))
    async def read_session() -> None:
        return None

    @post("/hybrid", auth=any_of("session", "bearer"))
    async def hybrid_handler() -> None:
        return None

    @post("/bearer", auth=required("bearer"), opt={"exclude_from_csrf": True})
    async def bearer_handler() -> None:
        return None

    csrf_config = CSRFConfig(secret=token_hex())
    security_plugin = SecurityPlugin(
        _compiler_config(names=("session", "bearer"), session_names=frozenset({"session"}))
    )
    app = Litestar(
        route_handlers=[read_session, session_handler, hybrid_handler, bearer_handler],
        csrf_config=csrf_config,
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


def test_csrf_config_is_application_owned_and_route_override_is_strict() -> None:
    configured = CSRFConfig(secret=token_hex())
    app_config = AppConfig(csrf_config=configured)

    result = SecurityPlugin().on_app_init(app_config)

    assert result.csrf_config is configured
    external = ExternalCSRF(name="edge", validate=lambda _path, _method, _policy: True)
    with pytest.raises(ImproperlyConfiguredException, match="native and external CSRF"):
        SecurityPlugin(SecurityConfig(external_csrf=external)).on_app_init(AppConfig(csrf_config=configured))

    for value in (False, None, 1, "yes"):

        @post(f"/invalid-{value!s}", auth=public(), csrf_required=value)
        async def invalid_handler() -> None:
            return None

        with pytest.raises(ImproperlyConfiguredException, match=r"csrf_required must be exactly True"):
            Litestar(route_handlers=[invalid_handler], csrf_config=configured, plugins=[SecurityPlugin()])

    @post("/owned", auth=public())
    async def owned_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"only on individual HTTP route handlers"):
        Litestar(
            route_handlers=[owned_handler],
            opt={"csrf_required": True},
            csrf_config=configured,
            plugins=[SecurityPlugin()],
        )

    @post("/session", auth=required("session"), opt={configured.exclude_from_csrf_key: True})
    async def excluded_session() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"Session-capable routes cannot exclude native CSRF"):
        Litestar(
            route_handlers=[excluded_session],
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
        (CSRFConfig(secret=token_hex(), exclude_from_csrf_key="auth"), "reserved"),
        (CSRFConfig(secret=token_hex(), exclude_from_csrf_key="csrf_required"), "reserved"),
        (CSRFConfig(secret=token_hex(), exclude_from_csrf_key="litestar_security_plan"), "reserved"),
        (CSRFConfig(secret=token_hex(), exclude_from_csrf_key="litestar_security_csrf"), "reserved"),
    ],
    ids=[
        "path-exclusion",
        "unsafe-safe-method",
        "missing-safe-method",
        "blank-opt-key",
        "policy-opt-key",
        "csrf-required-opt-key",
        "plan-opt-key",
        "csrf-opt-key",
    ],
)
def test_native_csrf_rejects_competing_bypass_configuration(csrf_config: CSRFConfig, match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        SecurityPlugin().on_app_init(AppConfig(csrf_config=csrf_config))


def test_native_csrf_rejects_invalid_runtime_configuration_shapes() -> None:
    invalid_safe_methods = CSRFConfig(secret=token_hex())
    invalid_safe_methods.safe_methods = cast("Any", None)
    with pytest.raises(ImproperlyConfiguredException, match="safe methods"):
        SecurityPlugin().on_app_init(AppConfig(csrf_config=invalid_safe_methods))

    app_config = AppConfig()
    app_config.csrf_config = cast("Any", object())
    with pytest.raises(ImproperlyConfiguredException, match="Litestar CSRFConfig"):
        SecurityPlugin().on_app_init(app_config)


@pytest.mark.parametrize(
    ("kwargs", "match"), [({"external_csrf": object()}, "ExternalCSRF assertion")], ids=["invalid-external"]
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

    @post("/session", auth=required("session"))
    async def session_handler() -> None:
        return None

    @post("/login", auth=public(), csrf_required=True)
    async def login_handler() -> None:
        return None

    @post("/public", auth=public())
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

    @post("/rejected", auth=public(), csrf_required=True)
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


@pytest.mark.parametrize("manual_exclusion", [False, None, 0, "true"])
def test_native_csrf_rejects_manual_exclusion_and_uses_litestar_cookie_header_flow(manual_exclusion: Any) -> None:
    csrf_config = CSRFConfig(secret=token_hex())

    @post("/manual", auth=public(), opt={csrf_config.exclude_from_csrf_key: manual_exclusion})
    async def manual_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"exclusions must be exactly True.*POST /manual"):
        Litestar(route_handlers=[manual_handler], csrf_config=csrf_config, plugins=[SecurityPlugin()])

    @get("/login", auth=public(), csrf_required=True)
    async def login_form() -> str:
        return "form"

    @post("/login", auth=public(), csrf_required=True)
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
    @get("/missing", auth=required("missing"))
    async def handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"GET /missing"):
        Litestar(route_handlers=[handler], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])


def test_route_compiler_rejects_invalid_metadata_and_conflicting_private_plan() -> None:
    @get("/invalid", opt={"auth": object()})
    async def invalid_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"Invalid.*GET /invalid"):
        Litestar(route_handlers=[invalid_handler], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())])

    @get("/invalid-auth", auth=object())
    async def invalid_auth_handler() -> None:
        return None

    with pytest.raises(ImproperlyConfiguredException, match=r"Invalid.*GET /invalid-auth"):
        Litestar(
            route_handlers=[invalid_auth_handler], openapi_config=None, plugins=[SecurityPlugin(_compiler_config())]
        )

    @get("/conflict", auth=public())
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

    invalid_router = Router(path="/reference", route_handlers=[], opt={"auth": object()})
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
    assert namespace == {"CurrentUser": CurrentUser, "Principal": Principal, "SecurityContext": SecurityContext}

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


def test_local_session_requires_application_session_and_csrf_middleware() -> None:
    csrf = CSRFConfig(secret=token_hex())
    _, native_middleware = _native_session_backend("client")
    local_auth = _local_session_auth()

    with pytest.raises(ImproperlyConfiguredException, match="native Litestar session middleware"):
        SecurityPlugin(SecurityConfig(local_auth=local_auth)).on_app_init(AppConfig(csrf_config=csrf))

    with pytest.raises(ImproperlyConfiguredException, match="exactly one native or external CSRF"):
        SecurityPlugin(SecurityConfig(local_auth=local_auth)).on_app_init(AppConfig(middleware=[native_middleware]))

    result = SecurityPlugin(SecurityConfig(local_auth=local_auth)).on_app_init(
        AppConfig(csrf_config=csrf, middleware=[native_middleware])
    )

    assert result.csrf_config is csrf
    assert native_middleware in result.middleware


def test_local_session_rejects_native_and_external_csrf_combination() -> None:
    _, native_middleware = _native_session_backend("client")
    native = CSRFConfig(secret=token_hex())
    external = ExternalCSRF(name="edge", validate=lambda _path, _method, _policy: True)

    with pytest.raises(ImproperlyConfiguredException, match="combine native and external CSRF"):
        SecurityPlugin(SecurityConfig(local_auth=_local_session_auth(), external_csrf=external)).on_app_init(
            AppConfig(csrf_config=native, middleware=[native_middleware])
        )


def test_local_auth_external_csrf_becomes_route_enforcement_and_rejects_conflicts() -> None:
    calls: list[tuple[str, str, AuthenticationPolicy]] = []

    def validate(path: str, method: str, policy: AuthenticationPolicy) -> bool:
        calls.append((path, method, policy))
        return True

    external = ExternalCSRF(name="local-edge", validate=validate)
    _, native_middleware = _native_session_backend("client")

    @post("/session", auth=required("session"))
    async def session_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[session_handler],
        middleware=[native_middleware],
        plugins=[SecurityPlugin(SecurityConfig(local_auth=_local_session_auth(), external_csrf=external))],
    )

    assert app.csrf_config is None
    assert _http_plan(app, "/session", "POST").csrf_enforcement == "local-edge"
    assert [(path, method) for path, method, _ in calls] == [("/session", "POST")]


@pytest.mark.parametrize(
    ("native_cookie", "csrf_cookie", "binding_cookie"),
    [("shared", "csrf", "shared"), ("native", "shared", "shared"), ("shared", "shared", "binding")],
    ids=["binding-native", "binding-csrf", "native-csrf"],
)
def test_local_session_cookie_names_must_be_pairwise_distinct(
    native_cookie: str, csrf_cookie: str, binding_cookie: str
) -> None:
    csrf = CSRFConfig(secret=token_hex(), cookie_name=csrf_cookie)
    _, native_middleware = _native_session_backend("client", key=native_cookie)
    binding = SessionBindingConfig(pepper=b"binding-pepper-for-plugin-tests!", cookie_name=binding_cookie, max_age=600)

    with pytest.raises(ImproperlyConfiguredException, match="cookie names must be distinct"):
        SecurityPlugin(SecurityConfig(local_auth=_local_session_auth(binding=binding))).on_app_init(
            AppConfig(csrf_config=csrf, middleware=[native_middleware])
        )


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
    _, native_middleware = _native_session_backend(
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
    plugin = SecurityPlugin(SecurityConfig(local_auth=_local_session_auth(binding=binding)))
    app_config = AppConfig(csrf_config=csrf, middleware=[native_middleware])

    if match is None:
        result = plugin.on_app_init(app_config)
        assert result.csrf_config is csrf
    else:
        with pytest.raises(ImproperlyConfiguredException, match=match):
            plugin.on_app_init(app_config)


def test_local_session_requires_a_backend_and_secure_samesite_none() -> None:
    csrf = CSRFConfig(secret=token_hex())
    binding = SessionBindingConfig(
        pepper=b"binding-pepper-for-plugin-tests!",
        cookie_name="binding",
        secure=False,
        allow_insecure=True,
        max_age=600,
    )
    local_auth = _local_session_auth(binding=binding)

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
    with pytest.raises(ImproperlyConfiguredException, match="SameSite=None"):
        SecurityPlugin(SecurityConfig(local_auth=local_auth)).on_app_init(
            AppConfig(csrf_config=csrf, middleware=[config.middleware])
        )


@pytest.mark.parametrize("backend_kind", ["client", "server"])
def test_local_session_native_backends_have_registry_and_openapi_parity(
    backend_kind: Literal["client", "server"],
) -> None:
    csrf = CSRFConfig(secret=token_hex())
    binding = SessionBindingConfig(pepper=b"binding-pepper-for-plugin-tests!", max_age=600)
    local_auth = _local_session_auth(binding=binding)
    _, native_middleware = _native_session_backend(backend_kind)
    config = SecurityConfig(local_auth=local_auth)

    @get("/session", auth=required("session"))
    async def session_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[session_handler],
        csrf_config=csrf,
        middleware=[native_middleware],
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
    assert native_middleware_count == 1
    assert runtime.owned_session_backend is None
    assert app.middleware.index(native_middleware) < app.middleware.index(security_middleware)


def test_local_token_profile_registers_one_composite_bearer_and_native_openapi(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    capabilities = _local_session_accounts()
    for name in (
        "create_family",
        "prepare_rotation",
        "revoke_family",
        "revoke_for_account",
        "revoke_token",
        "revoke_token_for_account",
        "rotate",
    ):
        setattr(capabilities, name, lambda *_args, **_kwargs: None)
    private_key, _public_key = jwt_key_material["EdDSA"]
    local_auth = LocalAuth.tokens(
        accounts=cast("Any", capabilities),
        secrets=_local_auth_secrets(refresh=True),
        key_ring=LocalKeyRing(
            issuer="https://local.example",
            active_signing_key=SigningKey(key_id="local-active", algorithm="EdDSA", private_key=private_key),
        ),
        token_audience="local-api",  # noqa: S106 - public JWT audience
    )

    @get("/token")
    async def token_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[token_handler],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth))],
    )
    security_middleware = next(
        item
        for item in app.middleware
        if isinstance(item, DefineMiddleware) and item.middleware is SecurityMiddlewareWrapper
    )
    registry = security_middleware.kwargs["config"].registry
    bearer = registry.get_mechanism("bearer")

    assert registry.slot_names == ("authorization.bearer",)
    assert registry.mechanism_names == ("bearer",)
    assert bearer.scheme_name == "bearer"
    assert _operation_security(app, "/token") == [{"bearer": []}]
    assert app.openapi_schema.components is not None
    assert app.openapi_schema.components.security_schemes == {
        "bearer": SecurityScheme(type="http", scheme="bearer", bearer_format="JWT")
    }


def test_local_token_profile_extends_one_existing_composite_bearer_owner(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    capabilities = _local_session_accounts()
    for name in (
        "create_family",
        "prepare_rotation",
        "revoke_family",
        "revoke_for_account",
        "revoke_token",
        "revoke_token_for_account",
        "rotate",
    ):
        setattr(capabilities, name, lambda *_args, **_kwargs: None)
    local_private_key, _local_public_key = jwt_key_material["EdDSA"]
    _external_private_key, external_public_key = jwt_key_material["RS256"]
    local_auth = LocalAuth.tokens(
        accounts=cast("Any", capabilities),
        secrets=_local_auth_secrets(refresh=True),
        key_ring=LocalKeyRing(
            issuer="https://local.example",
            active_signing_key=SigningKey(key_id="local-active", algorithm="EdDSA", private_key=local_private_key),
        ),
        token_audience="local-api",  # noqa: S106
    )
    external_slot = BearerTokenSlot(
        name="oidc",
        selector=BearerSlotSelector(issuers=frozenset({"https://oidc.example"}), audiences=frozenset({"oidc-api"})),
        verifier=PyJWTVerifier(
            config=JWTValidationConfig(
                issuer="https://oidc.example", audiences=frozenset({"oidc-api"}), algorithms=frozenset({"RS256"})
            ),
            key=external_public_key,
        ),
    )
    physical_slot, mechanism_value = CompositeBearerConfig(mechanism_name="bearer", slots=(external_slot,)).build(
        cast("Any", _CompilerResolver()), scheme_name="bearer"
    )

    @get("/token")
    async def token_handler() -> None:
        return None

    app = Litestar(
        route_handlers=[token_handler],
        openapi_config=OpenAPIConfig(title="Test", version="1.0"),
        plugins=[
            SecurityPlugin(SecurityConfig(slots=(physical_slot,), mechanisms=(mechanism_value,), local_auth=local_auth))
        ],
    )
    middleware = next(
        item
        for item in app.middleware
        if isinstance(item, DefineMiddleware) and item.middleware is SecurityMiddlewareWrapper
    )
    registry = middleware.kwargs["config"].registry
    bearer = registry.get_mechanism("bearer")

    assert registry.slot_names == ("authorization.bearer",)
    assert registry.mechanism_names == ("bearer",)
    assert tuple(slot.name for slot in bearer.authenticator.config.slots) == ("oidc", "local")  # type: ignore[attr-defined]
    assert _operation_security(app, "/token") == [{"bearer": []}]
    assert app.openapi_schema.components is not None
    assert app.openapi_schema.components.security_schemes == {
        "bearer": SecurityScheme(type="http", scheme="bearer", bearer_format="JWT")
    }


@pytest.mark.parametrize(
    ("owner_kind", "match"),
    [
        ("slot_only", "exactly one composite bearer owner"),
        ("standalone", "application's sole composite bearer owner"),
        ("named_composite", "mechanism to be named 'bearer'"),
    ],
)
def test_local_token_profile_rejects_a_second_bearer_owner(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
    owner_kind: Literal["slot_only", "standalone", "named_composite"],
    match: str,
) -> None:
    capabilities = _local_session_accounts()
    for name in (
        "create_family",
        "prepare_rotation",
        "revoke_family",
        "revoke_for_account",
        "revoke_token",
        "revoke_token_for_account",
        "rotate",
    ):
        setattr(capabilities, name, lambda *_args, **_kwargs: None)
    private_key, _public_key = jwt_key_material["EdDSA"]
    local_auth = LocalAuth.tokens(
        accounts=cast("Any", capabilities),
        secrets=_local_auth_secrets(refresh=True),
        key_ring=LocalKeyRing(
            issuer="https://local.example",
            active_signing_key=SigningKey(key_id="local-active", algorithm="EdDSA", private_key=private_key),
        ),
        token_audience="local-api",  # noqa: S106 - public JWT audience
    )

    if owner_kind == "named_composite":
        assert local_auth.bearer_slot is not None
        assert local_auth.bearer_resolver is not None
        physical_slot, composite = CompositeBearerConfig(
            mechanism_name="access", slots=(local_auth.bearer_slot,)
        ).build(local_auth.bearer_resolver, scheme_name="access")
        slots: tuple[Any, ...] = (physical_slot,)
        mechanisms: tuple[Any, ...] = (composite,)
    else:
        slots = (_CompilerSlot("authorization.bearer"),)
        mechanisms = (
            (
                AuthenticationMechanism(
                    authenticator=_CompilerAuthenticator("bearer", "authorization.bearer"), resolver=_CompilerResolver()
                ),
            )
            if owner_kind == "standalone"
            else ()
        )

    with pytest.raises(ImproperlyConfiguredException, match=match):
        Litestar(
            route_handlers=[],
            plugins=[SecurityPlugin(SecurityConfig(slots=slots, mechanisms=mechanisms, local_auth=local_auth))],
        )


def test_duplicate_native_sessions_fail_startup() -> None:
    sessions = [
        DefineMiddleware(SessionMiddleware, backend=object()),
        DefineMiddleware(SessionMiddleware, backend=object()),
    ]

    with pytest.raises(ImproperlyConfiguredException, match="multiple native Litestar session"):
        SecurityPlugin().on_app_init(AppConfig(middleware=sessions))


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
        (["security", "--version"], f"litestar-security, version {__version__}"),
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
