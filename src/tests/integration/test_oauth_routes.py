from datetime import datetime, timedelta, timezone
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

import pytest
from litestar import Litestar, Request, Response
from litestar.config.app import AppConfig
from litestar.datastructures import Cookie
from litestar.di import Provide
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException, ServiceUnavailableException
from litestar.stores.memory import MemoryStore
from litestar.testing import AsyncTestClient

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security.accounts import (
    LocalAccountResponse,
    RateLimitGuard,
    RateLimitPolicy,
    RefreshTokenResponse,
    StepUpCredential,
    StepUpService,
    StoreRateLimiter,
)
from litestar_security.authentication import AuthenticationEvidence, InvalidCredentials, VerificationUnavailable
from litestar_security.context import Principal
from litestar_security.providers.oauth import (
    AccountLinkError,
    InvalidOAuthCallback,
    InvalidProviderGrantError,
    LinkedProviderAccount,
    MemoryOAuthAccountStore,
    MemoryOAuthTransactionStore,
    MemoryTokenVault,
    OAuthAccountError,
    OAuthAccountService,
    OAuthAuthorization,
    OAuthConfig,
    OAuthLifecycleService,
    OAuthLinkRequest,
    OAuthLocalAuthTransport,
    OAuthLogoutResult,
    OAuthOperation,
    OAuthProviderError,
    OAuthProviderRegistration,
    OAuthRedirectPolicy,
    OAuthRouteResponse,
    OAuthScopeRequest,
    OAuthStepUpAuthorization,
    OAuthStepUpRequest,
    OAuthTransactionService,
    OAuthTransactionUnavailable,
    OIDCBackchannelLogoutRequest,
    OIDCLogoutIdentity,
    OIDCLogoutLifecycleService,
    ProtectedOAuthSecret,
    ProviderIdentity,
    ProviderTokenSet,
    SecretStr,
    StepUpOAuthAuthorizer,
    build_oauth_routes,
)
from litestar_security.providers.oauth._routes import _exact_https_url
from litestar_security.testing import FakeOAuthProvider, InMemoryStepUpStore

NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


class Provider:
    name = "example"


def oauth_fake_provider() -> FakeOAuthProvider:
    return FakeOAuthProvider(
        name="example",
        tokens=ProviderTokenSet(
            access_token=SecretStr("access"),
            token_type="Bearer",  # noqa: S106 - standardized OAuth token type
            scopes=frozenset({"profile"}),
            expires_at=NOW + timedelta(hours=1),
        ),
        identity=ProviderIdentity(
            provider="example",
            issuer="https://issuer.example",
            subject="subject",
            display_name="User",
            email=None,
            email_verified=False,
            raw_claims={},
        ),
    )


class RouteService:
    provider_names = frozenset({"example"})

    def __init__(self) -> None:
        self.operations: list[OAuthOperation] = []
        self.logout_redirect = False

    async def begin(  # noqa: PLR0913 - fake mirrors the explicit public service contract
        self,
        *,
        provider: str,
        operation: OAuthOperation,
        account_id: str | None,
        provider_account_id: str | None,
        return_to: str,
        scopes: frozenset[str] | None,
        step_up_grant: str | None,
        request: Request[Any, Any, Any],
    ) -> OAuthAuthorization:
        del account_id, provider_account_id, return_to, scopes, step_up_grant, request
        self.operations.append(operation)
        return OAuthAuthorization(
            url=f"https://issuer.example/authorize?provider={provider}",
            binding_cookie=Cookie(
                key="__Host-litestar-security-oauth",
                value="binding",
                path="/",
                secure=True,
                httponly=True,
                samesite="lax",
            ),
        )

    async def callback(
        self, *, provider: str, code: str, state: str, request: Request[Any, Any, Any]
    ) -> OAuthRouteResponse:
        del code, state, request
        return OAuthRouteResponse(detail="Authenticated.", provider_account_id=f"{provider}-account")

    async def unlink(self, **kwargs: object) -> OAuthRouteResponse:
        del kwargs
        return OAuthRouteResponse(detail="Unlinked.")

    async def revoke(self, **kwargs: object) -> OAuthRouteResponse:
        del kwargs
        return OAuthRouteResponse(detail="Revoked.")

    async def logout(self, **kwargs: object) -> OAuthLogoutResult:
        del kwargs
        return OAuthLogoutResult(redirect_url="https://issuer.example/logout" if self.logout_redirect else None)


class Protector:
    active_key_version = "v1"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        del associated_data
        return ProtectedOAuthSecret(ciphertext=secret[::-1], key_version=self.active_key_version)

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        del associated_data
        return protected.ciphertext[::-1]


class LocalTransport:
    def __init__(self) -> None:
        self.established: list[str] = []
        self.logged_out: list[str] = []

    async def establish(
        self,
        *,
        account_id: str,
        identity: ProviderIdentity,
        request: Request[Any, Any, Any],
        authenticated_at: datetime,
    ) -> OAuthRouteResponse:
        del identity, request, authenticated_at
        self.established.append(account_id)
        return OAuthRouteResponse(detail="Authenticated.", provider_account_id=account_id)

    async def logout(self, *, account_id: str, request: Request[Any, Any, Any]) -> None:
        del request
        self.logged_out.append(account_id)


class SessionLogout:
    async def logout(self, request: Request[Any, Any, Any]) -> None:
        del request


class VerifiedLocalServices:
    refresh_tokens = None

    def __init__(self) -> None:
        self.session_auth = SessionLogout()
        self.established: list[str] = []

    async def verified_login(self, request: Request[Any, Any, Any], account_id: str, **kwargs: object) -> object:
        del request, kwargs
        self.established.append(account_id)
        return LocalAccountResponse(account_id=account_id, display_name="User")


class ConfigurableLocalServices:
    def __init__(
        self, result: object, *, session_auth: object | None = None, refresh_tokens: object | None = None
    ) -> None:
        self.result = result
        self.session_auth = session_auth
        self.refresh_tokens = refresh_tokens

    async def verified_login(self, request: Request[Any, Any, Any], account_id: str, **kwargs: object) -> object:
        del request, account_id, kwargs
        return self.result


class StepUpAuthorizer:
    def __init__(self, *, epoch: int = 2) -> None:
        self.epoch = epoch
        self.purposes: list[str] = []

    async def authorize(
        self, *, grant: str, account_id: str, purpose: str, request: Request[Any, Any, Any]
    ) -> OAuthStepUpAuthorization:
        del grant, account_id, request
        self.purposes.append(purpose)
        return OAuthStepUpAuthorization(security_epoch=self.epoch, session_binding="session-binding")

    async def current_security_epoch(self, account_id: str) -> int:
        del account_id
        return self.epoch

    def session_binding(self, request: Request[Any, Any, Any]) -> str:
        del request
        return "session-binding"


class CallbackStepUpService:
    """Return one controlled step-up callback result."""

    def __init__(self, result: object) -> None:
        self.result = result

    async def consume(self, _grant: str, **kwargs: object) -> object:
        del kwargs
        return self.result


class BrokenCallbackStepUpService:
    """Simulate an unavailable application-owned step-up service."""

    async def consume(self, _grant: str, **kwargs: object) -> object:
        del _grant, kwargs
        raise RuntimeError


def step_up_oauth_authorizer(
    *, epochs: dict[str, int | None], transport_binding: bytes = b"transport-binding"
) -> tuple[StepUpOAuthAuthorizer, StepUpService]:
    async def current_epoch(account_id: str) -> int | None:
        return epochs.get(account_id)

    service = StepUpService(InMemoryStepUpStore(), clock=lambda: NOW, entropy=lambda _size: b"s" * 32)
    return (
        StepUpOAuthAuthorizer(
            service=service,
            current_epoch=current_epoch,
            transport_binding=lambda _request: transport_binding,
            session_binding=lambda _request: "session-binding",
        ),
        service,
    )


async def issue_step_up_grant(
    service: StepUpService, *, epoch: int, purpose: str, transport_binding: bytes = b"transport-binding"
) -> str:
    grant = await service.issue(
        principal_id="account-1",
        security_epoch=epoch,
        purpose=purpose,
        transport_binding=transport_binding,
        evidence=AuthenticationEvidence(
            mechanism="totp", slot="mfa", authenticated_at=NOW, methods=frozenset({"totp"})
        ),
    )
    assert isinstance(grant, StepUpCredential)
    return grant.token


class LogoutConsumer:
    def __init__(self) -> None:
        self.tokens: list[str] = []
        self.verified_token_ids: list[str] = []

    async def consume(self, provider: str, logout_token: str, *, now: datetime) -> OIDCLogoutIdentity:
        del now
        self.tokens.append(logout_token)
        identity = OIDCLogoutIdentity(
            provider, "https://issuer.example", "subject", "sid-1", "jti-1", NOW + timedelta(minutes=5)
        )
        self.verified_token_ids.append(identity.token_id)
        return identity


class LogoutSessions:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.consumed: set[str] = set()
        self.frontchannel_owners: dict[tuple[str, str, str], str] = {}
        self.frontchannel_consumed: set[tuple[str, str, str]] = set()

    async def consume_backchannel(self, identity: OIDCLogoutIdentity, *, now: datetime) -> int | None:
        del now
        if identity.token_id in self.consumed:
            return None
        self.consumed.add(identity.token_id)
        self.calls.append(cast("str", identity.session_id))
        return 1

    async def revoke_frontchannel(
        self, provider: str, issuer: str, session_id: str, *, binding: str, now: datetime
    ) -> int | None:
        del now
        key = (provider, issuer, session_id)
        if key in self.frontchannel_consumed or self.frontchannel_owners.get(key) != binding:
            return None
        self.frontchannel_consumed.add(key)
        self.calls.append(session_id)
        return 1


def oauth_config(*, register_routes: bool = True) -> OAuthConfig:
    return OAuthConfig(oauth_service=RouteService(), providers=(Provider(),), register_routes=register_routes)


def lifecycle_service(  # noqa: PLR0913 - test builder mirrors explicit lifecycle dependencies
    *,
    provider: FakeOAuthProvider,
    store: MemoryOAuthAccountStore | None = None,
    step_up: StepUpAuthorizer | None = None,
    local: LocalTransport | None = None,
    vault: MemoryTokenVault | None = None,
    rp_logout: bool = True,
    clock: object = lambda: NOW,
) -> OAuthLifecycleService:
    async def provision(identity: ProviderIdentity) -> str:
        del identity
        return "account-1"

    return OAuthLifecycleService(
        registrations=(
            OAuthProviderRegistration(
                provider=provider,
                redirect_uri="https://app.example/auth/oauth/example/callback",
                default_scopes=frozenset({"profile"}),
                expected_issuer="https://issuer.example",
                end_session_endpoint="https://issuer.example/logout" if rp_logout else None,
                post_logout_redirect_uri="https://app.example/logged-out" if rp_logout else None,
            ),
        ),
        transactions=OAuthTransactionService(
            store=MemoryOAuthTransactionStore(protector=Protector()),
            pepper=b"p" * 32,
            redirects=OAuthRedirectPolicy(
                callback_uris={"example": frozenset({"https://app.example/auth/oauth/example/callback"})}
            ),
        ),
        accounts=OAuthAccountService(store=store or MemoryOAuthAccountStore(), vault=vault, provision=provision),
        local=local or LocalTransport(),
        step_up=step_up,
        clock=cast("Any", clock),
    )


def oauth_app(*, openapi: bool, oauth_service: RouteService | None = None, authenticated: bool = True) -> Litestar:
    config = OAuthConfig(oauth_service=oauth_service or RouteService(), providers=(Provider(),))

    def provide_principal() -> Principal[object]:
        return Principal(id="account-1") if authenticated else Principal[object].anonymous()

    kwargs = {
        "route_handlers": [build_oauth_routes(config)],
        "dependencies": {"principal": Provide(provide_principal, sync_to_thread=False)},
    }
    return Litestar(**kwargs) if openapi else Litestar(**kwargs, openapi_config=None)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_step_up_oauth_authorizer_consumes_one_grant_once() -> None:
    authorizer, service = step_up_oauth_authorizer(epochs={"account-1": 2})
    request = cast("Request[Any, Any, Any]", type("BrowserRequest", (), {})())
    grant = await issue_step_up_grant(service, epoch=2, purpose="oauth-link")

    authorization = await authorizer.authorize(
        grant=grant, account_id="account-1", purpose="oauth-link", request=request
    )

    assert authorization == OAuthStepUpAuthorization(security_epoch=2, session_binding="session-binding")
    with pytest.raises(NotAuthorizedException, match="Fresh step-up") as consumed:
        await authorizer.authorize(grant=grant, account_id="account-1", purpose="oauth-link", request=request)
    assert consumed.value.status_code == 401


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("issued_purpose", "requested_purpose", "issued_binding"),
    [("oauth-link", "oauth-unlink", b"transport-binding"), ("oauth-link", "oauth-link", b"other-binding")],
)
async def test_step_up_oauth_authorizer_rejects_wrong_purpose_or_transport_binding(
    issued_purpose: str, requested_purpose: str, issued_binding: bytes
) -> None:
    authorizer, service = step_up_oauth_authorizer(epochs={"account-1": 2})
    request = cast("Request[Any, Any, Any]", type("BrowserRequest", (), {})())
    grant = await issue_step_up_grant(service, epoch=2, purpose=issued_purpose, transport_binding=issued_binding)

    with pytest.raises(NotAuthorizedException, match="Fresh step-up") as denied:
        await authorizer.authorize(grant=grant, account_id="account-1", purpose=requested_purpose, request=request)

    assert denied.value.status_code == 401


@pytest.mark.anyio
async def test_step_up_oauth_authorizer_rechecks_epoch_for_callback_proof() -> None:
    epochs: dict[str, int | None] = {"account-1": 2}
    authorizer, step_up = step_up_oauth_authorizer(epochs=epochs)
    service = lifecycle_service(provider=oauth_fake_provider(), step_up=cast("Any", authorizer))
    request = cast("Request[Any, Any, Any]", type("BrowserRequest", (), {"cookies": {}})())
    grant = await issue_step_up_grant(step_up, epoch=2, purpose="oauth-link")

    start = await service.begin(
        provider="example",
        operation=OAuthOperation.LINK,
        account_id="account-1",
        provider_account_id=None,
        return_to="/",
        scopes=None,
        step_up_grant=grant,
        request=request,
    )
    epochs["account-1"] = 3
    request.cookies["__Host-litestar-security-oauth"] = start.binding_cookie.value

    with pytest.raises(OAuthAccountError):
        await service.callback(
            provider="example", code="code", state=parse_qs(urlsplit(start.url).query)["state"][0], request=request
        )


@pytest.mark.anyio
async def test_step_up_oauth_authorizer_maps_epoch_callback_failure_to_503() -> None:
    async def broken_epoch(_account_id: str) -> int | None:
        raise OSError

    service = StepUpService(InMemoryStepUpStore(), clock=lambda: NOW, entropy=lambda _size: b"s" * 32)
    authorizer = StepUpOAuthAuthorizer(
        service=service,
        current_epoch=broken_epoch,
        transport_binding=lambda _request: b"transport-binding",
        session_binding=lambda _request: "session-binding",
    )

    with pytest.raises(ServiceUnavailableException, match="Step-up authentication is unavailable") as unavailable:
        await authorizer.current_security_epoch("account-1")

    assert unavailable.value.status_code == 503


@pytest.mark.parametrize("invalid_dependency", ["service", "current_epoch", "transport_binding", "session_binding"])
def test_step_up_oauth_authorizer_rejects_malformed_configuration(invalid_dependency: str) -> None:
    async def current_epoch(_account_id: str) -> int:
        return 2

    values: dict[str, object] = {
        "service": CallbackStepUpService(object()),
        "current_epoch": current_epoch,
        "transport_binding": lambda _request: b"transport-binding",
        "session_binding": lambda _request: "session-binding",
    }
    values[invalid_dependency] = object()

    with pytest.raises(ImproperlyConfiguredException, match="authorizer configuration"):
        StepUpOAuthAuthorizer(**values)  # type: ignore[arg-type]


@pytest.mark.anyio
@pytest.mark.parametrize("epoch", [None, True, -1, 1 << 64])
async def test_step_up_oauth_authorizer_rejects_malformed_epoch_callback(epoch: object) -> None:
    async def current_epoch(_account_id: str) -> object:
        return epoch

    authorizer = StepUpOAuthAuthorizer(
        service=CallbackStepUpService(object()),
        current_epoch=current_epoch,  # type: ignore[arg-type]
        transport_binding=lambda _request: b"transport-binding",
        session_binding=lambda _request: "session-binding",
    )
    request = cast("Request[Any, Any, Any]", object())

    with pytest.raises(ServiceUnavailableException, match="Step-up authentication is unavailable"):
        await authorizer.authorize(grant="grant", account_id="account-1", purpose="oauth-link", request=request)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("transport_binding", "result", "exception"),
    [
        (None, object(), NotAuthorizedException),
        (b"", object(), NotAuthorizedException),
        (bytearray(b"binding"), object(), NotAuthorizedException),
        (b"binding", InvalidCredentials(), NotAuthorizedException),
        (b"binding", VerificationUnavailable(), ServiceUnavailableException),
    ],
)
async def test_step_up_oauth_authorizer_sanitizes_transport_and_consume_results(
    transport_binding: object, result: object, exception: type[Exception]
) -> None:
    async def current_epoch(_account_id: str) -> int:
        return 2

    authorizer = StepUpOAuthAuthorizer(
        service=CallbackStepUpService(result),
        current_epoch=current_epoch,
        transport_binding=lambda _request: transport_binding,  # type: ignore[return-value]
        session_binding=lambda _request: "session-binding",
    )
    request = cast("Request[Any, Any, Any]", object())

    with pytest.raises(exception):
        await authorizer.authorize(grant="grant", account_id="account-1", purpose="oauth-link", request=request)


@pytest.mark.anyio
@pytest.mark.parametrize("session_binding", ["", b"session-binding"])
async def test_step_up_oauth_authorizer_rejects_malformed_session_callback(session_binding: object) -> None:
    async def current_epoch(_account_id: str) -> int:
        return 2

    authorizer = StepUpOAuthAuthorizer(
        service=CallbackStepUpService(object()),
        current_epoch=current_epoch,
        transport_binding=lambda _request: b"transport-binding",
        session_binding=lambda _request: session_binding,  # type: ignore[return-value]
    )
    request = cast("Request[Any, Any, Any]", object())

    with pytest.raises(ServiceUnavailableException, match="Step-up authentication is unavailable"):
        await authorizer.authorize(grant="grant", account_id="account-1", purpose="oauth-link", request=request)


@pytest.mark.anyio
@pytest.mark.parametrize("failing_callback", ["transport", "session"])
async def test_step_up_oauth_authorizer_sanitizes_binding_callback_failures(failing_callback: str) -> None:
    async def current_epoch(_account_id: str) -> int:
        return 2

    def broken_callback(_request: Request[Any, Any, Any]) -> bytes | str:
        raise RuntimeError

    authorizer = StepUpOAuthAuthorizer(
        service=CallbackStepUpService(object()),
        current_epoch=current_epoch,
        transport_binding=(
            broken_callback if failing_callback == "transport" else lambda _request: b"transport-binding"
        ),
        session_binding=(broken_callback if failing_callback == "session" else lambda _request: "session-binding"),
    )
    request = cast("Request[Any, Any, Any]", object())

    with pytest.raises(ServiceUnavailableException, match="Step-up authentication is unavailable"):
        await authorizer.authorize(grant="grant", account_id="account-1", purpose="oauth-link", request=request)


@pytest.mark.anyio
async def test_step_up_oauth_authorizer_sanitizes_consume_failure() -> None:
    async def current_epoch(_account_id: str) -> int:
        return 2

    authorizer = StepUpOAuthAuthorizer(
        service=BrokenCallbackStepUpService(),
        current_epoch=current_epoch,
        transport_binding=lambda _request: b"transport-binding",
        session_binding=lambda _request: "session-binding",
    )
    request = cast("Request[Any, Any, Any]", object())

    with pytest.raises(ServiceUnavailableException, match="Step-up authentication is unavailable"):
        await authorizer.authorize(grant="grant", account_id="account-1", purpose="oauth-link", request=request)


def test_oauth_config_caches_routes_and_plugin_registers_once() -> None:
    config = oauth_config()
    assert config.build_route_handlers() is config.build_route_handlers()
    assert set(config.build_route_handlers()[0].dependencies) == {"oauth_service"}

    plugin: SecurityPlugin[object] = SecurityPlugin(SecurityConfig(oauth=config))
    app_config = plugin.on_app_init(AppConfig())
    second = plugin.on_app_init(app_config)

    assert second.route_handlers.count(config.build_route_handlers()[0]) == 1


def test_oauth_config_can_disable_generated_routes() -> None:
    config = oauth_config(register_routes=False)

    assert config.build_route_handlers() == ()
    assert SecurityPlugin(SecurityConfig[object](oauth=config)).on_app_init(AppConfig()).route_handlers == []


@pytest.mark.anyio
async def test_concrete_lifecycle_composes_login_transaction_provider_account_and_local_transport() -> None:
    provider = FakeOAuthProvider(
        name="example",
        tokens=ProviderTokenSet(
            access_token=SecretStr("access"),
            token_type="Bearer",  # noqa: S106 - standardized OAuth token type
            scopes=frozenset({"profile"}),
            expires_at=NOW + timedelta(hours=1),
        ),
        identity=ProviderIdentity(
            provider="example",
            issuer="https://issuer.example",
            subject="subject",
            display_name="User",
            email=None,
            email_verified=False,
            raw_claims={"sub": "subject"},
        ),
    )

    async def provision(identity: ProviderIdentity) -> str:
        assert identity.subject == "subject"
        return "account-1"

    local_services = VerifiedLocalServices()
    local = OAuthLocalAuthTransport(local_auth_service=cast("Any", local_services), transport="session")
    service = OAuthLifecycleService(
        registrations=(
            OAuthProviderRegistration(
                provider=provider,
                redirect_uri="https://app.example/auth/oauth/example/callback",
                default_scopes=frozenset({"profile"}),
                expected_issuer="https://issuer.example",
            ),
        ),
        transactions=OAuthTransactionService(
            store=MemoryOAuthTransactionStore(protector=Protector()),
            pepper=b"p" * 32,
            redirects=OAuthRedirectPolicy(
                callback_uris={"example": frozenset({"https://app.example/auth/oauth/example/callback"})}
            ),
        ),
        accounts=OAuthAccountService(store=MemoryOAuthAccountStore(), provision=provision),
        local=local,
        step_up=StepUpAuthorizer(),
        clock=lambda: NOW,
    )
    app = Litestar(
        route_handlers=[build_oauth_routes(OAuthConfig(oauth_service=service, providers=(provider,)))],
        dependencies={"principal": Provide(Principal.anonymous, sync_to_thread=False)},
        openapi_config=None,
    )

    async with AsyncTestClient(app=app, base_url="https://app.example") as client:
        login = await client.get("/auth/oauth/example/login", follow_redirects=False)
        state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
        callback = await client.get("/auth/oauth/example/callback", params={"code": "code", "state": state})

    assert callback.json() == {"detail": "Authenticated.", "account_id": "account-1"}
    assert local_services.established == ["account-1"]
    assert provider.calls == ["authorize", "exchange", "identity"]


@pytest.mark.anyio
async def test_concrete_lifecycle_composes_link_scope_revoke_unlink_and_logout() -> None:
    provider = FakeOAuthProvider(
        name="example",
        tokens=ProviderTokenSet(
            access_token=SecretStr("access"),
            token_type="Bearer",  # noqa: S106 - standardized OAuth token type
            scopes=frozenset({"profile", "email"}),
            expires_at=NOW + timedelta(hours=1),
            id_token=SecretStr("header.payload.signature"),
        ),
        identity=ProviderIdentity(
            provider="example",
            issuer="https://issuer.example",
            subject="subject",
            display_name="User",
            email=None,
            email_verified=False,
            raw_claims={"sub": "subject"},
        ),
    )
    store = MemoryOAuthAccountStore(login_method_counts={"account-1": 1})
    step_up = StepUpAuthorizer()
    local = LocalTransport()
    vault = MemoryTokenVault(provider="example", client_id="client", protector=Protector())
    service = lifecycle_service(provider=provider, store=store, step_up=step_up, local=local, vault=vault)
    request = cast("Request[Any, Any, Any]", type("BrowserRequest", (), {"cookies": {}})())

    link_start = await service.begin(
        provider="example",
        operation=OAuthOperation.LINK,
        account_id="account-1",
        provider_account_id=None,
        return_to="/",
        scopes=None,
        step_up_grant="grant",
        request=request,
    )
    request.cookies["__Host-litestar-security-oauth"] = link_start.binding_cookie.value
    linked = await service.callback(
        provider="example", code="code", state=parse_qs(urlsplit(link_start.url).query)["state"][0], request=request
    )
    assert isinstance(linked, OAuthRouteResponse)
    provider_account_id = cast("str", linked.provider_account_id)

    scope_start = await service.begin(
        provider="example",
        operation=OAuthOperation.SCOPE_UPGRADE,
        account_id="account-1",
        provider_account_id=provider_account_id,
        return_to="/",
        scopes=frozenset({"email"}),
        step_up_grant="grant",
        request=request,
    )
    updated = await service.callback(
        provider="example", code="code", state=parse_qs(urlsplit(scope_start.url).query)["state"][0], request=request
    )
    assert isinstance(updated, OAuthRouteResponse)
    assert updated.detail == "Scopes updated."
    logout = await service.logout(provider="example", account_id="account-1", request=request)
    assert logout.redirect_url is not None
    assert "post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Flogged-out" in logout.redirect_url
    assert "id_token_hint=header.payload.signature" in logout.redirect_url
    assert "header.payload.signature" not in repr(logout)
    assert (
        await service.revoke(provider="example", account_id="account-1", step_up_grant="grant", request=request)
    ).detail == "Revoked."
    assert (
        await service.unlink(
            provider="example",
            provider_account_id=provider_account_id,
            account_id="account-1",
            step_up_grant="grant",
            request=request,
        )
    ).detail == "Unlinked."
    assert local.logged_out == ["account-1"]
    assert step_up.purposes == ["oauth-link", "oauth-scope-upgrade", "oauth-provider-token-management", "oauth-unlink"]


@pytest.mark.anyio
async def test_lifecycle_and_local_transport_reject_invalid_or_unavailable_paths() -> None:
    provider = FakeOAuthProvider(
        name="example",
        tokens=ProviderTokenSet(
            access_token=SecretStr("access"),
            token_type="Bearer",  # noqa: S106 - standardized OAuth token type
            scopes=frozenset({"profile"}),
            expires_at=NOW + timedelta(hours=1),
        ),
        identity=ProviderIdentity(
            provider="example",
            issuer="https://issuer.example",
            subject="subject",
            display_name="User",
            email=None,
            email_verified=False,
            raw_claims={},
        ),
    )
    request = cast("Request[Any, Any, Any]", type("BrowserRequest", (), {"cookies": {}})())
    service = lifecycle_service(provider=provider)

    with pytest.raises(NotAuthorizedException):
        await service.begin(
            provider="example",
            operation=OAuthOperation.LINK,
            account_id=None,
            provider_account_id=None,
            return_to="/",
            scopes=None,
            step_up_grant=None,
            request=request,
        )
    with pytest.raises(NotAuthorizedException, match="step-up"):
        await service.begin(
            provider="example",
            operation=OAuthOperation.LINK,
            account_id="account-1",
            provider_account_id=None,
            return_to="/",
            scopes=None,
            step_up_grant="grant",
            request=request,
        )
    with pytest.raises(OAuthAccountError):
        await lifecycle_service(provider=provider, step_up=StepUpAuthorizer()).revoke(
            provider="example", account_id="account-1", step_up_grant="grant", request=request
        )
    with pytest.raises(NotAuthorizedException):
        await service.begin(
            provider="unknown",
            operation=OAuthOperation.LOGIN,
            account_id=None,
            provider_account_id=None,
            return_to="/",
            scopes=None,
            step_up_grant=None,
            request=request,
        )
    naive_clock_service = lifecycle_service(provider=provider, clock=lambda: NOW.replace(tzinfo=None))
    with pytest.raises(ImproperlyConfiguredException, match="clock"):
        await naive_clock_service.begin(
            provider="example",
            operation=OAuthOperation.LOGIN,
            account_id=None,
            provider_account_id=None,
            return_to="/",
            scopes=None,
            step_up_grant=None,
            request=request,
        )

    refresh_response = RefreshTokenResponse(
        access_token="e30.e30.YQ",  # noqa: S106 - compact JWT fixture
        refresh_token="rt_aWlpaWlpaWlpaWlpaWlpaQ.c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M",  # noqa: S106
        expires_in=600,
    )
    token_calls: list[str] = []

    async def token_logout(account_id: str) -> None:
        token_calls.append(account_id)

    for result, exception in (
        (VerificationUnavailable(), ServiceUnavailableException),
        (object(), NotAuthorizedException),
    ):
        transport = OAuthLocalAuthTransport(
            local_auth_service=cast("Any", ConfigurableLocalServices(result, session_auth=SessionLogout())),
            transport="session",
        )
        with pytest.raises(exception):
            await transport.establish(
                account_id="account-1", identity=provider.identity, request=request, authenticated_at=NOW
            )
    token_transport = OAuthLocalAuthTransport(
        local_auth_service=cast("Any", ConfigurableLocalServices(refresh_response, refresh_tokens=object())),
        transport="tokens",
        token_logout=token_logout,
    )
    assert isinstance(
        await token_transport.establish(
            account_id="account-1", identity=provider.identity, request=request, authenticated_at=NOW
        ),
        Response,
    )
    await token_transport.logout(account_id="account-1", request=request)
    assert token_calls == ["account-1"]


@pytest.mark.anyio
async def test_lifecycle_rejects_scope_callback_without_target_and_unlinks_missing_target() -> None:
    provider = FakeOAuthProvider(
        name="example",
        tokens=ProviderTokenSet(
            access_token=SecretStr("access"),
            token_type="Bearer",  # noqa: S106 - standardized OAuth token type
            scopes=frozenset({"profile"}),
            expires_at=NOW + timedelta(hours=1),
        ),
        identity=ProviderIdentity(
            provider="example",
            issuer="https://issuer.example",
            subject="subject",
            display_name="User",
            email=None,
            email_verified=False,
            raw_claims={},
        ),
    )
    step_up = StepUpAuthorizer()
    service = lifecycle_service(provider=provider, step_up=step_up)
    request = cast("Request[Any, Any, Any]", type("BrowserRequest", (), {"cookies": {}})())
    start = await service.begin(
        provider="example",
        operation=OAuthOperation.SCOPE_UPGRADE,
        account_id="account-1",
        provider_account_id=None,
        return_to="/",
        scopes=None,
        step_up_grant="grant",
        request=request,
    )
    request.cookies["__Host-litestar-security-oauth"] = start.binding_cookie.value
    with pytest.raises(OAuthAccountError):
        await service.callback(
            provider="example", code="code", state=parse_qs(urlsplit(start.url).query)["state"][0], request=request
        )

    result = await service.unlink(
        provider="example",
        provider_account_id="missing",
        account_id="account-1",
        step_up_grant="grant",
        request=request,
    )
    assert result.detail == "Provider account not unlinked."


@pytest.mark.anyio
async def test_lifecycle_callback_requires_original_step_up_context() -> None:
    provider = oauth_fake_provider()
    service = lifecycle_service(provider=provider)
    request = cast("Request[Any, Any, Any]", type("BrowserRequest", (), {"cookies": {}})())
    start = await service.transactions.start(
        operation=OAuthOperation.LINK,
        provider="example",
        redirect_uri="https://app.example/auth/oauth/example/callback",
        return_to="/",
        requested_scopes=frozenset({"profile"}),
        account_id="account-1",
        now=NOW,
        include_nonce=False,
    )
    request.cookies["__Host-litestar-security-oauth"] = start.browser_binding.get_secret_value()

    with pytest.raises(OAuthAccountError):
        await service.callback(provider="example", code="code", state=start.state.get_secret_value(), request=request)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"redirect_uri": "http://app.example/callback"},
        {"default_scopes": frozenset()},
        {"default_scopes": frozenset({""})},
        {"expected_issuer": "http://issuer.example"},
        {"include_nonce": 1},
        {"end_session_endpoint": "http://issuer.example/logout"},
        {"end_session_endpoint": "https://issuer.example/logout?next=https://evil.example"},
        {"post_logout_redirect_uri": "http://app.example/logged-out"},
        {"end_session_endpoint": "https://issuer.example/logout"},
    ],
)
def test_oauth_provider_registration_rejects_invalid_metadata(kwargs: dict[str, object]) -> None:
    values: dict[str, object] = {
        "provider": oauth_fake_provider(),
        "redirect_uri": "https://app.example/callback",
        "default_scopes": frozenset({"profile"}),
    }
    values.update(kwargs)
    with pytest.raises(ImproperlyConfiguredException, match="registration"):
        OAuthProviderRegistration(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("https://app.example/callback", True),
        (" https://app.example/callback", False),
        ("https://app.example/*", False),
        ("https://app.example\\callback", False),
        ("https://app.example:65536/callback", False),
        ("https://user@app.example/callback", False),
        ("https://app.example/callback?next=/", False),
        ("https://app.example/callback#fragment", False),
        (object(), False),
    ],
)
def test_exact_https_url_rejects_noncanonical_or_malformed_values(value: object, valid: object) -> None:
    assert _exact_https_url(value) is valid  # type: ignore[arg-type]


def test_oauth_lifecycle_rejects_invalid_dependency_graph() -> None:
    provider = oauth_fake_provider()
    valid = lifecycle_service(provider=provider)
    registration = OAuthProviderRegistration(
        provider=provider, redirect_uri="https://app.example/callback", default_scopes=frozenset({"profile"})
    )
    with pytest.raises(ImproperlyConfiguredException, match="lifecycle"):
        OAuthLifecycleService(
            registrations=(registration, registration),
            transactions=valid.transactions,
            accounts=valid.accounts,
            local=valid.local,
        )


@pytest.mark.anyio
async def test_lifecycle_logout_omits_unsupported_route_and_survives_provider_state_outage() -> None:
    provider = oauth_fake_provider()
    request = cast("Request[Any, Any, Any]", object())
    unsupported = lifecycle_service(provider=provider, rp_logout=False)
    assert (await unsupported.logout(provider="example", account_id="account-1", request=request)).redirect_url is None

    class FailingAccountStore(MemoryOAuthAccountStore):
        async def resolve_provider_account(self, account_id: str, provider: str) -> LinkedProviderAccount | None:
            del account_id, provider
            raise RuntimeError

    unavailable = lifecycle_service(provider=provider, store=FailingAccountStore())
    result = await unavailable.logout(provider="example", account_id="account-1", request=request)
    assert result.redirect_url == (
        "https://issuer.example/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Flogged-out"
    )


@pytest.mark.parametrize(
    ("local_auth_service", "transport", "token_logout"),
    [
        (object(), None, None),
        (ConfigurableLocalServices(object()), "invalid", None),
        (ConfigurableLocalServices(object()), "session", None),
        (ConfigurableLocalServices(object()), "tokens", None),
        (ConfigurableLocalServices(object(), refresh_tokens=object()), None, None),
    ],
)
def test_local_transport_rejects_incomplete_configuration(
    local_auth_service: object, transport: str | None, token_logout: object
) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="transport"):
        OAuthLocalAuthTransport(
            local_auth_service=cast("Any", local_auth_service),
            transport=transport,
            token_logout=cast("Any", token_logout),
        )


@pytest.mark.anyio
async def test_local_transport_logout_reports_each_unavailable_transport() -> None:
    request = cast("Request[Any, Any, Any]", object())

    class UnavailableSession:
        async def logout(self, request: Request[Any, Any, Any]) -> VerificationUnavailable:
            del request
            return VerificationUnavailable()

    async def failing_token_logout(account_id: str) -> None:
        del account_id
        raise RuntimeError

    transport = OAuthLocalAuthTransport(
        local_auth_service=cast(
            "Any", ConfigurableLocalServices(object(), session_auth=UnavailableSession(), refresh_tokens=object())
        ),
        token_logout=failing_token_logout,
    )
    with pytest.raises(ServiceUnavailableException, match="logout"):
        await transport.logout(account_id="account-1", request=request)

    async def successful_token_logout(account_id: str) -> None:
        del account_id

    session_unavailable = OAuthLocalAuthTransport(
        local_auth_service=cast(
            "Any", ConfigurableLocalServices(object(), session_auth=UnavailableSession(), refresh_tokens=object())
        ),
        token_logout=successful_token_logout,
    )
    with pytest.raises(ServiceUnavailableException, match="logout"):
        await session_unavailable.logout(account_id="account-1", request=request)

    session_only = OAuthLocalAuthTransport(
        local_auth_service=cast("Any", ConfigurableLocalServices(object(), session_auth=UnavailableSession())),
        transport="session",
    )
    with pytest.raises(ServiceUnavailableException, match="logout"):
        await session_only.logout(account_id="account-1", request=request)


@pytest.mark.anyio
async def test_oidc_front_and_backchannel_logout_routes_delegate_verified_lifecycle() -> None:
    consumer = LogoutConsumer()
    sessions = LogoutSessions()
    sessions.frontchannel_owners[("example", "https://issuer.example", "sid-front")] = "front-binding"
    oidc_logout = OIDCLogoutLifecycleService(
        provider_issuers={"example": "https://issuer.example"}, consumer=consumer, sessions=sessions, clock=lambda: NOW
    )
    config = OAuthConfig(oauth_service=RouteService(), providers=(Provider(),), oidc_service=oidc_logout)
    router = build_oauth_routes(config)
    assert set(router.dependencies) == {"oauth_service", "oidc_service"}
    app = Litestar(
        route_handlers=[router],
        dependencies={"principal": Provide(Principal.anonymous, sync_to_thread=False)},
        openapi_config=None,
    )

    async with AsyncTestClient(app=app) as client:
        client.cookies.set("__Host-litestar-security-oauth", "front-binding")
        front = await client.get(
            "/auth/oidc/example/frontchannel-logout", params={"iss": "https://issuer.example", "sid": "sid-front"}
        )
        back = await client.post("/auth/oidc/example/backchannel-logout", data={"logout_token": "signed-token"})
        replay = await client.post("/auth/oidc/example/backchannel-logout", data={"logout_token": "signed-token"})

    assert front.status_code == 200
    assert back.status_code == 200
    assert replay.status_code == 401
    assert consumer.tokens == ["signed-token", "signed-token"]
    assert consumer.verified_token_ids == ["jti-1", "jti-1"]
    assert sessions.consumed == {"jti-1"}
    assert sessions.calls == ["sid-front", "sid-1"]


@pytest.mark.anyio
async def test_frontchannel_logout_requires_ownership_binding_and_consumes_replay_marker() -> None:
    sessions = LogoutSessions()
    sessions.frontchannel_owners[("example", "https://issuer.example", "sid-front")] = "front-binding"
    oidc_logout = OIDCLogoutLifecycleService(
        provider_issuers={"example": "https://issuer.example"},
        consumer=LogoutConsumer(),
        sessions=sessions,
        clock=lambda: NOW,
    )
    config = OAuthConfig(oauth_service=RouteService(), providers=(Provider(),), oidc_service=oidc_logout)
    app = Litestar(
        route_handlers=[build_oauth_routes(config)],
        dependencies={"principal": Provide(Principal.anonymous, sync_to_thread=False)},
        openapi_config=None,
    )
    params = {"iss": "https://issuer.example", "sid": "sid-front"}

    async with AsyncTestClient(app=app) as client:
        unbound = await client.get("/auth/oidc/example/frontchannel-logout", params=params)
        client.cookies.set("__Host-litestar-security-oauth", "foreign-binding")
        foreign = await client.get("/auth/oidc/example/frontchannel-logout", params=params)
        client.cookies.set("__Host-litestar-security-oauth", "front-binding")
        owned = await client.get("/auth/oidc/example/frontchannel-logout", params=params)
        replayed = await client.get("/auth/oidc/example/frontchannel-logout", params=params)

    # A bare cross-site GET carries no binding cookie, so a guessed sid revokes nothing.
    assert unbound.status_code == 401
    assert foreign.status_code == 401
    assert owned.status_code == 200
    assert owned.json() == {"detail": "OIDC sessions revoked.", "revoked_sessions": 1}
    assert replayed.status_code == 401
    assert sessions.calls == ["sid-front"]


@pytest.mark.anyio
async def test_frontchannel_logout_consumes_budget_and_rejects_bursts_with_retry_after() -> None:
    guard = RateLimitGuard(
        limiter=StoreRateLimiter(
            policies={"oidc.logout.frontchannel": RateLimitPolicy(limit=2, window=timedelta(minutes=5))},
            store=MemoryStore(),
            clock=lambda: NOW,
        ),
        pepper=b"p" * 32,
    )
    oidc_logout = OIDCLogoutLifecycleService(
        provider_issuers={"example": "https://issuer.example"},
        consumer=LogoutConsumer(),
        sessions=LogoutSessions(),
        rate_limits=guard,
        clock=lambda: NOW,
    )
    config = OAuthConfig(oauth_service=RouteService(), providers=(Provider(),), oidc_service=oidc_logout)
    app = Litestar(
        route_handlers=[build_oauth_routes(config)],
        dependencies={"principal": Provide(Principal.anonymous, sync_to_thread=False)},
        openapi_config=None,
    )
    params = {"iss": "https://issuer.example", "sid": "sid-front"}

    async with AsyncTestClient(app=app) as client:
        statuses = [
            (await client.get("/auth/oidc/example/frontchannel-logout", params=params)).status_code for _ in range(3)
        ]
        limited = await client.get("/auth/oidc/example/frontchannel-logout", params=params)

    # A rejected attempt still consumes budget, so unauthenticated sid probing is bounded.
    assert statuses == [401, 401, 429]
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) >= 1


@pytest.mark.anyio
async def test_frontchannel_logout_fails_closed_when_the_limiter_is_unavailable() -> None:
    class BrokenLimiter:
        async def acquire(self, request: object) -> object:
            del request
            raise RuntimeError

    oidc_logout = OIDCLogoutLifecycleService(
        provider_issuers={"example": "https://issuer.example"},
        consumer=LogoutConsumer(),
        sessions=LogoutSessions(),
        rate_limits=RateLimitGuard(limiter=BrokenLimiter(), pepper=b"p" * 32),
        clock=lambda: NOW,
    )
    config = OAuthConfig(oauth_service=RouteService(), providers=(Provider(),), oidc_service=oidc_logout)
    app = Litestar(
        route_handlers=[build_oauth_routes(config)],
        dependencies={"principal": Provide(Principal.anonymous, sync_to_thread=False)},
        openapi_config=None,
    )

    async with AsyncTestClient(app=app) as client:
        client.cookies.set("__Host-litestar-security-oauth", "front-binding")
        response = await client.get(
            "/auth/oidc/example/frontchannel-logout", params={"iss": "https://issuer.example", "sid": "sid-front"}
        )

    assert response.status_code == 503


@pytest.mark.anyio
async def test_frontchannel_logout_degrades_to_subject_limiting_when_client_key_extraction_fails() -> None:
    guard = RateLimitGuard(
        limiter=StoreRateLimiter(
            policies={"oidc.logout.frontchannel": RateLimitPolicy(limit=2, window=timedelta(minutes=5))},
            store=MemoryStore(),
            clock=lambda: NOW,
        ),
        pepper=b"p" * 32,
    )
    oidc_logout = OIDCLogoutLifecycleService(
        provider_issuers={"example": "https://issuer.example"},
        consumer=LogoutConsumer(),
        sessions=LogoutSessions(),
        rate_limits=guard,
        client_key=lambda _request: 1 / 0,
        clock=lambda: NOW,
    )
    request = cast("Request[Any, Any, Any]", type("BrowserRequest", (), {"cookies": {}})())

    with pytest.raises(NotAuthorizedException, match="request"):
        await oidc_logout.frontchannel("example", "https://issuer.example", "sid-front", request=request)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"provider_issuers": {}},
        {"provider_issuers": {"example": "http://issuer.example"}},
        {"consumer": object()},
        {"sessions": object()},
        {"rate_limits": object()},
        {"client_key": object()},
        {"clock": None},
    ],
)
def test_oidc_logout_lifecycle_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    values: dict[str, object] = {
        "provider_issuers": {"example": "https://issuer.example"},
        "consumer": LogoutConsumer(),
        "sessions": LogoutSessions(),
        "clock": lambda: NOW,
    }
    values.update(kwargs)
    with pytest.raises(ImproperlyConfiguredException, match="logout service configuration"):
        OIDCLogoutLifecycleService(**values)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_oidc_logout_lifecycle_rejects_mismatches_unknown_provider_and_naive_clock() -> None:
    sessions = LogoutSessions()
    request = cast(
        "Request[Any, Any, Any]",
        type("BrowserRequest", (), {"cookies": {"__Host-litestar-security-oauth": "front-binding"}})(),
    )
    unbound_request = cast("Request[Any, Any, Any]", type("BrowserRequest", (), {"cookies": {}})())

    class MismatchedConsumer(LogoutConsumer):
        async def consume(self, provider: str, logout_token: str, *, now: datetime) -> OIDCLogoutIdentity:
            del provider, logout_token, now
            return OIDCLogoutIdentity("other", "https://issuer.example", None, "sid", "jti", NOW + timedelta(minutes=5))

    service = OIDCLogoutLifecycleService(
        provider_issuers={"example": "https://issuer.example"},
        consumer=MismatchedConsumer(),
        sessions=sessions,
        clock=lambda: NOW,
    )
    with pytest.raises(NotAuthorizedException, match="token"):
        await service.backchannel("example", "signed")
    with pytest.raises(NotAuthorizedException, match="request"):
        await service.frontchannel("example", "https://wrong.example", "sid", request=request)
    with pytest.raises(NotAuthorizedException, match="provider"):
        await service.frontchannel("missing", "https://issuer.example", "sid", request=request)
    with pytest.raises(NotAuthorizedException, match="request"):
        await service.frontchannel("example", "https://issuer.example", " ", request=request)
    with pytest.raises(NotAuthorizedException, match="request"):
        await service.frontchannel("example", "https://issuer.example", "sid", request=unbound_request)
    # An unowned binding is rejected in the same shape as every other refusal.
    with pytest.raises(NotAuthorizedException, match="request"):
        await service.frontchannel("example", "https://issuer.example", "sid", request=request)

    class BrokenSessions(LogoutSessions):
        async def revoke_frontchannel(
            self, provider: str, issuer: str, session_id: str, *, binding: str, now: datetime
        ) -> int | None:
            del provider, issuer, session_id, binding, now
            raise RuntimeError

    unavailable = OIDCLogoutLifecycleService(
        provider_issuers={"example": "https://issuer.example"},
        consumer=LogoutConsumer(),
        sessions=BrokenSessions(),
        clock=lambda: NOW,
    )
    with pytest.raises(ServiceUnavailableException, match="unavailable"):
        await unavailable.frontchannel("example", "https://issuer.example", "sid", request=request)

    naive = OIDCLogoutLifecycleService(
        provider_issuers={"example": "https://issuer.example"},
        consumer=LogoutConsumer(),
        sessions=sessions,
        clock=lambda: NOW.replace(tzinfo=None),
    )
    with pytest.raises(ImproperlyConfiguredException, match="clock"):
        await naive.frontchannel("example", "https://issuer.example", "sid", request=request)


@pytest.mark.anyio
async def test_plugin_closes_lifecycle_owned_oauth_providers() -> None:
    events: list[str] = []

    class ClosableProvider:
        name = "example"

        async def aclose(self) -> None:
            events.append("close")

    config = OAuthConfig(oauth_service=RouteService(), providers=(ClosableProvider(),), register_routes=False)
    plugin = SecurityPlugin[object](SecurityConfig[object](oauth=config))
    app_config = plugin.on_app_init(AppConfig())
    assert plugin.on_app_init(app_config).lifespan == app_config.lifespan
    app = Litestar(route_handlers=[], plugins=[plugin])

    async with AsyncTestClient(app=app):
        assert events == []

    assert events == ["close"]


@pytest.mark.anyio
async def test_plugin_reports_oauth_provider_shutdown_failure() -> None:
    class BrokenProvider:
        name = "example"

        async def aclose(self) -> None:
            raise RuntimeError

    config = OAuthConfig(oauth_service=RouteService(), providers=(BrokenProvider(),), register_routes=False)
    app = Litestar(route_handlers=[], plugins=[SecurityPlugin[object](SecurityConfig[object](oauth=config))])

    with pytest.RaisesGroup(pytest.RaisesExc(ImproperlyConfiguredException, match="shutdown")):
        async with AsyncTestClient(app=app):
            pass


@pytest.mark.parametrize(
    "kwargs",
    [
        {"oauth_service": object()},
        {"providers": ()},
        {"providers": (Provider(), Provider())},
        {"route_prefix": "auth"},
        {"register_routes": 1},
    ],
)
def test_oauth_config_rejects_invalid_startup(kwargs: dict[str, object]) -> None:
    values: dict[str, object] = {"oauth_service": RouteService(), "providers": (Provider(),)}
    values.update(kwargs)

    with pytest.raises(ImproperlyConfiguredException, match="OAuth"):
        OAuthConfig(**values)  # type: ignore[arg-type]


def test_oauth_config_rejects_mismatched_oidc_logout_providers() -> None:
    oidc_logout = OIDCLogoutLifecycleService(
        provider_issuers={"other": "https://issuer.example"},
        consumer=LogoutConsumer(),
        sessions=LogoutSessions(),
        clock=lambda: NOW,
    )
    with pytest.raises(ImproperlyConfiguredException, match="OIDC logout providers"):
        OAuthConfig(oauth_service=RouteService(), providers=(Provider(),), oidc_service=oidc_logout)


@pytest.mark.anyio
async def test_public_login_and_callback_have_binding_and_no_store_headers() -> None:
    app = oauth_app(openapi=False)

    async with AsyncTestClient(app=app) as client:
        login = await client.get("/auth/oauth/example/login", follow_redirects=False)
        callback = await client.get("/auth/oauth/example/callback?code=code&state=state")

    assert login.status_code == 302
    assert login.headers["location"] == "https://issuer.example/authorize?provider=example"
    assert "__Host-litestar-security-oauth=binding" in login.headers["set-cookie"]
    assert "HttpOnly" in login.headers["set-cookie"]
    assert "Secure" in login.headers["set-cookie"]
    assert login.headers["cache-control"] == "no-store"
    assert callback.status_code == 200
    assert callback.json() == {"detail": "Authenticated.", "provider_account_id": "example-account"}
    assert callback.headers["cache-control"] == "no-store"


def test_oauth_dtos_are_frozen_camel_case_and_redact_step_up() -> None:
    link = OAuthLinkRequest(step_up_grant="secret", return_to="/")
    scope = OAuthScopeRequest(
        provider_account_id="provider-account", scopes=frozenset({"email"}), step_up_grant="secret"
    )
    action = OAuthStepUpRequest(step_up_grant="secret")

    with pytest.raises(AttributeError):
        link.return_to = "/other"  # type: ignore[misc]
    assert "secret" not in repr(link)
    assert "secret" not in repr(scope)
    assert "secret" not in repr(action)
    assert "secret" not in repr(
        OIDCBackchannelLogoutRequest(logout_token="secret")  # noqa: S106 - redaction fixture
    )


@pytest.mark.anyio
async def test_authenticated_routes_delegate_to_shared_service() -> None:
    service = RouteService()
    app = oauth_app(openapi=False, oauth_service=service)

    async with AsyncTestClient(app=app) as client:
        link = await client.post(
            "/auth/oauth/example/link", json={"step_up_grant": "grant", "return_to": "/"}, follow_redirects=False
        )
        scope = await client.post(
            "/auth/oauth/example/scopes",
            json={
                "provider_account_id": "provider-account",
                "scopes": ["email"],
                "step_up_grant": "grant",
                "return_to": "/",
            },
            follow_redirects=False,
        )
        unlink = await client.post("/auth/oauth/example/links/provider-account/unlink", json={"step_up_grant": "grant"})
        revoke = await client.post("/auth/oauth/example/revoke", json={"step_up_grant": "grant"})
        logout = await client.post("/auth/oauth/example/logout")
        service.logout_redirect = True
        redirected_logout = await client.post("/auth/oauth/example/logout", follow_redirects=False)

    assert link.status_code == 302
    assert scope.status_code == 302
    # Neither revoking provider tokens nor logging out creates anything.
    assert (unlink.status_code, revoke.status_code, logout.status_code) == (200, 200, 200)
    # An operation that resolved no identifier omits the member rather than nulling it.
    assert unlink.json() == {"detail": "Unlinked."}
    assert revoke.json() == {"detail": "Revoked."}
    assert logout.json() == {"detail": "Logged out."}
    assert redirected_logout.headers["location"] == "https://issuer.example/logout"
    assert service.operations == [OAuthOperation.LINK, OAuthOperation.SCOPE_UPGRADE]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/auth/oauth/example/link", {"step_up_grant": "grant", "returnTo": "/dashboard"}),
        ("/auth/oauth/example/link", {"step_up_grant": "grant", "return_to": "/", "prompt": "consent"}),
        (
            "/auth/oauth/example/scopes",
            {"providerAccountId": "provider-account", "scopes": ["email"], "step_up_grant": "grant"},
        ),
        ("/auth/oauth/example/revoke", {"stepUpGrant": "grant"}),
    ],
)
async def test_oauth_routes_reject_unknown_and_camel_case_body_members(path: str, payload: dict[str, object]) -> None:
    app = oauth_app(openapi=False, oauth_service=RouteService())

    async with AsyncTestClient(app=app) as client:
        response = await client.post(path, json=payload, follow_redirects=False)

    assert response.status_code == 400, response.text


@pytest.mark.anyio
async def test_lifecycle_response_names_each_identifier_it_carries() -> None:
    oidc_logout = OIDCLogoutLifecycleService(
        provider_issuers={"example": "https://issuer.example"},
        consumer=LogoutConsumer(),
        sessions=LogoutSessions(),
        clock=lambda: NOW,
    )
    config = OAuthConfig(oauth_service=RouteService(), providers=(Provider(),), oidc_service=oidc_logout)
    app = Litestar(
        route_handlers=[build_oauth_routes(config)],
        dependencies={"principal": Provide(Principal.anonymous, sync_to_thread=False)},
        openapi_config=None,
    )

    async with AsyncTestClient(app=app) as client:
        logout = await client.post("/auth/oidc/example/backchannel-logout", data={"logout_token": "signed-token"})

    # A revoked-session count is a count, not an account identifier.
    assert logout.json() == {"detail": "OIDC sessions revoked.", "revoked_sessions": 1}


@pytest.mark.anyio
async def test_backchannel_logout_form_rejects_unknown_members() -> None:
    oidc_logout = OIDCLogoutLifecycleService(
        provider_issuers={"example": "https://issuer.example"},
        consumer=LogoutConsumer(),
        sessions=LogoutSessions(),
        clock=lambda: NOW,
    )
    config = OAuthConfig(oauth_service=RouteService(), providers=(Provider(),), oidc_service=oidc_logout)
    app = Litestar(
        route_handlers=[build_oauth_routes(config)],
        dependencies={"principal": Provide(Principal.anonymous, sync_to_thread=False)},
        openapi_config=None,
    )

    async with AsyncTestClient(app=app) as client:
        accepted = await client.post("/auth/oidc/example/backchannel-logout", data={"logout_token": "signed-token"})
        rejected = await client.post(
            "/auth/oidc/example/backchannel-logout", data={"logout_token": "signed-token", "state": "extra"}
        )

    assert accepted.status_code == 200, accepted.text
    assert rejected.status_code == 400, rejected.text


@pytest.mark.anyio
async def test_route_service_rejects_anonymous_principal() -> None:
    app = oauth_app(openapi=False, authenticated=False)

    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/oauth/example/link", json={"step_up_grant": "grant", "return_to": "/"}, follow_redirects=False
        )

    assert response.status_code == 401


class RaisingRouteService(RouteService):
    def __init__(self, exception: Exception) -> None:
        super().__init__()
        self.exception = exception

    async def callback(
        self, *, provider: str, code: str, state: str, request: Request[Any, Any, Any]
    ) -> OAuthRouteResponse:
        del provider, code, state, request
        raise self.exception


def raising_oauth_app(exception: Exception) -> Litestar:
    config = OAuthConfig(oauth_service=RaisingRouteService(exception), providers=(Provider(),))
    return Litestar(
        route_handlers=[build_oauth_routes(config)],
        dependencies={"principal": Provide(Principal.anonymous, sync_to_thread=False)},
        openapi_config=None,
        debug=True,
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("exception", "status", "retry_after"),
    [
        (InvalidOAuthCallback(), 401, None),
        (OAuthTransactionUnavailable(), 503, None),
        (OAuthProviderError(), 503, None),
        (OAuthProviderError(retry_after=30), 503, "30"),
        (InvalidProviderGrantError(), 503, None),
        (AccountLinkError(), 409, None),
        (OAuthAccountError(), 400, None),
    ],
)
async def test_oauth_routes_classify_domain_exceptions_without_tracebacks(
    exception: Exception, status: int, retry_after: str | None
) -> None:
    app = raising_oauth_app(exception)

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/auth/oauth/example/callback", params={"code": "code", "state": "state"})

    assert response.status_code == status, response.text
    assert response.headers.get("retry-after") == retry_after
    assert "Traceback" not in response.text
    assert type(exception).__name__ not in response.text


@pytest.mark.anyio
@pytest.mark.parametrize("empty", ["code", "state"])
async def test_empty_code_or_state_callback_classifies_as_unauthorized(empty: str) -> None:
    provider = oauth_fake_provider()
    service = lifecycle_service(provider=provider)
    app = Litestar(
        route_handlers=[build_oauth_routes(OAuthConfig(oauth_service=service, providers=(provider,)))],
        dependencies={"principal": Provide(Principal.anonymous, sync_to_thread=False)},
        openapi_config=None,
        debug=True,
    )

    async with AsyncTestClient(app=app, base_url="https://app.example") as client:
        login = await client.get("/auth/oauth/example/login", follow_redirects=False)
        state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
        params = {"code": "code", "state": state, empty: ""}
        response = await client.get("/auth/oauth/example/callback", params=params)

    assert response.status_code == 401, response.text
    assert "Traceback" not in response.text


@pytest.mark.anyio
async def test_empty_cookie_binding_on_login_behaves_as_absent() -> None:
    provider = oauth_fake_provider()
    service = lifecycle_service(provider=provider)
    app = Litestar(
        route_handlers=[build_oauth_routes(OAuthConfig(oauth_service=service, providers=(provider,)))],
        dependencies={"principal": Provide(Principal.anonymous, sync_to_thread=False)},
        openapi_config=None,
        debug=True,
    )

    async with AsyncTestClient(app=app, base_url="https://app.example") as client:
        response = await client.get(
            "/auth/oauth/example/login", follow_redirects=False, headers={"cookie": "__Host-litestar-security-oauth="}
        )

    assert response.status_code == 302, response.text


@pytest.mark.anyio
async def test_replayed_callback_state_classifies_as_unauthorized() -> None:
    provider = oauth_fake_provider()
    service = lifecycle_service(provider=provider)
    app = Litestar(
        route_handlers=[build_oauth_routes(OAuthConfig(oauth_service=service, providers=(provider,)))],
        dependencies={"principal": Provide(Principal.anonymous, sync_to_thread=False)},
        openapi_config=None,
        debug=True,
    )

    async with AsyncTestClient(app=app, base_url="https://app.example") as client:
        login = await client.get("/auth/oauth/example/login", follow_redirects=False)
        state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
        first = await client.get("/auth/oauth/example/callback", params={"code": "code", "state": state})
        replayed = await client.get("/auth/oauth/example/callback", params={"code": "code", "state": state})

    assert first.status_code == 200
    assert replayed.status_code == 401, replayed.text
    assert "Traceback" not in replayed.text


def test_openapi_never_contains_provider_secrets_or_protocol_credentials() -> None:
    app = oauth_app(openapi=True)

    document = str(app.openapi_schema.to_schema())

    for forbidden in ("client_secret", "access_token", "refresh_token", "raw_claims", "nonce", "state"):
        assert forbidden not in document.lower()
