"""Native Litestar route bundle for interactive OAuth provider lifecycles."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any, Protocol, cast, runtime_checkable
from urllib.parse import urlencode

import msgspec
from litestar import Controller, Request, Response, Router, get, post
from litestar.datastructures import CacheControlHeader, Cookie
from litestar.di import NamedDependency, Provide
from litestar.enums import RequestEncodingType
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException, ServiceUnavailableException
from litestar.openapi.datastructures import ResponseSpec
from litestar.params import Body, FromPath, FromQuery, JSONBody, QueryParameter, SkipValidation
from litestar.status_codes import (
    HTTP_200_OK,
    HTTP_302_FOUND,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_503_SERVICE_UNAVAILABLE,
)

from litestar_security.authentication import public, required
from litestar_security.context import Principal
from litestar_security.providers.oauth._accounts import (
    OAuthAccountError,
    OAuthAccountService,
    OAuthLinkProof,
    UnlinkStatus,
)
from litestar_security.providers.oauth._provider import OAuthProvider, ProviderGrant, ProviderIdentity
from litestar_security.providers.oauth._transactions import (
    OAUTH_BINDING_COOKIE_NAME,
    OAuthOperation,
    OAuthTransactionService,
    SecretStr,
    oauth_binding_cookie,
)
from litestar_security.schema import WireStruct

__all__ = (
    "OAuthAuthorization",
    "OAuthConfig",
    "OAuthLifecycleService",
    "OAuthLinkRequest",
    "OAuthLocalTransport",
    "OAuthLogoutResult",
    "OAuthProviderRegistration",
    "OAuthRouteResponse",
    "OAuthRouteService",
    "OAuthScopeRequest",
    "OAuthStepUpAuthorization",
    "OAuthStepUpAuthorizer",
    "OAuthStepUpRequest",
    "OIDCBackchannelLogoutRequest",
    "OIDCLogoutIdentity",
    "OIDCLogoutLifecycleService",
    "OIDCLogoutTokenConsumer",
    "OIDCSessionLogoutStore",
    "build_oauth_routes",
)


class OAuthRouteResponse(WireStruct, frozen=True, kw_only=True, omit_defaults=True):
    """Secret-free provider lifecycle response.

    Each identifier has its own member, and a response carries only the members
    its operation actually resolved. Linking reports the provider account it
    bound, establishing a local session reports the local account, and a logout
    reports how many sessions it revoked.
    """

    detail: str
    provider_account_id: str | None = None
    account_id: str | None = None
    revoked_sessions: int | None = None


class OAuthLinkRequest(WireStruct, frozen=True, kw_only=True):
    """Purpose-bound link request."""

    step_up_grant: str
    return_to: str = "/"

    def __repr__(self) -> str:
        """Redact the one-time step-up credential."""
        return f"{type(self).__name__}(step_up_grant=<redacted>, return_to={self.return_to!r})"


class OAuthScopeRequest(WireStruct, frozen=True, kw_only=True):
    """Incremental provider-scope request."""

    provider_account_id: str
    scopes: frozenset[str]
    step_up_grant: str
    return_to: str = "/"

    def __repr__(self) -> str:
        """Redact the one-time step-up credential."""
        return (
            f"{type(self).__name__}(provider_account_id={self.provider_account_id!r}, "
            f"scopes={self.scopes!r}, step_up_grant=<redacted>, return_to={self.return_to!r})"
        )


class OAuthStepUpRequest(WireStruct, frozen=True, kw_only=True):
    """Provider-account action requiring fresh step-up."""

    step_up_grant: str

    def __repr__(self) -> str:
        """Redact the one-time step-up credential."""
        return f"{type(self).__name__}(step_up_grant=<redacted>)"


class OIDCBackchannelLogoutRequest(WireStruct, frozen=True, kw_only=True):
    """OIDC back-channel logout token form, decoded from a form-encoded body."""

    logout_token: str

    def __repr__(self) -> str:
        """Redact the signed logout token."""
        return f"{type(self).__name__}(logout_token=<redacted>)"


class OAuthAuthorization(msgspec.Struct, frozen=True, kw_only=True):
    """Authorization redirect and dedicated browser-binding cookie."""

    url: str
    binding_cookie: Cookie


class OAuthLogoutResult(msgspec.Struct, frozen=True, kw_only=True):
    """Local logout result plus optional validated provider redirect."""

    detail: str = "Logged out."
    redirect_url: str | None = None

    def __repr__(self) -> str:
        """Redact a redirect that may contain an OIDC id-token hint."""
        redirect = "None" if self.redirect_url is None else "<redacted>"
        return f"{type(self).__name__}(detail={self.detail!r}, redirect_url={redirect})"


_OAUTH_PUBLIC_RESPONSES = {
    HTTP_400_BAD_REQUEST: ResponseSpec(OAuthRouteResponse, description="The provider request is invalid."),
    HTTP_401_UNAUTHORIZED: ResponseSpec(OAuthRouteResponse, description="The provider exchange was rejected."),
    HTTP_503_SERVICE_UNAVAILABLE: ResponseSpec(OAuthRouteResponse, description="The provider is unavailable."),
}


_OAUTH_AUTHENTICATED_RESPONSES = {
    **_OAUTH_PUBLIC_RESPONSES,
    HTTP_401_UNAUTHORIZED: ResponseSpec(OAuthRouteResponse, description="Authentication or step-up is required."),
}


@dataclass(frozen=True, slots=True)
class OAuthProviderRegistration:
    """Static routing and protocol metadata for one interactive provider."""

    provider: OAuthProvider
    redirect_uri: str
    default_scopes: frozenset[str]
    expected_issuer: str | None = None
    include_nonce: bool = False
    end_session_endpoint: str | None = None
    post_logout_redirect_uri: str | None = None

    def __post_init__(self) -> None:
        """Require immutable registration metadata matching the provider."""
        if (
            not isinstance(cast("object", self.provider), OAuthProvider)
            or not self.redirect_uri.startswith("https://")
            or self.default_scopes.__class__ is not frozenset
            or not self.default_scopes
            or any(not scope.strip() for scope in self.default_scopes)
            or (self.expected_issuer is not None and not self.expected_issuer.startswith("https://"))
            or self.include_nonce.__class__ is not bool
            or (self.end_session_endpoint is not None and not self.end_session_endpoint.startswith("https://"))
            or (self.post_logout_redirect_uri is not None and not self.post_logout_redirect_uri.startswith("https://"))
            or ((self.end_session_endpoint is None) != (self.post_logout_redirect_uri is None))
        ):
            message = "OAuth provider registration is invalid"
            raise ImproperlyConfiguredException(detail=message)


@dataclass(frozen=True, slots=True)
class OAuthStepUpAuthorization:
    """Authoritative account epoch and transport binding from consumed step-up."""

    security_epoch: int
    session_binding: str | None


@dataclass(frozen=True, slots=True)
class OIDCLogoutIdentity:
    """Verified logout-token identity after atomic replay consumption."""

    provider: str
    issuer: str
    subject: str | None
    session_id: str | None
    token_id: str
    expires_at: datetime


@runtime_checkable
class OIDCLogoutTokenConsumer(Protocol):
    """Verify logout-token signature/claims/events and atomically consume jti."""

    async def consume(self, provider: str, logout_token: str, *, now: datetime) -> OIDCLogoutIdentity:
        """Return one verified non-replayed logout identity."""
        ...  # pragma: no cover


@runtime_checkable
class OIDCSessionLogoutStore(Protocol):
    """Atomically consume logout jti and revoke mapped local sessions."""

    async def consume_backchannel(self, identity: OIDCLogoutIdentity, *, now: datetime) -> int | None:
        """Consume jti and revoke sessions atomically, returning none on replay."""
        ...  # pragma: no cover

    async def revoke_frontchannel(
        self, provider: str, issuer: str, session_id: str, *, binding: str, now: datetime
    ) -> int | None:
        """Atomically consume the one-shot front-channel marker and revoke owned sessions.

        An implementation must revoke only the sessions that the presented
        browser binding owns for the exact ``(provider, issuer, session_id)``
        tuple, and must consume the replay marker in the same operation, so a
        repeated or unowned request observes ``None`` instead of a second
        revocation.

        Args:
            provider: Configured provider name.
            issuer: The already-validated configured issuer.
            session_id: The provider session identifier being revoked.
            binding: The browser-binding value presented by the caller.
            now: The aware revocation time.

        Returns:
            The revoked-session count, or ``None`` for a replayed or unowned
            request.
        """
        ...  # pragma: no cover


@runtime_checkable
class OAuthStepUpAuthorizer(Protocol):
    """Consume purpose-bound grants and expose current authoritative epochs."""

    async def authorize(
        self, *, grant: str, account_id: str, purpose: str, request: Request[Any, Any, Any]
    ) -> OAuthStepUpAuthorization:
        """Consume one exact step-up grant for the current transport."""
        ...  # pragma: no cover

    async def current_security_epoch(self, account_id: str) -> int:
        """Return the current authoritative account security epoch."""
        ...  # pragma: no cover

    def session_binding(self, request: Request[Any, Any, Any]) -> str | None:
        """Return the current transport binding used by callback validation."""
        ...  # pragma: no cover


@runtime_checkable
class OAuthLocalTransport(Protocol):
    """Establish and revoke the configured local authentication transport."""

    async def establish(
        self,
        *,
        account_id: str,
        identity: ProviderIdentity,
        request: Request[Any, Any, Any],
        authenticated_at: datetime,
    ) -> OAuthRouteResponse | Response[Any]:
        """Establish a session, token pair, or explicit hybrid transport."""
        ...  # pragma: no cover

    async def logout(self, *, account_id: str, request: Request[Any, Any, Any]) -> None:
        """Invalidate the configured local transport."""
        ...  # pragma: no cover


@runtime_checkable
class OAuthRouteService(Protocol):
    """Application boundary used identically by generated or custom controllers."""

    @property
    def provider_names(self) -> frozenset[str]:
        """Return the exact configured interactive provider names."""
        ...  # pragma: no cover

    async def begin(  # noqa: PLR0913 - every transaction and request binding remains explicit
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
        """Create one transaction and return its safe redirect."""
        ...  # pragma: no cover

    async def callback(
        self, *, provider: str, code: str, state: str, request: Request[Any, Any, Any]
    ) -> OAuthRouteResponse | Response[Any]:
        """Consume a callback and issue the configured local transport."""
        ...  # pragma: no cover

    async def unlink(
        self,
        *,
        provider: str,
        provider_account_id: str,
        account_id: str,
        step_up_grant: str,
        request: Request[Any, Any, Any],
    ) -> OAuthRouteResponse:
        """Atomically unlink a provider account."""
        ...  # pragma: no cover

    async def revoke(
        self, *, provider: str, account_id: str, step_up_grant: str, request: Request[Any, Any, Any]
    ) -> OAuthRouteResponse:
        """Locally delete and attempt upstream revocation."""
        ...  # pragma: no cover

    async def logout(self, *, provider: str, account_id: str, request: Request[Any, Any, Any]) -> OAuthLogoutResult:
        """Complete local logout independently of provider availability."""
        ...  # pragma: no cover


class OAuthLifecycleService:
    """Concrete OAuth transaction, provider, account, and local-login workflow."""

    __slots__ = ("_registrations", "accounts", "clock", "local", "step_up", "transactions")

    def __init__(  # noqa: PLR0913 - lifecycle dependencies remain explicit and independently replaceable
        self,
        *,
        registrations: tuple[OAuthProviderRegistration, ...],
        transactions: OAuthTransactionService,
        accounts: OAuthAccountService,
        local: OAuthLocalTransport,
        step_up: OAuthStepUpAuthorizer | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        """Build one application-lifecycle-owned OAuth service graph."""
        names = tuple(registration.provider.name for registration in registrations)
        if (
            not registrations
            or len(names) != len(set(names))
            or transactions.__class__ is not OAuthTransactionService
            or accounts.__class__ is not OAuthAccountService
            or not isinstance(cast("object", local), OAuthLocalTransport)
            or (step_up is not None and not isinstance(cast("object", step_up), OAuthStepUpAuthorizer))
            or not callable(clock)
        ):
            message = "OAuth lifecycle service configuration is invalid"
            raise ImproperlyConfiguredException(detail=message)
        self._registrations = {registration.provider.name: registration for registration in registrations}
        self.transactions = transactions
        self.accounts = accounts
        self.local = local
        self.step_up = step_up
        self.clock = clock

    @property
    def provider_names(self) -> frozenset[str]:
        """Return configured provider names."""
        return frozenset(self._registrations)

    async def begin(  # noqa: PLR0913 - all transaction bindings remain explicit
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
        """Consume required step-up and create one bound authorization transaction."""
        registration = self._registration(provider)
        authorization: OAuthStepUpAuthorization | None = None
        if operation is not OAuthOperation.LOGIN:
            if account_id is None or step_up_grant is None:
                raise NotAuthorizedException(detail="Fresh step-up authentication required")
            purpose = "oauth-link" if operation is OAuthOperation.LINK else "oauth-scope-upgrade"
            authorization = await self._authorize(step_up_grant, account_id, purpose, request)
        requested_scopes = registration.default_scopes | (scopes or frozenset())
        cookie_value = request.cookies.get(OAUTH_BINDING_COOKIE_NAME)
        existing_binding = SecretStr(cookie_value) if cookie_value is not None else None
        start = await self.transactions.start(
            operation=operation,
            provider=provider,
            redirect_uri=registration.redirect_uri,
            return_to=return_to,
            requested_scopes=requested_scopes,
            now=self._now(),
            include_nonce=registration.include_nonce,
            expected_issuer=registration.expected_issuer,
            account_id=account_id,
            session_binding=(
                authorization.session_binding if authorization is not None else self._session_binding(request)
            ),
            browser_binding=existing_binding,
            security_epoch=authorization.security_epoch if authorization is not None else None,
            provider_account_id=provider_account_id,
        )
        return OAuthAuthorization(
            url=registration.provider.build_authorization_url(start),
            binding_cookie=oauth_binding_cookie(start.browser_binding),
        )

    async def callback(
        self, *, provider: str, code: str, state: str, request: Request[Any, Any, Any]
    ) -> OAuthRouteResponse | Response[Any]:
        """Consume one callback and complete its stored login, link, or scope purpose."""
        registration = self._registration(provider)
        transaction = await self.transactions.consume(
            state=state,
            browser_binding=request.cookies.get(OAUTH_BINDING_COOKIE_NAME, ""),
            provider=provider,
            operation=None,
            session_binding=self._session_binding(request),
            now=self._now(),
        )
        now = self._now()
        tokens = await registration.provider.exchange_code(code=SecretStr(code), transaction=transaction, now=now)
        identity = await registration.provider.resolve_identity(tokens, transaction=transaction, now=now)
        grant = ProviderGrant(scopes=tokens.scopes, expires_at=tokens.expires_at)
        if transaction.operation is OAuthOperation.LOGIN:
            linked = await self.accounts.login(identity, grant, tokens, now=now)
            return await self.local.establish(
                account_id=linked.account_id, identity=identity, request=request, authenticated_at=now
            )
        proof = await self._callback_proof(transaction.account_id, transaction.security_epoch, transaction.operation)
        if transaction.operation is OAuthOperation.LINK:
            linked = await self.accounts.link(proof, identity, grant, tokens, now=now)
            return OAuthRouteResponse(detail="Linked.", provider_account_id=linked.provider_account_id)
        if transaction.provider_account_id is None:
            raise OAuthAccountError
        linked = await self.accounts.apply_scope_upgrade(
            proof, transaction.provider_account_id, grant, required_scopes=transaction.requested_scopes, now=now
        )
        return OAuthRouteResponse(detail="Scopes updated.", provider_account_id=linked.provider_account_id)

    async def unlink(
        self,
        *,
        provider: str,
        provider_account_id: str,
        account_id: str,
        step_up_grant: str,
        request: Request[Any, Any, Any],
    ) -> OAuthRouteResponse:
        """Consume step-up and atomically unlink one account-owned provider identity."""
        self._registration(provider)
        authorization = await self._authorize(step_up_grant, account_id, "oauth-unlink", request)
        proof = self._proof(account_id, "oauth-unlink", authorization.security_epoch, authorization.security_epoch)
        result = await self.accounts.unlink(proof, provider_account_id, now=self._now())
        detail = "Unlinked." if result.status is UnlinkStatus.UNLINKED else "Provider account not unlinked."
        return OAuthRouteResponse(detail=detail, provider_account_id=result.provider_account_id)

    async def revoke(
        self, *, provider: str, account_id: str, step_up_grant: str, request: Request[Any, Any, Any]
    ) -> OAuthRouteResponse:
        """Consume step-up and revoke the exact account-owned provider grant."""
        registration = self._registration(provider)
        await self._authorize(step_up_grant, account_id, "oauth-provider-token-management", request)
        linked = await self.accounts.store.resolve_provider_account(account_id, provider)
        if linked is None:
            raise OAuthAccountError
        await self.accounts.revoke(linked.provider_account_id, registration.provider, now=self._now())
        return OAuthRouteResponse(detail="Revoked.", provider_account_id=linked.provider_account_id)

    async def logout(self, *, provider: str, account_id: str, request: Request[Any, Any, Any]) -> OAuthLogoutResult:
        """Complete local logout before returning an optional fixed RP redirect."""
        registration = self._registration(provider)
        await self.local.logout(account_id=account_id, request=request)
        if registration.end_session_endpoint is None:
            return OAuthLogoutResult()
        parameters: dict[str, str] = {"post_logout_redirect_uri": cast("str", registration.post_logout_redirect_uri)}
        try:
            linked = await self.accounts.store.resolve_provider_account(account_id, provider)
            stored = (
                await self.accounts.vault.get_for_refresh(linked.provider_account_id, now=self._now())
                if linked is not None and self.accounts.vault is not None
                else None
            )
        except Exception:  # noqa: BLE001 - local logout remains successful when optional provider state is unavailable
            stored = None
        if stored is not None and stored.tokens.id_token is not None:
            parameters["id_token_hint"] = stored.tokens.id_token.get_secret_value()
        separator = "&" if "?" in registration.end_session_endpoint else "?"
        return OAuthLogoutResult(redirect_url=f"{registration.end_session_endpoint}{separator}{urlencode(parameters)}")

    def _registration(self, provider: str) -> OAuthProviderRegistration:
        registration = self._registrations.get(provider)
        if registration is None:
            raise NotAuthorizedException(detail="OAuth provider is not configured")
        return registration

    async def _authorize(
        self, grant: str, account_id: str, purpose: str, request: Request[Any, Any, Any]
    ) -> OAuthStepUpAuthorization:
        if self.step_up is None:
            raise NotAuthorizedException(detail="Fresh step-up authentication required")
        return await self.step_up.authorize(grant=grant, account_id=account_id, purpose=purpose, request=request)

    async def _callback_proof(
        self, account_id: str | None, security_epoch: int | None, operation: OAuthOperation
    ) -> OAuthLinkProof:
        if account_id is None or security_epoch is None or self.step_up is None:
            raise OAuthAccountError
        current_epoch = await self.step_up.current_security_epoch(account_id)
        purpose = "oauth-link" if operation is OAuthOperation.LINK else "oauth-scope-upgrade"
        return self._proof(account_id, purpose, current_epoch, security_epoch)

    @staticmethod
    def _proof(account_id: str, purpose: str, current_epoch: int, transaction_epoch: int) -> OAuthLinkProof:
        return OAuthLinkProof(
            account_id=account_id,
            purpose=purpose,
            security_epoch=current_epoch,
            transaction_account_id=account_id,
            transaction_security_epoch=transaction_epoch,
            consumed=True,
        )

    def _session_binding(self, request: Request[Any, Any, Any]) -> str | None:
        return self.step_up.session_binding(request) if self.step_up is not None else None

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            message = "OAuth lifecycle clock must return aware time"
            raise ImproperlyConfiguredException(detail=message)
        return value.astimezone(timezone.utc)


class OIDCLogoutLifecycleService:
    """Concrete verified OIDC front- and back-channel local logout workflow."""

    __slots__ = ("clock", "consumer", "provider_issuers", "sessions")

    def __init__(
        self,
        *,
        provider_issuers: Mapping[str, str],
        consumer: OIDCLogoutTokenConsumer,
        sessions: OIDCSessionLogoutStore,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        """Build one fixed-issuer logout service."""
        if (
            not provider_issuers
            or any(
                not provider.strip() or not issuer.startswith("https://")
                for provider, issuer in provider_issuers.items()
            )
            or not isinstance(cast("object", consumer), OIDCLogoutTokenConsumer)
            or not isinstance(cast("object", sessions), OIDCSessionLogoutStore)
            or not callable(clock)
        ):
            message = "OIDC logout service configuration is invalid"
            raise ImproperlyConfiguredException(detail=message)
        self.provider_issuers = dict(provider_issuers)
        self.consumer = consumer
        self.sessions = sessions
        self.clock = clock

    @property
    def provider_names(self) -> frozenset[str]:
        """Return providers supporting OIDC logout."""
        return frozenset(self.provider_issuers)

    async def backchannel(self, provider: str, logout_token: str) -> OAuthRouteResponse:
        """Verify and atomically consume a logout token before local revocation."""
        self._issuer(provider)
        now = self._now()
        identity = await self.consumer.consume(provider, logout_token, now=now)
        if identity.provider != provider or identity.issuer != self.provider_issuers[provider]:
            raise NotAuthorizedException(detail="OIDC logout token is invalid")
        revoked = await self.sessions.consume_backchannel(identity, now=now)
        if revoked is None:
            raise NotAuthorizedException(detail="OIDC logout token is invalid")
        return OAuthRouteResponse(detail="OIDC sessions revoked.", revoked_sessions=revoked)

    async def frontchannel(
        self, provider: str, issuer: str, session_id: str, *, request: Request[Any, Any, Any]
    ) -> OAuthRouteResponse:
        """Revoke one exact provider-session mapping the caller's binding owns.

        Args:
            provider: Configured provider route segment.
            issuer: The ``iss`` query value, which must equal the configured issuer.
            session_id: The ``sid`` query value naming the provider session.
            request: The request whose browser-binding cookie proves ownership.

        Returns:
            The revoked-session count response.

        Raises:
            NotAuthorizedException: If the issuer, session id, binding, ownership,
                or replay marker is rejected. Every refusal shares one shape.
            ServiceUnavailableException: If the session store is unavailable.
        """
        configured_issuer = self._issuer(provider)
        binding = request.cookies.get(OAUTH_BINDING_COOKIE_NAME)
        if issuer != configured_issuer or not session_id.strip() or binding is None or not binding.strip():
            raise NotAuthorizedException(detail="OIDC logout request is invalid")
        now = self._now()
        try:
            revoked = await self.sessions.revoke_frontchannel(provider, issuer, session_id, binding=binding, now=now)
        except Exception:  # noqa: BLE001 - an unavailable store must answer 503 without leaking store internals
            raise ServiceUnavailableException(detail="OIDC logout is unavailable") from None
        if revoked is None:
            raise NotAuthorizedException(detail="OIDC logout request is invalid")
        return OAuthRouteResponse(detail="OIDC sessions revoked.", revoked_sessions=revoked)

    def _issuer(self, provider: str) -> str:
        issuer = self.provider_issuers.get(provider)
        if issuer is None:
            raise NotAuthorizedException(detail="OIDC logout provider is not configured")
        return issuer

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            message = "OIDC logout clock must return aware time"
            raise ImproperlyConfiguredException(detail=message)
        return value.astimezone(timezone.utc)


class OAuthConfig:
    """Interactive provider route configuration and service graph."""

    __slots__ = ("_route_handlers", "oauth_service", "oidc_service", "providers", "register_routes", "route_prefix")

    def __init__(
        self,
        *,
        oauth_service: OAuthRouteService,
        providers: tuple[object, ...],
        oidc_service: OIDCLogoutLifecycleService | None = None,
        route_prefix: str = "/auth",
        register_routes: bool = True,
    ) -> None:
        """Validate provider uniqueness and generated-route ownership.

        Args:
            oauth_service: Shared route and custom-controller service.
            providers: Configured interactive providers.
            oidc_service: Optional verified OIDC logout workflow.
            route_prefix: Absolute non-root mount path.
            register_routes: Whether the plugin installs generated routes.
        """
        oauth_service_value = cast("object", oauth_service)
        if not isinstance(oauth_service_value, OAuthRouteService):
            message = "OAuth route service is invalid"
            raise ImproperlyConfiguredException(detail=message)
        names = tuple(getattr(provider, "name", None) for provider in providers)
        if (
            not providers
            or any(not isinstance(name, str) or not name.strip() for name in names)
            or len(names) != len(set(names))
            or frozenset(cast("tuple[str, ...]", names)) != oauth_service.provider_names
        ):
            message = "OAuth providers are invalid"
            raise ImproperlyConfiguredException(detail=message)
        if oidc_service is not None and (
            oidc_service.__class__ is not OIDCLogoutLifecycleService
            or not oidc_service.provider_names.issubset(frozenset(cast("tuple[str, ...]", names)))
        ):
            message = "OIDC logout providers are invalid"
            raise ImproperlyConfiguredException(detail=message)
        normalized_prefix = route_prefix.rstrip("/")
        if (
            not normalized_prefix.startswith("/")
            or normalized_prefix == ""
            or "//" in normalized_prefix
            or any(value in normalized_prefix for value in ("\\", "{", "}", "?", "#"))
        ):
            message = "OAuth route prefix is invalid"
            raise ImproperlyConfiguredException(detail=message)
        register_routes_value = cast("object", register_routes)
        if register_routes_value.__class__ is not bool:
            message = "OAuth route registration flag is invalid"
            raise ImproperlyConfiguredException(detail=message)
        self.oauth_service = oauth_service
        self.providers = providers
        self.oidc_service = oidc_service
        self.route_prefix = normalized_prefix
        self.register_routes = register_routes
        self._route_handlers: tuple[Router, ...] | None = None

    def build_route_handlers(self) -> tuple[Router, ...]:
        """Build and cache generated OAuth routes."""
        if not self.register_routes:
            return ()
        if self._route_handlers is None:
            self._route_handlers = (build_oauth_routes(self),)
        return self._route_handlers


def build_oauth_routes(config: OAuthConfig) -> Router:
    """Build native generated OAuth lifecycle routes.

    Args:
        config: Validated provider route configuration.

    Returns:
        One no-store router.
    """

    def provide_oauth_service() -> OAuthRouteService:
        return config.oauth_service

    oidc_dependencies: dict[str, Provide] = {}
    if config.oidc_service is not None:

        def provide_oidc_service() -> OIDCLogoutLifecycleService:
            return cast("OIDCLogoutLifecycleService", config.oidc_service)

        oidc_dependencies["oidc_service"] = Provide(provide_oidc_service, sync_to_thread=False, use_cache=False)

    return Router(
        path=config.route_prefix,
        route_handlers=[_OAuthController, *([_OIDCLogoutController] if config.oidc_service is not None else [])],
        cache_control=CacheControlHeader(no_store=True),
        response_headers={"Pragma": "no-cache"},
        dependencies={
            "oauth_service": Provide(provide_oauth_service, sync_to_thread=False, use_cache=False),
            **oidc_dependencies,
        },
    )


def _account_id(principal: Principal[Any]) -> str:
    if not principal.is_authenticated:
        raise NotAuthorizedException(detail="Authentication required")
    return cast("str", principal.id)


def _authorization_response(result: OAuthAuthorization) -> Response[None]:
    return Response(
        content=None, status_code=HTTP_302_FOUND, headers={"Location": result.url}, cookies=[result.binding_cookie]
    )


class _OAuthController(Controller):
    path = "/oauth/{provider:str}"
    tags = ("OAuth providers",)

    @get(
        "/login",
        name="oauth.login",
        operation_id="OAuthLogin",
        summary="Begin provider login",
        description=(
            "Start a public login transaction and redirect to the provider. A dedicated browser-binding "
            "cookie is set so the callback can only be completed by the browser that began the flow."
        ),
        response_description="A redirect to the provider authorization endpoint.",
        status_code=HTTP_302_FOUND,
        responses=_OAUTH_PUBLIC_RESPONSES,
        auth=public(),
    )
    async def login(
        self,
        provider: FromPath[str],
        request: Request[Any, Any, Any],
        oauth_service: NamedDependency[SkipValidation[OAuthRouteService]],
        return_to: FromQuery[str] = "/",
    ) -> Response[None]:
        """Create a public login transaction."""
        result = await oauth_service.begin(
            provider=provider,
            operation=OAuthOperation.LOGIN,
            account_id=None,
            provider_account_id=None,
            return_to=return_to,
            scopes=None,
            step_up_grant=None,
            request=request,
        )
        return _authorization_response(result)

    @get(
        "/callback",
        name="oauth.callback",
        operation_id="OAuthCallback",
        summary="Complete a provider transaction",
        description=(
            "Consume one transaction-bound callback and establish the configured local transport. The "
            "stored transaction, its browser binding, and the parameters the provider returned must all agree."
        ),
        response_description="The authenticated local account, or the issued token pair.",
        status_code=HTTP_200_OK,
        responses=_OAUTH_PUBLIC_RESPONSES,
        auth=public(),
    )
    async def callback(
        self,
        provider: FromPath[str],
        code: FromQuery[str],
        oauth_state: Annotated[str, QueryParameter(name="state", include_in_schema=False)],
        request: Request[Any, Any, Any],
        oauth_service: NamedDependency[SkipValidation[OAuthRouteService]],
    ) -> OAuthRouteResponse | Response[Any]:
        """Consume a transaction-bound callback and issue local authentication."""
        return await oauth_service.callback(provider=provider, code=code, state=oauth_state, request=request)

    @post(
        "/link",
        name="oauth.link",
        operation_id="OAuthLink",
        summary="Link a provider account",
        description="Start a step-up-authorized transaction that links a provider identity to the caller's account.",
        response_description="A redirect to the provider authorization endpoint.",
        status_code=HTTP_302_FOUND,
        responses=_OAUTH_AUTHENTICATED_RESPONSES,
        auth=required(),
    )
    async def link(
        self,
        provider: FromPath[str],
        data: JSONBody[OAuthLinkRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_service: NamedDependency[SkipValidation[OAuthRouteService]],
    ) -> Response[None]:
        """Begin an authenticated provider link."""
        result = await oauth_service.begin(
            provider=provider,
            operation=OAuthOperation.LINK,
            account_id=_account_id(principal),
            provider_account_id=None,
            return_to=data.return_to,
            scopes=None,
            step_up_grant=data.step_up_grant,
            request=request,
        )
        return _authorization_response(result)

    @post(
        "/links/{provider_account_id:str}/unlink",
        name="oauth.unlink",
        operation_id="OAuthUnlink",
        summary="Unlink a provider account",
        description=(
            "Unlink one provider identity after exact step-up. An unlink that would leave the account with "
            "no login method is refused."
        ),
        response_description="The unlink outcome.",
        status_code=HTTP_200_OK,
        responses=_OAUTH_AUTHENTICATED_RESPONSES,
        auth=required(),
    )
    async def unlink(  # noqa: PLR0913 - Litestar injects each route binding explicitly
        self,
        *,
        provider: FromPath[str],
        provider_account_id: FromPath[str],
        data: JSONBody[OAuthStepUpRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_service: NamedDependency[SkipValidation[OAuthRouteService]],
    ) -> OAuthRouteResponse:
        """Unlink one provider identity without removing the final login method."""
        return await oauth_service.unlink(
            provider=provider,
            provider_account_id=provider_account_id,
            account_id=_account_id(principal),
            step_up_grant=data.step_up_grant,
            request=request,
        )

    @post(
        "/scopes",
        name="oauth.scopes",
        operation_id="OAuthScopeUpgrade",
        summary="Request additional provider scopes",
        description="Start a step-up-authorized transaction that requests further scopes for a linked account.",
        response_description="A redirect to the provider authorization endpoint.",
        status_code=HTTP_302_FOUND,
        responses=_OAUTH_AUTHENTICATED_RESPONSES,
        auth=required(),
    )
    async def scopes(
        self,
        provider: FromPath[str],
        data: JSONBody[OAuthScopeRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_service: NamedDependency[SkipValidation[OAuthRouteService]],
    ) -> Response[None]:
        """Begin allowlisted incremental provider consent."""
        result = await oauth_service.begin(
            provider=provider,
            operation=OAuthOperation.SCOPE_UPGRADE,
            account_id=_account_id(principal),
            provider_account_id=data.provider_account_id,
            return_to=data.return_to,
            scopes=data.scopes,
            step_up_grant=data.step_up_grant,
            request=request,
        )
        return _authorization_response(result)

    @post(
        "/revoke",
        name="oauth.revoke",
        operation_id="OAuthRevoke",
        summary="Revoke stored provider tokens",
        description=(
            "Delete the locally stored provider tokens for the caller. The deletion is local and final "
            "regardless of whether the upstream revocation call succeeds."
        ),
        response_description="The revocation outcome.",
        status_code=HTTP_200_OK,
        responses=_OAUTH_AUTHENTICATED_RESPONSES,
        auth=required(),
    )
    async def revoke(
        self,
        provider: FromPath[str],
        data: JSONBody[OAuthStepUpRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_service: NamedDependency[SkipValidation[OAuthRouteService]],
    ) -> OAuthRouteResponse:
        """Delete local provider tokens regardless of upstream retry state."""
        return await oauth_service.revoke(
            provider=provider, account_id=_account_id(principal), step_up_grant=data.step_up_grant, request=request
        )

    @post(
        "/logout",
        name="oauth.logout",
        operation_id="OAuthLogout",
        summary="Log out of the provider session",
        description=(
            "End the local session and, when the provider registration supplies an end-session endpoint, "
            "redirect onward to it."
        ),
        response_description="The logout outcome, or a redirect to the provider end-session endpoint.",
        status_code=HTTP_200_OK,
        responses=_OAUTH_AUTHENTICATED_RESPONSES,
        auth=required(),
    )
    async def logout(
        self,
        provider: FromPath[str],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_service: NamedDependency[SkipValidation[OAuthRouteService]],
    ) -> Response[OAuthRouteResponse] | OAuthRouteResponse:
        """Complete local logout, then optionally redirect to a validated RP endpoint."""
        result = await oauth_service.logout(provider=provider, account_id=_account_id(principal), request=request)
        if result.redirect_url is not None:
            return Response(
                content=OAuthRouteResponse(detail=result.detail),
                status_code=HTTP_302_FOUND,
                headers={"Location": result.redirect_url},
            )
        return OAuthRouteResponse(detail=result.detail)


class _OIDCLogoutController(Controller):
    path = "/oidc/{provider:str}"
    tags = ("OIDC logout",)

    @get(
        "/frontchannel-logout",
        name="oidc.logout.frontchannel",
        operation_id="OIDCFrontchannelLogout",
        summary="Front-channel logout",
        description=(
            "Revoke the local sessions that the caller's browser binding owns for one exact issuer and "
            "provider session identifier. The revocation consumes a one-shot marker, so a repeated request "
            "is rejected."
        ),
        response_description="How many local sessions were revoked.",
        status_code=HTTP_200_OK,
        responses=_OAUTH_PUBLIC_RESPONSES,
        auth=public(),
    )
    async def frontchannel_logout(  # noqa: PLR0913 - Litestar injects each route binding explicitly
        self,
        provider: FromPath[str],
        issuer: Annotated[str, QueryParameter(name="iss")],
        session_id: Annotated[str, QueryParameter(name="sid")],
        request: Request[Any, Any, Any],
        oidc_service: NamedDependency[SkipValidation[OIDCLogoutLifecycleService]],
    ) -> OAuthRouteResponse:
        """Revoke local sessions the caller's binding owns for one exact issuer and sid."""
        return await oidc_service.frontchannel(provider, issuer, session_id, request=request)

    @post(
        "/backchannel-logout",
        name="oidc.logout.backchannel",
        operation_id="OIDCBackchannelLogout",
        summary="Back-channel logout",
        description=(
            "Verify a logout token, consume its identifier so it cannot be replayed, and revoke the local "
            "sessions it maps to."
        ),
        response_description="How many local sessions were revoked.",
        status_code=HTTP_200_OK,
        responses=_OAUTH_PUBLIC_RESPONSES,
        auth=public(),
    )
    async def backchannel_logout(
        self,
        provider: FromPath[str],
        data: Annotated[OIDCBackchannelLogoutRequest, Body(media_type=RequestEncodingType.URL_ENCODED)],
        oidc_service: NamedDependency[SkipValidation[OIDCLogoutLifecycleService]],
    ) -> OAuthRouteResponse:
        """Verify a logout token, consume its jti, and revoke mapped sessions."""
        return await oidc_service.backchannel(provider, data.logout_token)
