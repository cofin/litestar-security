"""Native Litestar route bundle for interactive OAuth provider lifecycles."""

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from logging import getLogger
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Protocol, cast, runtime_checkable
from urllib.parse import urlencode, urlsplit

import msgspec
from litestar import Controller, Request, Response, Router, get, post
from litestar.datastructures import CacheControlHeader, Cookie
from litestar.di import NamedDependency, Provide
from litestar.enums import RequestEncodingType
from litestar.exceptions import (
    ClientException,
    HTTPException,
    ImproperlyConfiguredException,
    NotAuthorizedException,
    ServiceUnavailableException,
    TooManyRequestsException,
)
from litestar.exceptions.responses import (
    create_exception_response,  # pyright: ignore[reportUnknownVariableType] - Litestar returns an unparameterized Response
)
from litestar.middleware._internal.exceptions.middleware import (
    get_exception_handler,  # pyright: ignore[reportUnknownVariableType] - Litestar types the resolved handler unparameterized
)
from litestar.params import Body, FromPath, FromQuery, JSONBody, QueryParameter, SkipValidation
from litestar.response import Redirect
from litestar.status_codes import (
    HTTP_200_OK,
    HTTP_302_FOUND,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_409_CONFLICT,
    HTTP_429_TOO_MANY_REQUESTS,
    HTTP_503_SERVICE_UNAVAILABLE,
)
from litestar.types import Empty
from litestar.utils.scope.state import ScopeState

from litestar_security._docs import ROUTE_TAGS, RouteDocs, apply_route_docs, raised_denial
from litestar_security._dto import apply_wire_dtos
from litestar_security._internal import GENERATED_ROUTE_OPT_KEY
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable, public, required
from litestar_security.context import Principal
from litestar_security.providers.oauth._accounts import (
    AccountLinkError,
    LinkedProviderAccount,
    OAuthAccountError,
    OAuthAccountService,
    OAuthLinkProof,
    UnlinkStatus,
)
from litestar_security.providers.oauth._provider import (
    OAuthProvider,
    OAuthProviderError,
    ProviderGrant,
    ProviderIdentity,
)
from litestar_security.providers.oauth._transactions import (
    OAUTH_BINDING_COOKIE_NAME,
    InvalidOAuthCallback,
    OAuthOperation,
    OAuthTransactionService,
    OAuthTransactionUnavailable,
    SecretStr,
    oauth_binding_cookie,
)
from litestar_security.schema import WirePolicy, WireStruct

if TYPE_CHECKING:
    from litestar_security.accounts import RateLimitGuard, StepUpService

__all__ = (
    "OIDC_FRONTCHANNEL_LOGOUT",
    "OAuthAuthorization",
    "OAuthCallbackOutcome",
    "OAuthConfig",
    "OAuthLifecycle",
    "OAuthLifecycleService",
    "OAuthLink",
    "OAuthLocalTransport",
    "OAuthLogout",
    "OAuthOperationSummary",
    "OAuthProviderRegistration",
    "OAuthScopeUpgrade",
    "OAuthStepUp",
    "OAuthStepUpAuthorization",
    "OAuthStepUpAuthorizer",
    "OIDCBackchannelLogout",
    "OIDCLogoutIdentity",
    "OIDCLogoutLifecycleService",
    "OIDCLogoutTokenConsumer",
    "OIDCSessionLogoutStore",
    "StepUpOAuthAuthorizer",
    "build_oauth_routes",
)

OIDC_FRONTCHANNEL_LOGOUT = "oidc.logout.frontchannel"
"""Rate-limit operation name consumed by each front-channel logout attempt."""

_LOGGER = getLogger(__name__)
_OAUTH_PROVIDERS_TAG = ROUTE_TAGS["oauth.providers"].name
_OIDC_LOGOUT_TAG = ROUTE_TAGS["oidc.logout"].name
_MAXIMUM_TCP_PORT = 65_535
_MAXIMUM_SECURITY_EPOCH = 9_223_372_036_854_775_807


class OAuthOperationSummary(WireStruct, frozen=True, kw_only=True, omit_defaults=True):
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


class OAuthLink(WireStruct, frozen=True, kw_only=True):
    """Purpose-bound link request."""

    step_up_grant: str
    return_to: str = "/"

    def __repr__(self) -> str:
        """Redact the one-time step-up credential."""
        return f"{type(self).__name__}(step_up_grant=<redacted>, return_to={self.return_to!r})"


class OAuthScopeUpgrade(WireStruct, frozen=True, kw_only=True):
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


class OAuthStepUp(WireStruct, frozen=True, kw_only=True):
    """Provider-account action requiring fresh step-up."""

    step_up_grant: str

    def __repr__(self) -> str:
        """Redact the one-time step-up credential."""
        return f"{type(self).__name__}(step_up_grant=<redacted>)"


class OIDCBackchannelLogout(WireStruct, frozen=True, kw_only=True):
    """OIDC back-channel logout token form, decoded from a form-encoded body."""

    __wire_casing__: ClassVar[bool] = False
    """The provider sends the member name the specification defines, so no policy may rename it."""

    logout_token: str

    def __repr__(self) -> str:
        """Redact the signed logout token."""
        return f"{type(self).__name__}(logout_token=<redacted>)"


class OAuthAuthorization(msgspec.Struct, frozen=True, kw_only=True):
    """Authorization redirect and dedicated browser-binding cookie."""

    url: str
    binding_cookie: Cookie


@dataclass(frozen=True, slots=True)
class OAuthCallbackOutcome:
    """Presentation-neutral result of one consumed OAuth callback."""

    operation: OAuthOperation
    return_to: str
    identity: ProviderIdentity
    linked: LinkedProviderAccount
    authenticated_at: datetime
    provisioned: bool


class OAuthLogout(msgspec.Struct, frozen=True, kw_only=True):
    """Local logout confirmation plus optional validated provider redirect."""

    detail: str = "Logged out."
    redirect_url: str | None = None

    def __repr__(self) -> str:
        """Redact a redirect that may contain an OIDC id-token hint."""
        redirect = "None" if self.redirect_url is None else "<redacted>"
        return f"{type(self).__name__}(detail={self.detail!r}, redirect_url={redirect})"


# Every status below is raised, so the body is the one exception handling
# renders. OAuthOperationSummary stays on the statuses these routes return.
_OAUTH_PUBLIC_RESPONSES = {
    HTTP_400_BAD_REQUEST: raised_denial("The provider request is invalid."),
    HTTP_401_UNAUTHORIZED: raised_denial("The provider exchange was rejected."),
    HTTP_503_SERVICE_UNAVAILABLE: raised_denial("The provider is unavailable."),
}


_OAUTH_AUTHENTICATED_RESPONSES = {
    **_OAUTH_PUBLIC_RESPONSES,
    HTTP_401_UNAUTHORIZED: raised_denial("Authentication or step-up is required."),
}


_OIDC_FRONTCHANNEL_RESPONSES = {
    **_OAUTH_PUBLIC_RESPONSES,
    HTTP_429_TOO_MANY_REQUESTS: raised_denial("The request exceeded its rate limit."),
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
    retain_tokens: bool = False

    @classmethod
    def oidc(
        cls, *, provider: OAuthProvider, redirect_uri: str, post_logout_redirect_uri: str | None = None
    ) -> "OAuthProviderRegistration":
        """Derive an OIDC registration from one validated provider.

        Args:
            provider: Configured OIDC provider exposing validated metadata.
            redirect_uri: Exact application callback URI.
            post_logout_redirect_uri: Fixed return URI for provider logout.

        Returns:
            An immutable registration with nonce, issuer, scopes, logout, and retention derived.

        Raises:
            ImproperlyConfiguredException: If the provider is not a configured OIDC provider.
        """
        oidc = cast("Any", provider)
        metadata = getattr(oidc, "metadata", None)
        oauth = getattr(oidc, "oauth", None)
        config = getattr(oauth, "config", None)
        if metadata is None or config is None:
            message = "OIDC provider registration is invalid"
            raise ImproperlyConfiguredException(detail=message)
        end_session_endpoint = getattr(metadata, "end_session_endpoint", None)
        return cls(
            provider=provider,
            redirect_uri=redirect_uri,
            default_scopes=config.allowed_scopes,
            expected_issuer=metadata.issuer,
            include_nonce=True,
            end_session_endpoint=end_session_endpoint if post_logout_redirect_uri is not None else None,
            post_logout_redirect_uri=post_logout_redirect_uri,
            retain_tokens=bool(getattr(oidc, "retain_tokens_by_default", True)),
        )

    def __post_init__(self) -> None:
        """Require immutable registration metadata matching the provider."""
        if (
            not isinstance(cast("object", self.provider), OAuthProvider)
            or not _exact_https_url(self.redirect_uri)
            or self.default_scopes.__class__ is not frozenset
            or not self.default_scopes
            or any(not scope.strip() for scope in self.default_scopes)
            or (self.expected_issuer is not None and not _exact_https_url(self.expected_issuer))
            or self.include_nonce.__class__ is not bool
            or (self.end_session_endpoint is not None and not _exact_https_url(self.end_session_endpoint))
            or (self.post_logout_redirect_uri is not None and not _exact_https_url(self.post_logout_redirect_uri))
            or ((self.end_session_endpoint is None) != (self.post_logout_redirect_uri is None))
            or self.retain_tokens.__class__ is not bool
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
    """Verified logout-token identity whose ``jti`` awaits store consumption."""

    provider: str
    issuer: str
    subject: str | None
    session_id: str | None
    token_id: str
    expires_at: datetime


@runtime_checkable
class OIDCLogoutTokenConsumer(Protocol):
    """Verify logout-token signature, claims, and events, yielding its ``jti``."""

    async def consume(self, provider: str, logout_token: str, *, now: datetime) -> OIDCLogoutIdentity:
        """Return one verified logout identity without consuming its ``jti``."""
        ...  # pragma: no cover


@runtime_checkable
class OIDCSessionLogoutStore(Protocol):
    """Atomically consume a verified logout ``jti`` and revoke mapped sessions."""

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


@dataclass(frozen=True, slots=True)
class StepUpOAuthAuthorizer:
    """Adapt ``StepUpService`` grants to OAuth lifecycle authorization."""

    service: "StepUpService"
    current_epoch: Callable[[str], Awaitable[int | None]]
    transport_binding: Callable[[Request[Any, Any, Any]], bytes | None]
    session_binding: Callable[[Request[Any, Any, Any]], str | None]

    def __post_init__(self) -> None:
        """Require the concrete service and application-owned callbacks."""
        if (
            not callable(getattr(self.service, "consume", None))
            or not callable(self.current_epoch)
            or not callable(self.transport_binding)
            or not callable(self.session_binding)
        ):
            message = "OAuth step-up authorizer configuration is invalid"
            raise ImproperlyConfiguredException(detail=message)

    async def authorize(
        self, *, grant: str, account_id: str, purpose: str, request: Request[Any, Any, Any]
    ) -> OAuthStepUpAuthorization:
        """Consume one exact step-up grant for the current OAuth operation.

        Args:
            grant: One-time step-up grant presented by the authenticated account.
            account_id: Account the grant must belong to.
            purpose: Exact OAuth operation the grant authorizes.
            request: Request from which application callbacks derive bindings.

        Returns:
            The current epoch and optional callback-session binding.

        Raises:
            NotAuthorizedException: If the grant or transport binding is absent or invalid.
            ServiceUnavailableException: If the epoch or step-up service is unavailable.
        """
        security_epoch = await self.current_security_epoch(account_id)
        try:
            binding = self.transport_binding(request)
        except Exception:  # noqa: BLE001 - application-owned binding failures fail closed
            raise _step_up_unavailable() from None
        if binding is None or binding.__class__ is not bytes or not binding:
            raise NotAuthorizedException(detail="Fresh step-up authentication required")
        try:
            result = await self.service.consume(
                grant,
                principal_id=account_id,
                security_epoch=security_epoch,
                purpose=purpose,
                transport_binding=binding,
            )
        except Exception:  # noqa: BLE001 - a service failure must not escape as an OAuth decision
            raise _step_up_unavailable() from None
        if isinstance(result, InvalidCredentials):
            raise NotAuthorizedException(detail="Fresh step-up authentication required")
        if isinstance(result, VerificationUnavailable):
            raise _step_up_unavailable()
        try:
            session_binding = self.session_binding(request)
        except Exception:  # noqa: BLE001 - application-owned binding failures fail closed
            raise _step_up_unavailable() from None
        if session_binding is not None and (session_binding.__class__ is not str or not session_binding):
            raise _step_up_unavailable()
        return OAuthStepUpAuthorization(security_epoch=security_epoch, session_binding=session_binding)

    async def current_security_epoch(self, account_id: str) -> int:
        """Return the application callback's current valid epoch.

        Args:
            account_id: Account whose security epoch must be read.

        Returns:
            The current valid non-negative security epoch.

        Raises:
            ServiceUnavailableException: If the callback fails or returns no valid epoch.
        """
        try:
            epoch = await self.current_epoch(account_id)
        except Exception:  # noqa: BLE001 - epoch lookups are application-owned availability boundaries
            raise _step_up_unavailable() from None
        if not isinstance(epoch, int) or isinstance(epoch, bool):
            raise _step_up_unavailable()
        if epoch < 0 or epoch > _MAXIMUM_SECURITY_EPOCH:
            raise _step_up_unavailable()
        return epoch


def _step_up_unavailable() -> ServiceUnavailableException:
    return ServiceUnavailableException(detail="Step-up authentication is unavailable")


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
    ) -> OAuthOperationSummary | Response[Any]:
        """Establish a session, token pair, or explicit hybrid transport."""
        ...  # pragma: no cover

    async def logout(self, *, account_id: str, request: Request[Any, Any, Any]) -> None:
        """Invalidate the configured local transport."""
        ...  # pragma: no cover


@runtime_checkable
class OAuthLifecycle(Protocol):
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

    async def complete_callback(
        self, *, provider: str, code: str, state: str, request: Request[Any, Any, Any]
    ) -> OAuthCallbackOutcome:
        """Consume a callback and commit provider-account state without presentation adaptation."""
        ...  # pragma: no cover

    async def establish_login(
        self, outcome: OAuthCallbackOutcome, *, request: Request[Any, Any, Any]
    ) -> OAuthOperationSummary | Response[Any]:
        """Establish the configured local transport for a completed login."""
        ...  # pragma: no cover

    async def unlink(
        self,
        *,
        provider: str,
        provider_account_id: str,
        account_id: str,
        step_up_grant: str,
        request: Request[Any, Any, Any],
    ) -> OAuthOperationSummary:
        """Atomically unlink a provider account."""
        ...  # pragma: no cover

    async def revoke(
        self, *, provider: str, account_id: str, step_up_grant: str, request: Request[Any, Any, Any]
    ) -> OAuthOperationSummary:
        """Locally delete and attempt upstream revocation."""
        ...  # pragma: no cover

    async def logout(self, *, provider: str, account_id: str, request: Request[Any, Any, Any]) -> OAuthLogout:
        """Complete local logout independently of provider availability."""
        ...  # pragma: no cover


class OAuthLifecycleService:
    """Concrete OAuth transaction, provider, account, and local-login workflow."""

    __slots__ = ("_closed", "_registrations", "accounts", "clock", "local", "step_up", "transactions")

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
        for registration in registrations:
            configured = transactions.redirects.callback_uris.get(registration.provider.name)
            if configured is None or registration.redirect_uri not in configured:
                message = "OAuth provider callback URI is not allowed by the redirect policy"
                raise ImproperlyConfiguredException(detail=message)
        self._closed = False
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
        existing_binding = SecretStr(cookie_value) if cookie_value else None
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
    ) -> OAuthOperationSummary | Response[Any]:
        """Adapt a neutral callback outcome to the generated route response."""
        outcome = await self.complete_callback(provider=provider, code=code, state=state, request=request)
        if outcome.operation is OAuthOperation.LOGIN:
            return await self.establish_login(outcome, request=request)
        detail = "Linked." if outcome.operation is OAuthOperation.LINK else "Scopes updated."
        return OAuthOperationSummary(detail=detail, provider_account_id=outcome.linked.provider_account_id)

    async def complete_callback(
        self, *, provider: str, code: str, state: str, request: Request[Any, Any, Any]
    ) -> OAuthCallbackOutcome:
        """Consume a callback and commit account state without presenting HTTP or establishing a session."""
        if not code or not state:
            raise InvalidOAuthCallback
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
        provisioned = False
        if transaction.operation is OAuthOperation.LOGIN:
            login = await self.accounts.login(
                identity, grant, tokens, retain_tokens=registration.retain_tokens, now=now
            )
            linked = login.linked
            provisioned = login.provisioned
        else:
            proof = await self._callback_proof(
                transaction.account_id, transaction.security_epoch, transaction.operation
            )
            if transaction.operation is OAuthOperation.LINK:
                linked = await self.accounts.link(
                    proof, identity, grant, tokens, retain_tokens=registration.retain_tokens, now=now
                )
            else:
                if transaction.provider_account_id is None:
                    raise OAuthAccountError
                linked = await self.accounts.apply_scope_upgrade(
                    proof,
                    transaction.provider_account_id,
                    identity,
                    grant,
                    tokens,
                    required_scopes=transaction.requested_scopes,
                    retain_tokens=registration.retain_tokens,
                    now=now,
                )
        return OAuthCallbackOutcome(
            operation=transaction.operation,
            return_to=transaction.return_to,
            identity=identity,
            linked=linked,
            authenticated_at=now,
            provisioned=provisioned,
        )

    async def establish_login(
        self, outcome: OAuthCallbackOutcome, *, request: Request[Any, Any, Any]
    ) -> OAuthOperationSummary | Response[Any]:
        """Establish the configured local transport for a completed login only."""
        if outcome.__class__ is not OAuthCallbackOutcome or outcome.operation is not OAuthOperation.LOGIN:
            raise OAuthAccountError
        return await self.local.establish(
            account_id=outcome.linked.account_id,
            identity=outcome.identity,
            request=request,
            authenticated_at=outcome.authenticated_at,
        )

    async def aclose(self) -> None:
        """Close each lifecycle-owned provider exactly once."""
        if self._closed:
            return
        self._closed = True
        closers = tuple(
            cast("Callable[[], Awaitable[None]]", closer)
            for registration in self._registrations.values()
            if callable(closer := getattr(registration.provider, "aclose", None))
        )
        results = await asyncio.gather(*(closer() for closer in closers), return_exceptions=True)
        if any(isinstance(result, BaseException) for result in results):
            message = "OAuth provider shutdown failed"
            raise ImproperlyConfiguredException(detail=message)

    async def unlink(
        self,
        *,
        provider: str,
        provider_account_id: str,
        account_id: str,
        step_up_grant: str,
        request: Request[Any, Any, Any],
    ) -> OAuthOperationSummary:
        """Consume step-up and atomically unlink one account-owned provider identity."""
        self._registration(provider)
        authorization = await self._authorize(step_up_grant, account_id, "oauth-unlink", request)
        proof = self._proof(account_id, "oauth-unlink", authorization.security_epoch, authorization.security_epoch)
        result = await self.accounts.unlink(proof, provider, provider_account_id, now=self._now())
        detail = "Unlinked." if result.status is UnlinkStatus.UNLINKED else "Provider account not unlinked."
        return OAuthOperationSummary(detail=detail, provider_account_id=result.provider_account_id)

    async def revoke(
        self, *, provider: str, account_id: str, step_up_grant: str, request: Request[Any, Any, Any]
    ) -> OAuthOperationSummary:
        """Consume step-up and revoke the exact account-owned provider grant."""
        registration = self._registration(provider)
        await self._authorize(step_up_grant, account_id, "oauth-provider-token-management", request)
        linked = await self.accounts.store.resolve_provider_account(account_id, provider)
        if linked is None:
            raise OAuthAccountError
        await self.accounts.revoke(linked.provider_account_id, registration.provider, now=self._now())
        return OAuthOperationSummary(detail="Revoked.", provider_account_id=linked.provider_account_id)

    async def logout(self, *, provider: str, account_id: str, request: Request[Any, Any, Any]) -> OAuthLogout:
        """Complete local logout before returning an optional fixed RP redirect."""
        registration = self._registration(provider)
        await self.local.logout(account_id=account_id, request=request)
        if registration.end_session_endpoint is None:
            return OAuthLogout()
        parameters: dict[str, str] = {"post_logout_redirect_uri": cast("str", registration.post_logout_redirect_uri)}
        try:
            linked = await self.accounts.store.resolve_provider_account(account_id, provider)
            stored = (
                await self.accounts.store.get_tokens(linked.provider_account_id, now=self._now())
                if linked is not None
                else None
            )
        except Exception:  # noqa: BLE001 - local logout remains successful when optional provider state is unavailable
            stored = None
        if stored is not None and stored.tokens.id_token is not None:
            parameters["id_token_hint"] = stored.tokens.id_token.get_secret_value()
        separator = "&" if "?" in registration.end_session_endpoint else "?"
        return OAuthLogout(redirect_url=f"{registration.end_session_endpoint}{separator}{urlencode(parameters)}")

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

    __slots__ = ("client_key", "clock", "consumer", "provider_issuers", "rate_limits", "sessions")

    def __init__(  # noqa: PLR0913 - logout dependencies remain explicit and independently replaceable
        self,
        *,
        provider_issuers: Mapping[str, str],
        consumer: OIDCLogoutTokenConsumer,
        sessions: OIDCSessionLogoutStore,
        rate_limits: "RateLimitGuard | None" = None,
        client_key: Callable[[Request[Any, Any, Any]], str | None] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        """Build one fixed-issuer logout service.

        Args:
            provider_issuers: Exact configured issuer per provider.
            consumer: Logout-token verifier that yields a verified identity and ``jti``.
            sessions: Store that atomically consumes that ``jti`` and revokes mapped sessions.
            rate_limits: Optional budget consumed by each front-channel attempt.
            client_key: Trusted client identity extractor for the rate-limit
                client bucket, defaulting to the peer address without trusting
                any forwarding header.
            clock: Source of the current aware time.
        """
        from litestar_security.accounts import (  # noqa: PLC0415 - a module import would cycle back through providers
            RateLimitGuard,
            trusted_client_key,
        )

        if (
            not provider_issuers
            or any(
                not provider.strip() or not issuer.startswith("https://")
                for provider, issuer in provider_issuers.items()
            )
            or not isinstance(cast("object", consumer), OIDCLogoutTokenConsumer)
            or not isinstance(cast("object", sessions), OIDCSessionLogoutStore)
            or (rate_limits is not None and rate_limits.__class__ is not RateLimitGuard)
            or (client_key is not None and not callable(client_key))
            or not callable(clock)
        ):
            message = "OIDC logout service configuration is invalid"
            raise ImproperlyConfiguredException(detail=message)
        self.provider_issuers = dict(provider_issuers)
        self.consumer = consumer
        self.sessions = sessions
        self.rate_limits = rate_limits
        self.client_key = trusted_client_key if client_key is None else client_key
        self.clock = clock

    @property
    def provider_names(self) -> frozenset[str]:
        """Return providers supporting OIDC logout."""
        return frozenset(self.provider_issuers)

    async def backchannel(self, provider: str, logout_token: str) -> OAuthOperationSummary:
        """Verify a logout token, check its issuer, then consume and revoke through the store."""
        self._issuer(provider)
        now = self._now()
        identity = await self.consumer.consume(provider, logout_token, now=now)
        if identity.provider != provider or identity.issuer != self.provider_issuers[provider]:
            raise NotAuthorizedException(detail="OIDC logout token is invalid")
        revoked = await self.sessions.consume_backchannel(identity, now=now)
        if revoked is None:
            raise NotAuthorizedException(detail="OIDC logout token is invalid")
        return OAuthOperationSummary(detail="OIDC sessions revoked.", revoked_sessions=revoked)

    async def frontchannel(
        self, provider: str, issuer: str, session_id: str, *, request: Request[Any, Any, Any]
    ) -> OAuthOperationSummary:
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
            TooManyRequestsException: If the attempt exhausted its budget. The
                budget is consumed before any validation, so a rejected sid pays
                exactly as much as a revoking one.
            ServiceUnavailableException: If the session store or the limiter is
                unavailable. An outage never removes the limit or the binding.
        """
        if self.rate_limits is not None:
            from litestar_security.accounts import (  # noqa: PLC0415 - a module import would cycle back through providers
                RateLimited,
            )

            limited = await self.rate_limits.check(
                OIDC_FRONTCHANNEL_LOGOUT,
                client_key=self._client_key_for(request),
                identifier=session_id.strip() or None,
            )
            if isinstance(limited, RateLimited):
                headers = {"Retry-After": str(limited.retry_after)} if limited.retry_after is not None else None
                raise TooManyRequestsException(detail="Too many requests", headers=headers)
            if limited is not None:
                raise ServiceUnavailableException(detail="OIDC logout is unavailable")
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
        return OAuthOperationSummary(detail="OIDC sessions revoked.", revoked_sessions=revoked)

    def _issuer(self, provider: str) -> str:
        issuer = self.provider_issuers.get(provider)
        if issuer is None:
            raise NotAuthorizedException(detail="OIDC logout provider is not configured")
        return issuer

    def _client_key_for(self, request: Request[Any, Any, Any]) -> str | None:
        # A failing extractor degrades to sid-only limiting rather than failing
        # the request, because the subject bucket still bounds the attempt.
        try:
            return self.client_key(request)
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; degrade, do not fail
            _LOGGER.error("OIDC logout client key extractor failed")  # noqa: TRY400 - omit untrusted details
            return None

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            message = "OIDC logout clock must return aware time"
            raise ImproperlyConfiguredException(detail=message)
        return value.astimezone(timezone.utc)


class OAuthConfig:
    """Interactive provider route configuration and service graph."""

    __slots__ = ("_route_handlers", "docs", "oauth_service", "oidc_service", "register_routes", "route_prefix")

    def __init__(
        self,
        *,
        oauth_service: OAuthLifecycle,
        oidc_service: OIDCLogoutLifecycleService | None = None,
        route_prefix: str = "/auth",
        register_routes: bool = True,
        docs: "RouteDocs | None" = None,
    ) -> None:
        """Validate provider uniqueness and generated-route ownership.

        Args:
            oauth_service: Shared route and custom-controller service.
            oidc_service: Optional verified OIDC logout workflow.
            route_prefix: Absolute non-root mount path.
            register_routes: Whether the plugin installs generated routes.
            docs: Application-owned OpenAPI documentation for the generated
                routes: tag renames, tag descriptions, and optional operation-id
                and route-name transforms.

        Raises:
            ImproperlyConfiguredException: If any input is invalid.
        """
        oauth_service_value = cast("object", oauth_service)
        if not isinstance(oauth_service_value, OAuthLifecycle):
            message = "OAuth route service is invalid"
            raise ImproperlyConfiguredException(detail=message)
        names = oauth_service.provider_names
        if not names:
            message = "OAuth providers are invalid"
            raise ImproperlyConfiguredException(detail=message)
        if oidc_service is not None and (
            oidc_service.__class__ is not OIDCLogoutLifecycleService or not oidc_service.provider_names.issubset(names)
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
        if docs is not None and docs.__class__ is not RouteDocs:
            message = "OAuth documentation metadata must be RouteDocs"
            raise ImproperlyConfiguredException(detail=message)
        self.docs = RouteDocs() if docs is None else docs
        self.oauth_service = oauth_service
        self.oidc_service = oidc_service
        self.route_prefix = normalized_prefix
        self.register_routes = register_routes
        self._route_handlers: dict[WirePolicy, tuple[Router, ...]] = {}

    def build_route_handlers(self, *, wire: "WirePolicy | None" = None) -> tuple[Router, ...]:
        """Build and cache generated OAuth routes.

        One router is cached per wire policy rather than one overall, so a
        router stays a pure function of the configuration that caches it and two
        applications sharing this configuration with different casing each get
        their own.

        Args:
            wire: How the generated bodies are spelled on the wire. Defaults to
                the field names as Python spells them, with unknown members
                rejected.

        Returns:
            One router, or an empty tuple when ``register_routes`` is ``False``.
            The same object is returned for every call naming the same policy.
        """
        if not self.register_routes:
            return ()
        policy = WirePolicy() if wire is None else wire
        cached = self._route_handlers.get(policy)
        if cached is None:
            cached = self._route_handlers[policy] = (build_oauth_routes(self, policy),)
        return cached


def build_oauth_routes(config: OAuthConfig, wire: "WirePolicy | None" = None) -> Router:
    """Build native generated OAuth lifecycle routes.

    Args:
        config: Validated provider route configuration.
        wire: How the request and response bodies are spelled. Defaults to the
            field names as Python spells them, with unknown members rejected.

    Returns:
        One no-store router.
    """

    def provide_oauth_service() -> OAuthLifecycle:
        return config.oauth_service

    oidc_dependencies: dict[str, Provide] = {}
    if config.oidc_service is not None:

        def provide_oidc_service() -> OIDCLogoutLifecycleService:
            return cast("OIDCLogoutLifecycleService", config.oidc_service)

        oidc_dependencies["oidc_service"] = Provide(provide_oidc_service, sync_to_thread=False, use_cache=False)

    return apply_wire_dtos(
        apply_route_docs(
            Router(
                path=config.route_prefix,
                route_handlers=[
                    _OAuthController,
                    *([_OIDCLogoutController] if config.oidc_service is not None else []),
                ],
                cache_control=CacheControlHeader(no_store=True),
                response_headers={"Pragma": "no-cache"},
                opt={GENERATED_ROUTE_OPT_KEY: True},
                exception_handlers=_oauth_exception_handlers(),
                dependencies={
                    "oauth_service": Provide(provide_oauth_service, sync_to_thread=False, use_cache=False),
                    **oidc_dependencies,
                },
            ),
            config.docs,
        ),
        WirePolicy() if wire is None else wire,
    )


def _oauth_exception_handlers() -> (
    "dict[int | type[Exception], Callable[[Request[Any, Any, Any], Any], Response[Any]]]"
):
    """Classify each OAuth domain failure as the HTTP error it means.

    Classification has to happen somewhere the domain exception is still
    visible, and a router-level exception handler is the only layer Litestar
    offers that sees it: user middleware is installed *outside* the route's own
    ``ExceptionHandlerMiddleware``, so a failure raised by a handler never
    reaches it.

    What each entry must not do is answer the request itself. Litestar resolves
    one flattened handler map per route and calls a single winner, so a handler
    that builds the response here wins over every application-level handler for
    the resulting HTTP error - an application publishing its own error format
    would receive it on every route except its OAuth ones. Each entry therefore
    classifies and then hands the mapped exception to whichever handler the
    application would have used, falling back to Litestar's own rendering when
    the application configured none.

    Returns:
        The handler map registered on the generated OAuth router.
    """

    def _classified(request: Request[Any, Any, Any], mapped: HTTPException) -> Response[Any]:
        state = cast("Any", ScopeState.from_scope(request.scope))
        handlers = state.exception_handlers
        application_handler = None if handlers is Empty else cast("Any", get_exception_handler(handlers, mapped))
        if application_handler is not None:
            return cast("Response[Any]", application_handler(request, mapped))
        # The cast is redundant to mypy yet required by pyright, which sees the
        # native helper return an unparameterized Response.
        return cast("Response[Any]", create_exception_response(request=request, exc=mapped))  # type: ignore[redundant-cast]

    def _invalid_callback(request: Request[Any, Any, Any], exc: InvalidOAuthCallback) -> Response[Any]:
        return _classified(request, NotAuthorizedException(detail=str(exc)))

    def _provider_unavailable(request: Request[Any, Any, Any], exc: OAuthProviderError) -> Response[Any]:
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after is not None else None
        mapped = ServiceUnavailableException(detail="OAuth provider is unavailable", headers=headers)
        return _classified(request, mapped)

    def _store_unavailable(request: Request[Any, Any, Any], exc: OAuthTransactionUnavailable) -> Response[Any]:
        return _classified(request, ServiceUnavailableException(detail=str(exc)))

    def _link_conflict(request: Request[Any, Any, Any], exc: AccountLinkError) -> Response[Any]:
        return _classified(request, HTTPException(detail=str(exc), status_code=HTTP_409_CONFLICT))

    def _account_denied(request: Request[Any, Any, Any], exc: OAuthAccountError) -> Response[Any]:
        return _classified(request, ClientException(detail=str(exc)))

    # Subclasses precede their bases so the intended MRO resolution stays legible.
    return {
        InvalidOAuthCallback: _invalid_callback,  # 401
        OAuthProviderError: _provider_unavailable,  # 503, InvalidProviderGrantError included via MRO
        OAuthTransactionUnavailable: _store_unavailable,  # 503
        AccountLinkError: _link_conflict,  # 409
        OAuthAccountError: _account_denied,  # 400
    }


def _account_id(principal: Principal[Any]) -> str:
    if not principal.is_authenticated:
        raise NotAuthorizedException(detail="Authentication required")
    return cast("str", principal.id)


def _authorization_response(result: OAuthAuthorization) -> Redirect:
    return Redirect(result.url, status_code=HTTP_302_FOUND, cookies=[result.binding_cookie])


class _OAuthController(Controller):
    path = "/oauth/{provider:str}"
    tags = (_OAUTH_PROVIDERS_TAG,)

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
        oauth_service: NamedDependency[SkipValidation[OAuthLifecycle]],
        return_to: FromQuery[str] = "/",
    ) -> Redirect:
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
        oauth_service: NamedDependency[SkipValidation[OAuthLifecycle]],
    ) -> OAuthOperationSummary | Response[Any]:
        """Consume a transaction-bound callback and issue local authentication."""
        outcome = await oauth_service.complete_callback(
            provider=provider, code=code, state=oauth_state, request=request
        )
        if outcome.operation is OAuthOperation.LOGIN:
            return await oauth_service.establish_login(outcome, request=request)
        detail = "Linked." if outcome.operation is OAuthOperation.LINK else "Scopes updated."
        return OAuthOperationSummary(detail=detail, provider_account_id=outcome.linked.provider_account_id)

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
        data: JSONBody[OAuthLink],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_service: NamedDependency[SkipValidation[OAuthLifecycle]],
    ) -> Redirect:
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
        data: JSONBody[OAuthStepUp],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_service: NamedDependency[SkipValidation[OAuthLifecycle]],
    ) -> OAuthOperationSummary:
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
        data: JSONBody[OAuthScopeUpgrade],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_service: NamedDependency[SkipValidation[OAuthLifecycle]],
    ) -> Redirect:
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
        data: JSONBody[OAuthStepUp],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        oauth_service: NamedDependency[SkipValidation[OAuthLifecycle]],
    ) -> OAuthOperationSummary:
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
        oauth_service: NamedDependency[SkipValidation[OAuthLifecycle]],
    ) -> Response[OAuthOperationSummary] | OAuthOperationSummary:
        """Complete local logout, then optionally redirect to a validated RP endpoint."""
        result = await oauth_service.logout(provider=provider, account_id=_account_id(principal), request=request)
        if result.redirect_url is not None:
            # Response rather than litestar.response.Redirect: this 302 carries
            # the logout detail as its JSON body, which Redirect cannot express.
            return Response(
                content=OAuthOperationSummary(detail=result.detail),
                status_code=HTTP_302_FOUND,
                headers={"Location": result.redirect_url},
            )
        return OAuthOperationSummary(detail=result.detail)


class _OIDCLogoutController(Controller):
    path = "/oidc/{provider:str}"
    tags = (_OIDC_LOGOUT_TAG,)

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
        responses=_OIDC_FRONTCHANNEL_RESPONSES,
        auth=public(),
    )
    async def frontchannel_logout(
        self,
        provider: FromPath[str],
        issuer: Annotated[str, QueryParameter(name="iss")],
        session_id: Annotated[str, QueryParameter(name="sid")],
        request: Request[Any, Any, Any],
        oidc_service: NamedDependency[SkipValidation[OIDCLogoutLifecycleService]],
    ) -> OAuthOperationSummary:
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
        data: Annotated[OIDCBackchannelLogout, Body(media_type=RequestEncodingType.URL_ENCODED)],
        oidc_service: NamedDependency[SkipValidation[OIDCLogoutLifecycleService]],
    ) -> OAuthOperationSummary:
        """Verify a logout token, consume its jti, and revoke mapped sessions."""
        return await oidc_service.backchannel(provider, data.logout_token)


def _exact_https_url(value: str) -> bool:
    if value.__class__ is not str or value != value.strip() or "*" in value or "\\" in value:
        return False
    try:
        split = urlsplit(value)
        port = split.port
    except ValueError:
        return False
    return (
        split.scheme == "https"
        and bool(split.netloc)
        and split.hostname is not None
        and split.username is None
        and split.password is None
        and not split.query
        and not split.fragment
        and (port is None or 1 <= port <= _MAXIMUM_TCP_PORT)
    )
