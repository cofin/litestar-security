"""Bridge verified OAuth identities into explicit local authentication transports."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, cast, runtime_checkable

from litestar import Request, Response
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException, ServiceUnavailableException
from litestar.status_codes import HTTP_200_OK

from litestar_security.accounts import LocalAccount, TokenPair
from litestar_security.authentication import VerificationUnavailable
from litestar_security.context import AuthenticationEvidence
from litestar_security.providers.oauth._provider import ProviderIdentity
from litestar_security.providers.oauth._routes import OAuthOperationSummary

__all__ = ("OAuthLocalAuthTransport",)


@runtime_checkable
class _SessionLogout(Protocol):
    async def logout(self, request: Request[Any, Any, Any]) -> object: ...  # pragma: no cover


@runtime_checkable
class _VerifiedLocalAuthService(Protocol):
    session_auth: _SessionLogout | None
    refresh_tokens: object | None

    async def verified_login(
        self,
        request: Request[Any, Any, Any],
        account_id: str,
        *,
        transport: str | None,
        evidence: AuthenticationEvidence,
    ) -> LocalAccount | TokenPair | VerificationUnavailable | object: ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class OAuthLocalAuthTransport:
    """Establish session, token, or hybrid local credentials after OAuth login."""

    local_auth_service: _VerifiedLocalAuthService = field(repr=False)
    transport: str | None = None
    token_logout: Callable[[str], Awaitable[None]] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Require an explicit valid local transport selection."""
        if (
            not isinstance(cast("object", self.local_auth_service), _VerifiedLocalAuthService)
            or self.transport not in {None, "session", "tokens"}
            or (self.token_logout is not None and not callable(self.token_logout))
            or (self.transport == "session" and self.local_auth_service.session_auth is None)
            or (self.transport == "tokens" and self.local_auth_service.refresh_tokens is None)
            or (self.local_auth_service.refresh_tokens is not None and self.token_logout is None)
        ):
            message = "OAuth local authentication transport is invalid"
            raise ImproperlyConfiguredException(detail=message)

    async def establish(
        self,
        *,
        account_id: str,
        identity: ProviderIdentity,
        request: Request[Any, Any, Any],
        authenticated_at: datetime,
    ) -> OAuthOperationSummary | Response[Any]:
        """Establish the selected local transport with normalized OAuth evidence."""
        result = await self.local_auth_service.verified_login(
            request,
            account_id,
            transport=self.transport,
            evidence=AuthenticationEvidence(
                mechanism=f"oauth:{identity.provider}",
                slot="oauth",
                authenticated_at=authenticated_at,
                methods=frozenset({"oauth"}),
                traits=frozenset({"federated"}),
                acr=identity.acr,
                amr=identity.amr,
            ),
        )
        if isinstance(result, LocalAccount):
            return OAuthOperationSummary(detail="Authenticated.", account_id=account_id)
        if isinstance(result, TokenPair):
            return Response(content=result, status_code=HTTP_200_OK)
        if isinstance(result, VerificationUnavailable):
            raise ServiceUnavailableException(detail="Local authentication is unavailable")
        raise NotAuthorizedException(detail="Local authentication was rejected")

    async def logout(self, *, account_id: str, request: Request[Any, Any, Any]) -> None:
        """Invalidate every configured local transport independently."""
        unavailable = False
        if self.local_auth_service.session_auth is not None:
            result = await self.local_auth_service.session_auth.logout(request)
            unavailable = isinstance(result, VerificationUnavailable)
        if self.token_logout is not None:
            try:
                await self.token_logout(account_id)
            except Exception:  # noqa: BLE001 - application revocation failures become one sanitized outage
                unavailable = True
        if unavailable:
            raise ServiceUnavailableException(detail="Local logout is unavailable")
