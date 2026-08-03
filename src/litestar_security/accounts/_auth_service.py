"""The shared local-authentication service graph.

This module sits below both `_profiles` and the generated controllers. The
controllers need `LocalAuthService` at runtime to resolve their dependency
annotations, while `LocalAuthConfig` builds the route tree, so the service and
its default client-key extractor live here rather than beside the configuration
that constructs them.
"""

from dataclasses import dataclass, field
from logging import getLogger
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from litestar import Request

from litestar_security.accounts._login import PasswordLoginService, PasswordReauthenticationService
from litestar_security.accounts._passwords import PasswordPolicyResult
from litestar_security.accounts._rate_limits import RateLimited
from litestar_security.accounts._records import (
    InvalidLifecycleRequest,
    LocalAccount,
    PasswordChangeResult,
    PasswordChangeStatus,
    PasswordReauthenticationProof,
)
from litestar_security.accounts._recovery import PasswordChangeService, RecoveryTokenService
from litestar_security.accounts._refresh import RefreshTokenService
from litestar_security.accounts._refresh_tokens import RefreshTokenResponse
from litestar_security.accounts._registration import RegistrationService, VerificationTokenService
from litestar_security.accounts._schemas import LocalAccountResponse, LocalCredentials, LocalPasswordChangeRequest
from litestar_security.accounts._sessions import NativeSessionAuth, SessionAuthentication
from litestar_security.accounts._stores import LocalAccountCapabilities
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar.connection import ASGIConnection

__all__ = ("LocalAuthService", "trusted_client_key")

UserT = TypeVar("UserT")
_LOGGER = getLogger(__name__)


def trusted_client_key(connection: "ASGIConnection[Any, Any, Any, Any]") -> str | None:
    """Return the peer address, without trusting any forwarding header.

    This deliberately matches Litestar's own default: ``X-Forwarded-For`` and
    friends are attacker-controlled unless a proxy you operate rewrote them, so
    an application behind a proxy must replace this with an extractor that knows
    which hops it trusts. Returning ``None`` disables the client bucket and
    leaves the identifier bucket in force.

    Args:
        connection: The connection the attempt arrived on.

    Returns:
        The peer host, or ``None`` when the connection reports no client.
    """
    client = connection.client
    return client.host if client is not None else None


@dataclass(frozen=True, slots=True)
class LocalAuthService(Generic[UserT]):
    """Singleton service graph shared by generated and application controllers."""

    accounts: LocalAccountCapabilities[UserT] = field(repr=False)
    password_login: PasswordLoginService[UserT] = field(repr=False)
    password_reauthentication: PasswordReauthenticationService = field(repr=False)
    password_change: PasswordChangeService = field(repr=False)
    verification: VerificationTokenService[UserT] = field(repr=False)
    recovery: RecoveryTokenService[UserT] = field(repr=False)
    registration: RegistrationService[UserT] | None = field(default=None, repr=False)
    session_auth: NativeSessionAuth[UserT] | None = field(default=None, repr=False)
    refresh_tokens: RefreshTokenService[UserT] | None = field(default=None, repr=False)
    client_key: "Callable[[ASGIConnection[Any, Any, Any, Any]], str | None]" = field(
        default=trusted_client_key, repr=False, compare=False
    )

    def client_key_for(self, connection: "ASGIConnection[Any, Any, Any, Any]") -> str | None:
        """Return the trusted client bucket key, or ``None`` when it cannot be derived.

        A failing extractor degrades to identifier-only limiting rather than
        failing the request, because the subject bucket still bounds the attempt.

        Args:
            connection: The connection to derive the bucket key from.

        Returns:
            The client bucket key, or ``None`` to skip client-keyed limiting.
        """
        try:
            return self.client_key(connection)
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; degrade, do not fail
            _LOGGER.error("Local authentication client key extractor failed")  # noqa: TRY400 - omit untrusted details
            return None

    async def session_login(
        self, request: Request[Any, Any, Any], credentials: LocalCredentials
    ) -> LocalAccountResponse | RateLimited | InvalidCredentials | VerificationUnavailable:
        """Authenticate a password and establish fixation-safe session state.

        Args:
            request: The request whose session state to write.
            credentials: The submitted identifier and password.

        Returns:
            The signed-in account projection, or a sanitized outcome. A rejected
            identifier and a rejected password produce the same outcome.
        """
        account = await self.password_login.authenticate(
            credentials.identifier, credentials.password, client_key=self.client_key_for(request)
        )
        if not isinstance(account, LocalAccount):
            return account
        session_auth = self.session_auth
        if session_auth is None:
            return VerificationUnavailable()
        established = await session_auth.establish(request, account)
        if not isinstance(established, SessionAuthentication):
            return established
        return LocalAccountResponse(account_id=account.account_id, display_name=account.display_name)

    async def token_login(
        self, request: Request[Any, Any, Any], credentials: LocalCredentials
    ) -> RefreshTokenResponse | RateLimited | InvalidCredentials | VerificationUnavailable:
        """Authenticate a password and issue one access/refresh pair.

        Args:
            request: The request, read only for the rate-limit client key.
            credentials: The submitted identifier and password.

        Returns:
            The issued token pair, or a sanitized outcome. A rejected identifier
            and a rejected password produce the same outcome.
        """
        account = await self.password_login.authenticate(
            credentials.identifier, credentials.password, client_key=self.client_key_for(request)
        )
        if not isinstance(account, LocalAccount):
            return account
        refresh_tokens = self.refresh_tokens
        if refresh_tokens is None:
            return VerificationUnavailable()
        return await refresh_tokens.issue(account)

    async def passkey_login(
        self,
        request: Request[Any, Any, Any],
        account_id: str,
        *,
        transport: str | None,
        evidence: AuthenticationEvidence,
    ) -> LocalAccountResponse | RefreshTokenResponse | InvalidCredentials | VerificationUnavailable:
        """Establish a configured local transport after verified passkey evidence.

        Args:
            request: Request whose native session may be established.
            account_id: Account proven by the WebAuthn service.
            transport: ``session`` or ``tokens`` when both are configured.
            evidence: Fully verified passkey evidence to preserve in session state.

        Returns:
            The established session projection, issued token pair, or a
            sanitized rejection.
        """
        return await self.verified_login(request, account_id, transport=transport, evidence=evidence)

    async def verified_login(  # noqa: PLR0911 - transport selection preserves distinct safe failures
        self,
        request: Request[Any, Any, Any],
        account_id: str,
        *,
        transport: str | None,
        evidence: AuthenticationEvidence,
    ) -> LocalAccountResponse | RefreshTokenResponse | InvalidCredentials | VerificationUnavailable:
        """Establish a local transport after externally verified authentication.

        Args:
            request: Request whose native session may be established.
            account_id: Account resolved by the verified authentication method.
            transport: ``session`` or ``tokens`` when both are configured.
            evidence: Fully verified evidence to preserve in local credentials.

        Returns:
            The established session projection, issued token pair, or sanitized
            rejection.
        """
        try:
            account = await self.accounts.get_by_id(account_id)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if account is None or not account.active:
            return InvalidCredentials()
        if transport == "session" or (
            transport is None and self.session_auth is not None and self.refresh_tokens is None
        ):
            session_auth = self.session_auth
            if session_auth is None:
                return InvalidCredentials()
            established = await session_auth.establish(request, account, evidence=evidence)
            if not isinstance(established, SessionAuthentication):
                return established
            return LocalAccountResponse(account_id=account.account_id, display_name=account.display_name)
        if transport == "tokens" or (
            transport is None and self.refresh_tokens is not None and self.session_auth is None
        ):
            refresh_tokens = self.refresh_tokens
            if refresh_tokens is None:
                return InvalidCredentials()
            return await refresh_tokens.issue(account, evidence=evidence)
        return InvalidCredentials()

    async def change_session_password(  # noqa: PLR0911 - preserve explicit sanitized outcomes
        self, request: Request[Any, Any, Any], account_id: str, data: LocalPasswordChangeRequest
    ) -> (
        PasswordChangeResult
        | PasswordPolicyResult
        | InvalidCredentials
        | InvalidLifecycleRequest
        | VerificationUnavailable
    ):
        """Change a password and atomically prepare the current session rebind.

        Args:
            request: The request whose session is rebound on success.
            account_id: The authenticated caller's account.
            data: The current password, the replacement, and the compromise flag.

        Returns:
            The change outcome, a policy violation, or a sanitized failure. On
            success the caller keeps a usable session and every other credential
            for the account is invalidated.
        """
        session_auth = self.session_auth
        if session_auth is None:
            return VerificationUnavailable()
        proof = await self.password_reauthentication.verify(account_id, data.current_password)
        if not isinstance(proof, PasswordReauthenticationProof):
            return proof
        if data.compromise:
            result = await self.password_change.change(account_id, data.password, proof=proof, compromise=True)
            if isinstance(result, PasswordChangeResult) and result.status is PasswordChangeStatus.CHANGED:
                await session_auth.logout(request)
            return result
        authentication = session_auth.current_authentication(request)
        if authentication is None or authentication.account_id != account_id:
            return InvalidCredentials()
        try:
            account = await self.accounts.get_by_id(account_id)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if account is None or account.security_epoch != proof.security_epoch:
            return InvalidCredentials()
        plan = session_auth.prepare_password_rebind(request, account)
        if isinstance(plan, VerificationUnavailable):
            return plan
        result = await self.password_change.change(
            account_id,
            data.password,
            proof=proof,
            current_session_id=plan.prior_session_id,
            replacement_session=plan.command,
        )
        if (
            isinstance(result, PasswordChangeResult)
            and result.status is PasswordChangeStatus.CHANGED
            and result.security_epoch is not None
        ):
            await session_auth.activate_password_rebind(request, plan, result.security_epoch)
        return result

    async def change_token_password(
        self, account_id: str, data: LocalPasswordChangeRequest
    ) -> (
        PasswordChangeResult
        | PasswordPolicyResult
        | InvalidCredentials
        | InvalidLifecycleRequest
        | VerificationUnavailable
    ):
        """Change a bearer-authenticated password and revoke local transports.

        Args:
            account_id: The account named by the caller's access token.
            data: The current password, the replacement, and the compromise flag.

        Returns:
            The change outcome, a policy violation, or a sanitized failure. On
            success every credential for the account, including the caller's, is
            invalidated.
        """
        proof = await self.password_reauthentication.verify(account_id, data.current_password)
        if not isinstance(proof, PasswordReauthenticationProof):
            return proof
        return await self.password_change.change(account_id, data.password, proof=proof, compromise=data.compromise)
