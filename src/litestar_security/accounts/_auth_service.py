"""The shared local-authentication service graph.

This module sits below both `_profiles` and the generated controllers. The
controllers need `LocalAuthService` at runtime to resolve their dependency
annotations, while `LocalAuthConfig` builds the route tree, so the service and
its default client-key extractor live here rather than beside the configuration
that constructs them.
"""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from logging import getLogger
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast

from litestar import Request
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.accounts._login import PasswordLoginService, PasswordReauthenticationService
from litestar_security.accounts._mfa_login import MFALoginChallenge, MFALoginService, MFARequired
from litestar_security.accounts._operations import LOGIN_MFA
from litestar_security.accounts._passwords import PasswordPolicyResult
from litestar_security.accounts._rate_limits import RateLimited, RateLimitGuard
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
from litestar_security.accounts._sessions import NativeSessionAuth, SessionAuthentication
from litestar_security.accounts._stores import LocalAccountCapabilities
from litestar_security.accounts.schemas import LocalAccountResponse, LocalCredentials, LocalPasswordChangeRequest
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence

if TYPE_CHECKING:
    from collections.abc import Callable, Collection

    from litestar.connection import ASGIConnection

__all__ = ("LocalAuthService", "forwarded_client_key", "trusted_client_key")

UserT = TypeVar("UserT")
_LOGGER = getLogger(__name__)
_MAXIMUM_TCP_PORT = 65_535


def _parse_forwarded_address(raw: str) -> "IPv4Address | IPv6Address | None":
    """Parse an IPv4 or IPv6 address from a forwarded-address value."""
    candidate = raw.strip()
    if candidate.startswith("["):
        end = candidate.find("]")
        if end == -1:
            return None
        host = candidate[1:end]
        suffix = candidate[end + 1 :]
        if suffix and not _valid_forwarded_port(suffix):
            return None
    elif candidate.count(":") == 1:
        host, port = candidate.rsplit(":", 1)
        if not _valid_forwarded_port(f":{port}"):
            return None
    else:
        host = candidate
    try:
        address = ip_address(host)
    except ValueError:
        return None
    return address.ipv4_mapped if isinstance(address, IPv6Address) and address.ipv4_mapped is not None else address


def _valid_forwarded_port(suffix: str) -> bool:
    port = suffix.removeprefix(":") if suffix.startswith(":") else ""
    return port.isascii() and port.isdigit() and 1 <= int(port) <= _MAXIMUM_TCP_PORT


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


def _trusted_proxy_networks(trusted_proxies: "Collection[str]") -> tuple[IPv4Network | IPv6Network, ...]:
    try:
        networks = tuple(ip_network(proxy, strict=False) for proxy in trusted_proxies)
    except (TypeError, ValueError) as error:
        msg = "Trusted proxies must be CIDR networks"
        raise ImproperlyConfiguredException(detail=msg) from error
    if not networks:
        msg = "at least one trusted proxy is required"
        raise ImproperlyConfiguredException(detail=msg)
    return networks


def _forwarded_header_name(header: object) -> str:
    if not isinstance(header, str) or not (normalized := header.strip().lower()):
        msg = "Forwarding header must be a nonempty header name"
        raise ImproperlyConfiguredException(detail=msg)
    return normalized


def forwarded_client_key(
    *, trusted_proxies: "Collection[str]", header: str = "x-forwarded-for", max_hops: int = 3
) -> "Callable[[ASGIConnection[Any, Any, Any, Any]], str | None]":
    """Build a client-key extractor which trusts forwarding data from known proxies.

    The extractor accepts the forwarding header only when the directly connected
    peer belongs to ``trusted_proxies``. It then walks at most ``max_hops``
    addresses from right to left and returns the first address outside those
    networks. Invalid forwarding data falls back to the direct peer, preserving
    a client rate-limit bucket instead of disabling it.

    Args:
        trusted_proxies: CIDR networks for reverse-proxy hops operated by the
            application.
        header: The forwarding header name to read from a trusted peer.
        max_hops: Maximum rightmost forwarding entries to inspect.

    Returns:
        An extractor that returns a normalized client address, the direct peer
        when forwarding data is unavailable or unsafe, or ``None`` when the
        connection has no peer.

    Raises:
        ImproperlyConfiguredException: If the networks, header name, or hop
            limit are invalid.
    """
    networks = _trusted_proxy_networks(trusted_proxies)
    if max_hops.__class__ is not int or max_hops < 1:
        msg = "Maximum forwarding hops must be a positive integer"
        raise ImproperlyConfiguredException(detail=msg)
    header = _forwarded_header_name(header)

    def _trusted(address: "IPv4Address | IPv6Address") -> bool:
        return any(address in network for network in networks)

    def extractor(connection: "ASGIConnection[Any, Any, Any, Any]") -> str | None:
        """Return the forwarded client address only when the direct peer is trusted."""
        client = connection.client
        if client is None:
            return None
        peer = _parse_forwarded_address(client.host)
        if peer is None or not _trusted(peer):
            return client.host
        raw_header = connection.headers.get(header)
        if not raw_header:
            return client.host
        for raw in reversed(raw_header.split(",")[-max_hops:]):
            address = _parse_forwarded_address(raw)
            if address is None:
                return client.host
            if not _trusted(address):
                return str(address)
        return client.host

    return extractor


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
    rate_limits: RateLimitGuard | None = field(default=None, repr=False, compare=False)
    mfa_login: MFALoginService | None = field(default=None, repr=False, compare=False)
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
    ) -> LocalAccountResponse | MFARequired | RateLimited | InvalidCredentials | VerificationUnavailable:
        """Authenticate a password and establish fixation-safe session state.

        Args:
            request: The request whose session state to write.
            credentials: The submitted identifier and password.

        Returns:
            The signed-in account projection, or a sanitized outcome. A rejected
            identifier and a rejected password produce the same outcome.
        """
        client_key = self.client_key_for(request)
        account = await self.password_login.authenticate(
            credentials.identifier, credentials.password, client_key=client_key
        )
        if not isinstance(account, LocalAccount):
            return account
        mfa_login = self.mfa_login
        if mfa_login is not None:
            return await mfa_login.issue(cast("LocalAccount[object]", account), client_key=client_key)
        session_auth = self.session_auth
        if session_auth is None:
            return VerificationUnavailable()
        established = await session_auth.establish(request, account)
        if not isinstance(established, SessionAuthentication):
            return established
        return LocalAccountResponse(account_id=account.account_id, display_name=account.display_name)

    async def token_login(
        self, request: Request[Any, Any, Any], credentials: LocalCredentials
    ) -> RefreshTokenResponse | MFARequired | RateLimited | InvalidCredentials | VerificationUnavailable:
        """Authenticate a password and issue one access/refresh pair.

        Args:
            request: The request, read only for the rate-limit client key.
            credentials: The submitted identifier and password.

        Returns:
            The issued token pair, or a sanitized outcome. A rejected identifier
            and a rejected password produce the same outcome.
        """
        client_key = self.client_key_for(request)
        account = await self.password_login.authenticate(
            credentials.identifier, credentials.password, client_key=client_key
        )
        if not isinstance(account, LocalAccount):
            return account
        mfa_login = self.mfa_login
        if mfa_login is not None:
            return await mfa_login.issue(cast("LocalAccount[object]", account), client_key=client_key)
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
        expected_security_epoch: int | None = None,
    ) -> LocalAccountResponse | RefreshTokenResponse | InvalidCredentials | VerificationUnavailable:
        """Establish a local transport after externally verified authentication.

        Args:
            request: Request whose native session may be established.
            account_id: Account resolved by the verified authentication method.
            transport: ``session`` or ``tokens`` when both are configured.
            evidence: Fully verified evidence to preserve in local credentials.
            expected_security_epoch: When set, reject an account whose epoch
                changed since the preceding authentication boundary.

        Returns:
            The established session projection, issued token pair, or sanitized
            rejection.
        """
        try:
            account = await self.accounts.get_by_id(account_id)
        except Exception:  # noqa: BLE001 - application port failures become one sanitized outcome
            return VerificationUnavailable()
        if (
            account is None
            or not account.active
            or (expected_security_epoch is not None and account.security_epoch != expected_security_epoch)
        ):
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

    async def complete_mfa_login(  # noqa: PLR0911, PLR0913 - security order requires explicit inputs/outcomes
        self,
        request: Request[Any, Any, Any],
        challenge: str,
        *,
        account_id: str,
        method: str,
        code: str,
        method_id: str | None = None,
        transport: str | None = None,
    ) -> LocalAccountResponse | RefreshTokenResponse | RateLimited | InvalidCredentials | VerificationUnavailable:
        """Complete an MFA-gated password login through the normal issuer path.

        The rate limit, authoritative account read, and atomic challenge consume
        deliberately happen before factor verification and issuance. Therefore a
        replay or concurrent completion cannot establish a second transport.
        """
        rate_limits = self.rate_limits
        mfa_login = self.mfa_login
        if rate_limits is None or mfa_login is None:
            return VerificationUnavailable()
        client_key = self.client_key_for(request)
        try:
            limited = await rate_limits.check(LOGIN_MFA, client_key=client_key, identifier=account_id)
        except Exception:  # noqa: BLE001 - application-supplied guard failures fail closed
            return VerificationUnavailable()
        if limited is not None:
            return limited
        try:
            account = await self.accounts.get_by_id(account_id)
        except Exception:  # noqa: BLE001 - do not disclose account-port failures
            return VerificationUnavailable()
        if account is None or not account.active:
            return InvalidCredentials()
        try:
            consumed = await mfa_login.consume(
                challenge, account_id=account_id, security_epoch=account.security_epoch, client_key=client_key
            )
        except Exception:  # noqa: BLE001 - an unavailable challenge port must not leak through the route
            return VerificationUnavailable()
        if not isinstance(consumed, MFALoginChallenge):
            return consumed
        try:
            factor = await mfa_login.verify(consumed, method=method, method_id=method_id, code=code)
        except Exception:  # noqa: BLE001 - an unavailable factor port must not leak through the route
            return VerificationUnavailable()
        if not isinstance(factor, AuthenticationEvidence):
            return factor
        evidence = AuthenticationEvidence(
            mechanism="password",
            slot="local",
            authenticated_at=factor.authenticated_at,
            methods=frozenset({"password"}) | factor.methods,
            traits=factor.traits,
            amr=("pwd", "otp"),
        )
        return await self.verified_login(
            request,
            account.account_id,
            transport=transport,
            evidence=evidence,
            expected_security_epoch=consumed.security_epoch,
        )

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
