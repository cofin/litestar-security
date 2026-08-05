"""Native Litestar controllers for the built-in local-auth routes."""

from typing import TYPE_CHECKING, Annotated, Any, NoReturn, cast

from litestar import Controller, Request, Response, Router, delete, get, post
from litestar.connection import ASGIConnection
from litestar.datastructures import CacheControlHeader
from litestar.di import NamedDependency, Provide
from litestar.exceptions import (
    ClientException,
    NotAuthorizedException,
    ServiceUnavailableException,
    TooManyRequestsException,
)
from litestar.handlers import BaseRouteHandler
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Tag
from litestar.params import FromPath, HeaderParameter, JSONBody, SkipValidation
from litestar.status_codes import (
    HTTP_200_OK,
    HTTP_202_ACCEPTED,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_429_TOO_MANY_REQUESTS,
    HTTP_503_SERVICE_UNAVAILABLE,
)

from litestar_security._docs import ROUTE_TAGS
from litestar_security.accounts._auth_service import LocalAuthService
from litestar_security.accounts._mfa_login import MFARequired
from litestar_security.accounts._rate_limits import RateLimited
from litestar_security.accounts._records import (
    ConsumeOutcome,
    ConsumeStatus,
    LifecycleAccepted,
    LifecycleRejected,
    LocalAuthMode,
    PasswordChangeOutcome,
    PasswordChangeStatus,
    PasswordResetOutcome,
    PasswordResetStatus,
    RegistrationMode,
)
from litestar_security.accounts._refresh_tokens import TokenPair
from litestar_security.accounts.schemas import (
    LocalAccount,
    LocalCredentials,
    LocalIdentifier,
    LocalInvitationRegistration,
    LocalMFAChallenge,
    LocalMFACompletion,
    LocalPasswordChange,
    LocalPasswordReset,
    LocalRegistration,
    LocalSession,
    LocalSessionList,
    LocalToken,
    RouteStatus,
)
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable, public, required
from litestar_security.context import Principal, SecurityContext

if TYPE_CHECKING:
    from litestar_security.accounts._profiles import LocalAuthConfig

__all__ = ("LOCAL_AUTH_TAGS", "build_local_auth_routes", "requires_local_bearer")


_SESSIONS_TAG = ROUTE_TAGS["local.sessions"].name
_TOKENS_TAG = ROUTE_TAGS["local.tokens"].name
_REGISTRATION_TAG = ROUTE_TAGS["local.registration"].name
_PASSWORDS_TAG = ROUTE_TAGS["local.passwords"].name
_VERIFICATION_TAG = ROUTE_TAGS["local.verification"].name


LOCAL_AUTH_TAGS: tuple[Tag, ...] = tuple(tag for key, tag in ROUTE_TAGS.items() if key.startswith("local."))


_LOCAL_BAD_REQUEST_RESPONSES = {
    HTTP_400_BAD_REQUEST: ResponseSpec(RouteStatus, description="The lifecycle request is invalid."),
    HTTP_429_TOO_MANY_REQUESTS: ResponseSpec(RouteStatus, description="The operation exceeded its rate limit."),
    HTTP_503_SERVICE_UNAVAILABLE: ResponseSpec(RouteStatus, description="The authentication service is unavailable."),
}


_LOCAL_AUTH_REQUIRED_RESPONSES = {
    HTTP_401_UNAUTHORIZED: ResponseSpec(RouteStatus, description="Authentication is required."),
    HTTP_503_SERVICE_UNAVAILABLE: _LOCAL_BAD_REQUEST_RESPONSES[HTTP_503_SERVICE_UNAVAILABLE],
}


_LOCAL_MFA_LOGIN_RESPONSES = {
    **_LOCAL_BAD_REQUEST_RESPONSES,
    HTTP_403_FORBIDDEN: ResponseSpec(
        LocalMFAChallenge, description="The password was verified and the returned challenge requires a second factor."
    ),
}


_LOCAL_SESSION_MFA_LOGIN_RESPONSES = {
    HTTP_200_OK: ResponseSpec(LocalAccount, description="The signed-in account projection."),
    **_LOCAL_MFA_LOGIN_RESPONSES,
}


_LOCAL_TOKEN_MFA_LOGIN_RESPONSES = {
    HTTP_200_OK: ResponseSpec(TokenPair, description="A newly issued access and refresh token pair."),
    **_LOCAL_MFA_LOGIN_RESPONSES,
}


_LOCAL_REAUTHENTICATION_RESPONSES = {**_LOCAL_BAD_REQUEST_RESPONSES, **_LOCAL_AUTH_REQUIRED_RESPONSES}


def requires_local_bearer(connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler) -> None:
    """Require bearer evidence produced by the configured local JWT slot.

    Args:
        connection: The connection being authorized.
        _: The route handler, unused.

    Raises:
        NotAuthorizedException: If the connection carries no local bearer evidence.
    """
    context = connection.auth
    if not isinstance(context, SecurityContext) or not any(evidence.slot == "local" for evidence in context.evidence):
        raise NotAuthorizedException(detail="Authentication required")


def build_local_auth_routes(config: "LocalAuthConfig[Any]") -> Router:
    """Build one native Litestar route tree for an explicit local-auth profile.

    Which controllers are mounted follows the profile: session routes for a
    session or hybrid profile, token routes for a token or hybrid profile, and a
    registration route only when the policy allows one.

    Args:
        config: The configured profile the routes are built for.

    Returns:
        One router mounted at the profile's route prefix, with caching disabled
        and the shared service graph provided as a dependency.
    """

    def provide_local_auth_service() -> LocalAuthService[Any]:
        return config.local_auth_service

    route_handlers: list[type[Controller]] = [_LocalLifecycleController]
    mfa_login = config.mfa_login
    if config.mode in {LocalAuthMode.SESSION, LocalAuthMode.HYBRID}:
        route_handlers.extend((_LocalSessionController, _LocalSessionPasswordController))
        if mfa_login is not None:
            route_handlers.append(_LocalSessionMFAController)
    if config.mode in {LocalAuthMode.TOKENS, LocalAuthMode.HYBRID}:
        route_handlers.append(_LocalTokenController)
        if mfa_login is not None:
            route_handlers.append(_LocalTokenMFAController)
        if config.mode is LocalAuthMode.TOKENS:
            route_handlers.append(_LocalTokenOnlyPasswordController)
        else:
            route_handlers.append(_LocalTokenPasswordController)
    if config.registration.mode is RegistrationMode.PUBLIC:
        route_handlers.append(_LocalRegistrationController)
    elif config.registration.mode is RegistrationMode.INVITE_ONLY:
        route_handlers.append(_LocalInvitationRegistrationController)
    return Router(
        path=config.route_prefix,
        route_handlers=route_handlers,
        cache_control=CacheControlHeader(no_store=True),
        dependencies={"local_auth_service": Provide(provide_local_auth_service, sync_to_thread=False, use_cache=False)},
        response_headers={"Pragma": "no-cache"},
    )


def _route_response(content: RouteStatus, *, status_code: int) -> Response[RouteStatus]:
    return Response(content=content, status_code=status_code)


def _mfa_required_response(outcome: MFARequired) -> Response[LocalMFAChallenge]:
    """Project the internal challenge outcome onto its typed public 403 response."""
    return Response(
        content=LocalMFAChallenge(
            code=outcome.code,
            challenge=outcome.challenge,
            account_id=outcome.account_id,
            expires_at=outcome.expires_at,
            methods=tuple(sorted(outcome.methods)),
        ),
        status_code=HTTP_403_FORBIDDEN,
    )


def _route_error(outcome: object, *, credentials: bool = False) -> NoReturn:
    if isinstance(outcome, RateLimited):
        headers = {"Retry-After": str(outcome.retry_after)} if outcome.retry_after is not None else None
        raise TooManyRequestsException(detail="Too many requests.", headers=headers)
    if isinstance(outcome, VerificationUnavailable):
        raise ServiceUnavailableException(detail="Authentication service is unavailable.")
    if credentials:
        raise NotAuthorizedException(detail="Authentication required.")
    raise ClientException(detail="The request is invalid.")


def _principal_account_id(principal: Principal[Any]) -> str | None:
    return principal.id if principal.is_authenticated else None


class _LocalSessionController(Controller):
    path = "/"
    tags = (_SESSIONS_TAG,)

    @post(
        "/login",
        name="local.session.login",
        operation_id="LocalSessionLogin",
        summary="Session login",
        description=(
            "Verify a password and establish one native session. A rejected identifier and a rejected "
            "password are reported identically."
        ),
        response_description="The signed-in account projection.",
        status_code=HTTP_200_OK,
        responses=_LOCAL_SESSION_MFA_LOGIN_RESPONSES,
        auth=public(),
        csrf_required=True,
    )
    async def login(
        self,
        data: JSONBody[LocalCredentials],
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[LocalAccount | LocalMFAChallenge]:
        """Authenticate a password and establish one native session."""
        result = await local_auth_service.session_login(request, data)
        if isinstance(result, MFARequired):
            return cast("Response[LocalAccount | LocalMFAChallenge]", _mfa_required_response(result))
        if not isinstance(result, LocalAccount):
            _route_error(result)
        return Response(content=result, status_code=HTTP_200_OK)

    @post(
        "/logout",
        name="local.session.logout",
        operation_id="LocalSessionLogout",
        summary="Session logout",
        description="Revoke the caller's current session and clear its browser credentials.",
        response_description="The session was revoked.",
        status_code=HTTP_200_OK,
        responses=_LOCAL_AUTH_REQUIRED_RESPONSES,
        auth=required("session"),
    )
    async def logout(
        self,
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[RouteStatus]:
        """Revoke the caller's current session and clear browser authentication."""
        session_auth = local_auth_service.session_auth
        if session_auth is None:
            _route_error(VerificationUnavailable())
        result = await session_auth.logout(request)
        if isinstance(result, VerificationUnavailable):
            _route_error(result)
        return _route_response(RouteStatus(detail="Logged out."), status_code=HTTP_200_OK)

    @get(
        "/sessions",
        name="local.session.list",
        operation_id="LocalSessionList",
        summary="List sessions",
        description=(
            "List the caller's own active sessions, with the session used for this request flagged as "
            "current. A caller can never see another account's sessions."
        ),
        response_description="The caller's active sessions.",
        responses=_LOCAL_AUTH_REQUIRED_RESPONSES,
        auth=required("session"),
    )
    async def list_sessions(
        self,
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[LocalSessionList]:
        """List only the authenticated caller's safe session projections."""
        account_id = _principal_account_id(principal)
        session_auth = local_auth_service.session_auth
        if account_id is None or session_auth is None:
            _route_error(InvalidCredentials(), credentials=True)
        current = session_auth.current_authentication(request)
        try:
            sessions = await session_auth.list_sessions(
                account_id, current_session_id=current.session_id if current is not None else None
            )
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            _route_error(VerificationUnavailable())
        return Response(
            content=LocalSessionList(
                sessions=tuple(
                    LocalSession(
                        session_id=session.session_id,
                        current=session.current,
                        created_at=session.created_at,
                        last_seen_at=session.last_seen_at,
                        expires_at=session.expires_at,
                        display_metadata=dict(session.display_metadata),
                    )
                    for session in sessions
                )
            ),
            status_code=HTTP_200_OK,
        )

    @delete(
        "/sessions/{session_id:str}",
        name="local.session.revoke",
        operation_id="LocalSessionRevoke",
        summary="Revoke session",
        description=(
            "Revoke one of the caller's own sessions. Revoking a session the caller does not own is "
            "reported the same way as revoking one that does not exist."
        ),
        response_description="The session was revoked.",
        status_code=HTTP_200_OK,
        responses=_LOCAL_AUTH_REQUIRED_RESPONSES,
        auth=required("session"),
    )
    async def revoke_session(
        self,
        session_id: FromPath[str],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[RouteStatus]:
        """Revoke one session qualified by caller ownership."""
        account_id = _principal_account_id(principal)
        session_auth = local_auth_service.session_auth
        if account_id is None or session_auth is None:
            _route_error(InvalidCredentials(), credentials=True)
        result = await session_auth.revoke_session(request, account_id, session_id)
        if isinstance(result, VerificationUnavailable):
            _route_error(result)
        return _route_response(RouteStatus(detail="Session revoked."), status_code=HTTP_200_OK)


class _LocalSessionMFAController(Controller):
    """Complete MFA-gated native-session password logins."""

    path = "/"
    tags = (_SESSIONS_TAG,)

    @post(
        "/login/mfa",
        name="local.session.login.mfa",
        operation_id="LocalSessionMFALogin",
        summary="Complete session login MFA",
        description="Complete the one-time MFA challenge returned by session password login.",
        response_description="The signed-in account projection.",
        status_code=HTTP_200_OK,
        responses=_LOCAL_BAD_REQUEST_RESPONSES,
        auth=public(),
        csrf_required=True,
    )
    async def complete(
        self,
        data: JSONBody[LocalMFACompletion],
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[LocalAccount]:
        """Verify one challenge factor and establish the native session transport."""
        result = await local_auth_service.complete_mfa_login(
            request,
            data.challenge,
            account_id=data.account_id,
            method=data.method,
            method_id=data.method_id,
            code=data.code,
            transport="session",
        )
        if not isinstance(result, LocalAccount):
            _route_error(result)
        return Response(content=result, status_code=HTTP_200_OK)


class _LocalTokenController(Controller):
    path = "/"
    tags = (_TOKENS_TAG,)

    @post(
        "/token",
        name="local.token.login",
        operation_id="LocalTokenLogin",
        summary="Token login",
        description=(
            "Verify a password and issue an access and refresh token pair. This route shares its rate-limit "
            "budget with session login, so alternating between the two does not widen the allowance."
        ),
        response_description="A newly issued access and refresh token pair.",
        status_code=HTTP_200_OK,
        responses=_LOCAL_TOKEN_MFA_LOGIN_RESPONSES,
        auth=public(),
    )
    async def login(
        self,
        data: JSONBody[LocalCredentials],
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[TokenPair | LocalMFAChallenge]:
        """Authenticate a password and issue a local access/refresh pair."""
        result = await local_auth_service.token_login(request, data)
        if isinstance(result, MFARequired):
            return cast("Response[TokenPair | LocalMFAChallenge]", _mfa_required_response(result))
        if not isinstance(result, TokenPair):
            _route_error(result)
        return Response(content=result, status_code=HTTP_200_OK)

    @post(
        "/token/refresh",
        name="local.token.refresh",
        operation_id="LocalTokenRefresh",
        summary="Rotate refresh token",
        description=(
            "Exchange one opaque refresh token for a new pair. Rotation is strict: presenting a token that "
            "was already consumed revokes the whole family. Retry a lost response with the same "
            "`Idempotency-Key` to receive the original pair instead of tripping that reuse detection."
        ),
        response_description="A newly rotated access and refresh token pair.",
        status_code=HTTP_200_OK,
        responses=_LOCAL_BAD_REQUEST_RESPONSES,
        auth=public(),
    )
    async def refresh(
        self,
        data: JSONBody[LocalToken],
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
        idempotency_key: Annotated[str | None, HeaderParameter(name="Idempotency-Key")] = None,
    ) -> Response[TokenPair]:
        """Strictly rotate one opaque refresh token."""
        refresh_tokens = local_auth_service.refresh_tokens
        if refresh_tokens is None:
            _route_error(VerificationUnavailable())
        result = await refresh_tokens.rotate(
            data.token, idempotency_key=idempotency_key, client_key=local_auth_service.client_key_for(request)
        )
        if not isinstance(result, TokenPair):
            _route_error(result)
        return Response(content=result, status_code=HTTP_200_OK)

    @post(
        "/token/revoke",
        name="local.token.revoke",
        operation_id="LocalTokenRevoke",
        summary="Revoke refresh token",
        description=(
            "Revoke the presented refresh token and the rest of its family. The caller must hold a valid "
            "access token for the account that owns the token."
        ),
        response_description="The token family was revoked.",
        status_code=HTTP_200_OK,
        guards=(requires_local_bearer,),
        responses=_LOCAL_AUTH_REQUIRED_RESPONSES,
        auth=required("bearer"),
    )
    async def revoke(
        self,
        data: JSONBody[LocalToken],
        principal: NamedDependency[Principal[Any]],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[RouteStatus]:
        """Revoke the authenticated caller's presented local refresh family."""
        account_id = _principal_account_id(principal)
        refresh_tokens = local_auth_service.refresh_tokens
        if account_id is None or refresh_tokens is None:
            _route_error(InvalidCredentials(), credentials=True)
        result = await refresh_tokens.revoke_for_account(account_id, data.token)
        if isinstance(result, VerificationUnavailable):
            _route_error(result)
        return _route_response(RouteStatus(detail="Token revoked."), status_code=HTTP_200_OK)


class _LocalTokenMFAController(Controller):
    """Complete MFA-gated token password logins."""

    path = "/"
    tags = (_TOKENS_TAG,)

    @post(
        "/token/mfa",
        name="local.token.login.mfa",
        operation_id="LocalTokenMFALogin",
        summary="Complete token login MFA",
        description="Complete the one-time MFA challenge returned by token password login.",
        response_description="A newly issued access and refresh token pair.",
        status_code=HTTP_200_OK,
        responses=_LOCAL_BAD_REQUEST_RESPONSES,
        auth=public(),
    )
    async def complete(
        self,
        data: JSONBody[LocalMFACompletion],
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[TokenPair]:
        """Verify one challenge factor and issue the token transport."""
        result = await local_auth_service.complete_mfa_login(
            request,
            data.challenge,
            account_id=data.account_id,
            method=data.method,
            method_id=data.method_id,
            code=data.code,
            transport="tokens",
        )
        if not isinstance(result, TokenPair):
            _route_error(result)
        return Response(content=result, status_code=HTTP_200_OK)


class _LocalLifecycleController(Controller):
    # No controller tag: Litestar unions tags up the ownership chain, so one declared
    # here would widen every handler rather than let recovery and verification group
    # separately. Each handler owns its group instead.
    path = "/"

    @post(
        "/password/recovery",
        name="local.password.recovery",
        operation_id="LocalPasswordRecovery",
        summary="Request password recovery",
        description=(
            "Request a recovery token for an identifier. The response is identical whether or not the "
            "account exists, so it never confirms one."
        ),
        response_description="The request was accepted for processing.",
        status_code=HTTP_202_ACCEPTED,
        responses=_LOCAL_BAD_REQUEST_RESPONSES,
        tags=(_PASSWORDS_TAG,),
        auth=public(),
    )
    async def recovery(
        self,
        data: JSONBody[LocalIdentifier],
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[LifecycleAccepted]:
        """Return the common recovery-request response for every identifier."""
        result = await local_auth_service.recovery.request(
            data.identifier, client_key=local_auth_service.client_key_for(request)
        )
        if not isinstance(result, LifecycleAccepted):
            _route_error(result)
        return Response(content=result, status_code=HTTP_202_ACCEPTED)

    @post(
        "/password/reset",
        name="local.password.reset",
        operation_id="LocalPasswordReset",
        summary="Reset password",
        description=(
            "Consume one recovery token and replace the account password. The token is single-use, and a "
            "successful reset raises the account security epoch, invalidating every credential issued before it."
        ),
        response_description="The password was replaced.",
        status_code=HTTP_200_OK,
        responses=_LOCAL_BAD_REQUEST_RESPONSES,
        tags=(_PASSWORDS_TAG,),
        auth=public(),
    )
    async def reset(
        self,
        data: JSONBody[LocalPasswordReset],
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[RouteStatus]:
        """Consume one recovery token and replace its account password."""
        result = await local_auth_service.recovery.reset(
            data.token, data.password, client_key=local_auth_service.client_key_for(request)
        )
        if isinstance(result, PasswordResetOutcome) and result.status is PasswordResetStatus.RESET:
            return _route_response(RouteStatus(detail="Password reset complete."), status_code=HTTP_200_OK)
        _route_error(result)

    @post(
        "/verification",
        name="local.verification.resend",
        operation_id="LocalVerificationResend",
        summary="Request account verification",
        description=(
            "Request a verification token for an identifier. The response is identical whether or not the "
            "account exists or is already verified, so it never confirms one."
        ),
        response_description="The request was accepted for processing.",
        status_code=HTTP_202_ACCEPTED,
        responses=_LOCAL_BAD_REQUEST_RESPONSES,
        tags=(_VERIFICATION_TAG,),
        auth=public(),
    )
    async def verification(
        self,
        data: JSONBody[LocalIdentifier],
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[LifecycleAccepted]:
        """Return the common verification-request response for every identifier."""
        result = await local_auth_service.verification.resend(
            data.identifier, client_key=local_auth_service.client_key_for(request)
        )
        if not isinstance(result, LifecycleAccepted):
            _route_error(result)
        return Response(content=result, status_code=HTTP_202_ACCEPTED)

    @post(
        "/verification/confirm",
        name="local.verification.confirm",
        operation_id="LocalVerificationConfirm",
        summary="Confirm account verification",
        description="Consume one single-use verification token and mark its account verified.",
        response_description="The account was verified.",
        status_code=HTTP_200_OK,
        responses=_LOCAL_BAD_REQUEST_RESPONSES,
        tags=(_VERIFICATION_TAG,),
        auth=public(),
    )
    async def confirm_verification(
        self,
        data: JSONBody[LocalToken],
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[RouteStatus]:
        """Consume one account-verification token."""
        result = await local_auth_service.verification.consume(
            data.token, client_key=local_auth_service.client_key_for(request)
        )
        if isinstance(result, ConsumeOutcome) and result.status is ConsumeStatus.CONSUMED:
            return _route_response(RouteStatus(detail="Account verified."), status_code=HTTP_200_OK)
        _route_error(result)


class _LocalRegistrationController(Controller):
    path = "/"
    tags = (_REGISTRATION_TAG,)

    @post(
        "/register",
        name="local.registration",
        operation_id="LocalRegister",
        summary="Register",
        description=(
            "Create an account under the public registration policy. The response is identical whether or "
            "not the identifier was already taken, so it never confirms an existing account."
        ),
        response_description="The registration was accepted for processing.",
        status_code=HTTP_202_ACCEPTED,
        responses=_LOCAL_BAD_REQUEST_RESPONSES,
        auth=public(),
    )
    async def register(
        self,
        data: JSONBody[LocalRegistration],
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[LifecycleAccepted]:
        """Apply the configured public registration policy."""
        registration = local_auth_service.registration
        if registration is None:
            _route_error(LifecycleRejected())
        result = await registration.register(
            data.identifier,
            data.password,
            display_name=data.display_name,
            invitation_token=None,
            client_key=local_auth_service.client_key_for(request),
        )
        if isinstance(result, LifecycleAccepted):
            return Response(content=result, status_code=HTTP_202_ACCEPTED)
        _route_error(result)


class _LocalInvitationRegistrationController(Controller):
    path = "/"
    tags = (_REGISTRATION_TAG,)

    @post(
        "/register",
        name="local.registration",
        operation_id="LocalRegister",
        summary="Register with an invitation",
        description=(
            "Create an account with a single-use invitation token under the invite-only registration "
            "policy. The response is identical for a rejected token and a taken identifier."
        ),
        response_description="The registration was accepted for processing.",
        status_code=HTTP_202_ACCEPTED,
        responses=_LOCAL_BAD_REQUEST_RESPONSES,
        auth=public(),
    )
    async def register(
        self,
        data: JSONBody[LocalInvitationRegistration],
        request: Request[Any, Any, Any],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[LifecycleAccepted]:
        """Apply the configured invite-only registration policy."""
        registration = local_auth_service.registration
        if registration is None:
            _route_error(LifecycleRejected())
        result = await registration.register(
            data.identifier,
            data.password,
            display_name=data.display_name,
            invitation_token=data.invitation_token,
            client_key=local_auth_service.client_key_for(request),
        )
        if isinstance(result, LifecycleAccepted):
            return Response(content=result, status_code=HTTP_202_ACCEPTED)
        _route_error(result)


class _LocalSessionPasswordController(Controller):
    path = "/"
    tags = (_PASSWORDS_TAG,)

    @post(
        "/password/change",
        name="local.session.password.change",
        operation_id="LocalPasswordChange",
        summary="Change password",
        description=(
            "Replace the caller's password after re-verifying the current one. The caller's own session is "
            "rebound and stays usable; every other session and credential for the account is invalidated."
        ),
        response_description="The password was replaced.",
        status_code=HTTP_200_OK,
        responses=_LOCAL_REAUTHENTICATION_RESPONSES,
        auth=required("session"),
    )
    async def change(
        self,
        data: JSONBody[LocalPasswordChange],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[RouteStatus]:
        """Change the session caller's password and rebind its session."""
        account_id = _principal_account_id(principal)
        if account_id is None:
            _route_error(InvalidCredentials(), credentials=True)
        result = await local_auth_service.change_session_password(request, account_id, data)
        return _password_change_response(result)


class _LocalTokenPasswordController(Controller):
    path = "/"
    tags = (_PASSWORDS_TAG,)

    @post(
        "/token/password/change",
        name="local.token.password.change",
        operation_id="LocalTokenPasswordChange",
        summary="Change password (bearer)",
        description=(
            "Replace the password of the account named by the caller's access token, after re-verifying "
            "the current one. Every credential for the account, including the caller's own, is invalidated."
        ),
        response_description="The password was replaced.",
        status_code=HTTP_200_OK,
        guards=(requires_local_bearer,),
        responses=_LOCAL_REAUTHENTICATION_RESPONSES,
        auth=required("bearer"),
    )
    async def change(
        self,
        data: JSONBody[LocalPasswordChange],
        principal: NamedDependency[Principal[Any]],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[RouteStatus]:
        """Change the local bearer caller's password."""
        account_id = _principal_account_id(principal)
        if account_id is None:
            _route_error(InvalidCredentials(), credentials=True)
        result = await local_auth_service.change_token_password(account_id, data)
        return _password_change_response(result)


class _LocalTokenOnlyPasswordController(Controller):
    path = "/"
    tags = (_PASSWORDS_TAG,)

    # Token-only deployments have no session route to collide with, so password change
    # keeps the same path and operation id it has under a session profile.
    @post(
        "/password/change",
        name="local.token.password.change",
        operation_id="LocalPasswordChange",
        summary="Change password",
        description=(
            "Replace the password of the account named by the caller's access token, after re-verifying "
            "the current one. Every credential for the account, including the caller's own, is invalidated."
        ),
        response_description="The password was replaced.",
        status_code=HTTP_200_OK,
        guards=(requires_local_bearer,),
        responses=_LOCAL_REAUTHENTICATION_RESPONSES,
        auth=required("bearer"),
    )
    async def change(
        self,
        data: JSONBody[LocalPasswordChange],
        principal: NamedDependency[Principal[Any]],
        local_auth_service: NamedDependency[SkipValidation[LocalAuthService[Any]]],
    ) -> Response[RouteStatus]:
        """Change the local bearer caller's password."""
        account_id = _principal_account_id(principal)
        if account_id is None:
            _route_error(InvalidCredentials(), credentials=True)
        result = await local_auth_service.change_token_password(account_id, data)
        return _password_change_response(result)


def _password_change_response(result: object) -> Response[RouteStatus]:
    if isinstance(result, PasswordChangeOutcome) and result.status is PasswordChangeStatus.CHANGED:
        return _route_response(RouteStatus(detail="Password changed."), status_code=HTTP_200_OK)
    if isinstance(result, InvalidCredentials):
        _route_error(result)
    _route_error(result)
