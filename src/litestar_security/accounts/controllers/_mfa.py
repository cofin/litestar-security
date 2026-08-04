"""Native Litestar route bundle for MFA, passkeys, and step-up."""

from base64 import urlsafe_b64decode
from collections.abc import Callable
from dataclasses import dataclass
from secrets import token_urlsafe
from typing import Any, NoReturn, TypeVar

from litestar import Controller, Request, Response, Router, get, post
from litestar.connection import ASGIConnection
from litestar.datastructures import CacheControlHeader
from litestar.di import NamedDependency, Provide
from litestar.exceptions import NotAuthorizedException, ServiceUnavailableException, TooManyRequestsException
from litestar.openapi.datastructures import ResponseSpec
from litestar.params import FromPath, JSONBody, SkipValidation
from litestar.status_codes import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_409_CONFLICT,
    HTTP_429_TOO_MANY_REQUESTS,
    HTTP_503_SERVICE_UNAVAILABLE,
)

from litestar_security.accounts._auth_service import LocalAuthService
from litestar_security.accounts._mfa import MFAService, RecoveryCodeGrant, StepUpCredential, StepUpService
from litestar_security.accounts._operations import (
    MFA_RECOVERY_REPLACE,
    MFA_TOTP_ENROLL,
    MFA_TOTP_REMOVE,
    MFA_TOTP_VERIFY,
    PASSKEY_ASSERT,
    PASSKEY_AUTH_OPTIONS,
    PASSKEY_REGISTER_OPTIONS,
    PASSKEY_REGISTER_VERIFY,
    PASSKEY_REMOVE,
    PASSWORD_VERIFY,
)
from litestar_security.accounts._passkeys import PasskeyRecord, PasskeyService, WebAuthnOptions
from litestar_security.accounts._rate_limits import RateLimited, RateLimitGuard
from litestar_security.accounts._records import (
    PasswordReauthenticationProof,
    RevokeLoginMethodResult,
    RevokeLoginMethodStatus,
)
from litestar_security.accounts._stores import SecurityEpochStore
from litestar_security.accounts.schemas import (
    PasskeyAuthenticationOptionsRequest,
    PasskeyOptionsResponse,
    PasskeyRegistrationOptionsRequest,
    PasskeySummaryResponse,
    PasskeyVerifyRequest,
    RecoveryCodesResponse,
    RouteStatusResponse,
    StepUpAuthorizedRequest,
    StepUpRequest,
    StepUpResponse,
    TOTPEnrollmentRequest,
    TOTPEnrollmentResponse,
    TOTPVerificationRequest,
)
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable, optional, public, required
from litestar_security.context import AuthenticationEvidence, Principal

__all__ = ("build_mfa_routes",)

_MFA_TAG = "Multi-factor authentication"
_PASSKEY_TAG = "Passkeys"
_STEP_UP_TAG = "Step-up authentication"
# Every step-up purpose the controller consumes, mapped to the factors that may
# satisfy it. Deny-by-default: a purpose absent here is rejected (see issue()),
# never treated as "any factor allowed". Only password and passkey prove
# possession of a strong factor, so totp and recovery-code stay excluded. Keep
# in sync with the purpose literals passed to _consume_step_up.
_PURPOSE_METHODS = {
    "totp-enroll": frozenset({"password", "passkey"}),
    "totp-remove": frozenset({"password", "passkey"}),
    "recovery-codes": frozenset({"password", "passkey"}),
    "passkey-register": frozenset({"password", "passkey"}),
    "passkey-remove": frozenset({"password", "passkey"}),
}
ContentT = TypeVar("ContentT")


@dataclass(frozen=True, slots=True)
class _MFAFeatureService:
    mfa: MFAService | None
    passkeys: PasskeyService | None
    step_up: StepUpService
    epochs: SecurityEpochStore
    rate_limits: RateLimitGuard | None
    client_key: Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] | None
    local_auth: LocalAuthService[Any] | None


def build_mfa_routes(  # noqa: PLR0913 - explicit route bundle capabilities remain independently replaceable
    *,
    step_up: StepUpService,
    epochs: SecurityEpochStore,
    mfa: MFAService | None = None,
    passkeys: PasskeyService | None = None,
    rate_limits: RateLimitGuard | None = None,
    client_key: Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] | None = None,
    local_auth: LocalAuthService[Any] | None = None,
    session_capable: bool = False,
    token_capable: bool = False,
    route_prefix: str = "/auth",
) -> Router:
    """Build generated MFA and passkey routes around explicit services.

    Args:
        step_up: Purpose-bound grant service shared by every sensitive route.
        epochs: Authoritative security-epoch store.
        mfa: Optional TOTP and recovery-code service.
        passkeys: Optional WebAuthn service.
        rate_limits: Optional shared abuse-prevention hook.
        client_key: Trusted connection-to-client bucket derivation.
        local_auth: Local transport issuance services.
        session_capable: Whether passkey login may establish a browser session.
        token_capable: Whether passkey login may issue local access/refresh tokens.
        route_prefix: Absolute path under which the route bundle is mounted.

    Returns:
        One native Litestar router containing only enabled feature controllers.

    Raises:
        ValueError: If neither factor service is enabled.
    """
    if mfa is None and passkeys is None:
        message = "At least one MFA or passkey service must be enabled"
        raise ValueError(message)
    mfa_service = _MFAFeatureService(
        mfa=mfa,
        passkeys=passkeys,
        step_up=step_up,
        epochs=epochs,
        rate_limits=rate_limits,
        client_key=client_key,
        local_auth=local_auth,
    )
    handlers: list[type[Controller]] = [_StepUpController]
    if mfa is not None:
        handlers.append(_MFAController)
    if passkeys is not None:
        handlers.append(_PasskeyController)
        if session_capable and token_capable:
            handlers.extend((_PasskeyHybridSessionController, _PasskeyHybridTokenController))
        else:
            handlers.append(
                _PasskeySessionAuthenticationController if session_capable else _PasskeyTokenAuthenticationController
            )
    return Router(
        path=route_prefix,
        route_handlers=handlers,
        cache_control=CacheControlHeader(no_store=True),
        response_headers={"Pragma": "no-cache"},
        dependencies={"mfa_service": Provide(lambda: mfa_service, sync_to_thread=False, use_cache=False)},
    )


def _response(content: ContentT, status_code: int = HTTP_200_OK) -> Response[ContentT]:
    return Response(content=content, status_code=status_code)


def _error(outcome: object) -> NoReturn:
    if isinstance(outcome, RateLimited):
        headers = {"Retry-After": str(outcome.retry_after)} if outcome.retry_after is not None else None
        raise TooManyRequestsException(detail="Too many requests.", headers=headers)
    if isinstance(outcome, VerificationUnavailable):
        raise ServiceUnavailableException(detail="Authentication service is unavailable.")
    raise NotAuthorizedException(detail="Authentication required.")


def _principal_id(principal: Principal[Any]) -> str | None:
    return principal.id if principal.is_authenticated else None


def _transport_binding(request: Request[Any, Any, Any]) -> bytes:
    authorization = request.headers.get("authorization")
    cookies = request.headers.get("cookie")
    value = authorization or cookies
    return value.encode("utf-8") if value else b""


async def _current_epoch(mfa_service: _MFAFeatureService, account_id: str) -> int | VerificationUnavailable:
    try:
        epoch = await mfa_service.epochs.current_epoch(account_id)
    except Exception:  # noqa: BLE001 - application port failures become one safe route outcome
        return VerificationUnavailable()
    return epoch if isinstance(epoch, int) and not isinstance(epoch, bool) and epoch >= 0 else VerificationUnavailable()


async def _check_rate_limit(
    mfa_service: _MFAFeatureService, request: Request[Any, Any, Any], operation: str, account_id: str
) -> RateLimited | VerificationUnavailable | None:
    guard = mfa_service.rate_limits
    if guard is None:
        return None
    try:
        client_key = mfa_service.client_key(request) if mfa_service.client_key is not None else None
    except Exception:  # noqa: BLE001 - application callback failures degrade to the identifier bucket
        client_key = None
    return await guard.check(operation, client_key=client_key, identifier=account_id)


async def _consume_step_up(
    *, mfa_service: _MFAFeatureService, request: Request[Any, Any, Any], account_id: str, purpose: str, grant: str
) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
    epoch = await _current_epoch(mfa_service, account_id)
    if isinstance(epoch, VerificationUnavailable):
        return epoch
    return await mfa_service.step_up.consume(
        grant,
        principal_id=account_id,
        security_epoch=epoch,
        purpose=purpose,
        transport_binding=_transport_binding(request),
    )


_MFA_BAD_REQUEST_RESPONSES = {
    HTTP_400_BAD_REQUEST: ResponseSpec(RouteStatusResponse, description="The request is invalid."),
    HTTP_401_UNAUTHORIZED: ResponseSpec(RouteStatusResponse, description="Authentication or step-up is required."),
    HTTP_429_TOO_MANY_REQUESTS: ResponseSpec(RouteStatusResponse, description="The operation exceeded its rate limit."),
    HTTP_503_SERVICE_UNAVAILABLE: ResponseSpec(RouteStatusResponse, description="The factor service is unavailable."),
}


_MFA_CONFLICT_RESPONSES = {
    **_MFA_BAD_REQUEST_RESPONSES,
    HTTP_409_CONFLICT: ResponseSpec(RouteStatusResponse, description="The change would remove the final login method."),
}


class _StepUpController(Controller):
    tags = (_STEP_UP_TAG,)

    @post(
        "/step-up/{purpose:str}",
        name="security.step_up",
        operation_id="SecurityStepUp",
        summary="Obtain a step-up grant",
        description=(
            "Present a configured factor to obtain one short-lived grant bound to this exact purpose, "
            "the caller's current security epoch, and the current transport. A grant for one purpose "
            "cannot authorize another."
        ),
        response_description="The reveal-once grant and its expiry.",
        status_code=HTTP_200_OK,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=required(),
    )
    async def issue(
        self,
        purpose: FromPath[str],
        data: JSONBody[StepUpRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[StepUpResponse]:
        """Verify one factor and issue a purpose-bound grant."""
        account_id = _principal_id(principal)
        if account_id is None:  # pragma: no cover - required authentication rejects anonymous requests first
            _error(InvalidCredentials())
        allowed_methods = _PURPOSE_METHODS.get(purpose)
        if allowed_methods is None or data.method not in allowed_methods:
            _error(InvalidCredentials())
        operation = PASSWORD_VERIFY if data.method == "password" else PASSKEY_ASSERT
        limited = await _check_rate_limit(mfa_service, request, operation, account_id)
        if limited is not None:
            _error(limited)
        evidence = await self._verify_factor(account_id, data, request, mfa_service)
        if not isinstance(evidence, AuthenticationEvidence):
            _error(evidence)
        epoch = await _current_epoch(mfa_service, account_id)
        if isinstance(epoch, VerificationUnavailable):
            _error(epoch)
        grant = await mfa_service.step_up.issue(
            principal_id=account_id,
            security_epoch=epoch,
            purpose=purpose,
            transport_binding=_transport_binding(request),
            evidence=evidence,
        )
        if not isinstance(grant, StepUpCredential):
            _error(grant)
        return _response(StepUpResponse(grant=grant.token, purpose=grant.purpose, expires_at=grant.expires_at))

    @staticmethod
    async def _verify_factor(
        account_id: str, data: StepUpRequest, request: Request[Any, Any, Any], mfa_service: _MFAFeatureService
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        if data.method == "password" and mfa_service.local_auth is not None:
            proof = await mfa_service.local_auth.password_reauthentication.verify(account_id, data.credential)
            if not isinstance(proof, PasswordReauthenticationProof):
                return proof
            return AuthenticationEvidence(
                mechanism="password",
                slot="mfa",
                authenticated_at=proof.authenticated_at,
                expires_at=proof.expires_at,
                methods=frozenset({"password"}),
                amr=("pwd",),
            )
        if data.method == "passkey" and mfa_service.passkeys is not None:
            return await mfa_service.passkeys.verify_authentication(
                account_id, binding=_transport_binding(request), response=data.credential
            )
        return InvalidCredentials()


class _MFAController(Controller):
    tags = (_MFA_TAG,)

    @post(
        "/mfa/totp/enroll",
        name="mfa.totp.enroll",
        operation_id="MFAEnrollTOTP",
        summary="Begin TOTP enrollment",
        description=(
            "Create one pending TOTP enrollment and reveal its provisioning URI exactly once. The factor "
            "is not usable until it is verified."
        ),
        response_description="The reveal-once provisioning URI and its expiry.",
        status_code=HTTP_201_CREATED,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=required(),
    )
    async def enroll_totp(
        self,
        data: JSONBody[TOTPEnrollmentRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[TOTPEnrollmentResponse]:
        """Begin TOTP enrollment after consuming exact step-up."""
        account_id = _principal_id(principal)
        totp_service = mfa_service.mfa
        if (
            account_id is None or totp_service is None
        ):  # pragma: no cover - controller registration and auth guarantee both
            _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_service, request, MFA_TOTP_ENROLL, account_id)
        if limited is not None:
            _error(limited)
        assurance = await _consume_step_up(
            mfa_service=mfa_service,
            request=request,
            account_id=account_id,
            purpose="totp-enroll",
            grant=data.step_up_grant,
        )
        if not isinstance(assurance, AuthenticationEvidence):
            _error(assurance)
        result = await totp_service.begin_totp_enrollment(account_id, label=data.label)
        if isinstance(result, VerificationUnavailable):
            _error(result)
        return _response(
            TOTPEnrollmentResponse(
                enrollment_id=result.enrollment_id,
                method_id=result.method_id,
                provisioning_uri=result.provisioning_uri,
                expires_at=result.expires_at,
            ),
            HTTP_201_CREATED,
        )

    @post(
        "/mfa/totp/verify",
        name="mfa.totp.verify",
        operation_id="MFAVerifyTOTPEnrollment",
        summary="Activate TOTP enrollment",
        description=(
            "Activate one pending enrollment by presenting a current code. Activating the first factor "
            "reveals the caller's recovery codes once."
        ),
        response_description="The reveal-once recovery-code set.",
        status_code=HTTP_200_OK,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=required(),
    )
    async def verify_totp(
        self,
        data: JSONBody[TOTPVerificationRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[RecoveryCodesResponse]:
        """Activate TOTP and return a recovery-code set once."""
        account_id = _principal_id(principal)
        totp_service = mfa_service.mfa
        if (
            account_id is None or totp_service is None
        ):  # pragma: no cover - controller registration and auth guarantee both
            _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_service, request, MFA_TOTP_VERIFY, account_id)
        if limited is not None:
            _error(limited)
        recovery = await totp_service.activate_totp_with_recovery_codes(account_id, data.enrollment_id, data.code)
        if not isinstance(recovery, RecoveryCodeGrant):
            _error(recovery)
        return _response(RecoveryCodesResponse(codes=recovery.codes))

    @post(
        "/mfa/totp/{method_id:str}/remove",
        name="mfa.totp.remove",
        operation_id="MFARemoveTOTP",
        summary="Remove a TOTP factor",
        description=(
            "Remove one TOTP factor after exact step-up. A removal that would leave the account with no "
            "login method is refused."
        ),
        response_description="The removal outcome.",
        status_code=HTTP_200_OK,
        responses=_MFA_CONFLICT_RESPONSES,
        auth=required(),
    )
    async def remove_totp(
        self,
        method_id: FromPath[str],
        data: JSONBody[StepUpAuthorizedRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[RouteStatusResponse]:
        """Remove TOTP through exact step-up and final-method protection."""
        account_id = _principal_id(principal)
        totp_service = mfa_service.mfa
        if (
            account_id is None or totp_service is None
        ):  # pragma: no cover - controller registration and auth guarantee both
            _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_service, request, MFA_TOTP_REMOVE, account_id)
        if limited is not None:
            _error(limited)
        assurance = await _consume_step_up(
            mfa_service=mfa_service,
            request=request,
            account_id=account_id,
            purpose="totp-remove",
            grant=data.step_up_grant,
        )
        if not isinstance(assurance, AuthenticationEvidence):
            _error(assurance)
        result = await totp_service.remove_totp_method(account_id, method_id)
        return _removal_response(result)

    @post(
        "/mfa/recovery-codes",
        name="mfa.recovery_codes.replace",
        operation_id="MFAReplaceRecoveryCodes",
        summary="Replace recovery codes",
        description=(
            "Invalidate the caller's existing recovery codes and reveal a replacement set exactly once. "
            "The previous set stops working immediately."
        ),
        response_description="The reveal-once replacement code set.",
        status_code=HTTP_200_OK,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=required(),
    )
    async def recovery_codes(
        self,
        data: JSONBody[StepUpAuthorizedRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[RecoveryCodesResponse]:
        """Replace recovery codes after exact step-up."""
        account_id = _principal_id(principal)
        totp_service = mfa_service.mfa
        if (
            account_id is None or totp_service is None
        ):  # pragma: no cover - controller registration and auth guarantee both
            _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_service, request, MFA_RECOVERY_REPLACE, account_id)
        if limited is not None:
            _error(limited)
        assurance = await _consume_step_up(
            mfa_service=mfa_service,
            request=request,
            account_id=account_id,
            purpose="recovery-codes",
            grant=data.step_up_grant,
        )
        if not isinstance(assurance, AuthenticationEvidence):
            _error(assurance)
        result = await totp_service.generate_recovery_codes(account_id)
        if not isinstance(result, RecoveryCodeGrant):
            _error(result)
        return _response(RecoveryCodesResponse(codes=result.codes))


class _PasskeyController(Controller):
    tags = (_PASSKEY_TAG,)

    @post(
        "/passkeys/registration/options",
        name="passkey.registration.options",
        operation_id="PasskeyRegistrationOptions",
        summary="Request passkey registration options",
        description=(
            "Return bound WebAuthn registration options after exact step-up. The reveal-once binding "
            "returned alongside them must be presented unchanged to the verification route."
        ),
        response_description="The WebAuthn options and their reveal-once binding.",
        status_code=HTTP_200_OK,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=required(),
    )
    async def registration_options(
        self,
        data: JSONBody[PasskeyRegistrationOptionsRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[PasskeyOptionsResponse]:
        """Create registration options after exact step-up."""
        account_id = _principal_id(principal)
        passkey_service = mfa_service.passkeys
        if (
            account_id is None or passkey_service is None
        ):  # pragma: no cover - controller registration and auth guarantee both
            _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_service, request, PASSKEY_REGISTER_OPTIONS, account_id)
        if limited is not None:
            _error(limited)
        assurance = await _consume_step_up(
            mfa_service=mfa_service,
            request=request,
            account_id=account_id,
            purpose="passkey-register",
            grant=data.step_up_grant,
        )
        if not isinstance(assurance, AuthenticationEvidence):
            _error(assurance)
        result = await passkey_service.begin_registration(
            account_id, user_name=data.user_name, binding=_transport_binding(request)
        )
        return _options_response(result)

    @post(
        "/passkeys/registration/verify",
        name="passkey.registration.verify",
        operation_id="PasskeyRegistrationVerify",
        summary="Register a passkey",
        description="Complete one registration ceremony and store the credential against the caller's account.",
        response_description="The registration outcome.",
        status_code=HTTP_201_CREATED,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=required(),
    )
    async def registration_verify(
        self,
        data: JSONBody[PasskeyVerifyRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[RouteStatusResponse]:
        """Verify and store one passkey registration."""
        account_id = _principal_id(principal)
        passkey_service = mfa_service.passkeys
        if account_id is None or passkey_service is None or data.account_id != account_id:
            _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_service, request, PASSKEY_REGISTER_VERIFY, account_id)
        if limited is not None:
            _error(limited)
        result = await passkey_service.verify_registration(
            account_id, binding=_transport_binding(request), response=data.response
        )
        if not hasattr(result, "credential_id"):
            _error(result)
        return _response(RouteStatusResponse(detail="Passkey registered."), HTTP_201_CREATED)

    @post(
        "/passkeys/authentication/options",
        name="passkey.authentication.options",
        operation_id="PasskeyAuthenticationOptions",
        summary="Request passkey authentication options",
        description=(
            "Return WebAuthn authentication options and a reveal-once binding. The binding lets the public "
            "verification route complete the ceremony without relying on an existing cookie or token."
        ),
        response_description="The WebAuthn options and their reveal-once binding.",
        status_code=HTTP_200_OK,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=optional(required()),
    )
    async def authentication_options(
        self,
        data: JSONBody[PasskeyAuthenticationOptionsRequest],
        request: Request[Any, Any, Any],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[PasskeyOptionsResponse]:
        """Create public account-bound assertion options."""
        passkey_service = mfa_service.passkeys
        if passkey_service is None:  # pragma: no cover - this controller is registered only with a passkey service
            _error(VerificationUnavailable())
        limited = await _check_rate_limit(mfa_service, request, PASSKEY_AUTH_OPTIONS, data.account_id)
        if limited is not None:
            _error(limited)
        binding = token_urlsafe(32)
        result = await passkey_service.begin_authentication(data.account_id, binding=binding.encode("ascii"))
        return _options_response(result, binding=binding)

    @get(
        "/passkeys",
        name="passkey.list",
        operation_id="PasskeyList",
        summary="List registered passkeys",
        description="List only the caller's own credential metadata; no public key or challenge material is returned.",
        response_description="The caller's own registered credentials.",
        status_code=HTTP_200_OK,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=required(),
    )
    async def list_passkeys(
        self,
        principal: NamedDependency[Principal[Any]],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[tuple[PasskeySummaryResponse, ...]]:
        """List only caller-owned safe credential metadata."""
        account_id = _principal_id(principal)
        passkey_service = mfa_service.passkeys
        if (
            account_id is None or passkey_service is None
        ):  # pragma: no cover - controller registration and auth guarantee both
            _error(InvalidCredentials())
        result = await passkey_service.list_credentials(account_id)
        if isinstance(result, VerificationUnavailable):
            _error(result)
        return _response(tuple(_summary_response(summary) for summary in result))

    @post(
        "/passkeys/{credential_id:str}/remove",
        name="passkey.remove",
        operation_id="PasskeyRemove",
        summary="Remove a passkey",
        description=(
            "Remove one of the caller's own credentials after exact step-up. A removal that would leave the "
            "account with no login method is refused."
        ),
        response_description="The removal outcome.",
        status_code=HTTP_200_OK,
        responses=_MFA_CONFLICT_RESPONSES,
        auth=required(),
    )
    async def remove_passkey(
        self,
        credential_id: FromPath[str],
        data: JSONBody[StepUpAuthorizedRequest],
        request: Request[Any, Any, Any],
        principal: NamedDependency[Principal[Any]],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[RouteStatusResponse]:
        """Remove a passkey through exact step-up and final-method protection."""
        account_id = _principal_id(principal)
        passkey_service = mfa_service.passkeys
        if (
            account_id is None or passkey_service is None
        ):  # pragma: no cover - controller registration and auth guarantee both
            _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_service, request, PASSKEY_REMOVE, account_id)
        if limited is not None:
            _error(limited)
        assurance = await _consume_step_up(
            mfa_service=mfa_service,
            request=request,
            account_id=account_id,
            purpose="passkey-remove",
            grant=data.step_up_grant,
        )
        if not isinstance(assurance, AuthenticationEvidence):
            _error(assurance)
        try:
            raw_id = urlsafe_b64decode(credential_id + "=" * (-len(credential_id) % 4))
        except (ValueError, TypeError):
            return _response(RouteStatusResponse(detail="The request is invalid."), HTTP_400_BAD_REQUEST)
        result = await passkey_service.remove_credential(account_id, raw_id)
        return _removal_response(result)


class _PasskeySessionAuthenticationController(Controller):
    tags = (_PASSKEY_TAG,)

    @post(
        "/passkeys/authentication/verify",
        name="passkey.authentication.session.verify",
        operation_id="PasskeyAuthenticationVerify",
        summary="Verify a passkey (session)",
        description=(
            "Complete one authentication ceremony and establish a browser session. "
            "The route enforces CSRF because it establishes a cookie-backed transport."
        ),
        response_description="The established local transport.",
        status_code=HTTP_200_OK,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=public(),
        csrf_required=True,
    )
    async def authentication_verify(
        self,
        data: JSONBody[PasskeyVerifyRequest],
        request: Request[Any, Any, Any],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[Any]:
        """Verify an assertion and establish a CSRF-protected local transport."""
        return await _verify_passkey_authentication(  # pragma: no cover - covered shared handler
            data, request, mfa_service
        )


class _PasskeyTokenAuthenticationController(Controller):
    tags = (_PASSKEY_TAG,)

    @post(
        "/passkeys/authentication/verify",
        name="passkey.authentication.tokens.verify",
        operation_id="PasskeyAuthenticationVerify",
        summary="Verify a passkey (tokens)",
        description=(
            "Complete one authentication ceremony and issue a local access and refresh "
            "pair. No browser CSRF cookie is required because no cookie transport is established."
        ),
        response_description="The established local transport.",
        status_code=HTTP_200_OK,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=public(),
    )
    async def authentication_verify(
        self,
        data: JSONBody[PasskeyVerifyRequest],
        request: Request[Any, Any, Any],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[Any]:
        """Verify an assertion and establish a token-only local transport."""
        return await _verify_passkey_authentication(data, request, mfa_service)


class _PasskeyHybridSessionController(Controller):
    tags = (_PASSKEY_TAG,)

    @post(
        "/passkeys/authentication/session/verify",
        name="passkey.authentication.hybrid.session.verify",
        operation_id="PasskeySessionAuthenticationVerify",
        summary="Verify a passkey for a session",
        description=(
            "Complete one authentication ceremony and establish the hybrid profile's session "
            "transport. CSRF policy is fixed by this route rather than selected by an untrusted request field."
        ),
        response_description="The established local transport.",
        status_code=HTTP_200_OK,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=public(),
        csrf_required=True,
    )
    async def authentication_verify(
        self,
        data: JSONBody[PasskeyVerifyRequest],
        request: Request[Any, Any, Any],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[Any]:
        """Verify an assertion and establish the hybrid profile's session transport."""
        return await _verify_passkey_authentication(  # pragma: no cover - covered shared handler
            data, request, mfa_service, transport="session"
        )


class _PasskeyHybridTokenController(Controller):
    tags = (_PASSKEY_TAG,)

    @post(
        "/passkeys/authentication/tokens/verify",
        name="passkey.authentication.hybrid.tokens.verify",
        operation_id="PasskeyTokenAuthenticationVerify",
        summary="Verify a passkey for tokens",
        description=(
            "Complete one authentication ceremony and issue the hybrid profile's local token pair. "
            "CSRF policy is fixed by this route rather than selected by an untrusted request field."
        ),
        response_description="The established local transport.",
        status_code=HTTP_200_OK,
        responses=_MFA_BAD_REQUEST_RESPONSES,
        auth=public(),
    )
    async def authentication_verify(
        self,
        data: JSONBody[PasskeyVerifyRequest],
        request: Request[Any, Any, Any],
        mfa_service: NamedDependency[SkipValidation[_MFAFeatureService]],
    ) -> Response[Any]:
        """Verify an assertion and establish the hybrid profile's token transport."""
        return await _verify_passkey_authentication(  # pragma: no cover - covered shared handler
            data, request, mfa_service, transport="tokens"
        )


async def _verify_passkey_authentication(
    data: PasskeyVerifyRequest,
    request: Request[Any, Any, Any],
    mfa_service: _MFAFeatureService,
    *,
    transport: str | None = None,
) -> Response[Any]:
    passkey_service = mfa_service.passkeys
    local_auth_service = mfa_service.local_auth
    if (
        passkey_service is None or local_auth_service is None
    ):  # pragma: no cover - plugin validates both before route registration
        _error(VerificationUnavailable())
    limited = await _check_rate_limit(mfa_service, request, PASSKEY_ASSERT, data.account_id)
    if limited is not None:
        _error(limited)
    if data.binding is None:
        _error(InvalidCredentials())
    evidence = await passkey_service.verify_authentication(
        data.account_id, binding=data.binding.encode("utf-8"), response=data.response
    )
    if not isinstance(evidence, AuthenticationEvidence):
        _error(evidence)
    selected_transport = transport if transport is not None else data.transport
    result = await local_auth_service.passkey_login(
        request, data.account_id, transport=selected_transport, evidence=evidence
    )
    if isinstance(result, (InvalidCredentials, VerificationUnavailable)):
        _error(result)
    return _response(result)


def _options_response(
    result: WebAuthnOptions | VerificationUnavailable, *, binding: str | None = None
) -> Response[Any]:
    if isinstance(result, VerificationUnavailable):
        _error(result)
    return _response(PasskeyOptionsResponse(options=result.json, expires_at=result.expires_at, binding=binding))


def _summary_response(summary: PasskeyRecord) -> PasskeySummaryResponse:
    return PasskeySummaryResponse(
        credential_id=summary.credential_id,
        display_name=summary.display_name,
        created_at=summary.created_at,
        last_used_at=summary.last_used_at,
        backup_eligible=summary.backup_eligible,
        backup_state=summary.backup_state,
        suspect=summary.suspect,
    )


def _removal_response(result: RevokeLoginMethodResult | VerificationUnavailable) -> Response[RouteStatusResponse]:
    if isinstance(result, VerificationUnavailable):
        _error(result)
    if result.status is RevokeLoginMethodStatus.REVOKED:
        return _response(RouteStatusResponse(detail="Login method removed."))
    if result.status is RevokeLoginMethodStatus.FINAL_METHOD:
        return _response(RouteStatusResponse(detail="At least one viable login method is required."), HTTP_409_CONFLICT)
    return _response(RouteStatusResponse(detail="The request is invalid."), HTTP_400_BAD_REQUEST)
