"""Native Litestar route bundle for MFA, passkeys, and step-up."""

from base64 import urlsafe_b64decode
from collections.abc import Callable
from dataclasses import dataclass
from secrets import token_urlsafe
from typing import Any, TypeVar

from litestar import Controller, Request, Response, Router, delete, get, post
from litestar.connection import ASGIConnection
from litestar.datastructures import CacheControlHeader
from litestar.di import NamedDependency, Provide
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

from litestar_security.accounts._mfa import MFAService, RecoveryCodes, StepUpGrant, StepUpService
from litestar_security.accounts._mfa_schemas import (
    MFAStatusResponse,
    PasskeyAuthenticationOptionsRequest,
    PasskeyOptionsResponse,
    PasskeyRegistrationOptionsRequest,
    PasskeySummaryResponse,
    PasskeyVerifyRequest,
    RecoveryCodesRequest,
    RecoveryCodesResponse,
    StepUpRequest,
    StepUpResponse,
    TOTPEnrollmentRequest,
    TOTPEnrollmentResponse,
    TOTPVerificationRequest,
)
from litestar_security.accounts._operations import (
    MFA_RECOVERY_CONSUME,
    MFA_RECOVERY_REPLACE,
    MFA_TOTP_ENROLL,
    MFA_TOTP_VERIFY,
    PASSKEY_ASSERT,
    PASSKEY_AUTH_OPTIONS,
    PASSKEY_REGISTER_OPTIONS,
    PASSKEY_REGISTER_VERIFY,
    PASSWORD_VERIFY,
)
from litestar_security.accounts._passkeys import PasskeyService, PasskeySummary, WebAuthnOptions
from litestar_security.accounts._profiles import LocalAuthServices
from litestar_security.accounts._rate_limits import RateLimited, RateLimitGuard
from litestar_security.accounts._records import (
    PasswordReauthenticationProof,
    RevokeLoginMethodResult,
    RevokeLoginMethodStatus,
)
from litestar_security.accounts._stores import SecurityEpochStore
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable, optional, public, required
from litestar_security.context import AuthenticationEvidence, Principal

__all__ = ("build_mfa_routes",)

_MFA_TAG = "Multi-factor authentication"
_PASSKEY_TAG = "Passkeys"
_STEP_UP_TAG = "Step-up authentication"
_PURPOSE_METHODS = {
    "totp-enroll": frozenset({"password", "passkey"}),
    "recovery-codes": frozenset({"password", "passkey"}),
}
ContentT = TypeVar("ContentT")


@dataclass(frozen=True, slots=True)
class _MFAFeatureServices:
    mfa: MFAService | None
    passkeys: PasskeyService | None
    step_up: StepUpService
    epochs: SecurityEpochStore
    rate_limits: RateLimitGuard | None
    client_key: Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] | None
    local_auth: LocalAuthServices[Any] | None


_ServicesDependency = NamedDependency[SkipValidation[_MFAFeatureServices]]
_PrincipalDependency = NamedDependency[Principal[Any]]


def build_mfa_routes(  # noqa: PLR0913 - explicit route bundle capabilities remain independently replaceable
    *,
    step_up: StepUpService,
    epochs: SecurityEpochStore,
    mfa: MFAService | None = None,
    passkeys: PasskeyService | None = None,
    rate_limits: RateLimitGuard | None = None,
    client_key: Callable[[ASGIConnection[Any, Any, Any, Any]], str | None] | None = None,
    local_auth: LocalAuthServices[Any] | None = None,
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
    services = _MFAFeatureServices(
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
        dependencies={"mfa_feature_services": Provide(lambda: services, sync_to_thread=False, use_cache=False)},
    )


def _response(content: ContentT, status_code: int = HTTP_200_OK) -> Response[ContentT]:
    return Response(content=content, status_code=status_code)


def _error(outcome: object) -> Response[Any]:
    if isinstance(outcome, RateLimited):
        response = _response(MFAStatusResponse(detail="Too many requests."), HTTP_429_TOO_MANY_REQUESTS)
        if outcome.retry_after is not None:
            response.headers["Retry-After"] = str(outcome.retry_after)
        return response
    if isinstance(outcome, VerificationUnavailable):
        return _response(
            MFAStatusResponse(detail="Authentication service is unavailable."), HTTP_503_SERVICE_UNAVAILABLE
        )
    return _response(MFAStatusResponse(detail="Authentication required."), HTTP_401_UNAUTHORIZED)


def _principal_id(principal: Principal[Any]) -> str | None:
    return principal.id if principal.is_authenticated else None


def _transport_binding(request: Request[Any, Any, Any]) -> bytes:
    authorization = request.headers.get("authorization")
    cookies = request.headers.get("cookie")
    value = authorization or cookies
    return value.encode("utf-8") if value else b""


async def _current_epoch(services: _MFAFeatureServices, account_id: str) -> int | VerificationUnavailable:
    try:
        epoch = await services.epochs.current_epoch(account_id)
    except Exception:  # noqa: BLE001 - application port failures become one safe route outcome
        return VerificationUnavailable()
    return epoch if isinstance(epoch, int) and not isinstance(epoch, bool) and epoch >= 0 else VerificationUnavailable()


async def _check_rate_limit(
    services: _MFAFeatureServices, request: Request[Any, Any, Any], operation: str, account_id: str
) -> RateLimited | VerificationUnavailable | None:
    guard = services.rate_limits
    if guard is None:
        return None
    try:
        client_key = services.client_key(request) if services.client_key is not None else None
    except Exception:  # noqa: BLE001 - application callback failures degrade to the identifier bucket
        client_key = None
    return await guard.check(operation, client_key=client_key, identifier=account_id)


async def _consume_step_up(
    *, services: _MFAFeatureServices, request: Request[Any, Any, Any], account_id: str, purpose: str, grant: str
) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
    epoch = await _current_epoch(services, account_id)
    if isinstance(epoch, VerificationUnavailable):
        return epoch
    return await services.step_up.consume(
        grant,
        principal_id=account_id,
        security_epoch=epoch,
        purpose=purpose,
        transport_binding=_transport_binding(request),
    )


class _StepUpController(Controller):
    tags = (_STEP_UP_TAG,)

    @post("/step-up/{purpose:str}", operation_id="SecurityStepUp", status_code=HTTP_200_OK, auth=required())
    async def issue(  # noqa: PLR0911 - each authentication boundary has one explicit safe outcome
        self,
        purpose: FromPath[str],
        data: JSONBody[StepUpRequest],
        request: Request[Any, Any, Any],
        principal: _PrincipalDependency,
        mfa_feature_services: _ServicesDependency,
    ) -> Response[StepUpResponse | MFAStatusResponse]:
        """Verify one factor and issue a purpose-bound grant."""
        account_id = _principal_id(principal)
        if account_id is None:  # pragma: no cover - required authentication rejects anonymous requests first
            return _error(InvalidCredentials())
        allowed_methods = _PURPOSE_METHODS.get(purpose)
        if allowed_methods is not None and data.method not in allowed_methods:
            return _error(InvalidCredentials())
        operation = {
            "password": PASSWORD_VERIFY,
            "totp": MFA_TOTP_VERIFY,
            "recovery-code": MFA_RECOVERY_CONSUME,
            "passkey": PASSKEY_ASSERT,
        }.get(data.method, MFA_TOTP_VERIFY)
        limited = await _check_rate_limit(mfa_feature_services, request, operation, account_id)
        if limited is not None:
            return _error(limited)
        evidence = await self._verify_factor(account_id, data, request, mfa_feature_services)
        if not isinstance(evidence, AuthenticationEvidence):
            return _error(evidence)
        epoch = await _current_epoch(mfa_feature_services, account_id)
        if isinstance(epoch, VerificationUnavailable):
            return _error(epoch)
        grant = await mfa_feature_services.step_up.issue(
            principal_id=account_id,
            security_epoch=epoch,
            purpose=purpose,
            transport_binding=_transport_binding(request),
            evidence=evidence,
        )
        if not isinstance(grant, StepUpGrant):
            return _error(grant)
        return _response(StepUpResponse(grant=grant.token, purpose=grant.purpose, expires_at=grant.expires_at))

    @staticmethod
    async def _verify_factor(
        account_id: str, data: StepUpRequest, request: Request[Any, Any, Any], services: _MFAFeatureServices
    ) -> AuthenticationEvidence | InvalidCredentials | VerificationUnavailable:
        if data.method == "password" and services.local_auth is not None:
            proof = await services.local_auth.password_reauthentication.verify(account_id, data.credential)
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
        if data.method == "totp" and data.method_id is not None and services.mfa is not None:
            return await services.mfa.verify_totp(account_id, data.method_id, data.credential)
        if data.method == "recovery-code" and services.mfa is not None:
            return await services.mfa.consume_recovery_code(account_id, data.credential)
        if data.method == "passkey" and services.passkeys is not None:
            return await services.passkeys.verify_authentication(
                account_id, binding=_transport_binding(request), response=data.credential
            )
        return InvalidCredentials()


class _MFAController(Controller):
    tags = (_MFA_TAG,)

    @post("/mfa/totp/enroll", operation_id="MFAEnrollTOTP", auth=required())
    async def enroll_totp(
        self,
        data: JSONBody[TOTPEnrollmentRequest],
        request: Request[Any, Any, Any],
        principal: _PrincipalDependency,
        mfa_feature_services: _ServicesDependency,
    ) -> Response[TOTPEnrollmentResponse | MFAStatusResponse]:
        """Begin TOTP enrollment after consuming exact step-up."""
        account_id = _principal_id(principal)
        service = mfa_feature_services.mfa
        if account_id is None or service is None:  # pragma: no cover - controller registration and auth guarantee both
            return _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_feature_services, request, MFA_TOTP_ENROLL, account_id)
        if limited is not None:
            return _error(limited)
        assurance = await _consume_step_up(
            services=mfa_feature_services,
            request=request,
            account_id=account_id,
            purpose="totp-enroll",
            grant=data.step_up_grant,
        )
        if not isinstance(assurance, AuthenticationEvidence):
            return _error(assurance)
        result = await service.begin_totp_enrollment(account_id, label=data.label)
        if isinstance(result, VerificationUnavailable):
            return _error(result)
        return _response(
            TOTPEnrollmentResponse(
                enrollment_id=result.enrollment_id,
                method_id=result.method_id,
                provisioning_uri=result.provisioning_uri,
                expires_at=result.expires_at,
            ),
            HTTP_201_CREATED,
        )

    @post("/mfa/totp/verify", operation_id="MFAVerifyTOTPEnrollment", auth=required())
    async def verify_totp(
        self,
        data: JSONBody[TOTPVerificationRequest],
        request: Request[Any, Any, Any],
        principal: _PrincipalDependency,
        mfa_feature_services: _ServicesDependency,
    ) -> Response[RecoveryCodesResponse | MFAStatusResponse]:
        """Activate TOTP and return a recovery-code set once."""
        account_id = _principal_id(principal)
        service = mfa_feature_services.mfa
        if account_id is None or service is None:  # pragma: no cover - controller registration and auth guarantee both
            return _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_feature_services, request, MFA_TOTP_VERIFY, account_id)
        if limited is not None:
            return _error(limited)
        recovery = await service.activate_totp_with_recovery_codes(account_id, data.enrollment_id, data.code)
        if not isinstance(recovery, RecoveryCodes):
            return _error(recovery)
        return _response(RecoveryCodesResponse(codes=recovery.codes))

    @delete("/mfa/totp/{method_id:str}", operation_id="MFARemoveTOTP", status_code=HTTP_200_OK, auth=required())
    async def remove_totp(
        self,
        method_id: FromPath[str],
        data: JSONBody[RecoveryCodesRequest],
        request: Request[Any, Any, Any],
        principal: _PrincipalDependency,
        mfa_feature_services: _ServicesDependency,
    ) -> Response[MFAStatusResponse]:
        """Remove TOTP through exact step-up and final-method protection."""
        account_id = _principal_id(principal)
        service = mfa_feature_services.mfa
        if account_id is None or service is None:  # pragma: no cover - controller registration and auth guarantee both
            return _error(InvalidCredentials())
        assurance = await _consume_step_up(
            services=mfa_feature_services,
            request=request,
            account_id=account_id,
            purpose="totp-remove",
            grant=data.step_up_grant,
        )
        if not isinstance(assurance, AuthenticationEvidence):
            return _error(assurance)
        result = await service.remove_totp_method(account_id, method_id)
        return _removal_response(result)

    @post("/mfa/recovery-codes", operation_id="MFAReplaceRecoveryCodes", auth=required())
    async def recovery_codes(
        self,
        data: JSONBody[RecoveryCodesRequest],
        request: Request[Any, Any, Any],
        principal: _PrincipalDependency,
        mfa_feature_services: _ServicesDependency,
    ) -> Response[RecoveryCodesResponse | MFAStatusResponse]:
        """Replace recovery codes after exact step-up."""
        account_id = _principal_id(principal)
        service = mfa_feature_services.mfa
        if account_id is None or service is None:  # pragma: no cover - controller registration and auth guarantee both
            return _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_feature_services, request, MFA_RECOVERY_REPLACE, account_id)
        if limited is not None:
            return _error(limited)
        assurance = await _consume_step_up(
            services=mfa_feature_services,
            request=request,
            account_id=account_id,
            purpose="recovery-codes",
            grant=data.step_up_grant,
        )
        if not isinstance(assurance, AuthenticationEvidence):
            return _error(assurance)
        result = await service.generate_recovery_codes(account_id)
        if not isinstance(result, RecoveryCodes):
            return _error(result)
        return _response(RecoveryCodesResponse(codes=result.codes))


class _PasskeyController(Controller):
    tags = (_PASSKEY_TAG,)

    @post("/passkeys/registration/options", operation_id="PasskeyRegistrationOptions", auth=required())
    async def registration_options(
        self,
        data: JSONBody[PasskeyRegistrationOptionsRequest],
        request: Request[Any, Any, Any],
        principal: _PrincipalDependency,
        mfa_feature_services: _ServicesDependency,
    ) -> Response[PasskeyOptionsResponse | MFAStatusResponse]:
        """Create registration options after exact step-up."""
        account_id = _principal_id(principal)
        service = mfa_feature_services.passkeys
        if account_id is None or service is None:  # pragma: no cover - controller registration and auth guarantee both
            return _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_feature_services, request, PASSKEY_REGISTER_OPTIONS, account_id)
        if limited is not None:
            return _error(limited)
        assurance = await _consume_step_up(
            services=mfa_feature_services,
            request=request,
            account_id=account_id,
            purpose="passkey-register",
            grant=data.step_up_grant,
        )
        if not isinstance(assurance, AuthenticationEvidence):
            return _error(assurance)
        result = await service.begin_registration(
            account_id, user_name=data.user_name, binding=_transport_binding(request)
        )
        return _options_response(result)

    @post("/passkeys/registration/verify", operation_id="PasskeyRegistrationVerify", auth=required())
    async def registration_verify(
        self,
        data: JSONBody[PasskeyVerifyRequest],
        request: Request[Any, Any, Any],
        principal: _PrincipalDependency,
        mfa_feature_services: _ServicesDependency,
    ) -> Response[MFAStatusResponse]:
        """Verify and store one passkey registration."""
        account_id = _principal_id(principal)
        service = mfa_feature_services.passkeys
        if account_id is None or service is None or data.account_id != account_id:
            return _error(InvalidCredentials())
        limited = await _check_rate_limit(mfa_feature_services, request, PASSKEY_REGISTER_VERIFY, account_id)
        if limited is not None:
            return _error(limited)
        result = await service.verify_registration(
            account_id, binding=_transport_binding(request), response=data.response
        )
        if not hasattr(result, "credential_id"):
            return _error(result)
        return _response(MFAStatusResponse(detail="Passkey registered."), HTTP_201_CREATED)

    @post("/passkeys/authentication/options", operation_id="PasskeyAuthenticationOptions", auth=optional(required()))
    async def authentication_options(
        self,
        data: JSONBody[PasskeyAuthenticationOptionsRequest],
        request: Request[Any, Any, Any],
        mfa_feature_services: _ServicesDependency,
    ) -> Response[PasskeyOptionsResponse | MFAStatusResponse]:
        """Create public account-bound assertion options."""
        service = mfa_feature_services.passkeys
        if service is None:  # pragma: no cover - this controller is registered only with a passkey service
            return _error(VerificationUnavailable())
        limited = await _check_rate_limit(mfa_feature_services, request, PASSKEY_AUTH_OPTIONS, data.account_id)
        if limited is not None:
            return _error(limited)
        binding = token_urlsafe(32)
        result = await service.begin_authentication(data.account_id, binding=binding.encode("ascii"))
        return _options_response(result, binding=binding)

    @get("/passkeys", operation_id="PasskeyList", auth=required())
    async def list_passkeys(
        self, principal: _PrincipalDependency, mfa_feature_services: _ServicesDependency
    ) -> Response[tuple[PasskeySummaryResponse, ...] | MFAStatusResponse]:
        """List only caller-owned safe credential metadata."""
        account_id = _principal_id(principal)
        service = mfa_feature_services.passkeys
        if account_id is None or service is None:  # pragma: no cover - controller registration and auth guarantee both
            return _error(InvalidCredentials())
        result = await service.list_credentials(account_id)
        if isinstance(result, VerificationUnavailable):
            return _error(result)
        return _response(tuple(_summary_response(summary) for summary in result))

    @delete("/passkeys/{credential_id:str}", operation_id="PasskeyRemove", status_code=HTTP_200_OK, auth=required())
    async def remove_passkey(
        self,
        credential_id: FromPath[str],
        data: JSONBody[RecoveryCodesRequest],
        request: Request[Any, Any, Any],
        principal: _PrincipalDependency,
        mfa_feature_services: _ServicesDependency,
    ) -> Response[MFAStatusResponse]:
        """Remove a passkey through exact step-up and final-method protection."""
        account_id = _principal_id(principal)
        service = mfa_feature_services.passkeys
        if account_id is None or service is None:  # pragma: no cover - controller registration and auth guarantee both
            return _error(InvalidCredentials())
        assurance = await _consume_step_up(
            services=mfa_feature_services,
            request=request,
            account_id=account_id,
            purpose="passkey-remove",
            grant=data.step_up_grant,
        )
        if not isinstance(assurance, AuthenticationEvidence):
            return _error(assurance)
        try:
            raw_id = urlsafe_b64decode(credential_id + "=" * (-len(credential_id) % 4))
        except (ValueError, TypeError):
            return _response(MFAStatusResponse(detail="The request is invalid."), HTTP_400_BAD_REQUEST)
        result = await service.remove_credential(account_id, raw_id)
        return _removal_response(result)


class _PasskeySessionAuthenticationController(Controller):
    tags = (_PASSKEY_TAG,)

    @post(
        "/passkeys/authentication/verify", operation_id="PasskeyAuthenticationVerify", auth=public(), csrf_required=True
    )
    async def authentication_verify(
        self,
        data: JSONBody[PasskeyVerifyRequest],
        request: Request[Any, Any, Any],
        mfa_feature_services: _ServicesDependency,
    ) -> Response[Any]:
        """Verify an assertion and establish a CSRF-protected local transport."""
        return await _verify_passkey_authentication(  # pragma: no cover - covered shared handler
            data, request, mfa_feature_services
        )


class _PasskeyTokenAuthenticationController(Controller):
    tags = (_PASSKEY_TAG,)

    @post("/passkeys/authentication/verify", operation_id="PasskeyAuthenticationVerify", auth=public())
    async def authentication_verify(
        self,
        data: JSONBody[PasskeyVerifyRequest],
        request: Request[Any, Any, Any],
        mfa_feature_services: _ServicesDependency,
    ) -> Response[Any]:
        """Verify an assertion and establish a token-only local transport."""
        return await _verify_passkey_authentication(data, request, mfa_feature_services)


class _PasskeyHybridSessionController(Controller):
    tags = (_PASSKEY_TAG,)

    @post(
        "/passkeys/authentication/session/verify",
        operation_id="PasskeySessionAuthenticationVerify",
        auth=public(),
        csrf_required=True,
    )
    async def authentication_verify(
        self,
        data: JSONBody[PasskeyVerifyRequest],
        request: Request[Any, Any, Any],
        mfa_feature_services: _ServicesDependency,
    ) -> Response[Any]:
        """Verify an assertion and establish the hybrid profile's session transport."""
        return await _verify_passkey_authentication(  # pragma: no cover - covered shared handler
            data, request, mfa_feature_services, transport="session"
        )


class _PasskeyHybridTokenController(Controller):
    tags = (_PASSKEY_TAG,)

    @post("/passkeys/authentication/tokens/verify", operation_id="PasskeyTokenAuthenticationVerify", auth=public())
    async def authentication_verify(
        self,
        data: JSONBody[PasskeyVerifyRequest],
        request: Request[Any, Any, Any],
        mfa_feature_services: _ServicesDependency,
    ) -> Response[Any]:
        """Verify an assertion and establish the hybrid profile's token transport."""
        return await _verify_passkey_authentication(  # pragma: no cover - covered shared handler
            data, request, mfa_feature_services, transport="tokens"
        )


async def _verify_passkey_authentication(
    data: PasskeyVerifyRequest,
    request: Request[Any, Any, Any],
    services: _MFAFeatureServices,
    *,
    transport: str | None = None,
) -> Response[Any]:
    service = services.passkeys
    local_auth = services.local_auth
    if service is None or local_auth is None:  # pragma: no cover - plugin validates both before route registration
        return _error(VerificationUnavailable())
    limited = await _check_rate_limit(services, request, PASSKEY_ASSERT, data.account_id)
    if limited is not None:
        return _error(limited)
    if data.binding is None:
        return _error(InvalidCredentials())
    evidence = await service.verify_authentication(
        data.account_id, binding=data.binding.encode("utf-8"), response=data.response
    )
    if not isinstance(evidence, AuthenticationEvidence):
        return _error(evidence)
    selected_transport = transport if transport is not None else data.transport
    result = await local_auth.passkey_login(request, data.account_id, transport=selected_transport, evidence=evidence)
    if isinstance(result, (InvalidCredentials, VerificationUnavailable)):
        return _error(result)
    return _response(result)


def _options_response(
    result: WebAuthnOptions | VerificationUnavailable, *, binding: str | None = None
) -> Response[Any]:
    if isinstance(result, VerificationUnavailable):
        return _error(result)
    return _response(PasskeyOptionsResponse(options=result.json, expires_at=result.expires_at, binding=binding))


def _summary_response(summary: PasskeySummary) -> PasskeySummaryResponse:
    return PasskeySummaryResponse(
        credential_id=summary.credential_id,
        display_name=summary.display_name,
        created_at=summary.created_at,
        last_used_at=summary.last_used_at,
        backup_eligible=summary.backup_eligible,
        backup_state=summary.backup_state,
        suspect=summary.suspect,
    )


def _removal_response(result: RevokeLoginMethodResult | VerificationUnavailable) -> Response[MFAStatusResponse]:
    if isinstance(result, VerificationUnavailable):
        return _error(result)
    if result.status is RevokeLoginMethodStatus.REVOKED:
        return _response(MFAStatusResponse(detail="Login method removed."))
    if result.status is RevokeLoginMethodStatus.FINAL_METHOD:
        return _response(MFAStatusResponse(detail="At least one viable login method is required."), HTTP_409_CONFLICT)
    return _response(MFAStatusResponse(detail="The request is invalid."), HTTP_400_BAD_REQUEST)
