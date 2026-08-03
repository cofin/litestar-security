"""Wire schemas for the generated local-authentication and MFA routes.

Every schema descends from `litestar_security.schema.WireStruct`, so the whole
package shares one casing and strictness policy: snake_case on the wire,
frozen, and unknown members rejected on decode.
"""

from litestar_security.accounts.schemas._local import (
    LocalAccountResponse,
    LocalCredentials,
    LocalIdentifierRequest,
    LocalInvitationRegistrationRequest,
    LocalMFACompletionRequest,
    LocalMFARequiredResponse,
    LocalPasswordChangeRequest,
    LocalPasswordResetRequest,
    LocalRegistrationRequest,
    LocalSessionListResponse,
    LocalSessionResponse,
    LocalTokenRequest,
    RouteStatusResponse,
)
from litestar_security.accounts.schemas._mfa import (
    PasskeyAuthenticationOptionsRequest,
    PasskeyOptionsResponse,
    PasskeyRegistrationOptionsRequest,
    PasskeySummaryResponse,
    PasskeyVerifyRequest,
    RecoveryCodesResponse,
    StepUpAuthorizedRequest,
    StepUpRequest,
    StepUpResponse,
    TOTPEnrollmentRequest,
    TOTPEnrollmentResponse,
    TOTPVerificationRequest,
)

__all__ = (
    "LocalAccountResponse",
    "LocalCredentials",
    "LocalIdentifierRequest",
    "LocalInvitationRegistrationRequest",
    "LocalMFACompletionRequest",
    "LocalMFARequiredResponse",
    "LocalPasswordChangeRequest",
    "LocalPasswordResetRequest",
    "LocalRegistrationRequest",
    "LocalSessionListResponse",
    "LocalSessionResponse",
    "LocalTokenRequest",
    "PasskeyAuthenticationOptionsRequest",
    "PasskeyOptionsResponse",
    "PasskeyRegistrationOptionsRequest",
    "PasskeySummaryResponse",
    "PasskeyVerifyRequest",
    "RecoveryCodesResponse",
    "RouteStatusResponse",
    "StepUpAuthorizedRequest",
    "StepUpRequest",
    "StepUpResponse",
    "TOTPEnrollmentRequest",
    "TOTPEnrollmentResponse",
    "TOTPVerificationRequest",
)
