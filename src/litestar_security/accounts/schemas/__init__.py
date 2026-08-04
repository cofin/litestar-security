"""Wire schemas for the generated local-authentication and MFA routes.

Every schema descends from `litestar_security.schema.WireStruct`, so the whole
package shares one casing and strictness policy: snake_case on the wire,
frozen, and unknown members rejected on decode.
"""

from litestar_security.accounts.schemas._local import (
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
    "LocalAccount",
    "LocalCredentials",
    "LocalIdentifier",
    "LocalInvitationRegistration",
    "LocalMFAChallenge",
    "LocalMFACompletion",
    "LocalPasswordChange",
    "LocalPasswordReset",
    "LocalRegistration",
    "LocalSession",
    "LocalSessionList",
    "LocalToken",
    "PasskeyAuthenticationOptionsRequest",
    "PasskeyOptionsResponse",
    "PasskeyRegistrationOptionsRequest",
    "PasskeySummaryResponse",
    "PasskeyVerifyRequest",
    "RecoveryCodesResponse",
    "RouteStatus",
    "StepUpAuthorizedRequest",
    "StepUpRequest",
    "StepUpResponse",
    "TOTPEnrollmentRequest",
    "TOTPEnrollmentResponse",
    "TOTPVerificationRequest",
)
