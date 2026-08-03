"""Typed JSON boundaries for generated MFA and passkey routes."""

from datetime import datetime

from litestar_security.schema import WireStruct

__all__ = (
    "PasskeyAuthenticationOptionsRequest",
    "PasskeyOptionsResponse",
    "PasskeyRegistrationOptionsRequest",
    "PasskeySummaryResponse",
    "PasskeyVerifyRequest",
    "RecoveryCodesResponse",
    "StepUpAuthorizedRequest",
    "StepUpRequest",
    "StepUpResponse",
    "TOTPEnrollmentRequest",
    "TOTPEnrollmentResponse",
    "TOTPVerificationRequest",
)


class TOTPEnrollmentRequest(WireStruct, frozen=True):
    """Request a protected TOTP enrollment."""

    label: str
    step_up_grant: str

    def __repr__(self) -> str:
        """Redact the one-time authorization grant."""
        return f"{type(self).__name__}(label={self.label!r}, step_up_grant=<redacted>)"


class TOTPEnrollmentResponse(WireStruct, frozen=True):
    """Reveal one TOTP provisioning URI."""

    enrollment_id: str
    method_id: str
    provisioning_uri: str
    expires_at: datetime

    def __repr__(self) -> str:
        """Redact the reveal-once provisioning URI."""
        return (
            f"{type(self).__name__}(enrollment_id={self.enrollment_id!r}, "
            f"method_id={self.method_id!r}, provisioning_uri=<redacted>, expires_at={self.expires_at!r})"
        )


class TOTPVerificationRequest(WireStruct, frozen=True):
    """Activate one pending TOTP enrollment."""

    enrollment_id: str
    code: str

    def __repr__(self) -> str:
        """Redact the presented one-time password."""
        return f"{type(self).__name__}(enrollment_id={self.enrollment_id!r}, code=<redacted>)"


class StepUpAuthorizedRequest(WireStruct, frozen=True):
    """Carry the grant authorizing one sensitive factor operation."""

    step_up_grant: str

    def __repr__(self) -> str:
        """Redact the one-time authorization grant."""
        return f"{type(self).__name__}(step_up_grant=<redacted>)"


class RecoveryCodesResponse(WireStruct, frozen=True):
    """Reveal a replacement recovery-code set once."""

    codes: tuple[str, ...]

    def __repr__(self) -> str:
        """Redact the reveal-once recovery-code set."""
        return f"{type(self).__name__}(codes=<redacted>)"


class StepUpRequest(WireStruct, frozen=True):
    """Present one configured factor for a purpose-bound grant."""

    method: str
    credential: str
    method_id: str | None = None

    def __repr__(self) -> str:
        """Redact the factor credential."""
        return f"{type(self).__name__}(method={self.method!r}, credential=<redacted>, method_id={self.method_id!r})"


class StepUpResponse(WireStruct, frozen=True):
    """Return one short-lived transport-bound grant."""

    grant: str
    purpose: str
    expires_at: datetime

    def __repr__(self) -> str:
        """Redact the reveal-once grant."""
        return f"{type(self).__name__}(grant=<redacted>, purpose={self.purpose!r}, expires_at={self.expires_at!r})"


class PasskeyRegistrationOptionsRequest(WireStruct, frozen=True):
    """Request bound passkey registration options."""

    user_name: str
    step_up_grant: str

    def __repr__(self) -> str:
        """Redact the one-time authorization grant."""
        return f"{type(self).__name__}(user_name={self.user_name!r}, step_up_grant=<redacted>)"


class PasskeyAuthenticationOptionsRequest(WireStruct, frozen=True):
    """Request bound passkey authentication options."""

    account_id: str


class PasskeyVerifyRequest(WireStruct, frozen=True):
    """Submit one browser WebAuthn JSON response."""

    account_id: str
    response: str
    binding: str | None = None
    transport: str | None = None

    def __repr__(self) -> str:
        """Redact the browser credential response."""
        return (
            f"{type(self).__name__}(account_id={self.account_id!r}, response=<redacted>, "
            f"binding=<redacted>, transport={self.transport!r})"
        )


class PasskeyOptionsResponse(WireStruct, frozen=True):
    """Carry dependency-independent WebAuthn JSON options."""

    options: str
    expires_at: datetime
    binding: str | None = None

    def __repr__(self) -> str:
        """Redact challenge-bearing WebAuthn options."""
        return f"{type(self).__name__}(options=<redacted>, expires_at={self.expires_at!r}, binding=<redacted>)"


class PasskeySummaryResponse(WireStruct, frozen=True):
    """Safe caller-owned credential metadata."""

    credential_id: str
    display_name: str | None
    created_at: datetime
    last_used_at: datetime | None
    backup_eligible: bool
    backup_state: bool
    suspect: bool
