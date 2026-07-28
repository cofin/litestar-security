"""Typed JSON boundaries for generated MFA and passkey routes."""

from datetime import datetime

import msgspec

__all__ = (
    "MFAStatusResponse",
    "PasskeyAuthenticationOptionsRequest",
    "PasskeyOptionsResponse",
    "PasskeyRegistrationOptionsRequest",
    "PasskeySummaryResponse",
    "PasskeyVerifyRequest",
    "RecoveryCodesRequest",
    "RecoveryCodesResponse",
    "StepUpRequest",
    "StepUpResponse",
    "TOTPEnrollmentRequest",
    "TOTPEnrollmentResponse",
    "TOTPVerificationRequest",
)


class TOTPEnrollmentRequest(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Request a protected TOTP enrollment."""

    label: str
    step_up_grant: str

    def __repr__(self) -> str:
        """Redact the one-time authorization grant."""
        return f"{type(self).__name__}(label={self.label!r}, step_up_grant=<redacted>)"


class TOTPEnrollmentResponse(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
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


class TOTPVerificationRequest(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Activate one pending TOTP enrollment."""

    enrollment_id: str
    code: str

    def __repr__(self) -> str:
        """Redact the presented one-time password."""
        return f"{type(self).__name__}(enrollment_id={self.enrollment_id!r}, code=<redacted>)"


class RecoveryCodesRequest(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Authorize a recovery-code replacement."""

    step_up_grant: str

    def __repr__(self) -> str:
        """Redact the one-time authorization grant."""
        return f"{type(self).__name__}(step_up_grant=<redacted>)"


class RecoveryCodesResponse(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Reveal a replacement recovery-code set once."""

    codes: tuple[str, ...]

    def __repr__(self) -> str:
        """Redact the reveal-once recovery-code set."""
        return f"{type(self).__name__}(codes=<redacted>)"


class MFAStatusResponse(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Return one redacted generated-route outcome."""

    detail: str


class StepUpRequest(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Present one configured factor for a purpose-bound grant."""

    method: str
    credential: str
    method_id: str | None = None

    def __repr__(self) -> str:
        """Redact the factor credential."""
        return (
            f"{type(self).__name__}(method={self.method!r}, credential=<redacted>, "
            f"method_id={self.method_id!r})"
        )


class StepUpResponse(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Return one short-lived transport-bound grant."""

    grant: str
    purpose: str
    expires_at: datetime

    def __repr__(self) -> str:
        """Redact the reveal-once grant."""
        return (
            f"{type(self).__name__}(grant=<redacted>, purpose={self.purpose!r}, "
            f"expires_at={self.expires_at!r})"
        )


class PasskeyRegistrationOptionsRequest(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Request bound passkey registration options."""

    user_name: str
    step_up_grant: str

    def __repr__(self) -> str:
        """Redact the one-time authorization grant."""
        return f"{type(self).__name__}(user_name={self.user_name!r}, step_up_grant=<redacted>)"


class PasskeyAuthenticationOptionsRequest(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Request bound passkey authentication options."""

    account_id: str


class PasskeyVerifyRequest(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Submit one browser WebAuthn JSON response."""

    account_id: str
    response: str

    def __repr__(self) -> str:
        """Redact the browser credential response."""
        return f"{type(self).__name__}(account_id={self.account_id!r}, response=<redacted>)"


class PasskeyOptionsResponse(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Carry dependency-independent WebAuthn JSON options."""

    options: str
    expires_at: datetime

    def __repr__(self) -> str:
        """Redact challenge-bearing WebAuthn options."""
        return f"{type(self).__name__}(options=<redacted>, expires_at={self.expires_at!r})"


class PasskeySummaryResponse(
    msgspec.Struct,
    frozen=True,
    rename="camel",
    forbid_unknown_fields=True,
):
    """Safe caller-owned credential metadata."""

    credential_id: str
    display_name: str | None
    created_at: datetime
    last_used_at: datetime | None
    backup_eligible: bool
    backup_state: bool
    suspect: bool
