"""Request and response payloads for the built-in local-auth routes."""

from datetime import datetime
from typing import Annotated

import msgspec

from litestar_security.schema import WireStruct

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
    "RouteStatusResponse",
)

_IDENTIFIER = msgspec.Meta(description="The account identifier, normally an email address.")
_NEW_PASSWORD = msgspec.Meta(description="The replacement password, checked against the configured password policy.")
_DISPLAY_NAME = msgspec.Meta(description="An optional human-readable name to store with the account.")


class LocalCredentials(WireStruct, frozen=True):
    """Password credentials accepted by generated login handlers."""

    identifier: Annotated[str, _IDENTIFIER]
    password: Annotated[str, msgspec.Meta(description="The account password.")]

    def __repr__(self) -> str:
        """Redact the presented password."""
        return f"{type(self).__name__}(identifier={self.identifier!r}, password=<redacted>)"


class LocalMFARequiredResponse(WireStruct, frozen=True):
    """A one-time challenge returned when password login requires MFA completion."""

    challenge: Annotated[str, msgspec.Meta(description="The opaque one-time challenge to present at completion.")]
    account_id: Annotated[str, msgspec.Meta(description="The account bound to this challenge.")]
    expires_at: Annotated[datetime, msgspec.Meta(description="When the opaque challenge can no longer be used.")]
    methods: Annotated[tuple[str, ...], msgspec.Meta(description="The permitted second-factor methods.")]
    code: Annotated[
        str, msgspec.Meta(description="The stable machine-readable MFA challenge outcome.")
    ] = "mfa_required"
    detail: Annotated[str, msgspec.Meta(description="The human-readable MFA challenge outcome.")] = (
        "Multi-factor authentication is required."
    )

    def __repr__(self) -> str:
        """Redact the opaque challenge credential."""
        return (
            f"{type(self).__name__}(challenge=<redacted>, account_id={self.account_id!r}, "
            f"expires_at={self.expires_at!r}, methods={self.methods!r}, code={self.code!r}, detail={self.detail!r})"
        )


class LocalMFACompletionRequest(WireStruct, frozen=True):
    """Typed input that completes a pending password-login MFA challenge."""

    challenge: Annotated[str, msgspec.Meta(description="The opaque one-time challenge from password login.")]
    account_id: Annotated[str, msgspec.Meta(description="The account identifier returned with the challenge.")]
    method: Annotated[str, msgspec.Meta(description="The selected second-factor method.")]
    code: Annotated[str, msgspec.Meta(description="The proof for the selected second-factor method.")]
    method_id: Annotated[
        str | None, msgspec.Meta(description="The selected TOTP method identifier, when required.")
    ] = None

    def __repr__(self) -> str:
        """Redact the one-time challenge and factor proof."""
        return (
            f"{type(self).__name__}(challenge=<redacted>, account_id={self.account_id!r}, method={self.method!r}, "
            f"code=<redacted>, method_id={self.method_id!r})"
        )


class LocalRegistrationRequest(WireStruct, frozen=True):
    """Typed public self-service registration input."""

    identifier: Annotated[str, _IDENTIFIER]
    password: Annotated[str, _NEW_PASSWORD]
    display_name: Annotated[str | None, _DISPLAY_NAME] = None

    def __repr__(self) -> str:
        """Redact the proposed password."""
        return (
            f"{type(self).__name__}(identifier={self.identifier!r}, password=<redacted>, "
            f"display_name={self.display_name!r})"
        )


class LocalInvitationRegistrationRequest(WireStruct, frozen=True):
    """Typed invite-only self-service registration input."""

    identifier: Annotated[str, _IDENTIFIER]
    password: Annotated[str, _NEW_PASSWORD]
    invitation_token: Annotated[str, msgspec.Meta(description="The single-use invitation token.")]
    display_name: Annotated[str | None, _DISPLAY_NAME] = None

    def __repr__(self) -> str:
        """Redact the proposed password and the single-use invitation token."""
        return (
            f"{type(self).__name__}(identifier={self.identifier!r}, password=<redacted>, "
            f"invitation_token=<redacted>, display_name={self.display_name!r})"
        )


class LocalIdentifierRequest(WireStruct, frozen=True):
    """Typed enumeration-resistant identifier request."""

    identifier: Annotated[str, _IDENTIFIER]


class LocalTokenRequest(WireStruct, frozen=True):
    """Typed one-time or refresh-token request."""

    token: Annotated[str, msgspec.Meta(description="The opaque token issued by a previous request.")]

    def __repr__(self) -> str:
        """Redact the presented token."""
        return f"{type(self).__name__}(token=<redacted>)"


class LocalPasswordResetRequest(WireStruct, frozen=True):
    """Typed password recovery completion input."""

    token: Annotated[str, msgspec.Meta(description="The single-use recovery token.")]
    password: Annotated[str, _NEW_PASSWORD]

    def __repr__(self) -> str:
        """Redact the recovery token and the replacement password."""
        return f"{type(self).__name__}(token=<redacted>, password=<redacted>)"


class LocalPasswordChangeRequest(WireStruct, frozen=True):
    """Typed authenticated password-change input."""

    current_password: Annotated[str, msgspec.Meta(description="The caller's current password.")]
    password: Annotated[str, _NEW_PASSWORD]
    compromise: Annotated[
        bool,
        msgspec.Meta(
            description=(
                "Set when the current password is believed compromised. The caller's own session is revoked "
                "with the others rather than rebound."
            )
        ),
    ] = False

    def __repr__(self) -> str:
        """Redact both the current and the replacement password."""
        return (
            f"{type(self).__name__}(current_password=<redacted>, password=<redacted>, compromise={self.compromise!r})"
        )


class LocalAccountResponse(WireStruct, frozen=True):
    """Minimal account projection returned after session login."""

    account_id: Annotated[str, msgspec.Meta(description="The stable application-owned account identifier.")]
    display_name: Annotated[str | None, _DISPLAY_NAME] = None


class RouteStatusResponse(WireStruct, frozen=True):
    """Stable generated-route status body, shared by every route in the tree."""

    detail: Annotated[str, msgspec.Meta(description="A human-readable outcome that never names an account.")]


class LocalSessionResponse(WireStruct, frozen=True):
    """JSON-safe generated-route session projection."""

    session_id: Annotated[str, msgspec.Meta(description="The session identifier, accepted by the revoke route.")]
    current: Annotated[bool, msgspec.Meta(description="Whether this is the session that made the request.")]
    created_at: Annotated[datetime, msgspec.Meta(description="When the session was established.")]
    last_seen_at: Annotated[datetime, msgspec.Meta(description="When the session was last used.")]
    expires_at: Annotated[datetime, msgspec.Meta(description="When the session expires without further use.")]
    display_metadata: Annotated[
        dict[str, str],
        msgspec.Meta(description="Application-supplied display fields, such as a device label or coarse location."),
    ]


class LocalSessionListResponse(WireStruct, frozen=True):
    """Safe caller-owned session inventory."""

    # Unquoted deliberately: the reference is backward, and on Python 3.10 a quoted
    # forward reference nested in a subscript stays an unresolved string, which drops
    # the element type from the generated schema.
    sessions: Annotated[tuple[LocalSessionResponse, ...], msgspec.Meta(description="The caller's own active sessions.")]
