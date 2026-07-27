"""Request and response payloads for the built-in local-auth routes."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated

from litestar.params import Parameter

__all__ = (
    "LocalAccountResponse",
    "LocalCredentials",
    "LocalIdentifierRequest",
    "LocalInvitationRegistrationRequest",
    "LocalPasswordChangeRequest",
    "LocalPasswordResetRequest",
    "LocalRegistrationRequest",
    "LocalRouteResponse",
    "LocalSessionListResponse",
    "LocalSessionResponse",
    "LocalTokenRequest",
)

_IDENTIFIER = Parameter(description="The account identifier, normally an email address.")
_NEW_PASSWORD = Parameter(description="The replacement password, checked against the configured password policy.")
_DISPLAY_NAME = Parameter(description="An optional human-readable name to store with the account.")


@dataclass(frozen=True, slots=True)
class LocalCredentials:
    """Password credentials accepted by generated login handlers."""

    identifier: Annotated[str, _IDENTIFIER]
    password: Annotated[str, Parameter(description="The account password.")] = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalRegistrationRequest:
    """Typed public self-service registration input."""

    identifier: Annotated[str, _IDENTIFIER]
    password: Annotated[str, _NEW_PASSWORD] = field(repr=False)
    display_name: Annotated[str | None, _DISPLAY_NAME] = None


@dataclass(frozen=True, slots=True)
class LocalInvitationRegistrationRequest:
    """Typed invite-only self-service registration input."""

    identifier: Annotated[str, _IDENTIFIER]
    password: Annotated[str, _NEW_PASSWORD] = field(repr=False)
    invitation_token: Annotated[str, Parameter(description="The single-use invitation token.")] = field(repr=False)
    display_name: Annotated[str | None, _DISPLAY_NAME] = None


@dataclass(frozen=True, slots=True)
class LocalIdentifierRequest:
    """Typed enumeration-resistant identifier request."""

    identifier: Annotated[str, _IDENTIFIER]


@dataclass(frozen=True, slots=True)
class LocalTokenRequest:
    """Typed one-time or refresh-token request."""

    token: Annotated[str, Parameter(description="The opaque token issued by a previous request.")] = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalPasswordResetRequest:
    """Typed password recovery completion input."""

    token: Annotated[str, Parameter(description="The single-use recovery token.")] = field(repr=False)
    password: Annotated[str, _NEW_PASSWORD] = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalPasswordChangeRequest:
    """Typed authenticated password-change input."""

    current_password: Annotated[str, Parameter(description="The caller's current password.")] = field(repr=False)
    password: Annotated[str, _NEW_PASSWORD] = field(repr=False)
    compromise: Annotated[
        bool,
        Parameter(
            description=(
                "Set when the current password is believed compromised. The caller's own session is revoked "
                "with the others rather than rebound."
            )
        ),
    ] = False


@dataclass(frozen=True, slots=True)
class LocalAccountResponse:
    """Minimal account projection returned after session login."""

    account_id: Annotated[str, Parameter(description="The stable application-owned account identifier.")]
    display_name: Annotated[str | None, _DISPLAY_NAME] = None


@dataclass(frozen=True, slots=True)
class LocalRouteResponse:
    """Stable generated-route status body."""

    detail: Annotated[str, Parameter(description="A human-readable outcome that never names an account.")]


@dataclass(frozen=True, slots=True)
class LocalSessionResponse:
    """JSON-safe generated-route session projection."""

    session_id: Annotated[str, Parameter(description="The session identifier, accepted by the revoke route.")]
    current: Annotated[bool, Parameter(description="Whether this is the session that made the request.")]
    created_at: Annotated[datetime, Parameter(description="When the session was established.")]
    last_seen_at: Annotated[datetime, Parameter(description="When the session was last used.")]
    expires_at: Annotated[datetime, Parameter(description="When the session expires without further use.")]
    display_metadata: Annotated[
        dict[str, str],
        Parameter(description="Application-supplied display fields, such as a device label or coarse location."),
    ]


@dataclass(frozen=True, slots=True)
class LocalSessionListResponse:
    """Safe caller-owned session inventory."""

    sessions: Annotated[tuple["LocalSessionResponse", ...], Parameter(description="The caller's own active sessions.")]
