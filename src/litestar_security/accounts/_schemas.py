"""Request and response payloads for the built-in local-auth routes."""

from dataclasses import dataclass, field
from datetime import datetime

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


@dataclass(frozen=True, slots=True)
class LocalCredentials:
    """Password credentials accepted by generated login handlers."""

    identifier: str
    password: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalRegistrationRequest:
    """Typed public self-service registration input."""

    identifier: str
    password: str = field(repr=False)
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class LocalInvitationRegistrationRequest:
    """Typed invite-only self-service registration input."""

    identifier: str
    password: str = field(repr=False)
    invitation_token: str = field(repr=False)
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class LocalIdentifierRequest:
    """Typed enumeration-resistant identifier request."""

    identifier: str


@dataclass(frozen=True, slots=True)
class LocalTokenRequest:
    """Typed one-time or refresh-token request."""

    token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalPasswordResetRequest:
    """Typed password recovery completion input."""

    token: str = field(repr=False)
    password: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class LocalPasswordChangeRequest:
    """Typed authenticated password-change input."""

    current_password: str = field(repr=False)
    password: str = field(repr=False)
    compromise: bool = False


@dataclass(frozen=True, slots=True)
class LocalAccountResponse:
    """Minimal account projection returned after session login."""

    account_id: str
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class LocalRouteResponse:
    """Stable generated-route status body."""

    detail: str


@dataclass(frozen=True, slots=True)
class LocalSessionResponse:
    """JSON-safe generated-route session projection."""

    session_id: str
    current: bool
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    display_metadata: dict[str, str]


@dataclass(frozen=True, slots=True)
class LocalSessionListResponse:
    """Safe caller-owned session inventory."""

    sessions: tuple["LocalSessionResponse", ...]
