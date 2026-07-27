"""Native-session registry and strict refresh-family contracts."""

from collections.abc import Mapping, Sequence  # noqa: TC003 - Litestar resolves public annotations at runtime
from dataclasses import dataclass, field
from datetime import datetime  # noqa: TC003 - Litestar resolves public annotations at runtime
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from litestar.exceptions import ImproperlyConfiguredException

if TYPE_CHECKING:
    from litestar_security.accounts.local import SecurityEvent

__all__ = (
    "CreateSessionCommand",
    "RefreshRotationStatus",
    "RefreshTokenFamilyStore",
    "RotateRefreshCommand",
    "RotateRefreshResult",
    "SessionAuthentication",
    "SessionBindingConfig",
    "SessionRecord",
    "SessionRegistry",
)

_EMPTY_DISPLAY_METADATA: "Mapping[str, str]" = MappingProxyType({})
_MINIMUM_PEPPER_BYTES = 32
_MAXIMUM_SECURITY_EPOCH = 9_223_372_036_854_775_807


def _valid_security_epoch(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAXIMUM_SECURITY_EPOCH


class RefreshRotationStatus(str, Enum):
    """Atomic refresh-token rotation outcomes."""

    ROTATED = "rotated"
    IDEMPOTENT_REPLAY = "idempotent_replay"
    REPLAY_DETECTED = "replay_detected"
    EXPIRED = "expired"
    REVOKED = "revoked"
    EPOCH_MISMATCH = "epoch_mismatch"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class SessionBindingConfig:
    """Independent proof-of-possession cookie configuration."""

    pepper: bytes = field(repr=False)
    cookie_name: str = "__Host-litestar-security-binding"
    secure: bool = True
    same_site: Literal["lax", "strict", "none"] = "lax"
    path: str = "/"
    domain: str | None = None

    def __post_init__(self) -> None:
        """Reject configurations that cannot provide the planned binding boundary."""
        if len(self.pepper) < _MINIMUM_PEPPER_BYTES:
            msg = "Session binding pepper must contain at least 32 bytes"
            raise ImproperlyConfiguredException(detail=msg)
        if not self.cookie_name:
            msg = "Session binding cookie name must not be blank"
            raise ImproperlyConfiguredException(detail=msg)
        if self.cookie_name.startswith("__Host-") and (self.secure, self.path, self.domain) != (True, "/", None):
            msg = "__Host- session binding cookies require Secure, Path=/, and no Domain"
            raise ImproperlyConfiguredException(detail=msg)


@dataclass(frozen=True, slots=True)
class SessionAuthentication:
    """Authentication state stored inside the native Litestar session."""

    session_id: str
    binding_id: str
    account_id: str
    security_epoch: int
    authenticated_at: "datetime"
    expires_at: "datetime"

    def __post_init__(self) -> None:
        """Reject session payloads outside the shared epoch domain."""
        if not _valid_security_epoch(self.security_epoch):
            msg = "Session authentication security epoch is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """Application-owned authenticated-session registry projection."""

    session_id: str
    binding_id: str
    binding_digest: bytes = field(repr=False)
    account_id: str
    security_epoch: int
    created_at: "datetime"
    last_seen_at: "datetime"
    expires_at: "datetime"
    display_metadata: "Mapping[str, str]" = field(default=_EMPTY_DISPLAY_METADATA)

    def __post_init__(self) -> None:
        """Freeze caller-supplied display metadata."""
        if not _valid_security_epoch(self.security_epoch):
            msg = "Session record security epoch is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "display_metadata", MappingProxyType(dict(self.display_metadata)))


@dataclass(frozen=True, slots=True)
class CreateSessionCommand:
    """Candidate authenticated-session record for one atomic creation."""

    session_id: str
    binding_id: str
    binding_digest: bytes = field(repr=False)
    account_id: str
    security_epoch: int
    created_at: "datetime"
    expires_at: "datetime"
    display_metadata: "Mapping[str, str]" = field(default=_EMPTY_DISPLAY_METADATA)

    def __post_init__(self) -> None:
        """Freeze caller-supplied display metadata."""
        if not _valid_security_epoch(self.security_epoch):
            msg = "Session creation security epoch is invalid"
            raise ValueError(msg)
        object.__setattr__(self, "display_metadata", MappingProxyType(dict(self.display_metadata)))


@runtime_checkable
class SessionRegistry(Protocol):
    """Atomic authenticated-session inventory and revocation boundary."""

    async def create(self, command: CreateSessionCommand, *, event: "SecurityEvent") -> SessionRecord:
        """Create a registry record with its durable event."""
        ...  # pragma: no cover

    async def get(self, session_id: str) -> SessionRecord | None:
        """Load one current session record."""
        ...  # pragma: no cover

    async def list_for_account(self, account_id: str) -> "Sequence[SessionRecord]":
        """List safe session metadata for one account."""
        ...  # pragma: no cover

    async def touch(self, session_id: str, *, now: "datetime") -> SessionRecord | None:
        """Apply the implementation's bounded last-seen write policy."""
        ...  # pragma: no cover

    async def revoke(self, session_id: str, *, event: "SecurityEvent") -> bool:
        """Revoke one authenticated session atomically."""
        ...  # pragma: no cover

    async def revoke_sessions_for_account(self, account_id: str, *, event: "SecurityEvent") -> int:
        """Revoke every authenticated session for an account."""
        ...  # pragma: no cover

    async def revoke_other_sessions(self, account_id: str, session_id: str, *, event: "SecurityEvent") -> int:
        """Revoke all account sessions except the named current session."""
        ...  # pragma: no cover

    async def rebind(
        self, prior_session_id: str, command: CreateSessionCommand, *, event: "SecurityEvent"
    ) -> SessionRecord | None:
        """Revoke a prior record and create its replacement atomically."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class RotateRefreshCommand:
    """Candidate one-time refresh rotation passed to an atomic store."""

    token_id: str
    token_digest: bytes = field(repr=False)
    account_id: str
    family_id: str
    security_epoch: int
    successor_id: str
    successor_digest: bytes = field(repr=False)
    successor_expires_at: "datetime"
    family_expires_at: "datetime"
    sealed_receipt: bytes = field(repr=False)
    receipt_expires_at: "datetime"
    idempotency_digest: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Reject refresh candidates outside the shared epoch domain."""
        if not _valid_security_epoch(self.security_epoch):
            msg = "Refresh rotation security epoch is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RotateRefreshResult:
    """Atomic strict rotation, idempotent receipt, or replay outcome."""

    status: RefreshRotationStatus
    sealed_receipt: bytes | None = field(default=None, repr=False)
    family_revoked: bool = False

    def __post_init__(self) -> None:
        """Reject contradictory receipt and revocation outcomes."""
        receipt_status = self.status in {RefreshRotationStatus.ROTATED, RefreshRotationStatus.IDEMPOTENT_REPLAY}
        if receipt_status != (self.sealed_receipt is not None) or (receipt_status and self.family_revoked):
            msg = "Successful refresh rotation results require exactly one sealed receipt"
            raise ValueError(msg)
        revoked_status = self.status in {RefreshRotationStatus.REPLAY_DETECTED, RefreshRotationStatus.REVOKED}
        if revoked_status != self.family_revoked:
            msg = "Replay or revoked refresh results must report family revocation"
            raise ValueError(msg)


@runtime_checkable
class RefreshTokenFamilyStore(Protocol):
    """Atomic strict refresh-family rotation and revocation boundary."""

    async def rotate(
        self, command: RotateRefreshCommand, *, now: "datetime", event: "SecurityEvent"
    ) -> RotateRefreshResult:
        """Rotate once, replay one sealed receipt, or revoke on reuse."""
        ...  # pragma: no cover

    async def revoke_family(self, family_id: str, *, event: "SecurityEvent") -> bool:
        """Revoke one refresh-token family."""
        ...  # pragma: no cover

    async def revoke_for_account(self, account_id: str, *, event: "SecurityEvent") -> int:
        """Revoke every refresh family for an account."""
        ...  # pragma: no cover
