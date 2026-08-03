"""Handshake, binding, and refresh contracts for a secured connection.

These are the value types and application-implemented ports the rest of the
package is expressed in, so they sit below configuration.
"""

from dataclasses import dataclass, field
from typing import Protocol, TypeVar, runtime_checkable

from litestar_security.context import AuthorizationSnapshot, Principal
from litestar_security.websocket._internal import _strict_text

__all__ = ("AuthorizationSnapshotRefresher", "WebSocketBinding", "WebSocketHandshake", "WebSocketRevocationSource")

UserT = TypeVar("UserT")


@dataclass(frozen=True, slots=True)
class WebSocketHandshake:
    """Describe credential transports presented by one WebSocket handshake."""

    origin: str | None
    uses_cookie_credentials: bool
    uses_authorization_header: bool
    connect_token: str | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class WebSocketBinding:
    """Secret-free identity and route binding supplied to revocation hooks."""

    connection_id: str
    subject_id: str
    credential_ids: frozenset[str]
    session_id: str | None
    route_name: str

    def __post_init__(self) -> None:
        """Normalize stable binding identifiers."""
        if (
            not _strict_text(self.connection_id)
            or not _strict_text(self.subject_id)
            or not _strict_text(self.route_name)
            or any(not _strict_text(value) for value in self.credential_ids)
            or (self.session_id is not None and not _strict_text(self.session_id))
        ):
            message = "WebSocket revocation binding is invalid"
            raise ValueError(message)
        object.__setattr__(self, "credential_ids", frozenset(self.credential_ids))


@runtime_checkable
class WebSocketRevocationSource(Protocol):
    """Event-driven application hook that returns when a binding is revoked."""

    async def wait(self, binding: WebSocketBinding) -> None:
        """Wait without polling until the supplied connection binding is revoked."""
        ...  # pragma: no cover


@runtime_checkable
class AuthorizationSnapshotRefresher(Protocol[UserT]):
    """Application hook returning one detached immutable authorization snapshot."""

    async def refresh(
        self, *, principal: Principal[UserT], previous: AuthorizationSnapshot, route_name: str
    ) -> AuthorizationSnapshot:
        """Resolve and return the next detached snapshot."""
        ...  # pragma: no cover
