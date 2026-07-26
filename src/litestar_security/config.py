"""Configuration for the Litestar Security plugin."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from litestar.middleware.session.base import BaseSessionBackend
    from litestar.types import Scope

    from litestar_security.authentication import AuthenticationMechanism, CredentialSlot, SecurityRuntimePlan

__all__ = ("SecurityConfig",)

UserT = TypeVar("UserT")


@dataclass(slots=True)
class SecurityConfig(Generic[UserT]):
    """Configure the per-application security runtime."""

    slots: Sequence[CredentialSlot[Any]] = ()
    mechanisms: Sequence[AuthenticationMechanism[Any, Any, UserT]] = ()
    require_default: bool = False
    session_backend: BaseSessionBackend[Any] | None = None
    plan_lookup: Callable[[Scope], SecurityRuntimePlan] | None = None

    def __post_init__(self) -> None:
        """Freeze ordered authentication collections."""
        self.slots = tuple(self.slots)
        self.mechanisms = tuple(self.mechanisms)
