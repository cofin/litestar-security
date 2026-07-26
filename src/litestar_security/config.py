"""Configuration for the Litestar Security plugin."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

from litestar.exceptions import ImproperlyConfiguredException
from litestar.middleware.session.base import BaseSessionBackend
from litestar.types import Scope

from litestar_security.authentication import (
    AuthenticationMechanism,
    AuthenticationPolicy,
    CredentialSlot,
    SecurityRuntimePlan,
    required,
)

__all__ = ("SecurityConfig",)

UserT = TypeVar("UserT")


@dataclass(slots=True)
class SecurityConfig(Generic[UserT]):
    """Configure the per-application security runtime."""

    slots: Sequence[CredentialSlot[Any]] = ()
    mechanisms: Sequence[AuthenticationMechanism[Any, Any, UserT]] = ()
    default_policy: AuthenticationPolicy = field(default_factory=required)
    openapi_policy: AuthenticationPolicy | None = None
    max_openapi_combinations: int = 32
    require_default: bool = False
    session_backend: BaseSessionBackend[Any] | None = None
    plan_lookup: Callable[[Scope], SecurityRuntimePlan] | None = None

    def __post_init__(self) -> None:
        """Freeze ordered authentication collections."""
        if self.max_openapi_combinations < 1:
            msg = "max_openapi_combinations must be positive"
            raise ImproperlyConfiguredException(detail=msg)
        self.slots = tuple(self.slots)
        self.mechanisms = tuple(self.mechanisms)
