"""Positive strict-typing fixture for the public runtime foundation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, assert_type, cast

from litestar_security import (
    CurrentUser,
    LitestarSessionHandle,
    NullSessionHandle,
    Principal,
    PrincipalDependency,
    SecurityContext,
    SecurityContextDependency,
)

if TYPE_CHECKING:
    from litestar.types import Scope


@dataclass(frozen=True)
class User:
    """Application user used by the fixture."""

    id: str


async def handler(principal: PrincipalDependency[User], security_context: SecurityContextDependency) -> None:
    """Use one signature for every principal/session state."""
    assert_type(principal, Principal[User])
    assert_type(security_context, SecurityContext)


def narrow_current_user(current_user: CurrentUser[User], principal: Principal[User]) -> None:
    """Prove current-user injection narrows while the principal remains honest."""
    assert_type(current_user, User)
    assert_type(principal.user, User | None)


anonymous: PrincipalDependency[User] = Principal.anonymous()
no_session: SecurityContextDependency = SecurityContext(session=NullSessionHandle())
native_scope = cast("Scope", {"type": "http", "session": {}})
native_session: SecurityContextDependency = SecurityContext(session=LitestarSessionHandle(native_scope))
