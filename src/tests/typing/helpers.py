"""Positive strict-typing fixture for the public typing helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from litestar import Controller, Litestar, Router, get
from typing_extensions import assert_type

from litestar_security import (
    AuthorizationPredicate,
    CurrentUser,
    LitestarSessionHandle,
    NullSessionHandle,
    Principal,
    PrincipalDependency,
    SecurityContext,
    SecurityContextDependency,
    all_of,
    any_of,
    guard_any_of,
    mechanism,
    optional,
    public,
    required,
    requires_authenticated,
    requires_scope,
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


anonymous: PrincipalDependency[User] = Principal[User].anonymous()
no_session: SecurityContextDependency = SecurityContext(session=NullSessionHandle())
native_scope = cast("Scope", {"type": "http", "session": {}})
native_session: SecurityContextDependency = SecurityContext(session=LitestarSessionHandle(native_scope))

authorization_guard: AuthorizationPredicate = guard_any_of(requires_authenticated(), requires_scope("reports:read"))
public_metadata = {"auth": public()}


@get("/handler", auth=optional(required(mechanism("oidc", "reports:read"))), guards=[authorization_guard])
async def secured_handler() -> None:
    """Type-check policy metadata and guards at handler ownership."""


class SecureController(Controller):
    """Type-check controller ownership."""

    path = "/controller"
    opt = {"auth": all_of("session", "api_key")}  # noqa: RUF012 - Litestar controller options are class-owned
    guards = (requires_authenticated(),)

    @get("/resource", auth=any_of("session", "api_key"), guards=[requires_scope("resource:read")])
    async def resource(self) -> None:
        """Type-check an owned handler override."""


secure_router = Router(
    path="/router",
    route_handlers=[secured_handler],
    opt={"auth": required("session")},
    guards=[requires_authenticated()],
)
typed_app = Litestar(
    route_handlers=[secure_router, SecureController],
    opt={"auth": required()},
    guards=[requires_authenticated()],
    openapi_config=None,
)
