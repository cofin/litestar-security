"""Positive strict-typing fixture for the public typing helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, cast

from litestar import Controller, Litestar, Router, get
from litestar.di import NamedDependency  # noqa: TC002 - Litestar resolves handler annotations at runtime
from typing_extensions import assert_type

from litestar_security import (
    AuthenticationPolicy,
    AuthorizationPredicate,
    CurrentUser,
    LitestarSessionHandle,
    NullSessionHandle,
    Principal,
    PublicController,
    SecureController,
    SecurityContext,
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


async def handler(
    principal: NamedDependency[Principal[User]], security_context: NamedDependency[SecurityContext]
) -> None:
    """Use one signature for every principal/session state."""
    assert_type(principal, Principal[User])
    assert_type(security_context, SecurityContext)


def narrow_current_user(current_user: CurrentUser[User], principal: Principal[User]) -> None:
    """Prove current-user injection narrows while the principal remains honest."""
    assert_type(current_user, User)
    assert_type(principal.user, User | None)


anonymous: Principal[User] = Principal[User].anonymous()
no_session: SecurityContext = SecurityContext(session=NullSessionHandle())
native_scope = cast("Scope", {"type": "http", "session": {}})
native_session: SecurityContext = SecurityContext(session=LitestarSessionHandle(native_scope))

authorization_guard: AuthorizationPredicate = guard_any_of(requires_authenticated(), requires_scope("reports:read"))
public_metadata = {"auth": public()}


@get("/handler", auth=optional(required(mechanism("oidc", "reports:read"))), guards=[authorization_guard])
async def secured_handler() -> None:
    """Type-check policy metadata and guards at handler ownership."""


class OwnedOptController(Controller):
    """Type-check controller ownership."""

    path = "/controller"
    opt = {"auth": all_of("session", "api_key")}  # noqa: RUF012 - Litestar controller options are class-owned
    guards = (requires_authenticated(),)

    @get("/resource", auth=any_of("session", "api_key"), guards=[requires_scope("resource:read")])
    async def resource(self) -> None:
        """Type-check an owned handler override."""


class SecureAccounts(SecureController):
    """Type-check the typed auth attribute."""

    path = "/secure-accounts"
    auth: ClassVar[AuthenticationPolicy] = required("session")


class OpenStatus(PublicController):
    """Type-check the public default."""

    path = "/status"


secure_router = Router(
    path="/router",
    route_handlers=[secured_handler],
    opt={"auth": required("session")},
    guards=[requires_authenticated()],
)
typed_app = Litestar(
    route_handlers=[secure_router, OwnedOptController, SecureAccounts, OpenStatus],
    opt={"auth": required()},
    guards=[requires_authenticated()],
    openapi_config=None,
)
