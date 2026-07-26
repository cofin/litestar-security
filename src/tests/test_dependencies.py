from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from litestar import Litestar, get
from litestar.config.app import AppConfig
from litestar.testing import TestClient

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security.authentication import Authenticated, AuthenticationMechanism, PresentedCredential
from litestar_security.context import AuthenticationEvidence, Principal, SecurityContext

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection

    from litestar_security.plugin import CurrentUser, PrincipalDependency, SecurityContextDependency

_NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)


@dataclass(frozen=True)
class _User:
    name: str


class _Slot:
    name = "test"

    def extract(self, _connection: ASGIConnection[Any, Any, Any, Any]) -> PresentedCredential[str]:
        return PresentedCredential("credential")


class _Authenticator:
    name = "test"
    slot = "test"
    participates_by_default = True

    async def authenticate(
        self, _credential: str, _connection: ASGIConnection[Any, Any, Any, Any]
    ) -> Authenticated[str]:
        return Authenticated(
            claims="subject",
            evidence=AuthenticationEvidence(mechanism=self.name, slot=self.slot, authenticated_at=_NOW),
        )


class _Resolver:
    def __init__(self, principal: Principal[_User]) -> None:
        self.principal = principal

    async def resolve(self, _claims: str) -> Principal[_User]:
        return self.principal


def _plugin(principal: Principal[_User]) -> SecurityPlugin:
    return SecurityPlugin(
        SecurityConfig(
            slots=(_Slot(),),
            mechanisms=(AuthenticationMechanism(authenticator=_Authenticator(), resolver=_Resolver(principal)),),
        )
    )


def test_providers_are_explicitly_non_threaded_and_request_local() -> None:
    plugin = SecurityPlugin()
    app_config = plugin.on_app_init(AppConfig())

    for provider in app_config.dependencies.values():
        assert provider.sync_to_thread is False
        assert provider.use_cache is False


def test_anonymous_principal_and_security_context_injection() -> None:
    @get("/")
    async def handler(
        principal: PrincipalDependency[_User], security_context: SecurityContextDependency
    ) -> dict[str, bool]:
        return {
            "anonymous": not principal.is_authenticated,
            "typed_context": isinstance(security_context, SecurityContext),
        }

    with TestClient(Litestar(route_handlers=[handler], plugins=[SecurityPlugin()])) as client:
        response = client.get("/")

    assert response.json() == {"anonymous": True, "typed_context": True}


def test_application_user_and_current_user_injection() -> None:
    user = _User(name="Ada")

    @get("/")
    async def handler(
        principal: PrincipalDependency[_User],
        security_context: SecurityContextDependency,
        current_user: CurrentUser[_User],
    ) -> dict[str, object]:
        return {"id": principal.id, "user": current_user.name, "evidence": security_context.evidence[0].mechanism}

    plugin = _plugin(Principal(id="user-1", user=user))
    with TestClient(Litestar(route_handlers=[handler], plugins=[plugin])) as client:
        response = client.get("/")

    assert response.json() == {"id": "user-1", "user": "Ada", "evidence": "test"}


def test_service_principal_injection_and_current_user_failure() -> None:
    @get("/principal")
    async def principal_handler(principal: PrincipalDependency[_User]) -> dict[str, object]:
        return {"id": principal.id, "has_user": principal.has_user}

    @get("/user")
    async def user_handler(current_user: CurrentUser[_User]) -> str:
        return current_user.name

    plugin = _plugin(Principal(id="service-1"))
    with TestClient(Litestar(route_handlers=[principal_handler, user_handler], plugins=[plugin])) as client:
        principal_response = client.get("/principal")
        user_response = client.get("/user")

    assert principal_response.json() == {"id": "service-1", "has_user": False}
    assert user_response.status_code == 401
