"""Session-scoped integration-test configuration."""

from datetime import datetime, timezone
from typing import Any

import pytest
from litestar import Litestar, Request, get
from litestar.connection import ASGIConnection

from litestar_security import SecurityPlugin
from litestar_security.authentication import Authenticated, AuthenticationMechanism, PresentedCredential, public
from litestar_security.config import SecurityConfig
from litestar_security.context import AuthenticationEvidence, Principal
from tests.fixtures import collaborators


@get("/", auth=public())
async def _public_profile_handler(request: Request[Any, Any, Any]) -> dict[str, bool]:
    return {"anonymous": not request.user.is_authenticated}


@get("/")
async def _required_profile_handler(request: Request[Any, Any, Any]) -> dict[str, str | None]:
    return {"principal_id": request.user.id}


class _StaticCredentialSlot:
    name = "profile"

    def extract(self, _connection: ASGIConnection[Any, Any, Any, Any]) -> PresentedCredential[str]:
        return PresentedCredential("profile-credential")


class _StaticAuthenticator:
    name = "profile"
    slot = "profile"
    participates_by_default = True

    async def authenticate(
        self, _credential: str, _connection: ASGIConnection[Any, Any, Any, Any]
    ) -> Authenticated[str]:
        return Authenticated(
            claims="profile-user",
            evidence=AuthenticationEvidence(
                mechanism=self.name, slot=self.slot, authenticated_at=datetime(2026, 1, 1, tzinfo=timezone.utc)
            ),
        )


class _StaticResolver:
    async def resolve(self, claims: str) -> Principal[str]:
        return Principal(id=claims, user=claims)


@pytest.fixture(scope="session")
def empty_security_config() -> SecurityConfig[object]:
    """Return immutable empty mechanism collections for plugin tests."""
    return SecurityConfig()


@pytest.fixture(scope="session")
def public_profile_app() -> Litestar:
    """Return a session app whose public profile and collaborators are immutable."""
    return Litestar(route_handlers=[_public_profile_handler], openapi_config=None, plugins=[SecurityPlugin()])


@pytest.fixture(scope="session")
def required_profile_app() -> Litestar:
    """Return a session app whose required profile retains no request state."""
    mechanism = AuthenticationMechanism(authenticator=_StaticAuthenticator(), resolver=_StaticResolver())
    config = SecurityConfig(slots=(_StaticCredentialSlot(),), mechanisms=(mechanism,))
    return Litestar(route_handlers=[_required_profile_handler], openapi_config=None, plugins=[SecurityPlugin(config)])


@pytest.fixture
def oauth_provider() -> object:
    """Return one recording OAuth provider because it accumulates calls."""
    return collaborators.build_oauth_provider()


@pytest.fixture
def oauth_transport() -> object:
    """Return one OAuth transport because it consumes its queued responses."""
    return collaborators.build_oauth_transport()


@pytest.fixture
def revocation_source() -> object:
    """Return one WebSocket revocation source because published revocations mutate it."""
    return collaborators.build_revocation_source()
