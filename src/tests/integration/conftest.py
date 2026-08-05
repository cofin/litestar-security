"""Session-scoped integration-test configuration."""

import pytest

from litestar_security.config import SecurityConfig
from tests.fixtures import collaborators


@pytest.fixture(scope="session")
def empty_security_config() -> SecurityConfig[object]:
    """Return immutable empty mechanism collections for plugin tests."""
    return SecurityConfig()


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
