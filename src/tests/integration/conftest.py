"""Session-scoped integration-test configuration."""

import pytest

from litestar_security.config import SecurityConfig


@pytest.fixture(scope="session")
def empty_security_config() -> SecurityConfig[object]:
    """Return immutable empty mechanism collections for plugin tests."""
    return SecurityConfig()
