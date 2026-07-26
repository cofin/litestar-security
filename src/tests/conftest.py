"""Shared test configuration."""

import pytest


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Use one async backend for the session."""
    return "asyncio"
