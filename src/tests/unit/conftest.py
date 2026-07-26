"""Session-scoped unit-test contracts."""

import pytest

from litestar_security.context import Principal


@pytest.fixture(scope="session")
def anonymous_principal() -> Principal[object]:
    """Return the immutable anonymous principal shared by unit tests."""
    return Principal.anonymous()
