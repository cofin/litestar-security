"""Session-scoped unit-test contracts."""

from collections.abc import Mapping

import pytest

import litestar_security.accounts as accounts_module
from litestar_security.context import Principal
from litestar_security.providers.jwt import LocalKeyRing, SigningKey


@pytest.fixture(scope="session")
def anonymous_principal() -> Principal[object]:
    """Return the immutable anonymous principal shared by unit tests."""
    return Principal.anonymous()


@pytest.fixture(scope="session")
def local_key_ring(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> LocalKeyRing:
    """Return one explicit immutable local EdDSA key ring."""
    private_key, _ = jwt_key_material["EdDSA"]
    return LocalKeyRing(
        issuer="https://local.example",
        active_signing_key=SigningKey(key_id="local-key", algorithm="EdDSA", private_key=private_key),
    )


@pytest.fixture
def password_hasher() -> "accounts_module.Argon2PasswordHasher":
    """Return one request-local hasher because its limiter tracks mutable loans."""
    return accounts_module.Argon2PasswordHasher()
