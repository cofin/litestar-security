"""Shared test configuration."""

import os
import random
from collections.abc import Mapping
from types import MappingProxyType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from litestar_security.testing import FakeClock
from tests.fixtures import collaborators

# ``tests.fixtures.factories`` is the load-bearing entry: ``register_fixture``
# applies ``pytest.fixture`` at decoration time, so pytest only needs the module
# loaded as a plugin for the factory fixtures to resolve. ``polyfactory.pytest_plugin``
# exposes no ``pytest_*`` hooks and is not sufficient on its own, but polyfactory
# declares no ``pytest11`` entry point either, so a release that does add hooks
# would otherwise be skipped silently. This is legal in this file only because
# ``testpaths`` makes it an initial conftest: re-verify it if the import mode
# changes or this file moves.
pytest_plugins = ["polyfactory.pytest_plugin", "tests.fixtures.factories"]

# Defined once in the fixtures package and re-exported here under the name the
# whole tree uses. It matches the kit's own default instant, so a clock-driven
# backend and a default-constructed one agree on now.
FIXED_NOW = collaborators.FIXED_NOW


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Shuffle collection reproducibly when the release-order probe opts in."""
    seed = os.getenv("LITESTAR_SECURITY_TEST_SHUFFLE_SEED")
    if seed is not None:
        random.Random(seed).shuffle(items)  # noqa: S311 - deterministic test ordering, not security


@pytest.fixture
def clock() -> FakeClock:
    """Return one test-owned clock because ``advance()`` mutates it."""
    return FakeClock(FIXED_NOW)


def _pem_pair(private_key: object) -> tuple[bytes, bytes]:
    """Serialize one asymmetric test key as immutable PKCS8/SPKI bytes."""
    private_bytes = private_key.private_bytes(  # type: ignore[attr-defined]
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(  # type: ignore[attr-defined]
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_bytes, public_bytes


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Use one async backend for the session."""
    return "asyncio"


@pytest.fixture(scope="session")
def jwt_key_material() -> Mapping[str, tuple[bytes, bytes]]:
    """Return immutable signing and verification material for every JWT algorithm."""
    return MappingProxyType({
        "EdDSA": _pem_pair(ed25519.Ed25519PrivateKey.generate()),
        "ES256": _pem_pair(ec.generate_private_key(ec.SECP256R1())),
        "RS256": _pem_pair(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        "RS256_ALT": _pem_pair(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        "HS256": (b"test-only-hs256-secret-material-32-bytes", b"test-only-hs256-secret-material-32-bytes"),
        "ES384": _pem_pair(ec.generate_private_key(ec.SECP384R1())),
        "RS1024": _pem_pair(
            rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - rejection fixture
        ),
    })
