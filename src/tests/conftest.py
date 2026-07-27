"""Shared test configuration."""

from collections.abc import Mapping
from types import MappingProxyType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


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
