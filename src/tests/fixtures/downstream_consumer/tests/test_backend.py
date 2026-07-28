"""Installed-wheel conformance tests for the downstream backend."""

import pytest
from consumer_backend import MappingAPIKeyStore

from litestar_security.providers.api_key import APIKeyStore
from litestar_security.testing import assert_api_key_store_conformance


def test_backend_structurally_implements_the_public_protocol() -> None:
    assert isinstance(MappingAPIKeyStore(), APIKeyStore)


@pytest.mark.anyio
async def test_backend_passes_the_imported_conformance_scenario() -> None:
    await assert_api_key_store_conformance(MappingAPIKeyStore)
