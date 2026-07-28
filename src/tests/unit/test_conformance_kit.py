"""Unit tests for the framework-neutral public conformance kit."""

from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from litestar_security.providers.api_key import APIKeyRecord
from litestar_security.testing import (
    InMemorySecurityBackend,
    StoreConformanceFactories,
    assert_api_key_store_conformance,
    assert_security_backend_conformance,
)

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


@pytest.mark.anyio
async def test_api_key_conformance_accepts_the_reference_store_in_isolation() -> None:
    await assert_api_key_store_conformance(lambda: InMemorySecurityBackend(clock=lambda: _NOW).api_keys)


@pytest.mark.anyio
async def test_api_key_conformance_names_a_non_atomic_rotation_invariant() -> None:
    @dataclass
    class BrokenStore:
        records: dict[str, APIKeyRecord]

        async def get(self, key_id: str) -> APIKeyRecord | None:
            return self.records.get(key_id)

        async def create(self, record: APIKeyRecord) -> None:
            self.records[record.key_id] = record

        async def rotate(
            self, *, current_key_id: str, replacement: APIKeyRecord, overlap_until: datetime | None, now: datetime
        ) -> None:
            del current_key_id, overlap_until, now
            self.records[replacement.key_id] = replacement

        async def revoke(self, *, key_id: str, now: datetime) -> None:
            del now
            self.records.pop(key_id, None)

    with pytest.raises(AssertionError, match=r"APIKeyStore\.rotate.*one atomic winner"):
        await assert_api_key_store_conformance(lambda: BrokenStore({}))


@pytest.mark.anyio
async def test_aggregate_conformance_runs_only_supplied_feature_factories() -> None:
    calls: list[str] = []

    def api_keys() -> object:
        calls.append("api-key")
        return InMemorySecurityBackend(clock=lambda: _NOW).api_keys

    await assert_security_backend_conformance(StoreConformanceFactories(api_key_store=api_keys))

    assert calls
    assert set(calls) == {"api-key"}


def test_conformance_factories_are_frozen_and_slotted() -> None:
    factories = StoreConformanceFactories()

    with pytest.raises((AttributeError, TypeError)):
        factories.extra = lambda: None  # type: ignore[attr-defined]
