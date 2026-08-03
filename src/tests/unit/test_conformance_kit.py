"""Unit tests for the framework-neutral public conformance kit."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone

import pytest
from anyio import Event, fail_after

import litestar_security.testing as testing_module
from litestar_security.providers.api_key import APIKeyRecord, APIKeyStore
from litestar_security.testing import (
    InMemorySecurityBackend,
    StoreConformanceFactories,
    _single_winner,  # pyright: ignore[reportPrivateUsage] - T1 verifies the private contender harness directly
    assert_api_key_store_conformance,
    assert_security_backend_conformance,
)

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


@dataclass
class _ControlledStore:
    records: dict[str, APIKeyRecord]
    persist_successor: bool = True
    revoke_current: bool = True
    rotated: bool = False

    async def get(self, key_id: str) -> APIKeyRecord | None:
        return self.records.get(key_id)

    async def create(self, record: APIKeyRecord) -> None:
        self.records[record.key_id] = record

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyRecord, overlap_until: datetime | None, now: datetime
    ) -> None:
        if self.rotated:
            raise ValueError
        self.rotated = True
        if self.revoke_current:
            self.records[current_key_id] = replace(
                self.records[current_key_id], revoked_at=now, overlap_until=overlap_until
            )
        if self.persist_successor:
            self.records[replacement.key_id] = replacement

    async def revoke(self, *, key_id: str, now: datetime) -> None:
        self.records[key_id] = replace(self.records[key_id], revoked_at=now)


@pytest.mark.anyio
async def test_single_winner_counts_only_successful_contenders() -> None:
    release = Event()
    started = 0

    def contender(*, outcome: bool) -> Callable[[], Awaitable[bool]]:
        async def attempt() -> bool:
            nonlocal started
            started += 1
            if started == 3:
                release.set()
            await release.wait()
            return outcome

        return attempt

    with fail_after(1):
        assert await _single_winner((contender(outcome=True), contender(outcome=False), contender(outcome=True))) == 2


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

    def api_keys() -> APIKeyStore:
        calls.append("api-key")
        return InMemorySecurityBackend(clock=lambda: _NOW).api_keys

    await assert_security_backend_conformance(StoreConformanceFactories(api_key_store=api_keys))

    assert calls
    assert set(calls) == {"api-key"}


def test_conformance_factories_are_frozen_and_slotted() -> None:
    factories = StoreConformanceFactories()

    with pytest.raises((AttributeError, TypeError)):
        factories.extra = lambda: None  # type: ignore[attr-defined]


def test_testing_surface_is_explicit_and_stable() -> None:
    assert testing_module.__all__ == (
        "BackendBarrier",
        "BackendEvent",
        "FakeClock",
        "FakeOAuthHTTPTransport",
        "FakeOAuthProvider",
        "InMemoryAPIKeyStore",
        "InMemoryLocalAccountStore",
        "InMemoryMFALoginChallengeStore",
        "InMemoryMFAStore",
        "InMemoryPasskeyStore",
        "InMemorySecurityBackend",
        "InMemoryStepUpStore",
        "InMemoryWebAuthnChallengeStore",
        "MemoryOAuthAccountStore",
        "MemoryOAuthTransactionStore",
        "MemoryTokenVault",
        "OAuthHTTPRequest",
        "StoreConformanceFactories",
        "assert_api_key_store_conformance",
        "assert_security_backend_conformance",
    )


@pytest.mark.anyio
async def test_conformance_detects_shared_factory_state() -> None:
    shared = _ControlledStore({})

    with pytest.raises(AssertionError, match="factory invariant"):
        await assert_api_key_store_conformance(lambda: shared)


@pytest.mark.anyio
async def test_conformance_detects_non_isolated_factory_storage() -> None:
    shared_records: dict[str, APIKeyRecord] = {}

    with pytest.raises(AssertionError, match="create/get isolation invariant"):
        await assert_api_key_store_conformance(lambda: _ControlledStore(shared_records))


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("persist_successor", "revoke_current", "invariant"),
    [(False, True, "partial-write invariant"), (True, False, "current-state invariant")],
)
async def test_conformance_detects_partial_rotation_states(
    persist_successor: bool,  # noqa: FBT001 - parametrized broken-store control
    revoke_current: bool,  # noqa: FBT001 - parametrized broken-store control
    invariant: str,
) -> None:
    with pytest.raises(AssertionError, match=invariant):
        await assert_api_key_store_conformance(
            lambda: _ControlledStore({}, persist_successor=persist_successor, revoke_current=revoke_current)
        )


@pytest.mark.anyio
async def test_empty_aggregate_conformance_requires_no_unrelated_store() -> None:
    await assert_security_backend_conformance(StoreConformanceFactories())
