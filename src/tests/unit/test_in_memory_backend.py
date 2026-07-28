"""Unit tests for the deterministic aggregate security backend."""

from datetime import datetime, timedelta, timezone

import pytest
from anyio import create_task_group

from litestar_security.providers.api_key import APIKeyRecord
from litestar_security.testing import InMemorySecurityBackend

_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)


def _record(key_id: str) -> APIKeyRecord:
    return APIKeyRecord(key_id=key_id, subject_id="subject-1", digest=b"d" * 32)


def test_in_memory_backend_defaults_are_deterministic_and_isolated() -> None:
    first = InMemorySecurityBackend()
    second = InMemorySecurityBackend()

    assert first.clock() == second.clock()
    assert first.next_identifier("account") == second.next_identifier("account") == "account-0001"
    assert first.entropy(4) == second.entropy(4) == bytes(range(4))
    assert first.password_hash == second.password_hash
    assert first.api_keys is not second.api_keys
    assert first.mfa is not second.mfa


def test_in_memory_backend_accepts_injected_deterministic_sources() -> None:
    test_hash = "$test$injected"
    backend = InMemorySecurityBackend(
        clock=lambda: _NOW,
        identifiers=lambda namespace, sequence: f"{namespace}:{sequence}",
        entropy=lambda length: b"x" * length,
        password_hash=test_hash,
    )

    assert backend.clock() is _NOW
    assert backend.next_identifier("session") == "session:1"
    assert backend.entropy(3) == b"xxx"
    assert backend.password_hash == test_hash


@pytest.mark.anyio
async def test_in_memory_api_key_store_has_one_atomic_rotation_winner() -> None:
    backend = InMemorySecurityBackend(clock=lambda: _NOW)
    current = _record("a2tra2tra2tra2tr")
    first = _record("ZmZmZmZmZmZmZmZm")
    second = _record("Z2dnZ2dnZ2dnZ2dn")
    await backend.api_keys.create(current)
    outcomes: list[str] = []

    async def rotate(replacement: APIKeyRecord) -> None:
        try:
            await backend.api_keys.rotate(
                current_key_id=current.key_id,
                replacement=replacement,
                overlap_until=_NOW + timedelta(seconds=30),
                now=_NOW,
            )
        except ValueError:
            outcomes.append("conflict")
        else:
            outcomes.append("rotated")

    async with create_task_group() as task_group:
        task_group.start_soon(rotate, first)
        task_group.start_soon(rotate, second)

    assert sorted(outcomes) == ["conflict", "rotated"]
    assert backend.call_counts["api_key.rotate"] == 2
    assert all("digest" not in event.details for event in backend.events)


@pytest.mark.anyio
async def test_in_memory_backend_barrier_and_failpoint_are_deterministic() -> None:
    backend = InMemorySecurityBackend()
    barrier = backend.install_barrier("api_key.create")
    record = _record("a2tra2tra2tra2tr")
    completed: list[None] = []

    async def create() -> None:
        completed.append(await backend.api_keys.create(record))

    async with create_task_group() as task_group:
        task_group.start_soon(create)
        await barrier.reached.wait()
        assert completed == []
        barrier.release.set()

    backend.set_failpoint("api_key.get", RuntimeError("injected failure"))
    with pytest.raises(RuntimeError, match="injected failure"):
        await backend.api_keys.get(record.key_id)

    assert backend.call_counts == {"api_key.create": 1, "api_key.get": 1}
    assert [event.operation for event in backend.events] == ["api_key.create", "api_key.get"]


def test_in_memory_backend_diagnostics_are_immutable_snapshots() -> None:
    backend = InMemorySecurityBackend()
    counts = backend.call_counts
    events = backend.events

    with pytest.raises(TypeError):
        counts["other"] = 1  # type: ignore[index]
    assert events == ()
