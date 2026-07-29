"""Unit tests for the deterministic aggregate security backend."""

from datetime import datetime, timedelta, timezone

import pytest
from anyio import create_task_group

from litestar_security.providers.api_key import APIKeyRecord
from litestar_security.providers.oauth import OAuthOperation, OAuthTransaction, SecretStr
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


@pytest.mark.parametrize("kwargs", [{"clock": object()}, {"identifiers": object()}, {"entropy": object()}])
def test_in_memory_backend_rejects_non_callable_sources(kwargs: dict[str, object]) -> None:
    with pytest.raises(TypeError, match="must be callable"):
        InMemorySecurityBackend(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("password_hash", ["", " "])
def test_in_memory_backend_rejects_blank_encoded_hash(password_hash: str) -> None:
    with pytest.raises(ValueError, match="password hash"):
        InMemorySecurityBackend(password_hash=password_hash)
    with pytest.raises(ValueError, match="password hash"):
        InMemorySecurityBackend(password_hash=object())  # type: ignore[arg-type]


def test_in_memory_backend_rejects_invalid_source_results() -> None:
    with pytest.raises(ValueError, match="naive"):
        InMemorySecurityBackend(clock=lambda: datetime(2026, 1, 1)).clock()  # noqa: DTZ001 - invalid clock fixture
    with pytest.raises(ValueError, match="identifier factory"):
        InMemorySecurityBackend(identifiers=lambda _namespace, _sequence: "").next_identifier("account")
    with pytest.raises(ValueError, match="identifier factory"):
        InMemorySecurityBackend(identifiers=lambda _namespace, _sequence: 1).next_identifier(  # type: ignore[arg-type]
            "account"
        )
    with pytest.raises(ValueError, match="length"):
        InMemorySecurityBackend().entropy(0)
    with pytest.raises(ValueError, match="entropy factory"):
        InMemorySecurityBackend(entropy=lambda _length: b"").entropy(4)
    with pytest.raises(ValueError, match="entropy factory"):
        InMemorySecurityBackend(entropy=lambda _length: "bad").entropy(4)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_in_memory_api_key_store_covers_duplicates_bounded_overlap_and_revoke() -> None:
    backend = InMemorySecurityBackend()
    current = APIKeyRecord(
        key_id="a2tra2tra2tra2tr", subject_id="subject-1", digest=b"d" * 32, expires_at=_NOW + timedelta(seconds=10)
    )
    replacement = _record("ZmZmZmZmZmZmZmZm")
    await backend.api_keys.create(current)
    with pytest.raises(ValueError, match="already exists"):
        await backend.api_keys.create(current)

    await backend.api_keys.rotate(
        current_key_id=current.key_id, replacement=replacement, overlap_until=_NOW + timedelta(seconds=30), now=_NOW
    )

    assert {record.key_id for record in backend.api_keys.records} == {current.key_id, replacement.key_id}
    assert (await backend.api_keys.get(current.key_id)).overlap_until == current.expires_at  # type: ignore[union-attr]
    await backend.api_keys.revoke(key_id=replacement.key_id, now=_NOW)
    assert (await backend.api_keys.get(replacement.key_id)).revoked_at == _NOW  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="does not exist"):
        await backend.api_keys.revoke(key_id="Z2dnZ2dnZ2dnZ2dn", now=_NOW)


@pytest.mark.anyio
async def test_in_memory_backend_controls_can_be_cleared() -> None:
    backend = InMemorySecurityBackend()
    backend.install_barrier("unused")
    backend.set_failpoint("api_key.get", RuntimeError("failure"))
    backend.clear_controls()

    assert await backend.api_keys.get("a2tra2tra2tra2tr") is None
    with pytest.raises(TypeError, match="requires an exception"):
        backend.set_failpoint("api_key.get", object())  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_in_memory_backend_default_oauth_protector_round_trips() -> None:
    backend = InMemorySecurityBackend()
    transaction = OAuthTransaction(
        state_digest=b"s" * 32,
        binding_digest=b"b" * 32,
        operation=OAuthOperation.LOGIN,
        provider="example",
        expected_issuer="https://issuer.example",
        redirect_uri="https://app.example/callback",
        return_to="/",
        requested_scopes=frozenset({"openid"}),
        pkce_verifier=SecretStr("v" * 43),
        nonce=SecretStr("n" * 43),
        expires_at=_NOW + timedelta(minutes=5),
    )
    await backend.oauth_transactions.create(transaction)

    consumed = await backend.oauth_transactions.consume(
        state_digest=transaction.state_digest,
        binding_digest=transaction.binding_digest,
        provider=transaction.provider,
        now=_NOW,
    )

    assert consumed == transaction
