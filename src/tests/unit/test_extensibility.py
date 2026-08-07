"""Cross-feature extension-boundary tests."""

import inspect
from datetime import datetime, timedelta, timezone
from threading import Event as ThreadEvent
from threading import Lock
from typing import Protocol

from anyio import CancelScope, CapacityLimiter, Event, create_task_group, from_thread
from anyio.lowlevel import checkpoint

import litestar_security.testing as testing_module
import litestar_security.workers as workers_module
from litestar_security.accounts import (
    LoginMethodStore,
    MFALoginChallenge,
    MFALoginChallengeStore,
    MFAStore,
    PasskeyStore,
    PasswordCredentialStore,
    RefreshTokenFamilyStore,
    RegistrationStore,
    StepUpStore,
    WebAuthnChallengeStore,
)
from litestar_security.providers.api_key import APIKeyStore
from litestar_security.providers.oauth import OAuthAccountStore, OAuthTransactionStore, OIDCSessionLogoutStore
from litestar_security.websocket import WebSocketConnectTokenStore

_ATOMIC_METHODS = {
    RegistrationStore: ("register",),
    PasswordCredentialStore: ("compare_and_replace_password", "replace_password_and_bump_epoch"),
    LoginMethodStore: ("revoke_login_method",),
    RefreshTokenFamilyStore: ("rotate",),
    MFAStore: ("advance_totp_counter", "consume_recovery_code"),
    OIDCSessionLogoutStore: ("consume_backchannel", "revoke_frontchannel"),
    MFALoginChallengeStore: ("consume",),
    WebAuthnChallengeStore: ("consume",),
    PasskeyStore: ("record_assertion",),
    OAuthTransactionStore: ("consume",),
    OAuthAccountStore: ("unlink_identity",),
    APIKeyStore: ("rotate",),
    StepUpStore: ("consume",),
    WebSocketConnectTokenStore: ("consume",),
}


def test_atomic_protocols_are_feature_owned_and_async() -> None:
    for protocol, methods in _ATOMIC_METHODS.items():
        assert issubclass(protocol, Protocol)
        assert protocol.__module__ != "litestar_security.testing"
        for method in methods:
            assert inspect.iscoroutinefunction(protocol.__dict__[method])


def test_capability_protocols_do_not_expose_generic_persistence_methods() -> None:
    for protocol in _ATOMIC_METHODS:
        assert not {"add", "update", "delete", "query", "transaction", "connection"}.intersection(protocol.__dict__)


async def test_mfa_login_challenge_reference_store_is_atomic_and_burns_mismatches() -> None:
    now = datetime(2026, 8, 3, tzinfo=timezone.utc)
    challenge = MFALoginChallenge(
        challenge_digest=b"d" * 32,
        account_id="account-1",
        security_epoch=0,
        client_key="client-1",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    store = testing_module.InMemoryMFALoginChallengeStore()

    assert isinstance(store, MFALoginChallengeStore)
    await store.put(challenge)

    assert await store.consume(b"d" * 32, account_id="other-account", security_epoch=0, now=now) is None
    assert await store.consume(b"d" * 32, account_id="account-1", security_epoch=0, now=now) is None

    winning_challenge = MFALoginChallenge(
        challenge_digest=b"e" * 32,
        account_id="account-1",
        security_epoch=0,
        client_key="client-1",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    await store.put(winning_challenge)
    outcomes: list[MFALoginChallenge | None] = []

    async def consume() -> None:
        outcomes.append(await store.consume(b"e" * 32, account_id="account-1", security_epoch=0, now=now))

    async with create_task_group() as task_group:
        task_group.start_soon(consume)
        task_group.start_soon(consume)

    assert sum(outcome is winning_challenge for outcome in outcomes) == 1
    assert outcomes.count(None) == 1


async def test_blocking_call_runner_enforces_its_capacity_limit() -> None:
    runner = workers_module.BlockingCallRunner(limiter=CapacityLimiter(1))
    first_started = Event()
    release = ThreadEvent()
    state_lock = Lock()
    active = 0
    maximum_active = 0
    completed: list[int] = []

    def operation(value: int) -> int:
        nonlocal active, maximum_active
        with state_lock:
            active += 1
            maximum_active = max(maximum_active, active)
        if value == 1:
            from_thread.run_sync(first_started.set)
        release.wait()
        with state_lock:
            active -= 1
        return value

    async def run(value: int) -> None:
        completed.append(await runner.run(operation, value))

    async with create_task_group() as task_group:
        task_group.start_soon(run, 1)
        await first_started.wait()
        task_group.start_soon(run, 2)
        await checkpoint()
        release.set()

    assert maximum_active == 1
    assert sorted(completed) == [1, 2]


async def test_blocking_call_runner_finishes_in_flight_mutation_before_cancellation() -> None:
    runner = workers_module.BlockingCallRunner(limiter=CapacityLimiter(1))
    started = Event()
    caller_finished = Event()
    release = ThreadEvent()
    scopes: list[CancelScope] = []
    mutations: list[str] = []

    def mutation() -> None:
        from_thread.run_sync(started.set)
        release.wait()
        mutations.append("committed")

    async def call() -> None:
        try:
            with CancelScope() as scope:
                scopes.append(scope)
                await runner.run(mutation)
        finally:
            caller_finished.set()

    async with create_task_group() as task_group:
        task_group.start_soon(call)
        await started.wait()
        scopes[0].cancel()
        await checkpoint()
        assert not caller_finished.is_set()
        release.set()

    assert mutations == ["committed"]
    assert caller_finished.is_set()
