from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from importlib import import_module
from threading import Event as ThreadEvent
from threading import Lock as ThreadLock
from threading import Thread
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from anyio import Event, create_task_group, fail_after, to_thread
from anyio import run as anyio_run
from litestar.exceptions import HTTPException, ImproperlyConfiguredException, TooManyRequestsException
from litestar.stores.memory import MemoryStore

import litestar_security.accounts as accounts_module
import litestar_security.accounts._rate_limits as rate_limits_module
import litestar_security.accounts.controllers._local as controllers_module
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from tests.fixtures.accounts import (
    AsyncOutcome,
    CollectingSink,
    ExplosiveHeaders,
    FailingSink,
    InterleavingStore,
    LifecycleStore,
    LocalAccessStore,
    ObservingLimiter,
    PasswordHasher,
    RaisingLimiter,
    ScriptedLimiter,
    lifecycle_account,
    local_access_account,
    memory_limiter,
    rate_limit_guard,
    refresh_service,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)


async def _assert_http_exception(
    awaitable: Awaitable[object], exception_type: type[HTTPException], *, status_code: int, detail: str
) -> HTTPException:
    with pytest.raises(exception_type) as exc_info:
        await awaitable
    assert exc_info.value.status_code == status_code
    assert exc_info.value.detail == detail
    return exc_info.value


def test_refresh_codec_rejects_runtime_non_text_token() -> None:
    codec = accounts_module.RefreshTokenCodec(pepper=b"p" * 32)
    assert isinstance(codec.verify(object()), InvalidCredentials)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("limit", "window"),
    [
        (0, timedelta(minutes=1)),
        (True, timedelta(minutes=1)),
        (10_000_000, timedelta(minutes=1)),
        (10, timedelta(0)),
        (10, timedelta(days=2)),
        (10, timedelta(seconds=1, microseconds=1)),
        (10, cast("Any", 60)),
    ],
)
def test_rate_limit_policy_rejects_unbounded_budgets(limit: object, window: object) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        accounts_module.RateLimitPolicy(limit=cast("Any", limit), window=cast("Any", window))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"operation": " "},
        {"operation": "local.login", "client_key": " "},
        {"operation": "local.login", "subject_digest": "x" * 513},
        {"operation": "local.login", "cost": 0},
        {"operation": "local.login", "cost": True},
    ],
)
def test_rate_limit_request_rejects_unbounded_bucket_keys(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="Rate limit"):
        accounts_module.RateLimitAttempt(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"allowed": cast("Any", 1)},
        {"allowed": False, "retry_after": 0},
        {"allowed": False, "retry_after": cast("Any", "5")},
        {"allowed": True, "retry_after": 5},
    ],
)
def test_rate_limit_decision_requires_a_retry_hint_only_on_denial(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"(?i)rate limit"):
        accounts_module.RateLimitDecision(**kwargs)


async def test_unlimited_rate_limiter_allows_every_attempt() -> None:
    decision = await accounts_module.UnlimitedRateLimiter().acquire(
        accounts_module.RateLimitAttempt(operation="local.login")
    )
    assert decision == accounts_module.RateLimitDecision(allowed=True)


@pytest.mark.parametrize("forwarded_for", ["203.0.113.9, 10.0.0.1", "198.51.100.1, 203.0.113.9, 10.0.0.1"])
def test_forwarded_client_key_uses_only_trusted_proxy_hops(forwarded_for: str) -> None:
    extractor = accounts_module.forwarded_client_key(trusted_proxies={"10.0.0.0/8"})
    connection = cast(
        "Any", SimpleNamespace(client=SimpleNamespace(host="10.0.0.5"), headers={"x-forwarded-for": forwarded_for})
    )

    assert extractor(connection) == "203.0.113.9"


@pytest.mark.parametrize("peer", ["203.0.113.8", "unparseable-peer"])
def test_forwarded_client_key_ignores_spoofed_header_from_an_untrusted_peer(peer: str) -> None:
    extractor = accounts_module.forwarded_client_key(trusted_proxies={"10.0.0.0/8"})
    connection = cast("Any", SimpleNamespace(client=SimpleNamespace(host=peer), headers=ExplosiveHeaders()))

    assert extractor(connection) == peer


def test_forwarded_client_key_returns_none_when_the_connection_has_no_peer() -> None:
    extractor = accounts_module.forwarded_client_key(trusted_proxies={"10.0.0.0/8"})

    assert extractor(cast("Any", SimpleNamespace(client=None, headers={}))) is None


def test_forwarded_client_key_normalizes_the_configured_header_name() -> None:
    extractor = accounts_module.forwarded_client_key(trusted_proxies={"10.0.0.0/8"}, header=" X-Client-Forwarded-For ")
    connection = cast(
        "Any",
        SimpleNamespace(client=SimpleNamespace(host="10.0.0.5"), headers={"x-client-forwarded-for": "203.0.113.9"}),
    )

    assert extractor(connection) == "203.0.113.9"


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"trusted_proxies": set()}, "at least one trusted proxy"),
        ({"trusted_proxies": {"not-a-cidr"}}, "CIDR networks"),
        ({"trusted_proxies": {"10.0.0.0/8"}, "max_hops": True}, "positive integer"),
        ({"trusted_proxies": {"10.0.0.0/8"}, "max_hops": 0}, "positive integer"),
        ({"trusted_proxies": {"10.0.0.0/8"}, "header": "  "}, "nonempty header name"),
    ],
)
def test_forwarded_client_key_validates_its_configuration(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.forwarded_client_key(**cast("Any", kwargs))


@pytest.mark.parametrize(
    ("peer", "header", "expected"),
    [
        ("::ffff:10.0.0.5", "203.0.113.9, 10.0.0.1", "203.0.113.9"),
        ("10.0.0.5", "203.0.113.9, malformed", "10.0.0.5"),
        ("unparseable-peer", "203.0.113.9", "unparseable-peer"),
    ],
)
def test_forwarded_client_key_normalizes_addresses_and_falls_back_safely(peer: str, header: str, expected: str) -> None:
    extractor = accounts_module.forwarded_client_key(trusted_proxies={"10.0.0.0/8"})
    connection = cast("Any", SimpleNamespace(client=SimpleNamespace(host=peer), headers={"x-forwarded-for": header}))

    assert extractor(connection) == expected


@pytest.mark.parametrize("headers", [{}, {"x-forwarded-for": "10.0.0.1, 10.0.0.2"}])
def test_forwarded_client_key_falls_back_when_no_external_hop_is_available(headers: dict[str, str]) -> None:
    extractor = accounts_module.forwarded_client_key(trusted_proxies={"10.0.0.0/8"})
    connection = cast("Any", SimpleNamespace(client=SimpleNamespace(host="10.0.0.5"), headers=headers))

    assert extractor(connection) == "10.0.0.5"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"store_name": " "},
        {"store": cast("Any", object())},
        {"clock": cast("Any", object())},
        {"policies": {" ": accounts_module.RateLimitPolicy(limit=1, window=timedelta(minutes=1))}},
        {"policies": {"local.login": cast("Any", object())}},
    ],
)
def test_store_rate_limiter_validates_its_configuration(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        accounts_module.StoreRateLimiter(**kwargs)


def test_store_rate_limiter_binds_only_a_native_store() -> None:
    limiter = accounts_module.StoreRateLimiter()
    with pytest.raises(ImproperlyConfiguredException):
        limiter.bind(cast("Any", object()))
    assert limiter.store is None


async def test_store_rate_limiter_allows_unconfigured_operations_and_fails_closed_without_a_store() -> None:
    limiter = memory_limiter()
    assert await limiter.acquire(accounts_module.RateLimitAttempt(operation="local.unbudgeted")) == (
        accounts_module.RateLimitDecision(allowed=True)
    )
    unbound = accounts_module.StoreRateLimiter()
    with pytest.raises(RuntimeError, match="store has not been resolved"):
        await unbound.acquire(accounts_module.RateLimitAttempt(operation="local.login", client_key="1.1.1.1"))


async def test_store_rate_limiter_denies_after_the_window_budget_and_recovers_next_window() -> None:
    moment = [datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)]
    limiter = memory_limiter(clock=lambda: moment[0])
    request = accounts_module.RateLimitAttempt(operation="local.login", client_key="1.1.1.1")
    decisions = [await limiter.acquire(request) for _ in range(11)]

    assert [decision.allowed for decision in decisions] == [True] * 10 + [False]
    assert decisions[-1].retry_after == 300

    moment[0] = moment[0] + timedelta(minutes=5)
    assert (await limiter.acquire(request)).allowed


async def test_store_rate_limiter_serializes_concurrent_single_bucket_acquires() -> None:
    limiter = accounts_module.StoreRateLimiter(
        policies={"concurrent": accounts_module.RateLimitPolicy(limit=5, window=timedelta(minutes=1))},
        store=InterleavingStore(),
    )
    request = accounts_module.RateLimitAttempt(operation="concurrent", client_key="shared")
    decisions: list[accounts_module.RateLimitDecision] = []

    async def acquire() -> None:
        decisions.append(await limiter.acquire(request))

    async with create_task_group() as task_group:
        for _ in range(20):
            task_group.start_soon(acquire)

    assert sum(decision.allowed for decision in decisions) == 5


async def test_store_rate_limiter_serializes_concurrent_shared_store_acquires() -> None:
    store = InterleavingStore()
    policies = {"concurrent": accounts_module.RateLimitPolicy(limit=5, window=timedelta(minutes=1))}
    first_limiter = accounts_module.StoreRateLimiter(policies=policies, store=store)
    second_limiter = accounts_module.StoreRateLimiter(policies=policies, store=store)
    request = accounts_module.RateLimitAttempt(operation="concurrent", client_key="shared")
    decisions: list[accounts_module.RateLimitDecision] = []

    async def acquire(limiter: accounts_module.StoreRateLimiter) -> None:
        decisions.append(await limiter.acquire(request))

    async with create_task_group() as task_group:
        for index in range(20):
            task_group.start_soon(acquire, first_limiter if index % 2 else second_limiter)

    assert sum(decision.allowed for decision in decisions) == 5


async def test_process_rate_limit_lock_releases_after_cancellation() -> None:
    lock = ThreadLock()
    entered = Event()
    blocked = Event()

    async def hold() -> None:
        async with rate_limits_module._hold_process_rate_limit_lock(lock):  # noqa: SLF001 - verify cleanup
            entered.set()
            await blocked.wait()

    async with create_task_group() as task_group:
        task_group.start_soon(hold)
        await entered.wait()
        task_group.cancel_scope.cancel()

    assert lock.acquire(blocking=False)
    lock.release()


async def test_process_rate_limit_lock_cancels_promptly_while_waiting() -> None:
    lock = ThreadLock()
    assert lock.acquire(blocking=False)
    started = Event()
    entered = Event()

    async def wait_for_lock() -> None:
        started.set()
        async with rate_limits_module._hold_process_rate_limit_lock(lock):  # noqa: SLF001 - cancellation regression
            entered.set()

    with fail_after(1):
        async with create_task_group() as task_group:
            task_group.start_soon(wait_for_lock)
            await started.wait()
            task_group.cancel_scope.cancel()

    assert not entered.is_set()
    assert not lock.acquire(blocking=False)
    lock.release()


def test_process_rate_limit_lock_supports_separate_event_loop_threads() -> None:
    lock = ThreadLock()
    first_entered = ThreadEvent()
    second_started = ThreadEvent()
    second_entered = ThreadEvent()
    release_first = ThreadEvent()
    failures: list[BaseException] = []

    async def first() -> None:
        async with rate_limits_module._hold_process_rate_limit_lock(lock):  # noqa: SLF001 - cross-loop regression
            first_entered.set()
            await to_thread.run_sync(release_first.wait)

    async def second() -> None:
        second_started.set()
        async with rate_limits_module._hold_process_rate_limit_lock(lock):  # noqa: SLF001 - cross-loop regression
            second_entered.set()

    def run(target: Callable[[], Awaitable[None]]) -> None:
        try:
            anyio_run(target)
        except BaseException as error:  # noqa: BLE001 - propagate thread failures through the parent test
            failures.append(error)

    first_thread = Thread(target=run, args=(first,), daemon=True)
    second_thread = Thread(target=run, args=(second,), daemon=True)
    try:
        first_thread.start()
        assert first_entered.wait(timeout=2)
        second_thread.start()
        assert second_started.wait(timeout=2)
        assert not second_entered.is_set()
    finally:
        release_first.set()
        first_thread.join(timeout=2)
        second_thread.join(timeout=2)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert not failures
    assert second_entered.is_set()


async def test_store_rate_limiter_serializes_each_multi_bucket_acquire() -> None:
    consumed: list[str] = []
    limiter = ObservingLimiter(
        policies={"concurrent": accounts_module.RateLimitPolicy(limit=5, window=timedelta(minutes=1))},
        store=InterleavingStore(),
        consumed=consumed,
    )
    first = accounts_module.RateLimitAttempt(operation="concurrent", client_key="client-a", subject_digest="subject-a")
    second = accounts_module.RateLimitAttempt(operation="concurrent", client_key="client-b", subject_digest="subject-b")

    async with create_task_group() as task_group:
        task_group.start_soon(limiter.acquire, first)
        task_group.start_soon(limiter.acquire, second)

    assert consumed in (
        ["client-a", "subject-a", "client-b", "subject-b"],
        ["client-b", "subject-b", "client-a", "subject-a"],
    )


async def test_store_rate_limiter_budgets_password_verify_by_default() -> None:
    limiter = memory_limiter()
    request = accounts_module.RateLimitAttempt(operation="local.password.verify", client_key="1.1.1.1")
    decisions = [await limiter.acquire(request) for _ in range(11)]

    assert [decision.allowed for decision in decisions] == [True] * 10 + [False]


async def test_store_rate_limiter_fails_closed_on_an_unreadable_counter() -> None:
    store = MemoryStore()
    limiter = accounts_module.StoreRateLimiter(store=store)
    request = accounts_module.RateLimitAttempt(operation="local.login", client_key="1.1.1.1")
    await limiter.acquire(request)
    key = next(iter(store._store))  # noqa: SLF001 - assert the stored counter shape directly
    await store.set(key, b"not-a-number")

    with pytest.raises(RuntimeError, match="counter is unreadable"):
        await limiter.acquire(request)


async def test_store_rate_limiter_denies_when_either_bucket_is_exhausted() -> None:
    limiter = memory_limiter()
    for _ in range(10):
        await limiter.acquire(accounts_module.RateLimitAttempt(operation="local.login", client_key="shared"))

    fresh_subject = accounts_module.RateLimitAttempt(
        operation="local.login", client_key="shared", subject_digest="unused-digest"
    )
    decision = await limiter.acquire(fresh_subject)

    assert not decision.allowed


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limiter": cast("Any", object())},
        {"pepper": b"short"},
        {"events": cast("Any", object())},
        {"clock": cast("Any", object())},
        {"event_ids": cast("Any", object())},
    ],
)
def test_rate_limit_guard_validates_its_ports(kwargs: dict[str, Any]) -> None:
    base: dict[str, Any] = {"limiter": accounts_module.UnlimitedRateLimiter(), "pepper": b"p" * 32}
    with pytest.raises(ImproperlyConfiguredException):
        accounts_module.RateLimitGuard(**{**base, **kwargs})


def test_rate_limit_guard_digests_never_carry_the_identifier() -> None:
    guard = rate_limit_guard(accounts_module.UnlimitedRateLimiter())

    digest = guard.subject_digest("user@example.com")

    assert "user@example.com" not in digest
    assert digest == guard.subject_digest("user@example.com")
    assert digest != guard.subject_digest("other@example.com")
    assert digest != rate_limit_guard(accounts_module.UnlimitedRateLimiter(), pepper=b"q" * 32).subject_digest(
        "user@example.com"
    )


@pytest.mark.parametrize("limiter", [RaisingLimiter(), ScriptedLimiter(cast("Any", object()))])
async def test_rate_limit_guard_fails_closed_when_the_limiter_is_unusable(limiter: object) -> None:
    outcome = await rate_limit_guard(limiter).check("local.login", client_key="1.1.1.1")

    assert isinstance(outcome, VerificationUnavailable)


async def test_rate_limit_guard_reports_denials_and_emits_one_account_free_event() -> None:
    sink = CollectingSink()
    guard = rate_limit_guard(
        ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=42)),
        events=sink,
        event_ids=lambda: "event-1",
    )

    outcome = await guard.check("local.login", client_key="1.1.1.1", identifier="user@example.com")

    assert outcome == accounts_module.RateLimited(retry_after=42)
    assert [(event.operation, event.outcome, event.account_id) for event in sink.events] == [
        ("local.login", "rate_limited", None)
    ]


async def test_rate_limit_guard_allows_and_passes_a_digested_subject() -> None:
    limiter = ScriptedLimiter(accounts_module.RateLimitDecision(allowed=True))
    guard = rate_limit_guard(limiter)

    assert await guard.check("local.login", client_key="1.1.1.1", identifier="user@example.com") is None
    assert limiter.requests[0].subject_digest == guard.subject_digest("user@example.com")
    assert limiter.requests[0].client_key == "1.1.1.1"


async def test_rate_limit_guard_logs_unbuildable_denial_events_without_changing_the_denial(
    caplog: pytest.LogCaptureFixture,
) -> None:
    guard = rate_limit_guard(
        ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=1)),
        clock=cast("Any", lambda: None),
    )

    outcome = await guard.check("local.login", client_key="1.1.1.1")

    assert outcome == accounts_module.RateLimited(retry_after=1)
    assert "Rate limit event could not be built" in caplog.text


async def test_rate_limit_guard_survives_a_failing_denial_sink(caplog: pytest.LogCaptureFixture) -> None:
    guard = rate_limit_guard(
        ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=1)), events=FailingSink()
    )

    outcome = await guard.check("local.login", client_key="1.1.1.1")

    assert outcome == accounts_module.RateLimited(retry_after=1)
    assert "Security event sink failed for local.login" in caplog.text


def test_validate_rate_limits_rejects_a_foreign_guard() -> None:
    rate_limits_module.validate_rate_limits(None, name="Service")
    with pytest.raises(ImproperlyConfiguredException, match="Service rate limits"):
        rate_limits_module.validate_rate_limits(object(), name="Service")


def _raising_normalizer(_identifier: str) -> str:
    msg = "normalizer down"
    raise RuntimeError(msg)


def _denyingrate_limit_guard(**kwargs: Any) -> Any:
    return rate_limit_guard(ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=7)), **kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"rate_limits": cast("Any", object())},
        {"events": cast("Any", object())},
        {"clock": cast("Any", object())},
        {"event_ids": cast("Any", object())},
    ],
)
def test_password_login_service_validates_limiting_and_audit_ports(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        accounts_module.PasswordLoginService(
            accounts=LocalAccessStore(local_access_account()), hasher=PasswordHasher(), **kwargs
        )


async def test_password_login_is_limited_before_any_password_work() -> None:
    hasher = PasswordHasher()
    service = accounts_module.PasswordLoginService(
        accounts=LocalAccessStore(local_access_account()), hasher=hasher, rate_limits=_denyingrate_limit_guard()
    )

    outcome = await service.authenticate("user@example.com", "secret", client_key="1.1.1.1", now=_JWT_NOW)

    assert outcome == accounts_module.RateLimited(retry_after=7)
    assert hasher.calls == []


async def test_password_login_still_consumes_a_budget_for_an_unnormalizable_identifier() -> None:
    limiter = ScriptedLimiter(accounts_module.RateLimitDecision(allowed=True))
    service = accounts_module.PasswordLoginService(
        accounts=LocalAccessStore(local_access_account()),
        hasher=PasswordHasher(),
        normalizer=cast("Any", _raising_normalizer),
        rate_limits=rate_limit_guard(limiter),
    )

    outcome = await service.authenticate("user@example.com", "secret", client_key="1.1.1.1", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)
    assert limiter.requests[0].subject_digest is None
    assert limiter.requests[0].client_key == "1.1.1.1"


async def test_password_login_logs_unbuildable_decision_events_without_changing_the_decision(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = accounts_module.PasswordLoginService(
        accounts=LocalAccessStore(None), hasher=PasswordHasher(), clock=cast("Any", lambda: None)
    )

    outcome = await service.authenticate("missing@example.com", "secret", now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert "Security event could not be built for local.login" in caplog.text


async def test_password_login_emits_one_decision_event_per_outcome() -> None:
    sink = CollectingSink()
    service = accounts_module.PasswordLoginService(
        accounts=LocalAccessStore(local_access_account()),
        hasher=PasswordHasher(
            accounts_module.PasswordVerificationOutcome(accounts_module.PasswordVerificationStatus.VERIFIED)
        ),
        events=sink,
        event_ids=lambda: "event-1",
    )
    denied = accounts_module.PasswordLoginService(
        accounts=LocalAccessStore(None), hasher=PasswordHasher(), events=sink, event_ids=lambda: "event-2"
    )

    await service.authenticate("user@example.com", "correct horse battery staple", now=_JWT_NOW)
    await denied.authenticate("missing@example.com", "correct horse battery staple", now=_JWT_NOW)

    assert [event.outcome for event in sink.events] == ["verified", "attempted"]


async def test_registration_is_limited_before_hashing() -> None:
    hasher = PasswordHasher()
    service = accounts_module.RegistrationService(
        accounts=LifecycleStore(),
        hasher=hasher,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        registration=accounts_module.RegistrationPolicy.public(),
        rate_limits=_denyingrate_limit_guard(),
    )

    outcome = await service.register("user@example.com", "correct horse battery staple", now=_JWT_NOW)

    assert outcome == accounts_module.RateLimited(retry_after=7)
    assert hasher.hash_calls == []


async def test_verification_resend_is_limited_and_reports_a_denial() -> None:
    store = LifecycleStore()
    service = accounts_module.VerificationTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        rate_limits=_denyingrate_limit_guard(),
    )

    assert await service.resend("user@example.com", now=_JWT_NOW) == accounts_module.RateLimited(retry_after=7)


async def test_verification_resend_consumes_a_budget_for_an_unnormalizable_identifier() -> None:
    limiter = ScriptedLimiter(accounts_module.RateLimitDecision(allowed=True))
    store = LifecycleStore()
    service = accounts_module.VerificationTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        normalizer=cast("Any", _raising_normalizer),
        rate_limits=rate_limit_guard(limiter),
    )

    assert isinstance(await service.resend("user@example.com", now=_JWT_NOW), accounts_module.LifecycleAccepted)
    assert limiter.requests[0].subject_digest is None


@pytest.mark.parametrize("family", ["verification", "recovery"])
async def test_uniform_durable_write_cost_for_present_and_absent_identifiers(family: str) -> None:
    counts: dict[str, int] = {}
    for name, account in (("present", lifecycle_account()), ("absent", None)):
        store = LifecycleStore(account=account)
        codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
        if family == "verification":
            outcome = await accounts_module.VerificationTokenService(accounts=store, store=store, tokens=codec).resend(
                "user@example.com", now=_JWT_NOW
            )
        else:
            outcome = await accounts_module.RecoveryTokenService(
                accounts=store, store=store, tokens=codec, hasher=PasswordHasher()
            ).request("user@example.com", now=_JWT_NOW)
        assert isinstance(outcome, accounts_module.LifecycleAccepted)
        counts[name] = len(store.issues) + len(store.absent_probes)

    assert counts["present"] == counts["absent"] == 1


async def test_verification_consume_buckets_only_the_client_never_the_token() -> None:
    limiter = ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=7))
    store = LifecycleStore()
    service = accounts_module.VerificationTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        rate_limits=rate_limit_guard(limiter),
    )

    outcome = await service.consume("vt_token.secret", client_key="1.1.1.1", now=_JWT_NOW)

    assert outcome == accounts_module.RateLimited(retry_after=7)
    assert store.consumptions == []
    assert limiter.requests[0].operation == "local.verification.consume"
    assert limiter.requests[0].client_key == "1.1.1.1"
    assert limiter.requests[0].subject_digest is None


async def test_generated_verification_confirm_reports_denials_with_the_client_bucket() -> None:
    captured: dict[str, object] = {}

    async def consume(token: object, *, client_key: str | None = None) -> object:
        del token
        captured["client_key"] = client_key
        return accounts_module.RateLimited(retry_after=7)

    services = cast(
        "Any",
        SimpleNamespace(verification=SimpleNamespace(consume=consume), client_key_for=lambda _connection: "1.1.1.1"),
    )
    handler = cast("Any", controllers_module._LocalLifecycleController.confirm_verification.fn)  # noqa: SLF001

    error = await _assert_http_exception(
        handler(
            None,
            accounts_module.LocalToken(token="vt_token.secret"),  # noqa: S106 - deterministic fixture token
            cast("Any", SimpleNamespace()),
            services,
        ),
        TooManyRequestsException,
        status_code=429,
        detail="Too many requests.",
    )

    assert error.headers["Retry-After"] == "7"
    assert captured["client_key"] == "1.1.1.1"


async def test_recovery_request_and_reset_are_limited() -> None:
    store = LifecycleStore()
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    service = accounts_module.RecoveryTokenService(
        accounts=store, store=store, tokens=codec, hasher=PasswordHasher(), rate_limits=_denyingrate_limit_guard()
    )

    assert await service.request("user@example.com", now=_JWT_NOW) == accounts_module.RateLimited(retry_after=7)
    reset = await service.reset("rc_token.secret", "correct horse battery staple", now=_JWT_NOW)
    assert reset == accounts_module.RateLimited(retry_after=7)


async def test_recovery_request_consumes_a_budget_for_an_unnormalizable_identifier() -> None:
    limiter = ScriptedLimiter(accounts_module.RateLimitDecision(allowed=True))
    store = LifecycleStore()
    service = accounts_module.RecoveryTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        hasher=PasswordHasher(),
        normalizer=cast("Any", _raising_normalizer),
        rate_limits=rate_limit_guard(limiter),
    )

    assert isinstance(await service.request("user@example.com", now=_JWT_NOW), accounts_module.LifecycleAccepted)
    assert limiter.requests[0].subject_digest is None


async def test_recovery_reset_buckets_only_the_client_never_the_token() -> None:
    limiter = ScriptedLimiter(accounts_module.RateLimitDecision(allowed=True))
    store = LifecycleStore()
    service = accounts_module.RecoveryTokenService(
        accounts=store,
        store=store,
        tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        hasher=PasswordHasher(),
        rate_limits=rate_limit_guard(limiter),
    )

    await service.reset("rc_token.secret", "correct horse battery staple", client_key="1.1.1.1", now=_JWT_NOW)

    assert limiter.requests[0].subject_digest is None
    assert limiter.requests[0].client_key == "1.1.1.1"


async def test_password_login_emits_an_attempt_event_for_a_known_account_with_a_wrong_password() -> None:
    sink = CollectingSink()
    service = accounts_module.PasswordLoginService(
        accounts=LocalAccessStore(local_access_account()),
        hasher=PasswordHasher(
            accounts_module.PasswordVerificationOutcome(accounts_module.PasswordVerificationStatus.INVALID)
        ),
        events=sink,
        event_ids=lambda: "event-1",
    )

    outcome = await service.authenticate("user@example.com", "wrong", now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert [(event.outcome, event.account_id) for event in sink.events] == [("attempted", "account-1")]


@pytest.mark.parametrize(("active", "verified"), [(False, True), (True, False)])
async def test_password_login_rejects_inactive_or_unverified_accounts_after_password_verification(
    active: bool,  # noqa: FBT001 - account state matrix
    verified: bool,  # noqa: FBT001 - account state matrix
) -> None:
    account = local_access_account(active=active, verified=verified)
    service = accounts_module.PasswordLoginService(
        accounts=LocalAccessStore(account),
        hasher=PasswordHasher(
            accounts_module.PasswordVerificationOutcome(accounts_module.PasswordVerificationStatus.VERIFIED)
        ),
    )
    assert isinstance(await service.authenticate("user@example.com", "correct", now=_JWT_NOW), InvalidCredentials)


async def test_password_login_maps_lookup_failures_and_mismatched_proofs_to_sanitized_outcomes() -> None:
    failing = accounts_module.PasswordLoginService(
        accounts=LocalAccessStore(local_access_account(), fail_lookup=True), hasher=PasswordHasher()
    )
    assert isinstance(await failing.authenticate("user@example.com", "secret", now=_JWT_NOW), VerificationUnavailable)

    account = local_access_account()
    service = accounts_module.PasswordLoginService(accounts=LocalAccessStore(account), hasher=PasswordHasher())
    object.__setattr__(
        service,
        "_reauthentication",
        SimpleNamespace(
            verify=AsyncOutcome(
                accounts_module.PasswordReauthenticationProof(
                    account_id="other-account",
                    security_epoch=account.security_epoch,
                    authenticated_at=_JWT_NOW,
                    expires_at=_JWT_NOW + timedelta(minutes=5),
                )
            )
        ),
    )
    assert isinstance(await service.authenticate("user@example.com", "secret", now=_JWT_NOW), InvalidCredentials)

    object.__setattr__(service, "_reauthentication", SimpleNamespace(verify=AsyncOutcome(VerificationUnavailable())))
    assert isinstance(await service.authenticate("user@example.com", "secret", now=_JWT_NOW), VerificationUnavailable)


async def test_refresh_rotation_is_limited_by_client_only() -> None:
    limiter = ScriptedLimiter(accounts_module.RateLimitDecision(allowed=False, retry_after=7))
    service, _store, _accounts, _account = refresh_service()
    limited = replace(service, rate_limits=rate_limit_guard(limiter))

    outcome = await limited.rotate("rt_token.secret", client_key="1.1.1.1", now=_JWT_NOW)

    assert outcome == accounts_module.RateLimited(retry_after=7)
    assert limiter.requests[0].subject_digest is None
    assert limiter.requests[0].operation == "local.refresh.rotate"


def test_route_errors_map_denials_to_429_with_a_retry_hint() -> None:
    with pytest.raises(TooManyRequestsException) as limited_info:
        controllers_module._route_error(accounts_module.RateLimited(retry_after=42))  # noqa: SLF001
    with pytest.raises(TooManyRequestsException) as unhinted_info:
        controllers_module._route_error(accounts_module.RateLimited())  # noqa: SLF001

    assert limited_info.value.status_code == 429
    assert limited_info.value.detail == "Too many requests."
    assert limited_info.value.headers["Retry-After"] == "42"
    assert unhinted_info.value.status_code == 429
    assert unhinted_info.value.detail == "Too many requests."
    assert not unhinted_info.value.headers or "Retry-After" not in unhinted_info.value.headers


@pytest.mark.parametrize("handler_name", ["recovery", "verification"])
async def test_generated_lifecycle_handlers_report_denials_instead_of_the_shared_accepted_response(
    handler_name: str,
) -> None:
    limited = accounts_module.RateLimited(retry_after=7)

    async def deny(*_args: object, **_kwargs: object) -> object:
        return limited

    services = cast(
        "Any",
        SimpleNamespace(
            recovery=SimpleNamespace(request=deny),
            verification=SimpleNamespace(resend=deny),
            client_key_for=lambda _connection: "1.1.1.1",
        ),
    )
    handler = cast("Any", getattr(controllers_module._LocalLifecycleController, handler_name).fn)  # noqa: SLF001
    identifier = accounts_module.LocalIdentifier(identifier="user@example.com")

    error = await _assert_http_exception(
        handler(None, identifier, cast("Any", SimpleNamespace()), services),
        TooManyRequestsException,
        status_code=429,
        detail="Too many requests.",
    )

    assert error.headers["Retry-After"] == "7"


def test_default_rate_limit_policies_map_exactly_the_rate_limited_operations() -> None:
    operations = import_module("litestar_security.accounts._operations")

    assert "RATE_LIMITED_OPERATIONS" in operations.__all__
    assert accounts_module.DEFAULT_RATE_LIMIT_POLICIES.keys() == operations.RATE_LIMITED_OPERATIONS
    assert {
        operations.MFA_TOTP_REMOVE,
        operations.PASSKEY_REMOVE,
        operations.PASSWORD_VERIFY,
        operations.VERIFICATION_CONSUME,
    } <= operations.RATE_LIMITED_OPERATIONS


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.5", "203.0.113.5"),
        ("203.0.113.5:4711", "203.0.113.5"),
        ("::1", "::1"),
        ("[::1]", "::1"),
        ("[::1]:4711", "::1"),
        ("::ffff:203.0.113.5", "203.0.113.5"),
        ("not-an-address", None),
        ("[unterminated", None),
        ("203.0.113.5:garbage", None),
        ("203.0.113.5:", None),
        ("[::1]garbage", None),
        ("[::1]:garbage", None),
        ("[::1]:", None),
        ("[::1]:0", None),
        ("[::1]:65536", None),
        ("", None),
    ],
)
def test_parse_forwarded_address_normalizes_supported_forms(raw: str, expected: str | None) -> None:
    auth_service = import_module("litestar_security.accounts._auth_service")

    address = auth_service.__dict__["_parse_forwarded_address"](raw)

    assert (None if address is None else str(address)) == expected
