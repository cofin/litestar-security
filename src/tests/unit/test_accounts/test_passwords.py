"""Unit tests for password policy and verification contracts."""

from datetime import datetime, timedelta, timezone
from threading import Lock as ThreadLock
from time import sleep
from typing import Any, cast

import pytest
from anyio import Event, create_task_group, to_thread
from anyio.lowlevel import checkpoint
from argon2 import PasswordHasher as Argon2Engine
from argon2 import extract_parameters as extract_argon2_parameters
from argon2.exceptions import VerificationError
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security.accounts as accounts_module
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.providers.jwks import WorkerLimits
from tests.fixtures.accounts import CredentialCleanup as _CredentialCleanup
from tests.fixtures.accounts import PasswordHasher as _PasswordHasher
from tests.fixtures.accounts import PasswordStore as _PasswordStore
from tests.fixtures.accounts import SecurityEvents as _SecurityEvents


@pytest.mark.parametrize(
    ("password", "identifier", "violations"),
    [
        ("a" * 11, None, {accounts_module.PasswordPolicyViolation.TOO_SHORT}),
        ("a" * 129, None, {accounts_module.PasswordPolicyViolation.TOO_LONG}),
        ("\ud800" * 12, None, {accounts_module.PasswordPolicyViolation.INVALID_TEXT}),
        (
            "é" * 513,
            None,
            {accounts_module.PasswordPolicyViolation.TOO_LONG, accounts_module.PasswordPolicyViolation.TOO_MANY_BYTES},
        ),
        (" USER@EXAMPLE.COM ", "user@example.com", {accounts_module.PasswordPolicyViolation.MATCHES_IDENTIFIER}),
        ("known compromised passphrase", None, {accounts_module.PasswordPolicyViolation.COMPROMISED}),
    ],
)
def test_password_policy_reports_only_secret_free_violations(
    password: str, identifier: str | None, violations: set["accounts_module.PasswordPolicyViolation"]
) -> None:
    policy = accounts_module.PasswordPolicy(compromised=lambda candidate: candidate == "known compromised passphrase")

    result = policy.check(password, normalized_identifier=identifier)

    assert result.violations == frozenset(violations)
    assert not result.accepted
    assert password not in repr(policy)
    assert password not in repr(result)


def test_password_policy_defaults_allow_unicode_spaces_and_long_passphrases() -> None:
    policy = accounts_module.PasswordPolicy()
    accepted = (
        "12chars-pass",
        "correct horse battery staple",
        "   spaced passphrase   ",
        "🦄 unicode passphrase",
        "é" * 128,
    )

    assert (policy.minimum_length, policy.maximum_length, policy.maximum_bytes) == (12, 128, 1_024)
    assert all(policy.check(password).accepted for password in accepted)
    assert policy.check("sufficiently long candidate", normalized_identifier="another@example.com").accepted
    assert accounts_module.normalize_identifier("  Usér@EXAMPLE.COM  ") == "usér@example.com"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"minimum_length": 0},
        {"minimum_length": True},
        {"maximum_length": 11},
        {"maximum_bytes": 0},
        {"maximum_bytes": 1_025},
        {"normalizer": None},
        {"compromised": object()},
    ],
)
def test_password_policy_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Password policy"):
        accounts_module.PasswordPolicy(**kwargs)  # type: ignore[arg-type]


def test_password_policy_skips_compromised_hook_for_invalid_candidates_and_validates_its_result() -> None:
    candidates: list[str] = []

    def compromised(candidate: str) -> object:
        candidates.append(candidate)
        return object()

    policy = accounts_module.PasswordPolicy(compromised=compromised)  # type: ignore[arg-type]

    assert policy.check("short").violations == frozenset({accounts_module.PasswordPolicyViolation.TOO_SHORT})
    assert candidates == []
    with pytest.raises(ImproperlyConfiguredException, match="must return bool"):
        policy.check("sufficiently long candidate")
    assert candidates == ["sufficiently long candidate"]
    assert (
        accounts_module
        .PasswordPolicy(compromised=lambda _candidate: False)
        .check("sufficiently long candidate")
        .accepted
    )


def test_password_policy_handles_invalid_runtime_text_and_normalizer_failures() -> None:
    invalid_text = accounts_module.PasswordPolicy().check(object())  # type: ignore[arg-type]
    invalid_normalizer = accounts_module.PasswordPolicy(
        normalizer=lambda _value: (_ for _ in ()).throw(ValueError)
    ).check("sufficiently long candidate", normalized_identifier="user@example.com")

    assert invalid_text.violations == frozenset({accounts_module.PasswordPolicyViolation.INVALID_TEXT})
    assert invalid_normalizer.violations == frozenset({accounts_module.PasswordPolicyViolation.INVALID_TEXT})
    with pytest.raises(ValueError, match="requires text"):
        accounts_module.normalize_identifier(object())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("status", "replacement_hash"),
    [
        (accounts_module.PasswordVerificationStatus.VERIFIED, None),
        (accounts_module.PasswordVerificationStatus.VERIFIED, "replacement-secret"),
        (accounts_module.PasswordVerificationStatus.INVALID, None),
        (accounts_module.PasswordVerificationStatus.MALFORMED, None),
        (accounts_module.PasswordVerificationStatus.TOO_LONG, None),
    ],
)
def test_password_verification_outcomes_are_discriminated_and_redacted(
    status: "accounts_module.PasswordVerificationStatus", replacement_hash: str | None
) -> None:
    result = accounts_module.PasswordVerificationOutcome(status=status, replacement_hash=replacement_hash)

    assert result.verified is (status is accounts_module.PasswordVerificationStatus.VERIFIED)
    assert "replacement-secret" not in repr(result)
    assert not hasattr(result, "__dict__")


def test_password_verification_outcome_rejects_replacement_for_failure() -> None:
    with pytest.raises(ValueError, match="replacement"):
        accounts_module.PasswordVerificationOutcome(
            status=accounts_module.PasswordVerificationStatus.INVALID, replacement_hash="replacement-secret"
        )


_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)


def _unavailable_password_check(_password: str) -> bool:
    raise OSError


async def test_argon2_hasher_uses_locked_id_parameters_and_detects_rehash(
    password_hasher: "accounts_module.Argon2PasswordHasher",
) -> None:
    candidate = "correct horse battery staple"
    encoded = await password_hasher.hash(candidate)
    current = await password_hasher.verify(encoded, candidate)
    legacy_engine = Argon2Engine(memory_cost=8_192, time_cost=1, parallelism=1, salt_len=16, hash_len=32)
    legacy = await to_thread.run_sync(legacy_engine.hash, candidate)
    legacy_result = await password_hasher.verify(legacy, candidate)

    parameters = extract_argon2_parameters(encoded)
    assert (
        parameters.type.name,
        parameters.version,
        parameters.memory_cost,
        parameters.time_cost,
        parameters.parallelism,
        parameters.salt_len,
        parameters.hash_len,
    ) == ("ID", 19, 19_456, 2, 1, 16, 32)
    assert (
        password_hasher.memory_cost,
        password_hasher.time_cost,
        password_hasher.parallelism,
        password_hasher.salt_len,
        password_hasher.hash_len,
    ) == (19_456, 2, 1, 16, 32)
    assert current == accounts_module.PasswordVerificationOutcome(
        status=accounts_module.PasswordVerificationStatus.VERIFIED
    )
    assert legacy_result.verified
    assert legacy_result.replacement_hash is not None
    assert legacy_result.replacement_hash.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert legacy not in repr(legacy_result)
    assert legacy_result.replacement_hash not in repr(legacy_result)


async def test_argon2_hasher_supports_strengthening_without_sync_startup_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Argon2Engine.hash

    def reject_sync_hash(_engine: Argon2Engine, _candidate: str | bytes, **_kwargs: object) -> str:
        raise AssertionError

    monkeypatch.setattr(Argon2Engine, "hash", reject_sync_hash)
    default_hasher = accounts_module.Argon2PasswordHasher()
    monkeypatch.setattr(Argon2Engine, "hash", original)
    strengthened = await accounts_module.Argon2PasswordHasher.create(time_cost=3)

    assert default_hasher.time_cost == 2
    assert extract_argon2_parameters(strengthened.dummy_hash).time_cost == 3
    assert (await strengthened.verify(None, "constant-work candidate")).status is (
        accounts_module.PasswordVerificationStatus.INVALID
    )


@pytest.mark.parametrize("operation", ["create", "hash"])
async def test_argon2_hasher_maps_worker_hash_failures(monkeypatch: pytest.MonkeyPatch, operation: str) -> None:
    def unavailable(_engine: Argon2Engine, _candidate: str | bytes, **_kwargs: object) -> str:
        raise RuntimeError

    monkeypatch.setattr(Argon2Engine, "hash", unavailable)
    operation_call = (
        accounts_module.Argon2PasswordHasher.create(time_cost=3)
        if operation == "create"
        else accounts_module.Argon2PasswordHasher().hash("sufficiently long candidate")
    )

    with pytest.raises(accounts_module.PasswordHashingUnavailableError):
        await operation_call


@pytest.mark.parametrize(
    "kwargs",
    [
        {"memory_cost": 19_455},
        {"memory_cost": 262_145},
        {"time_cost": True},
        {"time_cost": 11},
        {"parallelism": 9},
        {"salt_len": 65},
        {"hash_len": 65},
        {"worker_limits": object()},
        {"worker_limits": WorkerLimits(crypto_tokens=54)},
        {"dummy_hash": "not-an-argon2-hash"},
    ],
)
def test_argon2_hasher_rejects_weak_unsafe_or_mismatched_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Argon2"):
        accounts_module.Argon2PasswordHasher(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("memory_cost", [40_000, 999_999_999])
async def test_argon2_hasher_rejects_hostile_parameters_before_real_verification(
    monkeypatch: pytest.MonkeyPatch, password_hasher: "accounts_module.Argon2PasswordHasher", memory_cost: int
) -> None:
    hostile = password_hasher.dummy_hash.replace("m=19456", f"m={memory_cost}")
    calls: list[str | bytes] = []
    original = Argon2Engine.verify

    def tracked(engine: Argon2Engine, candidate_hash: str | bytes, candidate: str | bytes) -> bool:
        calls.append(candidate_hash)
        return original(engine, candidate_hash, candidate)

    monkeypatch.setattr(Argon2Engine, "verify", tracked)

    result = await password_hasher.verify(hostile, "constant-work candidate")

    assert result.status is accounts_module.PasswordVerificationStatus.MALFORMED
    assert calls == [password_hasher.dummy_hash]
    assert hostile not in repr(result)


async def test_argon2_hasher_accepts_exact_utf8_byte_boundary(
    password_hasher: "accounts_module.Argon2PasswordHasher",
) -> None:
    candidate = "a" * 1_024

    encoded = await password_hasher.hash(candidate)
    result = await password_hasher.verify(encoded, candidate)

    assert result.verified


async def test_argon2_hasher_equalizes_absent_wrong_and_malformed_verification_work(
    monkeypatch: pytest.MonkeyPatch, password_hasher: "accounts_module.Argon2PasswordHasher"
) -> None:
    presented = "incorrect passphrase"
    encoded = await password_hasher.hash("correct horse battery staple")
    calls: list[str | bytes] = []
    original = Argon2Engine.verify

    def tracked(engine: Argon2Engine, candidate_hash: str | bytes, candidate: str | bytes) -> bool:
        calls.append(candidate_hash)
        return original(engine, candidate_hash, candidate)

    monkeypatch.setattr(Argon2Engine, "verify", tracked)

    absent = await password_hasher.verify(None, presented)
    absent_calls = len(calls)
    calls.clear()
    wrong = await password_hasher.verify(encoded, presented)
    wrong_calls = len(calls)
    calls.clear()
    malformed = await password_hasher.verify("not-an-argon2-hash", presented)

    assert absent.status is accounts_module.PasswordVerificationStatus.INVALID
    assert wrong.status is accounts_module.PasswordVerificationStatus.INVALID
    assert malformed.status is accounts_module.PasswordVerificationStatus.MALFORMED
    assert (absent_calls, wrong_calls, len(calls)) == (1, 1, 1)
    assert all("incorrect passphrase" not in repr(result) for result in (absent, wrong, malformed))


async def test_argon2_hasher_maps_verification_library_failures_to_sanitized_outcomes(
    monkeypatch: pytest.MonkeyPatch, password_hasher: "accounts_module.Argon2PasswordHasher"
) -> None:
    encoded = await password_hasher.hash("correct horse battery staple")
    original = Argon2Engine.verify

    def malformed(engine: Argon2Engine, candidate_hash: str | bytes, candidate: str | bytes) -> bool:
        if candidate_hash == password_hasher.dummy_hash:
            return original(engine, candidate_hash, candidate)
        raise VerificationError

    monkeypatch.setattr(Argon2Engine, "verify", malformed)

    result = await password_hasher.verify(encoded, "constant-work candidate")

    assert result.status is accounts_module.PasswordVerificationStatus.MALFORMED

    def malformed_dummy(_engine: Argon2Engine, _candidate_hash: str | bytes, _candidate: str | bytes) -> bool:
        raise VerificationError

    monkeypatch.setattr(Argon2Engine, "verify", malformed_dummy)

    with pytest.raises(accounts_module.PasswordHashingUnavailableError):
        await password_hasher.verify(None, "constant-work candidate")


async def test_argon2_hasher_maps_unexpected_dummy_failure_to_unavailable(
    monkeypatch: pytest.MonkeyPatch, password_hasher: "accounts_module.Argon2PasswordHasher"
) -> None:
    def unavailable(_engine: Argon2Engine, _candidate_hash: str | bytes, _candidate: str | bytes) -> bool:
        raise RuntimeError

    monkeypatch.setattr(Argon2Engine, "verify", unavailable)

    with pytest.raises(accounts_module.PasswordHashingUnavailableError):
        await password_hasher.verify("not-an-argon2-hash", "constant-work candidate")


@pytest.mark.parametrize("encoded_hash", [object(), "a" * 1_025])
async def test_argon2_hasher_treats_invalid_hash_runtime_shapes_as_malformed(
    password_hasher: "accounts_module.Argon2PasswordHasher", encoded_hash: object
) -> None:
    result = await password_hasher.verify(encoded_hash, "constant-work candidate")  # type: ignore[arg-type]

    assert result.status is accounts_module.PasswordVerificationStatus.MALFORMED


async def test_argon2_hasher_rejects_oversized_or_invalid_text_before_workers(
    monkeypatch: pytest.MonkeyPatch, password_hasher: "accounts_module.Argon2PasswordHasher"
) -> None:
    worker_calls = 0
    original = Argon2Engine.verify

    def tracked(engine: Argon2Engine, candidate_hash: str | bytes, candidate: str | bytes) -> bool:
        nonlocal worker_calls
        worker_calls += 1
        return original(engine, candidate_hash, candidate)

    monkeypatch.setattr(Argon2Engine, "verify", tracked)

    oversized = await password_hasher.verify(None, "é" * 513)
    invalid_unicode = await password_hasher.verify(None, "\ud800")

    assert oversized.status is accounts_module.PasswordVerificationStatus.TOO_LONG
    assert invalid_unicode.status is accounts_module.PasswordVerificationStatus.INVALID
    assert worker_calls == 0
    with pytest.raises(ValueError, match="1,024 UTF-8 bytes"):
        await password_hasher.hash("a" * 1_025)
    with pytest.raises(ValueError, match="valid UTF-8"):
        await password_hasher.hash("\ud800")
    with pytest.raises(ValueError, match="must be text"):
        await password_hasher.hash(object())  # type: ignore[arg-type]


def test_argon2_hasher_maps_engine_configuration_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(**_kwargs: object) -> object:
        raise TypeError

    monkeypatch.setattr("litestar_security.accounts._passwords._Argon2Engine", unavailable)

    with pytest.raises(ImproperlyConfiguredException, match="Invalid Argon2"):
        accounts_module.Argon2PasswordHasher()


async def test_argon2_hasher_bounds_concurrency_and_maps_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    workers = WorkerLimits(crypto_tokens=2, timeout=1)
    hasher = accounts_module.Argon2PasswordHasher(worker_limits=workers)
    active = 0
    maximum_active = 0
    lock = ThreadLock()

    def slow_verify(_engine: Argon2Engine, _candidate_hash: str | bytes, _candidate: str | bytes) -> bool:
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        sleep(0.03)
        with lock:
            active -= 1
        return True

    monkeypatch.setattr(Argon2Engine, "verify", slow_verify)
    results: list[accounts_module.PasswordVerificationOutcome] = []

    async def verify() -> None:
        results.append(await hasher.verify(None, "constant-work password"))

    async with create_task_group() as task_group:
        for _ in range(6):
            task_group.start_soon(verify)

    assert maximum_active == 2
    assert len(results) == 6
    assert all(result.status is accounts_module.PasswordVerificationStatus.INVALID for result in results)

    active = 0
    maximum_active = 0
    timeout_hasher = accounts_module.Argon2PasswordHasher(worker_limits=WorkerLimits(crypto_tokens=2, timeout=0.001))
    completed = Event()
    timed_out = 0
    ticker_iterations = 0

    async def timed_verify() -> None:
        nonlocal timed_out
        with pytest.raises(accounts_module.PasswordHashingUnavailableError):
            await timeout_hasher.verify(None, "constant-work password")
        timed_out += 1

    async def run_timeout_batch() -> None:
        async with create_task_group() as batch:
            for _ in range(100):
                batch.start_soon(timed_verify)
        completed.set()

    async def ticker() -> None:
        nonlocal ticker_iterations
        while not completed.is_set():
            ticker_iterations += 1
            await checkpoint()

    async with create_task_group() as task_group:
        task_group.start_soon(run_timeout_batch)
        task_group.start_soon(ticker)

    assert (timed_out, active, maximum_active) == (100, 0, 2)
    assert ticker_iterations > 0


@pytest.mark.parametrize("failure", ["invalid", "unavailable", "store"])
async def test_password_reauthentication_maps_every_failure_to_domain_outcome(failure: str) -> None:
    store = _PasswordStore(fail_read=failure == "store")
    hasher = _PasswordHasher(unavailable=failure == "unavailable")
    service = accounts_module.PasswordReauthenticationService(accounts=store, hasher=hasher)

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable if failure in {"unavailable", "store"} else InvalidCredentials)
    assert store.replacements == []
    assert "presented secret" not in repr(service)
    assert "presented secret" not in repr(outcome)


@pytest.mark.parametrize(
    ("status", "encoded_hash"),
    [
        (accounts_module.PasswordVerificationStatus.INVALID, "current-hash"),
        (accounts_module.PasswordVerificationStatus.MALFORMED, "malformed-hash"),
        (accounts_module.PasswordVerificationStatus.TOO_LONG, "current-hash"),
        (accounts_module.PasswordVerificationStatus.INVALID, None),
    ],
)
async def test_password_reauthentication_collapses_credential_failures_without_rehash(
    status: accounts_module.PasswordVerificationStatus, encoded_hash: str | None
) -> None:
    store = _PasswordStore(encoded_hash)
    hasher = _PasswordHasher(accounts_module.PasswordVerificationOutcome(status))
    service = accounts_module.PasswordReauthenticationService(accounts=store, hasher=hasher)

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert store.replacements == []


@pytest.mark.parametrize(
    ("active", "verified", "outcome_type"),
    [
        (False, True, InvalidCredentials),
        (True, False, InvalidCredentials),
        (True, True, accounts_module.PasswordReauthenticationProof),
    ],
)
async def test_password_reauthentication_rejects_inactive_or_unverified_accounts_after_hash_verification(
    active: bool,  # noqa: FBT001 - parametrized account-state matrix
    verified: bool,  # noqa: FBT001 - parametrized account-state matrix
    outcome_type: type[object],
) -> None:
    store = _PasswordStore(active=active, verified=verified)
    hasher = _PasswordHasher(
        accounts_module.PasswordVerificationOutcome(accounts_module.PasswordVerificationStatus.VERIFIED)
    )
    service = accounts_module.PasswordReauthenticationService(accounts=store, hasher=hasher)

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, outcome_type)
    assert hasher.calls == [("current-hash", "presented secret")]
    assert store.replacements == []


@pytest.mark.parametrize("sink_mode", ["default", "available", "failure"])
async def test_password_reauthentication_emits_sanitized_malformed_hash_event(
    sink_mode: str, caplog: pytest.LogCaptureFixture
) -> None:
    store = _PasswordStore("malformed-secret-hash")
    hasher = _PasswordHasher(
        accounts_module.PasswordVerificationOutcome(accounts_module.PasswordVerificationStatus.MALFORMED)
    )
    events = _SecurityEvents(fail=sink_mode == "failure")
    event_options = {} if sink_mode == "default" else {"events": events}
    service = accounts_module.PasswordReauthenticationService(
        accounts=store, hasher=hasher, event_ids=lambda: "event-1", **event_options
    )

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    if sink_mode == "default":
        assert isinstance(service.events, accounts_module.NoOpSecurityEventSink)
    if sink_mode == "available":
        assert len(events.events) == 1
        event = events.events[0]
        assert (event.event_id, event.operation, event.outcome, event.account_id) == (
            "event-1",
            "local.password.verify",
            "malformed_hash",
            "account-1",
        )
        rendered = repr(event)
        assert "presented secret" not in rendered
        assert "malformed-secret-hash" not in rendered
    if sink_mode == "failure":
        assert "Security event sink failed" in caplog.text


@pytest.mark.parametrize(
    ("replace_result", "fail_replace", "outcome_type"),
    [
        (True, False, accounts_module.PasswordReauthenticationProof),
        (False, False, VerificationUnavailable),
        (object(), False, VerificationUnavailable),
        (True, True, VerificationUnavailable),
    ],
)
async def test_password_reauthentication_locks_atomic_rehash_outcomes(
    replace_result: object, *, fail_replace: bool, outcome_type: type[object]
) -> None:
    store = _PasswordStore(replace_result=replace_result, fail_replace=fail_replace)
    replacement = "$argon2id$replacement-secret"
    hasher = _PasswordHasher(
        accounts_module.PasswordVerificationOutcome(
            accounts_module.PasswordVerificationStatus.VERIFIED, replacement_hash=replacement
        )
    )
    service = accounts_module.PasswordReauthenticationService(accounts=store, hasher=hasher)

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, outcome_type)
    if not fail_replace:
        assert len(store.replacements) == 1
        assert store.replacements[0][1:3] == ("current-hash", replacement)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"evidence_ttl": timedelta(0)},
        {"evidence_ttl": timedelta(minutes=6)},
        {"clock": None},
        {"events": object()},
        {"event_ids": None},
        {"accounts": object()},
        {"hasher": object()},
    ],
)
def test_password_reauthentication_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    values = {"accounts": _PasswordStore(), "hasher": _PasswordHasher(), **kwargs}

    with pytest.raises(ImproperlyConfiguredException, match="Password reauthentication"):
        accounts_module.PasswordReauthenticationService(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("source", ["argument", "clock"])
async def test_password_reauthentication_rejects_naive_time_as_unavailable(source: str) -> None:
    naive = _JWT_NOW.replace(tzinfo=None)
    service = accounts_module.PasswordReauthenticationService(
        accounts=_PasswordStore(),
        hasher=_PasswordHasher(
            accounts_module.PasswordVerificationOutcome(accounts_module.PasswordVerificationStatus.VERIFIED)
        ),
        clock=lambda: naive,
    )

    outcome = await service.verify("account-1", "presented secret", now=naive if source == "argument" else None)

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.parametrize("account_id", [" ", object()])
async def test_password_reauthentication_rejects_invalid_account_ids_without_port_calls(account_id: object) -> None:
    hasher = _PasswordHasher()
    service = accounts_module.PasswordReauthenticationService(accounts=_PasswordStore(), hasher=hasher)

    outcome = await service.verify(account_id, "presented secret", now=_JWT_NOW)  # type: ignore[arg-type]

    assert isinstance(outcome, InvalidCredentials)
    assert hasher.calls == []


async def test_password_reauthentication_uses_an_aware_default_clock() -> None:
    service = accounts_module.PasswordReauthenticationService(
        accounts=_PasswordStore(),
        hasher=_PasswordHasher(
            accounts_module.PasswordVerificationOutcome(accounts_module.PasswordVerificationStatus.VERIFIED)
        ),
    )
    before = datetime.now(timezone.utc)

    outcome = await service.verify("account-1", "presented secret")

    after = datetime.now(timezone.utc)
    assert isinstance(outcome, accounts_module.PasswordReauthenticationProof)
    assert before <= outcome.authenticated_at <= after
    assert outcome.expires_at == outcome.authenticated_at + timedelta(minutes=5)


async def test_password_reauthentication_logs_blank_event_ids_without_changing_decision(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = accounts_module.PasswordReauthenticationService(
        accounts=_PasswordStore("malformed-hash"),
        hasher=_PasswordHasher(
            accounts_module.PasswordVerificationOutcome(accounts_module.PasswordVerificationStatus.MALFORMED)
        ),
        events=_SecurityEvents(),
        event_ids=lambda: " ",
    )

    outcome = await service.verify("account-1", "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert "Security event could not be built for local.password.verify" in caplog.text


async def test_password_reauthentication_returns_fresh_evidence_and_rehashes_atomically() -> None:
    replacement = "$argon2id$replacement-secret"
    store = _PasswordStore()
    hasher = _PasswordHasher(
        accounts_module.PasswordVerificationOutcome(
            accounts_module.PasswordVerificationStatus.VERIFIED, replacement_hash=replacement
        )
    )
    service = accounts_module.PasswordReauthenticationService(accounts=store, hasher=hasher)

    outcome = await service.verify(" account-1 ", "presented secret", now=_JWT_NOW)

    assert outcome == accounts_module.PasswordReauthenticationProof(
        account_id="account-1", security_epoch=1, authenticated_at=_JWT_NOW, expires_at=_JWT_NOW + timedelta(minutes=5)
    )
    assert hasher.calls == [("current-hash", "presented secret")]
    assert len(store.replacements) == 1
    account_id, expected_hash, new_hash, event = store.replacements[0]
    assert (account_id, expected_hash, new_hash) == ("account-1", "current-hash", replacement)
    assert (event.operation, event.outcome, event.account_id) == ("local.password.rehash", "updated", "account-1")
    assert "presented secret" not in repr(event)
    assert replacement not in repr(event)


def _password_proof(
    *, account_id: str = "account-1", security_epoch: int = 1, authenticated_at: datetime = _JWT_NOW
) -> accounts_module.PasswordReauthenticationProof:
    return accounts_module.PasswordReauthenticationProof(
        account_id=account_id,
        security_epoch=security_epoch,
        authenticated_at=authenticated_at,
        expires_at=authenticated_at + timedelta(minutes=5),
    )


def _replacement_session(*, security_epoch: int = 1) -> accounts_module.CreateSessionCommand:
    return accounts_module.CreateSessionCommand(
        session_id="bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4",
        binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
        binding_digest=b"b" * 32,
        account_id="account-1",
        security_epoch=security_epoch,
        created_at=_JWT_NOW,
        authenticated_at=_JWT_NOW,
        expires_at=_JWT_NOW + timedelta(hours=1),
    )


@pytest.mark.parametrize(
    ("proof", "now", "accepted"),
    [
        (_password_proof(), _JWT_NOW + timedelta(minutes=5), True),
        (_password_proof(), _JWT_NOW + timedelta(minutes=5, microseconds=1), False),
        (_password_proof(authenticated_at=_JWT_NOW + timedelta(seconds=1)), _JWT_NOW, False),
        (_password_proof(account_id="account-2"), _JWT_NOW, False),
    ],
)
async def test_password_change_requires_account_epoch_bound_recent_proof(
    proof: accounts_module.PasswordReauthenticationProof, now: datetime, *, accepted: bool
) -> None:
    store = _PasswordStore()
    service = accounts_module.PasswordChangeService(accounts=store, hasher=_PasswordHasher())

    outcome = await service.change("account-1", "correct horse battery staple", proof=proof, now=now)

    if accepted:
        assert outcome == accounts_module.PasswordChangeOutcome(
            accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2
        )
        assert len(store.bump_calls) == 1
    else:
        assert isinstance(outcome, InvalidCredentials)
        assert store.bump_calls == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"accounts": object()},
        {"hasher": object()},
        {"password_policy": object()},
        {"sessions": object()},
        {"refresh_tokens": object()},
        {"evidence_ttl": timedelta(0)},
        {"evidence_ttl": timedelta(minutes=6)},
        {"clock": None},
        {"event_ids": None},
    ],
)
def test_password_change_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    values = {"accounts": _PasswordStore(), "hasher": _PasswordHasher(), **kwargs}

    with pytest.raises(ImproperlyConfiguredException, match="Password change"):
        accounts_module.PasswordChangeService(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("case", "outcome_type"),
    [
        ("change_time", accounts_module.LifecycleRejected),
        ("force_time", accounts_module.LifecycleRejected),
        ("invalid_proof", InvalidCredentials),
        ("blank_account", accounts_module.LifecycleRejected),
        ("compromise_rebind", accounts_module.LifecycleRejected),
        ("missing_replacement", accounts_module.LifecycleRejected),
        ("missing_current", accounts_module.LifecycleRejected),
        ("no_session_registry", accounts_module.LifecycleRejected),
        ("blank_current", accounts_module.LifecycleRejected),
        ("naive_expiry", accounts_module.LifecycleRejected),
        ("policy_failure", VerificationUnavailable),
        ("policy_rejection", accounts_module.PasswordPolicyDecision),
        ("hash_failure", VerificationUnavailable),
        ("store_failure", VerificationUnavailable),
        ("event_failure", VerificationUnavailable),
        ("wrong_epoch", VerificationUnavailable),
    ],
)
async def test_password_change_fails_closed_before_or_after_the_atomic_boundary(
    case: str, outcome_type: type[object]
) -> None:
    store = _PasswordStore(
        fail_bump=case == "store_failure",
        bump_result=(
            accounts_module.PasswordChangeOutcome(accounts_module.PasswordChangeStatus.CHANGED, security_epoch=3)
            if case == "wrong_epoch"
            else None
        ),
    )
    hasher = _PasswordHasher(unavailable=case == "hash_failure")
    cleanup = _CredentialCleanup()
    service = accounts_module.PasswordChangeService(
        accounts=store,
        hasher=hasher,
        password_policy=accounts_module.PasswordPolicy(
            compromised=_unavailable_password_check if case == "policy_failure" else None
        ),
        sessions=None if case == "no_session_registry" else cleanup,
        event_ids=(lambda: " ") if case == "event_failure" else (lambda: "event-1"),
    )
    proof: object = object() if case == "invalid_proof" else _password_proof()
    replacement: accounts_module.CreateSessionCommand | None = _replacement_session()
    current_session_id: str | None = None
    compromise = False
    account_id = "account-1"
    password = "short" if case == "policy_rejection" else "correct horse battery staple"
    now = _JWT_NOW.replace(tzinfo=None) if case in {"change_time", "force_time"} else _JWT_NOW
    if case == "blank_account":
        account_id = " "
    elif case == "compromise_rebind":
        compromise = True
        current_session_id = "session-old"
    elif case == "missing_replacement":
        current_session_id = "session-old"
        replacement = None
    elif case == "missing_current":
        replacement = _replacement_session()
    elif case == "no_session_registry":
        current_session_id = "session-old"
    elif case == "blank_current":
        current_session_id = " "
    elif case == "naive_expiry":
        current_session_id = "session-old"
        replacement = _replacement_session()
        object.__setattr__(replacement, "expires_at", _JWT_NOW.replace(tzinfo=None))

    if case in {"blank_account", "force_time"}:
        outcome = await service.force_reset(account_id, password, expected_epoch=1, now=now)
    else:
        outcome = await service.change(
            account_id,
            password,
            proof=cast("accounts_module.PasswordReauthenticationProof", proof),
            current_session_id=current_session_id,
            replacement_session=replacement if current_session_id is not None or case == "missing_current" else None,
            compromise=compromise,
            now=now,
        )

    assert isinstance(outcome, outcome_type)


async def test_password_change_rebinds_only_current_session_at_new_epoch_and_revokes_all_refresh() -> None:
    store = _PasswordStore()
    cleanup = _CredentialCleanup()
    service = accounts_module.PasswordChangeService(
        accounts=store, hasher=_PasswordHasher(), sessions=cleanup, refresh_tokens=cleanup, event_ids=lambda: "event-1"
    )

    outcome = await service.change(
        "account-1",
        "correct horse battery staple",
        proof=_password_proof(),
        current_session_id="session-old",
        replacement_session=_replacement_session(),
        now=_JWT_NOW + timedelta(seconds=1),
    )

    assert outcome == accounts_module.PasswordChangeOutcome(
        accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2
    )
    assert [(account_id, session_id) for account_id, session_id, _event in cleanup.other_revocations] == [
        ("account-1", "session-old")
    ]
    assert len(cleanup.rebinds) == 1
    prior_session_id, command, event = cleanup.rebinds[0]
    assert (prior_session_id, command.account_id, command.security_epoch, command.created_at) == (
        "session-old",
        "account-1",
        2,
        _JWT_NOW,
    )
    assert (event.operation, event.account_id) == ("local.password.session_rebind", "account-1")
    assert [account_id for account_id, _event in cleanup.refresh_revocations] == ["account-1"]
    assert cleanup.session_revocations == []


@pytest.mark.parametrize("operation", ["compromise", "force_reset", "bearer"])
async def test_password_change_compromise_admin_and_bearer_paths_revoke_every_local_transport(operation: str) -> None:
    store = _PasswordStore()
    cleanup = _CredentialCleanup()
    service = accounts_module.PasswordChangeService(
        accounts=store, hasher=_PasswordHasher(), sessions=cleanup, refresh_tokens=cleanup
    )

    if operation == "force_reset":
        outcome = await service.force_reset("account-1", "correct horse battery staple", expected_epoch=1, now=_JWT_NOW)
    else:
        outcome = await service.change(
            "account-1",
            "correct horse battery staple",
            proof=_password_proof(),
            compromise=operation == "compromise",
            now=_JWT_NOW,
        )

    assert outcome == accounts_module.PasswordChangeOutcome(
        accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2
    )
    assert [account_id for account_id, _event in cleanup.session_revocations] == ["account-1"]
    assert [account_id for account_id, _event in cleanup.refresh_revocations] == ["account-1"]
    assert cleanup.rebinds == []
    assert cleanup.other_revocations == []


async def test_concurrent_password_changes_allow_exactly_one_epoch_compare_and_bump() -> None:
    store = _PasswordStore()
    cleanup = _CredentialCleanup()
    service = accounts_module.PasswordChangeService(
        accounts=store, hasher=_PasswordHasher(), sessions=cleanup, refresh_tokens=cleanup
    )
    outcomes: list[object] = []

    async def change() -> None:
        outcomes.append(
            await service.change("account-1", "correct horse battery staple", proof=_password_proof(), now=_JWT_NOW)
        )

    async with create_task_group() as task_group:
        task_group.start_soon(change)
        task_group.start_soon(change)

    statuses = [cast("accounts_module.PasswordChangeOutcome", outcome).status for outcome in outcomes]
    assert statuses.count(accounts_module.PasswordChangeStatus.CHANGED) == 1
    assert statuses.count(accounts_module.PasswordChangeStatus.CONFLICT) == 1
    assert len(cleanup.session_revocations) == 1
    assert len(cleanup.refresh_revocations) == 1


@pytest.mark.parametrize(
    ("epoch", "expected_status", "hash_calls"),
    [
        (9_223_372_036_854_775_806, accounts_module.PasswordChangeStatus.CHANGED, ["correct horse battery staple"]),
        (9_223_372_036_854_775_807, accounts_module.PasswordChangeStatus.EPOCH_EXHAUSTED, []),
    ],
)
async def test_password_change_never_wraps_security_epoch(
    epoch: int, expected_status: accounts_module.PasswordChangeStatus, hash_calls: list[str]
) -> None:
    store = _PasswordStore(security_epoch=epoch)
    hasher = _PasswordHasher()
    service = accounts_module.PasswordChangeService(accounts=store, hasher=hasher)

    outcome = await service.change(
        "account-1", "correct horse battery staple", proof=_password_proof(security_epoch=epoch), now=_JWT_NOW
    )

    assert isinstance(outcome, accounts_module.PasswordChangeOutcome)
    assert outcome.status is expected_status
    assert hasher.hash_calls == hash_calls


@pytest.mark.parametrize("failure", ["sessions", "refresh", "others", "rebind"])
async def test_committed_password_change_survives_best_effort_cleanup_failure(
    failure: str, caplog: pytest.LogCaptureFixture
) -> None:
    store = _PasswordStore()
    cleanup = _CredentialCleanup(failures=frozenset({failure}))
    service = accounts_module.PasswordChangeService(
        accounts=store, hasher=_PasswordHasher(), sessions=cleanup, refresh_tokens=cleanup
    )
    rebind = failure in {"others", "rebind"}

    outcome = await service.change(
        "account-1",
        "correct horse battery staple",
        proof=_password_proof(),
        current_session_id="session-old" if rebind else None,
        replacement_session=_replacement_session() if rebind else None,
        now=_JWT_NOW,
    )

    assert outcome == accounts_module.PasswordChangeOutcome(
        accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2
    )
    assert "cleanup failed" in caplog.text or "rebind failed" in caplog.text


@pytest.mark.parametrize(
    ("current_epoch", "presented_epoch", "fail", "outcome_type"),
    [
        (3, 3, False, type(None)),
        (3, 2, False, InvalidCredentials),
        (None, 3, False, InvalidCredentials),
        (True, 1, False, InvalidCredentials),
        (3, 3, True, VerificationUnavailable),
    ],
)
async def test_security_epoch_validator_maps_exact_current_invalid_and_unavailable_states(
    current_epoch: object, presented_epoch: int, *, fail: bool, outcome_type: type[object]
) -> None:
    store = _PasswordStore(security_epoch=cast("int", current_epoch), fail_read=fail)
    validator = accounts_module.SecurityEpochValidator(cast("Any", store))

    outcome = await validator.validate("account-1", presented_epoch)

    assert isinstance(outcome, outcome_type)


async def test_security_epoch_validator_rejects_invalid_configuration_and_presented_state() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Security epoch validator"):
        accounts_module.SecurityEpochValidator(cast("Any", object()))
    validator = accounts_module.SecurityEpochValidator(_PasswordStore())
    invalid_value: object = True
    invalid_epoch = cast("int", invalid_value)

    assert isinstance(await validator.validate(" ", 1), InvalidCredentials)
    assert isinstance(await validator.validate("account-1", invalid_epoch), InvalidCredentials)
