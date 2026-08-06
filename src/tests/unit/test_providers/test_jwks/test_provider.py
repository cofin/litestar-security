"""JWKS provider behavior.."""

import asyncio
import json
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast

import pytest
from anyio import CancelScope, CapacityLimiter, Event, create_task_group, fail_after, get_cancelled_exc_class
from anyio.lowlevel import checkpoint
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.providers.jwks import (
    AsyncJWKSFetcher,
    CachedJWKSProvider,
    JWKSCacheEntry,
    JWKSCachePolicy,
    JWKSFetchRequest,
    JWKSFetchResponse,
    normalize_fetcher,
)
from litestar_security.providers.jwt import VerificationKey
from tests.fixtures.collaborators import RecordingJWKSFetcher

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)

_JWT_ISSUER = "https://issuer.example"

_JWKS_URI = f"{_JWT_ISSUER}/.well-known/jwks.json"


def _RecordingJWKSFetcher(  # noqa: N802 - constructor-shaped adapter over the shared collaborator
    *responses: JWKSFetchResponse | Exception | Callable[[JWKSFetchRequest], JWKSFetchResponse],
) -> RecordingJWKSFetcher:
    return RecordingJWKSFetcher(list(responses))


class _BlockingJWKSFetcher:
    def __init__(
        self,
        *responses: JWKSFetchResponse | Exception | Callable[[JWKSFetchRequest], JWKSFetchResponse],
        immediate_calls: int = 0,
        maximum_calls: int = 1,
        issuers: tuple[str, ...] = (),
    ) -> None:
        self.responses = responses
        self.immediate_calls = immediate_calls
        self.maximum_calls = maximum_calls
        self.requests: list[JWKSFetchRequest] = []
        self.started = Event()
        self.started_by_issuer = {issuer: Event() for issuer in issuers}
        self.release = Event()
        self.finished = Event()
        self.active = 0
        self.cancelled = 0

    async def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        self.requests.append(request)
        call_number = len(self.requests)
        if call_number > self.maximum_calls:
            message = "Concurrent JWKS fetch escaped single-flight coordination"
            raise AssertionError(message)
        if call_number > self.immediate_calls:
            self.active += 1
            self.started.set()
            if issuer_started := self.started_by_issuer.get(request.issuer):
                issuer_started.set()
            try:
                await self.release.wait()
            except get_cancelled_exc_class():
                self.cancelled += 1
                raise
            finally:
                self.active -= 1
                if self.active == 0:
                    self.finished.set()
        response = self.responses[call_number - 1]
        if isinstance(response, Exception):
            raise response
        return response(request) if callable(response) else response


def _verification_jwk(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], algorithm: str = "EdDSA", key_id: str = "key-1"
) -> dict[str, object]:
    key = VerificationKey(key_id=key_id, algorithm=algorithm, key=jwt_key_material[algorithm][1])  # type: ignore[arg-type]
    return dict(cast("Mapping[str, object]", key.public_jwk))


def _jwks_body(*keys: Mapping[str, object]) -> bytes:
    return json.dumps({"keys": [dict(key) for key in keys]}, separators=(",", ":")).encode()


def _jwks_response(
    *keys: Mapping[str, object],
    status_code: int = 200,
    body: bytes | None = None,
    cache_control: str | None = None,
    etag: str | None = None,
) -> JWKSFetchResponse:
    headers: dict[str, str] = {"content-type": "application/json"}
    if cache_control is not None:
        headers["cache-control"] = cache_control
    if etag is not None:
        headers["etag"] = etag
    return JWKSFetchResponse(status_code=status_code, body=_jwks_body(*keys) if body is None else body, headers=headers)


def _jwks_entry(
    issuer: str = _JWT_ISSUER, jwks_uri: str = _JWKS_URI, algorithms: frozenset[str] = frozenset({"EdDSA"})
) -> JWKSCacheEntry:
    return JWKSCacheEntry(issuer=issuer, jwks_uri=jwks_uri, algorithms=algorithms)


def test_jwks_public_cache_defaults_and_fetcher_contract() -> None:
    policy = JWKSCachePolicy()
    response = JWKSFetchResponse(status_code=304, body=b"", headers={"cache-control": "max-age=60"})
    default_response = JWKSFetchResponse(status_code=304)
    fetcher = _RecordingJWKSFetcher(response)

    assert isinstance(fetcher, AsyncJWKSFetcher)
    assert policy.default_ttl == timedelta(minutes=15)
    assert policy.minimum_ttl == timedelta(seconds=30)
    assert policy.maximum_ttl == timedelta(hours=24)
    assert policy.unknown_kid_cooldown == timedelta(seconds=30)
    assert policy.stale_if_error == timedelta(0)
    assert policy.warm_on_startup is False
    assert policy.maximum_unknown_keys == 1024
    assert default_response.body == b""
    assert default_response.headers == {}
    with pytest.raises(TypeError):
        response.headers["cache-control"] = "changed"  # type: ignore[index]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"default_ttl": 30},
        {"default_ttl": timedelta(0)},
        {"minimum_ttl": timedelta(0)},
        {"maximum_ttl": timedelta(0)},
        {"minimum_ttl": timedelta(minutes=2), "maximum_ttl": timedelta(minutes=1)},
        {"default_ttl": timedelta(seconds=29)},
        {"default_ttl": timedelta(hours=25)},
        {"unknown_kid_cooldown": timedelta(0)},
        {"stale_if_error": timedelta(seconds=-1)},
        {"warm_on_startup": 1},
        {"maximum_document_bytes": 0},
        {"maximum_document_bytes": True},
        {"maximum_document_bytes": 1_048_577},
        {"maximum_keys": 0},
        {"maximum_keys": True},
        {"maximum_keys": 129},
        {"maximum_unknown_keys": 0},
        {"maximum_unknown_keys": True},
    ],
    ids=[
        "duration-type",
        "default-ttl",
        "minimum-ttl",
        "maximum-ttl",
        "ttl-order",
        "default-below-minimum",
        "default-above-maximum",
        "unknown-kid-cooldown",
        "negative-stale",
        "warmup-type",
        "document-bytes-zero",
        "document-bytes-bool",
        "document-bytes-maximum",
        "keys-zero",
        "keys-bool",
        "keys-maximum",
        "unknown-keys-zero",
        "unknown-keys-bool",
    ],
)
def test_jwks_cache_policy_rejects_unsafe_bounds(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        JWKSCachePolicy(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status_code": True},
        {"status_code": 99},
        {"status_code": 600},
        {"status_code": 200, "body": "body"},
        {"status_code": 200, "headers": {1: "value"}},
        {"status_code": 200, "headers": {"": "value"}},
        {"status_code": 200, "headers": {"name": 1}},
        {"status_code": 200, "headers": object()},
    ],
    ids=[
        "status-bool",
        "status-low",
        "status-high",
        "body-type",
        "header-name-type",
        "header-name-empty",
        "header-value-type",
        "header-mapping-type",
    ],
)
def test_jwks_fetch_response_rejects_invalid_transport_values(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        JWKSFetchResponse(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: JWKSCacheEntry(issuer=" ", jwks_uri=_JWKS_URI, algorithms=frozenset({"EdDSA"})),
        lambda: JWKSCacheEntry(issuer=_JWT_ISSUER, jwks_uri=" ", algorithms=frozenset({"EdDSA"})),
        lambda: JWKSCacheEntry(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, algorithms=frozenset()),
        lambda: JWKSCacheEntry(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, algorithms=frozenset({"none"})),
        lambda: CachedJWKSProvider(entries=(), fetcher=_RecordingJWKSFetcher()),
        lambda: CachedJWKSProvider(entries=(_jwks_entry(), _jwks_entry()), fetcher=_RecordingJWKSFetcher()),
        lambda: CachedJWKSProvider(
            entries=(object(),),  # type: ignore[arg-type]
            fetcher=_RecordingJWKSFetcher(),
        ),
        lambda: CachedJWKSProvider(
            entries=(_jwks_entry(),),
            fetcher=object(),  # type: ignore[arg-type]
        ),
    ],
    ids=[
        "issuer",
        "uri",
        "empty-algorithms",
        "unsupported-algorithm",
        "empty-entries",
        "duplicate-entry",
        "entry-type",
        "fetcher-type",
    ],
)
def test_jwks_provider_rejects_invalid_configured_entries(factory: Callable[[], object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        factory()


async def test_jwks_cold_load_uses_default_ttl_and_fresh_hit_does_no_fetch(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, etag='"generation-1"'), _jwks_response(jwk, etag='"generation-2"')
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    cold = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    fresh = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(minutes=14, seconds=59)
    )
    boundary = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(minutes=15))

    assert isinstance(cold, VerificationKey)
    assert fresh is cold
    assert isinstance(boundary, VerificationKey)
    assert fetcher.requests == [
        JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, etag=None),
        JWKSFetchRequest(issuer=_JWT_ISSUER, jwks_uri=_JWKS_URI, etag='"generation-1"'),
    ]


@pytest.mark.parametrize("cache_state", ["cold", "expired"])
async def test_jwks_concurrent_callers_share_one_refresh(
    cache_state: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    expired = cache_state == "expired"
    jwk = _verification_jwk(jwt_key_material)
    response = _jwks_response(jwk, cache_control="max-age=30", etag='"generation-1"')
    fetcher = _BlockingJWKSFetcher(
        response, response, immediate_calls=1 if expired else 0, maximum_calls=2 if expired else 1
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    now = _JWT_NOW
    if expired:
        assert isinstance(await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=now), VerificationKey)
        now += timedelta(seconds=30)
    outcomes: list[object | None] = [None] * 100

    async def select(index: int) -> None:
        outcomes[index] = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=now)

    async with create_task_group() as task_group:
        for index in range(len(outcomes)):
            task_group.start_soon(select, index)
        await fetcher.started.wait()
        await checkpoint()
        fetcher.release.set()

    expected_fetches = 2 if expired else 1
    assert len(fetcher.requests) == expected_fetches
    assert isinstance(outcomes[0], VerificationKey)
    assert all(outcome is outcomes[0] for outcome in outcomes)


async def test_jwks_cancelling_one_waiter_preserves_shared_refresh(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _BlockingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material), cache_control="max-age=60"))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    cancelled_scope: list[CancelScope] = []
    cancelled_outcomes: list[object] = []
    survivor_outcomes: list[object] = []
    survivor_started = Event()
    cancelled_finished = Event()

    async def cancelled_waiter() -> None:
        try:
            with CancelScope() as scope:
                cancelled_scope.append(scope)
                cancelled_outcomes.append(
                    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
                )
        finally:
            cancelled_finished.set()

    async def survivor() -> None:
        survivor_started.set()
        survivor_outcomes.append(await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW))

    async with create_task_group() as task_group:
        task_group.start_soon(cancelled_waiter)
        await fetcher.started.wait()
        task_group.start_soon(survivor)
        await survivor_started.wait()
        await checkpoint()
        cancelled_scope[0].cancel()
        with fail_after(1):
            await cancelled_finished.wait()
        assert fetcher.active == 1
        fetcher.release.set()

    assert cancelled_outcomes == []
    assert len(fetcher.requests) == 1
    assert len(survivor_outcomes) == 1
    assert isinstance(survivor_outcomes[0], VerificationKey)


async def test_jwks_independent_issuer_refreshes_proceed_concurrently(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    second_issuer = "https://issuer-two.example"
    second_uri = f"{second_issuer}/jwks"
    first = _verification_jwk(jwt_key_material, "EdDSA", "first")
    second = _verification_jwk(jwt_key_material, "ES256", "second")

    def respond(request: JWKSFetchRequest) -> JWKSFetchResponse:
        return _jwks_response(first if request.issuer == _JWT_ISSUER else second, cache_control="max-age=60")

    fetcher = _BlockingJWKSFetcher(respond, respond, maximum_calls=2, issuers=(_JWT_ISSUER, second_issuer))
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri, frozenset({"ES256"}))), fetcher=fetcher
    )
    outcomes: list[object] = []

    async def select(issuer: str, uri: str, kid: str, algorithm: str) -> None:
        outcomes.append(await provider.select_key(issuer, uri, kid, algorithm, now=_JWT_NOW))

    async with create_task_group() as task_group:
        task_group.start_soon(select, _JWT_ISSUER, _JWKS_URI, "first", "EdDSA")
        await fetcher.started_by_issuer[_JWT_ISSUER].wait()
        task_group.start_soon(select, second_issuer, second_uri, "second", "ES256")
        with fail_after(1):
            await fetcher.started_by_issuer[second_issuer].wait()
        fetcher.release.set()

    assert len(fetcher.requests) == 2
    assert {outcome.algorithm for outcome in outcomes if isinstance(outcome, VerificationKey)} == {"EdDSA", "ES256"}


async def test_jwks_fresh_issuer_path_is_lock_and_fetch_free(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    second_issuer = "https://fresh.example"
    second_uri = f"{second_issuer}/jwks"
    first = _jwks_response(_verification_jwk(jwt_key_material, key_id="first"), cache_control="max-age=30")
    second = _jwks_response(_verification_jwk(jwt_key_material, key_id="second"), cache_control="max-age=300")
    fetcher = _BlockingJWKSFetcher(first, second, first, immediate_calls=2, maximum_calls=3)

    class FailingLock:
        async def __aenter__(self) -> None:
            msg = "fresh selection acquired the entry lock"
            raise AssertionError(msg)

        async def __aexit__(self, *_args: object) -> None:
            return None

    provider = CachedJWKSProvider(entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri)), fetcher=fetcher)
    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "first", "EdDSA", now=_JWT_NOW)
    await provider.select_key(second_issuer, second_uri, "second", "EdDSA", now=_JWT_NOW)
    state = cast("Any", provider)._entries[(second_issuer, second_uri)]  # noqa: SLF001
    state.lock = FailingLock()
    fresh_result: list[object] = []

    async def refresh_expired() -> None:
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "first", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))

    async with create_task_group() as task_group:
        task_group.start_soon(refresh_expired)
        await fetcher.started.wait()
        with fail_after(0.1):
            fresh_result.append(
                await provider.select_key(
                    second_issuer, second_uri, "second", "EdDSA", now=_JWT_NOW + timedelta(seconds=30)
                )
            )
        fetcher.release.set()

    assert isinstance(fresh_result[0], VerificationKey)
    assert len(fetcher.requests) == 3


async def test_jwks_single_flight_and_cache_bounds(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    keys = tuple(_verification_jwk(jwt_key_material, key_id=f"known-{index}") for index in range(4))
    response = _jwks_response(*keys, cache_control="max-age=60")
    blocking_fetcher = _BlockingJWKSFetcher(response)
    cold_provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=blocking_fetcher)
    cold_results: list[object | None] = [None] * 100

    async def select_cold(index: int) -> None:
        cold_results[index] = await cold_provider.select_key(_JWT_ISSUER, _JWKS_URI, "known-0", "EdDSA", now=_JWT_NOW)

    async with create_task_group() as task_group:
        for index in range(len(cold_results)):
            task_group.start_soon(select_cold, index)
        await blocking_fetcher.started.wait()
        await checkpoint()
        blocking_fetcher.release.set()

    policy = JWKSCachePolicy(maximum_keys=4, maximum_unknown_keys=64)
    not_modified = JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"})
    bounded_fetcher = _RecordingJWKSFetcher(response, not_modified)
    bounded_provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=bounded_fetcher, policy=policy)
    await bounded_provider.select_key(_JWT_ISSUER, _JWKS_URI, "known-0", "EdDSA", now=_JWT_NOW)
    for _ in range(1_000):
        await bounded_provider.select_key(
            _JWT_ISSUER, _JWKS_URI, "repeated-unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=1)
        )
    for index in range(1_000):
        await bounded_provider.select_key(
            _JWT_ISSUER, _JWKS_URI, f"unknown-{index}", "EdDSA", now=_JWT_NOW + timedelta(seconds=1)
        )
    state = cast("Any", bounded_provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001
    snapshot = cast("Any", bounded_provider)._cache.get(_JWT_ISSUER, _JWKS_URI)  # noqa: SLF001

    assert len(blocking_fetcher.requests) == 1
    assert all(result is cold_results[0] for result in cold_results)
    assert len(bounded_fetcher.requests) == 2
    assert len(cast("Any", bounded_provider)._entries) == 1  # noqa: SLF001
    assert snapshot is not None
    assert len(snapshot.keys) <= policy.maximum_keys
    assert len(state.negative) <= policy.maximum_unknown_keys


async def test_jwks_fresh_unknown_key_forces_one_refresh_and_retries(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    rotated = _verification_jwk(jwt_key_material, key_id="rotated")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'),
        _jwks_response(known, rotated, cache_control="max-age=60", etag='"generation-2"'),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "rotated", "EdDSA", now=_JWT_NOW + timedelta(seconds=1))

    assert isinstance(outcome, VerificationKey)
    assert outcome.key_id == "rotated"
    assert len(fetcher.requests) == 2


async def test_jwks_unknown_selection_negative_cache_is_per_generation_tuple(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="shared")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(algorithms=frozenset({"EdDSA", "ES256"})),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    first = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "ES256", now=_JWT_NOW + timedelta(seconds=1))
    second = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "ES256", now=_JWT_NOW + timedelta(seconds=2))
    valid_tuple = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "shared", "EdDSA", now=_JWT_NOW + timedelta(seconds=2)
    )

    assert isinstance(first, InvalidCredentials)
    assert isinstance(second, InvalidCredentials)
    assert isinstance(valid_tuple, VerificationKey)
    assert len(fetcher.requests) == 2


async def test_jwks_expired_unknown_selection_is_cached_after_refresh(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=30", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    outcome = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=30)
    )
    repeated = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=31)
    )

    assert isinstance(outcome, InvalidCredentials)
    assert isinstance(repeated, InvalidCredentials)
    assert len(fetcher.requests) == 2


async def test_jwks_failed_forced_refresh_is_generation_limited_and_prunes_expired_negative(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'), OSError("temporary")
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    failed = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=1))
    suppressed = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=2)
    )
    after_cooldown = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=32)
    )

    assert isinstance(failed, VerificationUnavailable)
    assert isinstance(suppressed, InvalidCredentials)
    assert isinstance(after_cooldown, InvalidCredentials)
    assert len(fetcher.requests) == 2


async def test_jwks_generation_replacement_invalidates_unknown_key_negatives(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    replacement = _verification_jwk(jwt_key_material, key_id="replacement")
    formerly_unknown = _verification_jwk(jwt_key_material, key_id="absent")
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=30", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=30"}),
        _jwks_response(replacement, cache_control="max-age=30", etag='"generation-2"'),
        _jwks_response(replacement, formerly_unknown, cache_control="max-age=30", etag='"generation-3"'),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "absent", "EdDSA", now=_JWT_NOW + timedelta(seconds=1)),
        InvalidCredentials,
    )
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "replacement", "EdDSA", now=_JWT_NOW + timedelta(seconds=31)),
        VerificationKey,
    )
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "absent", "EdDSA", now=_JWT_NOW + timedelta(seconds=32))

    assert isinstance(outcome, VerificationKey)
    assert len(fetcher.requests) == 4


async def test_jwks_unknown_key_negative_cache_is_bounded_lru(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    known = _verification_jwk(jwt_key_material, key_id="known")
    not_modified = JWKSFetchResponse(status_code=304, headers={"cache-control": "max-age=60"})
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(known, cache_control="max-age=60", etag='"generation-1"'), *(not_modified for _ in range(5))
    )
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),), fetcher=fetcher, policy=JWKSCachePolicy(maximum_unknown_keys=3)
    )

    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW), VerificationKey
    )
    for kid in ("unknown-a", "unknown-b", "unknown-c", "unknown-d"):
        assert isinstance(
            await provider.select_key(_JWT_ISSUER, _JWKS_URI, kid, "EdDSA", now=_JWT_NOW + timedelta(seconds=1)),
            InvalidCredentials,
        )
    state = cast("Any", provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001
    assert tuple((generation, kid, algorithm) for generation, kid, algorithm in state.negative) == (
        (1, "unknown-b", "EdDSA"),
        (1, "unknown-c", "EdDSA"),
        (1, "unknown-d", "EdDSA"),
    )
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "unknown-a", "EdDSA", now=_JWT_NOW + timedelta(seconds=2)),
        InvalidCredentials,
    )

    assert len(state.negative) == 3
    assert tuple(key[1] for key in state.negative) == ("unknown-c", "unknown-d", "unknown-a")
    assert len(fetcher.requests) == 2


async def test_jwks_shared_refresh_failure_is_consistent_for_all_waiters(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    del jwt_key_material
    fetcher = _BlockingJWKSFetcher(OSError("shared fetch detail"))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    outcomes: list[object | None] = [None] * 100

    async def select(index: int) -> None:
        outcomes[index] = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    async with create_task_group() as task_group:
        for index in range(len(outcomes)):
            task_group.start_soon(select, index)
        await fetcher.started.wait()
        await checkpoint()
        fetcher.release.set()

    assert len(fetcher.requests) == 1
    assert isinstance(outcomes[0], VerificationUnavailable)
    assert all(outcome is outcomes[0] for outcome in outcomes)


async def test_jwks_pending_refresh_cancellation_is_sanitized() -> None:
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=_RecordingJWKSFetcher())
    cancelled_task = asyncio.create_task(checkpoint())
    cancelled_task.cancel()
    await checkpoint()
    state = cast("Any", provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001
    state.refresh = SimpleNamespace(task=cancelled_task)

    outcome = await cast("Any", provider)._refresh_singleflight(state, _JWT_NOW)  # noqa: SLF001

    assert isinstance(outcome, VerificationUnavailable)
    await provider.aclose()


async def test_jwks_close_cancels_and_awaits_live_refresh_tasks(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _BlockingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material)))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    async def select() -> None:
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    async with create_task_group() as task_group:
        task_group.start_soon(select)
        await fetcher.started.wait()
        task_group.start_soon(provider.aclose)
        with fail_after(1):
            await fetcher.finished.wait()

    assert fetcher.active == 0
    assert fetcher.cancelled == 1
    assert isinstance(
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW), VerificationUnavailable
    )


@pytest.mark.parametrize(
    ("cache_control", "fresh_offset", "expired_offset"),
    [
        ("public, max-age=1", timedelta(seconds=29), timedelta(seconds=30)),
        ("max-age=999999", timedelta(minutes=59, seconds=59), timedelta(hours=1)),
        ("public, malformed=value", timedelta(minutes=14, seconds=59), timedelta(minutes=15)),
    ],
    ids=["minimum-clamp", "maximum-clamp", "default-fallback"],
)
async def test_jwks_cache_control_ttl_is_clamped_or_defaults(
    cache_control: str,
    fresh_offset: timedelta,
    expired_offset: timedelta,
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    policy = JWKSCachePolicy(maximum_ttl=timedelta(hours=1))
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control=cache_control), _jwks_response(jwk, cache_control=cache_control)
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, policy=policy)

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + fresh_offset)
    assert len(fetcher.requests) == 1

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + expired_offset)
    assert len(fetcher.requests) == 2


@pytest.mark.parametrize("directive", ["no-cache", "no-store"])
async def test_jwks_no_cache_and_no_store_revalidate_immediately(
    directive: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control=directive, etag='"generation-1"'),
        _jwks_response(jwk, cache_control="max-age=60", etag='"generation-2"'),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    first = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    second = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(first, VerificationKey)
    assert isinstance(second, VerificationKey)
    assert len(fetcher.requests) == 2
    assert fetcher.requests[1].etag == '"generation-1"'


async def test_jwks_conditional_304_retains_snapshot_and_recomputes_freshness(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30", etag='"generation-1"'),
        JWKSFetchResponse(status_code=304, body=b"", headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    original = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    retained = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))
    fresh = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=89))

    assert retained is original
    assert fresh is original
    assert len(fetcher.requests) == 2
    assert fetcher.requests[1].etag == '"generation-1"'


async def test_jwks_304_without_a_live_snapshot_is_unavailable() -> None:
    fetcher = _RecordingJWKSFetcher(JWKSFetchResponse(status_code=304, body=b"", headers={}))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


async def test_jwks_fetcher_returning_wrong_response_type_is_unavailable() -> None:
    class _WrongResponseFetcher:
        async def fetch(self, _request: JWKSFetchRequest) -> object:
            return object()

    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),),
        fetcher=_WrongResponseFetcher(),  # type: ignore[arg-type]
    )

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


async def test_jwks_metrics_are_vendor_neutral_and_redacted(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    records: list[tuple[str, float | None, dict[str, str]]] = []

    class Metrics:
        def increment(self, name: str, *, attributes: Mapping[str, str] = {}) -> None:
            records.append((name, None, dict(attributes)))

        def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = {}) -> None:
            records.append((name, value, dict(attributes)))

    known = _verification_jwk(jwt_key_material, key_id="known")
    fetcher = _RecordingJWKSFetcher(_jwks_response(known, cache_control="max-age=60"), OSError("operational-detail"))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, metrics=Metrics())

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "known", "EdDSA", now=_JWT_NOW)
    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "attacker-kid", "EdDSA", now=_JWT_NOW)
    rendered = repr(records)

    assert {"security.jwks.refresh_success", "security.jwks.unknown_key", "security.jwks.refresh_failure"} <= {
        name for name, _, _ in records
    }
    assert all(value is None or value >= 0 for _, value, _ in records)
    assert all(secret not in rendered for secret in (_JWT_ISSUER, _JWKS_URI, "attacker-kid", "operational-detail"))


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"metrics": object()}, "must implement SecurityMetrics"),
        ({"fetcher_owned": 1}, "ownership must be boolean"),
        ({"worker_limits": object()}, "worker limits must be WorkerLimits"),
    ],
)
def test_jwks_provider_rejects_invalid_runtime_configuration(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        CachedJWKSProvider(
            entries=(_jwks_entry(),),
            fetcher=_RecordingJWKSFetcher(),
            **kwargs,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(("fetcher_owned", "expected_closes"), [(False, 0), (True, 1)])
async def test_jwks_provider_closes_only_owned_fetchers(
    *, fetcher_owned: bool, expected_closes: int, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    class Fetcher:
        def __init__(self) -> None:
            self.closes = 0

        async def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return _jwks_response(_verification_jwk(jwt_key_material))

        async def aclose(self) -> None:
            self.closes += 1

    fetcher = Fetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, fetcher_owned=fetcher_owned)

    await provider.aclose()
    await provider.aclose()

    assert fetcher.closes == expected_closes


async def test_jwks_provider_closes_owned_sync_fetcher_in_worker() -> None:
    class SyncFetcher:
        def __init__(self) -> None:
            self.closes = 0

        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')

        def close(self) -> None:
            self.closes += 1

    source = SyncFetcher()
    normalized = normalize_fetcher(source, limiter=CapacityLimiter(1))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=normalized, fetcher_owned=True)

    await provider.aclose()

    assert source.closes == 1


async def test_jwks_provider_accepts_owned_sync_fetcher_without_close() -> None:
    class SyncFetcher:
        def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')

    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),),
        fetcher=normalize_fetcher(SyncFetcher(), limiter=CapacityLimiter(1)),
        fetcher_owned=True,
    )

    await provider.aclose()


@pytest.mark.parametrize("close_mode", ["absent", "sync"])
async def test_jwks_provider_accepts_owned_fetchers_without_async_close(close_mode: str) -> None:
    class Fetcher:
        async def fetch(self, _request: JWKSFetchRequest) -> JWKSFetchResponse:
            return JWKSFetchResponse(status_code=200, body=b'{"keys":[]}')

    class SyncCloseFetcher(Fetcher):
        def aclose(self) -> None:
            return None

    fetcher = Fetcher() if close_mode == "absent" else SyncCloseFetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, fetcher_owned=True)

    await provider.aclose()
