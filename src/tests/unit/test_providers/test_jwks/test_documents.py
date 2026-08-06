"""JWKS document and lifecycle tests."""

import json
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.providers.jwks import (
    CachedJWKSProvider,
    JWKSCacheEntry,
    JWKSCachePolicy,
    JWKSFetchRequest,
    JWKSFetchResponse,
)
from litestar_security.providers.jwks import _documents as jwks_documents
from litestar_security.providers.jwt import VerificationKey
from tests.fixtures.collaborators import RecordingJWKSFetcher

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)

_NAIVE_JWT_NOW = datetime(2026, 7, 26)  # noqa: DTZ001 - explicit rejection fixture

_JWT_ISSUER = "https://issuer.example"

_JWKS_URI = f"{_JWT_ISSUER}/.well-known/jwks.json"


def _RecordingJWKSFetcher(  # noqa: N802 - constructor-shaped adapter over the shared collaborator
    *responses: JWKSFetchResponse | Exception | Callable[[JWKSFetchRequest], JWKSFetchResponse],
) -> RecordingJWKSFetcher:
    return RecordingJWKSFetcher(list(responses))


def _verification_jwk(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], algorithm: str = "EdDSA", key_id: str = "key-1"
) -> dict[str, object]:
    key = VerificationKey(key_id=key_id, algorithm=algorithm, key=jwt_key_material[algorithm][1])  # type: ignore[arg-type]
    return dict(cast("Mapping[str, object]", key.public_jwk))


def _raw_public_jwk(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], source_algorithm: str, algorithm: str, key_id: str
) -> dict[str, object]:
    public_key = serialization.load_pem_public_key(jwt_key_material[source_algorithm][1])
    serializer_algorithm = {"ES384": "ES256", "RS1024": "RS256"}.get(source_algorithm, source_algorithm)
    jwk = cast("dict[str, object]", jwt.get_algorithm_by_name(serializer_algorithm).to_jwk(public_key, as_dict=True))
    jwk.update({"alg": algorithm, "kid": key_id, "key_ops": ["verify"], "use": "sig"})
    return jwk


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


async def test_jwks_atomic_replacement_exposes_new_and_removes_old_keys(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    old = _verification_jwk(jwt_key_material, "EdDSA", "old")
    new = _verification_jwk(jwt_key_material, "ES256", "new")
    replacement = _jwks_response(new, cache_control="max-age=60", etag='"generation-2"')
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(old, cache_control="max-age=30", etag='"generation-1"'), replacement, replacement
    )
    entry = _jwks_entry(algorithms=frozenset({"EdDSA", "ES256"}))
    provider = CachedJWKSProvider(entries=(entry,), fetcher=fetcher)

    old_key = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "old", "EdDSA", now=_JWT_NOW)
    new_key = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "new", "ES256", now=_JWT_NOW + timedelta(seconds=30))
    removed = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "old", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))

    assert isinstance(old_key, VerificationKey)
    assert isinstance(new_key, VerificationKey)
    assert new_key.key_id == "new"
    assert isinstance(removed, InvalidCredentials)


@pytest.mark.parametrize(
    "failure",
    [
        OSError("fetch detail"),
        _jwks_response(status_code=500, body=b"upstream detail"),
        _jwks_response(status_code=404, body=b"upstream detail"),
        _jwks_response(body=b"{"),
        _jwks_response({"alg": "EdDSA", "crv": "Ed25519", "kid": "new", "kty": "OKP", "use": "sig", "x": "bad"}),
    ],
    ids=["fetch", "http-5xx", "http-4xx", "parse", "partial-key-parse"],
)
async def test_jwks_failed_refresh_does_not_mutate_live_snapshot(
    failure: JWKSFetchResponse | Exception, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30", etag='"generation-1"'),
        failure,
        JWKSFetchResponse(status_code=304, body=b"", headers={"cache-control": "max-age=60"}),
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)
    original = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    failed = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))
    retained = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=31))

    assert isinstance(failed, VerificationUnavailable)
    assert retained is original
    assert fetcher.requests[1].etag == '"generation-1"'
    assert fetcher.requests[2].etag == '"generation-1"'
    assert "detail" not in repr(failed)


async def test_jwks_stale_if_error_is_local_explicit_and_bounded(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30, stale-if-error=999", etag='"generation-1"'),
        OSError("temporary"),
        OSError("still unavailable"),
    )
    policy = JWKSCachePolicy(stale_if_error=timedelta(seconds=60))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher, policy=policy)

    original = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    stale = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))
    expired = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=90))

    assert stale is original
    assert isinstance(expired, VerificationUnavailable)


async def test_jwks_stale_if_error_never_accepts_an_unknown_key(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(_verification_jwk(jwt_key_material), cache_control="max-age=30"), OSError("temporary")
    )
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(),), fetcher=fetcher, policy=JWKSCachePolicy(stale_if_error=timedelta(seconds=60))
    )

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    outcome = await provider.select_key(
        _JWT_ISSUER, _JWKS_URI, "unknown", "EdDSA", now=_JWT_NOW + timedelta(seconds=30)
    )

    assert isinstance(outcome, VerificationUnavailable)


async def test_jwks_remote_stale_directive_cannot_enable_local_stale_use(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    jwk = _verification_jwk(jwt_key_material)
    fetcher = _RecordingJWKSFetcher(
        _jwks_response(jwk, cache_control="max-age=30, stale-if-error=999"), OSError("temporary")
    )
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW + timedelta(seconds=30))

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.parametrize(
    "case",
    [
        "body-limit",
        "key-limit",
        "duplicate-json",
        "invalid-json",
        "non-object-json",
        "non-finite-json",
        "excessive-json-depth",
        "keys-not-array",
        "key-not-object",
        "empty-keys",
        "private-member",
        "algorithm-not-configured",
        "wrong-use",
        "wrong-key-ops",
        "duplicate-selection-tuple",
        "missing-kid",
        "unsupported-key-type",
        "weak-rsa",
        "wrong-ec-curve",
    ],
)
async def test_jwks_rejects_unsafe_or_ambiguous_documents(  # noqa: C901, PLR0912, PLR0915
    case: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    valid = _verification_jwk(jwt_key_material)
    body: bytes
    entry_algorithms = frozenset({"EdDSA"})
    selected_algorithm = "EdDSA"
    if case == "body-limit":
        body = b"x" * 1_048_577
    elif case == "key-limit":
        keys = [{**valid, "kid": f"key-{index}"} for index in range(129)]
        body = _jwks_body(*keys)
    elif case == "duplicate-json":
        body = b'{"keys":[],"keys":[]}'
    elif case == "invalid-json":
        body = b"{"
    elif case == "non-object-json":
        body = b"[]"
    elif case == "non-finite-json":
        body = b'{"keys":[],"value":NaN}'
    elif case == "excessive-json-depth":
        nested: object = None
        for _ in range(65):
            nested = {"nested": nested}
        body = json.dumps({"keys": [valid], "extension": nested}, separators=(",", ":")).encode()
    elif case == "keys-not-array":
        body = b'{"keys":{}}'
    elif case == "key-not-object":
        body = b'{"keys":["key"]}'
    elif case == "empty-keys":
        body = _jwks_body()
    elif case == "private-member":
        body = _jwks_body({**valid, "d": "private"})
    elif case == "algorithm-not-configured":
        body = _jwks_body({**valid, "alg": "RS256"})
    elif case == "wrong-use":
        body = _jwks_body({**valid, "use": "enc"})
    elif case == "wrong-key-ops":
        body = _jwks_body({**valid, "key_ops": ["sign"]})
    elif case == "duplicate-selection-tuple":
        body = _jwks_body(valid, valid)
    elif case == "missing-kid":
        body = _jwks_body({key: value for key, value in valid.items() if key != "kid"})
    elif case == "unsupported-key-type":
        body = _jwks_body({**valid, "kty": "unsupported"})
    elif case == "weak-rsa":
        body = _jwks_body(_raw_public_jwk(jwt_key_material, "RS1024", "RS256", "key-1"))
        entry_algorithms = frozenset({"RS256"})
        selected_algorithm = "RS256"
    else:
        body = _jwks_body(_raw_public_jwk(jwt_key_material, "ES384", "ES256", "key-1"))
        entry_algorithms = frozenset({"ES256"})
        selected_algorithm = "ES256"
    fetcher = _RecordingJWKSFetcher(_jwks_response(body=body))
    provider = CachedJWKSProvider(entries=(_jwks_entry(algorithms=entry_algorithms),), fetcher=fetcher)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", selected_algorithm, now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


async def test_jwks_rejects_unsupported_prepared_key_type(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], monkeypatch: pytest.MonkeyPatch
) -> None:
    class _UnsupportedPyJWK:
        @staticmethod
        def from_dict(_value: dict[str, object], *, algorithm: str) -> SimpleNamespace:
            del algorithm
            return SimpleNamespace(key=object())

    monkeypatch.setattr(jwks_documents, "PyJWK", _UnsupportedPyJWK)
    fetcher = _RecordingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material)))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)

    assert isinstance(outcome, VerificationUnavailable)


async def test_jwks_entries_isolate_same_kid_by_issuer_uri_and_algorithm(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    second_issuer = "https://issuer-two.example"
    second_uri = f"{second_issuer}/jwks"
    first = _verification_jwk(jwt_key_material, "EdDSA", "shared")
    second = _verification_jwk(jwt_key_material, "ES256", "shared")

    def respond(request: JWKSFetchRequest) -> JWKSFetchResponse:
        return _jwks_response(first if request.issuer == _JWT_ISSUER else second, cache_control="max-age=60")

    fetcher = _RecordingJWKSFetcher(respond, respond)
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri, frozenset({"ES256"}))), fetcher=fetcher
    )

    first_key = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "shared", "EdDSA", now=_JWT_NOW)
    second_key = await provider.select_key(second_issuer, second_uri, "shared", "ES256", now=_JWT_NOW)

    assert isinstance(first_key, VerificationKey)
    assert isinstance(second_key, VerificationKey)
    assert first_key.algorithm == "EdDSA"
    assert second_key.algorithm == "ES256"
    assert tuple((request.issuer, request.jwks_uri) for request in fetcher.requests) == (
        (_JWT_ISSUER, _JWKS_URI),
        (second_issuer, second_uri),
    )


@pytest.mark.parametrize(
    ("issuer", "jwks_uri", "algorithm"),
    [
        ("https://unconfigured.example", _JWKS_URI, "EdDSA"),
        (_JWT_ISSUER, "https://unconfigured.example/jwks", "EdDSA"),
        (_JWT_ISSUER, _JWKS_URI, "RS256"),
    ],
    ids=["issuer", "uri", "algorithm"],
)
async def test_jwks_unconfigured_entry_coordinates_fail_without_fetch(
    issuer: str, jwks_uri: str, algorithm: str
) -> None:
    fetcher = _RecordingJWKSFetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    outcome = await provider.select_key(issuer, jwks_uri, "key-1", algorithm, now=_JWT_NOW)

    assert isinstance(outcome, InvalidCredentials)
    assert fetcher.requests == []


async def test_jwks_rejects_naive_time_without_fetch() -> None:
    fetcher = _RecordingJWKSFetcher()
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    with pytest.raises(ImproperlyConfiguredException):
        await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_NAIVE_JWT_NOW)

    assert fetcher.requests == []


@pytest.mark.parametrize(("warm_on_startup", "failure"), [(False, False), (True, False), (True, True)])
async def test_jwks_warmup_is_explicit_complete_and_failure_aware(
    *, warm_on_startup: bool, failure: bool, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    second_issuer = "https://issuer-two.example"
    second_uri = f"{second_issuer}/jwks"
    first_response: JWKSFetchResponse | Exception = (
        OSError("warmup unavailable")
        if failure
        else _jwks_response(_verification_jwk(jwt_key_material, "EdDSA", "first"))
    )
    second_response = _jwks_response(_verification_jwk(jwt_key_material, "ES256", "second"))
    fetcher = _RecordingJWKSFetcher(first_response, second_response)
    provider = CachedJWKSProvider(
        entries=(_jwks_entry(), _jwks_entry(second_issuer, second_uri, frozenset({"ES256"}))),
        fetcher=fetcher,
        policy=JWKSCachePolicy(warm_on_startup=warm_on_startup),
    )

    outcome = await provider.warmup(now=_JWT_NOW)
    repeated = outcome if failure else await provider.warmup(now=_JWT_NOW + timedelta(seconds=1))

    if not warm_on_startup:
        assert outcome is None
        assert repeated is None
        assert fetcher.requests == []
    else:
        assert isinstance(outcome, VerificationUnavailable) if failure else outcome is None
        assert isinstance(repeated, VerificationUnavailable) if failure else repeated is None
        assert tuple((request.issuer, request.jwks_uri) for request in fetcher.requests) == (
            (_JWT_ISSUER, _JWKS_URI),
            (second_issuer, second_uri),
        )


async def test_jwks_close_is_idempotent_and_prevents_selection_fetch(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    fetcher = _RecordingJWKSFetcher(_jwks_response(_verification_jwk(jwt_key_material)))
    provider = CachedJWKSProvider(entries=(_jwks_entry(),), fetcher=fetcher)

    await provider.aclose()
    await provider.aclose()
    outcome = await provider.select_key(_JWT_ISSUER, _JWKS_URI, "key-1", "EdDSA", now=_JWT_NOW)
    warmup = await provider.warmup(now=_JWT_NOW)
    state = cast("Any", provider)._entries[(_JWT_ISSUER, _JWKS_URI)]  # noqa: SLF001
    refresh = await cast("Any", provider)._refresh_singleflight(state, _JWT_NOW)  # noqa: SLF001

    assert isinstance(outcome, VerificationUnavailable)
    assert isinstance(warmup, VerificationUnavailable)
    assert isinstance(refresh, VerificationUnavailable)
    assert fetcher.requests == []
