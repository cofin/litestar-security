"""Unit tests for authentication outcomes and registry compilation."""

import base64
import json
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import httpx
import jwt
import pytest
from anyio import Event, get_cancelled_exc_class
from cryptography.hazmat.primitives import serialization
from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi.spec import SecurityScheme

from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationPolicy,
    AuthenticationRegistry,
    InvalidCredentials,
    MechanismRequirement,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
    all_of,
    any_of,
    at_least,
    mechanism,
    optional,
    public,
    required,
)
from litestar_security.config import ExternalCSRF, SecurityConfig
from litestar_security.context import AuthenticationEvidence, Principal
from litestar_security.providers.jwks import JWKSCacheEntry, JWKSFetchRequest, JWKSFetchResponse
from litestar_security.providers.jwt import JWTValidationConfig, PyJWTVerifier, VerificationKey
from litestar_security.providers.oidc import DiscoveryPolicy, OIDCDiscoveryClient, OIDCMetadata

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
_NAIVE_JWT_NOW = datetime(2026, 7, 26)  # noqa: DTZ001 - explicit rejection fixture
_JWT_ISSUER = "https://issuer.example"
_JWT_AUDIENCE = "litestar-security"
_OIDC_ISSUER = "https://issuer.example/tenant"
_OIDC_DISCOVERY_URL = f"{_OIDC_ISSUER}/.well-known/openid-configuration"
_OIDC_PUBLIC_IP = "93.184.216.34"
_JWKS_URI = f"{_JWT_ISSUER}/.well-known/jwks.json"
_MFA_VECTOR_NOW = datetime.fromtimestamp(59, tz=timezone.utc)
_MFA_ENCODED_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def _jwt_claims(**overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": _JWT_ISSUER,
        "sub": "user-1",
        "aud": _JWT_AUDIENCE,
        "exp": int((_JWT_NOW + timedelta(minutes=10)).timestamp()),
        "iat": int(_JWT_NOW.timestamp()),
        "nbf": int((_JWT_NOW - timedelta(seconds=1)).timestamp()),
        "client_id": "client-1",
        "jti": "token-1",
        "scope": "reports:read profile",
        "metadata": {"groups": ["finance", "operations"]},
    }
    claims.update(overrides)
    return claims


def _jwt_config(
    algorithm: str,
    *,
    access_token_profile: bool = True,
    subject_required: bool = True,
    required_claims: frozenset[str] = frozenset({"iss", "sub", "aud", "exp", "iat"}),
    maximum_lifetime: timedelta | None = timedelta(hours=1),
) -> JWTValidationConfig:
    return JWTValidationConfig(
        issuer=_JWT_ISSUER,
        audiences=frozenset({_JWT_AUDIENCE}),
        algorithms=frozenset({algorithm}),
        required_claims=required_claims,
        access_token_profile=access_token_profile,
        subject_required=subject_required,
        maximum_lifetime=maximum_lifetime,
    )


def _encode_jwt(
    signing_key: bytes,
    algorithm: str,
    *,
    claims: Mapping[str, object] | None = None,
    headers: Mapping[str, object] | None = None,
    include_key_id: bool = True,
) -> str:
    protected: dict[str, object] = {"typ": "at+jwt"}
    if include_key_id:
        protected["kid"] = "key-1"
    if headers:
        protected.update(headers)
    encoded = jwt.encode(dict(claims or _jwt_claims()), signing_key, algorithm=algorithm, headers=protected)
    return encoded.decode() if isinstance(encoded, bytes) else encoded


def _jwt_segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _compact_jwt(header: bytes, payload: bytes, signature: bytes = b"signature") -> str:
    return ".".join((_jwt_segment(header), _jwt_segment(payload), _jwt_segment(signature)))


class _Slot:
    def __init__(self, name: str) -> None:
        self.name = name

    def extract(self, _connection: object) -> NoCredentials:
        return NoCredentials()


class _Authenticator:
    def __init__(self, name: str, slot: str, *, participates_by_default: bool = True) -> None:
        self.name = name
        self.slot = slot
        self.participates_by_default = participates_by_default

    async def authenticate(self, _credential: str, _connection: object) -> NoCredentials:
        return NoCredentials()


class _Resolver:
    async def resolve(self, claims: str) -> Principal[object]:
        return Principal(id=claims)


class _RecordingJWTVerifier:
    def __init__(self, outcome: object, config: JWTValidationConfig) -> None:
        self.outcome = outcome
        self.config = config
        self.calls: list[tuple[str, datetime]] = []

    async def verify(self, token: str, *, now: datetime) -> object:
        self.calls.append((token, now))
        return self.outcome


def _recording_jwt_verifier(
    outcome: object, *, issuer: str = _JWT_ISSUER, audiences: frozenset[str] = frozenset({_JWT_AUDIENCE})
) -> _RecordingJWTVerifier:
    return _RecordingJWTVerifier(
        outcome, JWTValidationConfig(issuer=issuer, audiences=audiences, algorithms=frozenset({"HS256"}))
    )


class _FakeOIDCResolver:
    def __init__(self, answers: Mapping[str, tuple[str, ...]]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, int]] = []

    async def __call__(self, hostname: str, port: int) -> tuple[str, ...]:
        self.calls.append((hostname, port))
        if hostname not in self.answers:
            msg = f"Unexpected DNS lookup for {hostname}:{port}"
            raise AssertionError(msg)
        return self.answers[hostname]


class _RecordingMockTransport(httpx.MockTransport):
    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        super().__init__(handler)
        self.requests: list[httpx.Request] = []
        self.was_closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return await super().handle_async_request(request)

    async def aclose(self) -> None:
        self.was_closed = True
        await super().aclose()


class _ChunkedOIDCStream(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.was_iterated = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.was_iterated = True
        for chunk in self.chunks:
            yield chunk


def _oidc_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "issuer": _OIDC_ISSUER,
        "jwks_uri": f"{_OIDC_ISSUER}/jwks",
        "authorization_endpoint": f"{_OIDC_ISSUER}/authorize",
        "token_endpoint": f"{_OIDC_ISSUER}/token",
        "end_session_endpoint": f"{_OIDC_ISSUER}/logout",
        "id_token_signing_alg_values_supported": ["EdDSA", "RS256"],
    }
    document.update(overrides)
    return document


def _oidc_response(
    document: Mapping[str, object] | None = None,
    *,
    status_code: int = 200,
    content: bytes | None = None,
    content_type: str | None = "application/json",
) -> httpx.Response:
    headers = {} if content_type is None else {"content-type": content_type}
    body = (
        json.dumps(dict(document if document is not None else _oidc_document()), separators=(",", ":")).encode()
        if content is None
        else content
    )
    return httpx.Response(status_code, content=body, headers=headers)


def _oidc_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    policy: DiscoveryPolicy | None = None,
    algorithms: frozenset[str] = frozenset({"EdDSA", "ES256"}),
    answers: Mapping[str, tuple[str, ...]] | None = None,
) -> tuple[OIDCDiscoveryClient, _RecordingMockTransport, _FakeOIDCResolver]:
    transport = _RecordingMockTransport(handler)
    resolver = _FakeOIDCResolver(
        {"issuer.example": (_OIDC_PUBLIC_IP,), "keys.example": (_OIDC_PUBLIC_IP,)} if answers is None else answers
    )
    client = OIDCDiscoveryClient(
        policy=policy or DiscoveryPolicy(allowed_issuers=frozenset({_OIDC_ISSUER})),
        algorithms=algorithms,
        transport=transport,
        resolver=resolver,
    )
    return client, transport, resolver


async def _discover_and_close(client: OIDCDiscoveryClient, issuer: str = _OIDC_ISSUER) -> OIDCMetadata:
    try:
        return await client.discover(issuer)
    finally:
        await client.aclose()


class _RecordingJWKSFetcher:
    def __init__(
        self, *responses: JWKSFetchResponse | Exception | Callable[[JWKSFetchRequest], JWKSFetchResponse]
    ) -> None:
        self.responses = list(responses)
        self.requests: list[JWKSFetchRequest] = []

    async def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        self.requests.append(request)
        if not self.responses:
            message = "Unexpected JWKS fetch"
            raise AssertionError(message)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response(request) if callable(response) else response


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


def _mechanism(
    name: str, slot: str, *, participates_by_default: bool = True
) -> AuthenticationMechanism[str, str, object]:
    return AuthenticationMechanism(
        authenticator=_Authenticator(name, slot, participates_by_default=participates_by_default),  # type: ignore[arg-type]
        resolver=_Resolver(),
    )


def test_outcomes_are_distinct_immutable_and_secret_safe() -> None:
    evidence = AuthenticationEvidence(
        mechanism="local", slot="authorization.bearer", authenticated_at=datetime(2026, 7, 26, tzinfo=timezone.utc)
    )
    presented = PresentedCredential("secret-token")
    outcomes = (
        NoCredentials(),
        Authenticated(claims={"sub": "user-1"}, evidence=evidence),
        InvalidCredentials(),
        VerificationUnavailable(retry_after=30),
    )

    assert tuple(type(outcome) for outcome in outcomes) == (
        NoCredentials,
        Authenticated,
        InvalidCredentials,
        VerificationUnavailable,
    )
    assert "secret-token" not in repr(presented)
    with pytest.raises(FrozenInstanceError):
        outcomes[2].code = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("slots", "mechanisms", "match"),
    [
        ([_Slot(" ")], [], "slot name"),
        ([_Slot("cookie"), _Slot(" cookie ")], [], "Duplicate credential slot"),
        ([_Slot("cookie")], [_mechanism(" ", "cookie")], "mechanism name"),
        (
            [_Slot("cookie"), _Slot("header")],
            [_mechanism("local", "cookie"), _mechanism(" local ", "header")],
            "Duplicate authentication mechanism",
        ),
        ([_Slot("cookie")], [_mechanism("local", "missing")], "undefined credential slot"),
        (
            [_Slot("cookie")],
            [_mechanism("local", "cookie"), _mechanism("backup", "cookie")],
            "Duplicate owner for credential slot",
        ),
        (
            [_Slot("authorization.bearer")],
            [_mechanism("local-jwt", "authorization.bearer"), _mechanism("oidc", "authorization.bearer")],
            "authorization.bearer",
        ),
    ],
)
def test_registry_rejects_invalid_or_ambiguous_ownership(
    slots: list[_Slot], mechanisms: list[AuthenticationMechanism[str, str, object]], match: str
) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        AuthenticationRegistry(slots=slots, mechanisms=mechanisms)  # type: ignore[arg-type]


def test_registry_normalizes_order_and_default_participation() -> None:
    registry = AuthenticationRegistry(
        slots=[_Slot(" cookie "), _Slot(" x-api-key ")],  # type: ignore[list-item]
        mechanisms=[
            _mechanism(" local ", " cookie "),
            _mechanism(" api-key ", " x-api-key ", participates_by_default=False),
        ],
    )

    assert registry.slot_names == ("cookie", "x-api-key")
    assert registry.mechanism_names == ("local", "api-key")
    assert registry.default_mechanism_names == ("local",)
    assert registry.get_slot(" cookie ").name == " cookie "
    assert registry.get_mechanism(" api-key ").authenticator.name == " api-key "
    assert registry.get_mechanism_for_slot("cookie") is registry.get_mechanism("local")
    assert registry.get_mechanism_for_slot("unused") is None


def test_required_default_plan_rejects_zero_participants() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="required default authentication"):
        AuthenticationRegistry(
            slots=[_Slot("x-api-key")],  # type: ignore[list-item]
            mechanisms=[_mechanism("api-key", "x-api-key", participates_by_default=False)],
            require_default=True,
        )


def test_policy_helpers_are_immutable_hashable_and_deterministic() -> None:
    oidc = mechanism(" oidc ", " reports:read ", "profile")
    policies = (
        public(),
        required(),
        required("session"),
        any_of("session", oidc),
        all_of("session", oidc),
        at_least(2, "session", oidc, "api-key"),
        optional(all_of("session", oidc)),
    )

    assert oidc == MechanismRequirement("oidc", ("reports:read", "profile"))
    assert required("session") == any_of("session")
    assert policies == tuple(policies)
    assert len(set(policies)) == len(policies)
    with pytest.raises(FrozenInstanceError):
        oidc.name = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (AuthenticationPolicy, "policy helper"),
        (lambda: optional(object()), "policy helper"),  # type: ignore[arg-type]  # test invalid runtime input
        (lambda: mechanism(" "), "mechanism name"),
        (lambda: mechanism("oidc", " "), "scope"),
        (lambda: mechanism("oidc", "read", " read "), "Duplicate scope"),
        (any_of, "at least one"),
        (lambda: any_of("session", " session "), "Duplicate mechanism"),
        (all_of, "at least one"),
        (lambda: all_of("session", mechanism("session")), "Duplicate mechanism"),
        (lambda: optional(public()), "positive"),
        (lambda: optional(optional(required("session"))), "nested optional"),
        (lambda: at_least(0, "a"), "between 1 and"),
        (lambda: at_least(2, "a"), "between 1 and"),
        (lambda: at_least(1, "a", " a "), "Duplicate mechanism"),
    ],
)
def test_policy_helpers_reject_invalid_or_unfaithful_expressions(factory: Callable[[], object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        factory()


def test_required_without_arguments_is_the_implicit_secure_policy() -> None:
    config = SecurityConfig()

    assert not hasattr(config, "default_policy")
    assert not hasattr(config, "openapi_policy")
    assert required() != required("session")


@pytest.mark.parametrize(
    "kwargs", [{"scheme_name": "bearer"}, {"security_scheme": SecurityScheme(type="http", scheme="bearer")}]
)
def test_authentication_mechanism_requires_complete_openapi_scheme_pair(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="configured together"):
        AuthenticationMechanism(
            authenticator=_Authenticator("a", "slot-a"),  # type: ignore[arg-type]
            resolver=_Resolver(),
            **kwargs,
        )


def test_authentication_mechanism_declares_session_capability() -> None:
    mechanism_value = AuthenticationMechanism(
        authenticator=_Authenticator("session", "session"),  # type: ignore[arg-type]
        resolver=_Resolver(),
        session_capable=True,
    )

    assert mechanism_value.session_capable is True


def test_external_csrf_requires_a_named_integration() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="name must not be blank"):
        ExternalCSRF(name=" ", validate=lambda _path, _method, _policy: True)
    with pytest.raises(ImproperlyConfiguredException, match="name must be text"):
        ExternalCSRF(name=cast("Any", object()), validate=lambda _path, _method, _policy: True)
    with pytest.raises(ImproperlyConfiguredException, match="hook must be callable"):
        ExternalCSRF(name="edge", validate=cast("Any", object()))

    async def validate(_path: str, _method: str, _policy: AuthenticationPolicy) -> bool:
        return True

    with pytest.raises(ImproperlyConfiguredException, match="hook must be synchronous"):
        ExternalCSRF(name="edge", validate=cast("Any", validate))


@pytest.mark.parametrize("limit", [0, -1])
def test_security_config_requires_positive_openapi_combination_limit(limit: int) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=r"max_openapi_combinations.*positive"):
        SecurityConfig(max_openapi_combinations=limit)


def _routing_token(*, issuer: str, audiences: str | list[str], token_type: str | None = None) -> str:
    return _compact_jwt(
        json.dumps({"alg": "RS256", "kid": "shared", "typ": token_type or "at+jwt"}, separators=(",", ":")).encode(),
        json.dumps({"iss": issuer, "aud": audiences}, separators=(",", ":")).encode(),
    )


async def test_verified_claims_are_frozen_recursively_and_secret_safe(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    token = _encode_jwt(signing_key, "HS256", include_key_id=False)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)
    claims = outcome.claims
    with pytest.raises(FrozenInstanceError):
        claims.subject = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        verifier.config.issuer = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        claims.raw["sub"] = "changed"  # type: ignore[index]
    metadata = claims.raw["metadata"]
    assert isinstance(metadata, Mapping)
    with pytest.raises(TypeError):
        metadata["groups"] = []  # type: ignore[index]
    assert tuple(metadata["groups"]) == ("finance", "operations")  # type: ignore[arg-type]
    assert token not in repr(claims)
    assert token not in repr(verifier)
    assert verification_key.decode() not in repr(verifier)
