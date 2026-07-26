"""Unit tests for authentication outcomes and registry compilation."""

import base64
import json
from collections.abc import Callable, Mapping
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from typing import cast

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
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
    security,
)
from litestar_security.config import ExternalCSRF, SecurityConfig
from litestar_security.context import AuthenticationEvidence, Principal
from litestar_security.providers.jwt import (
    JWTClaims,
    JWTValidationConfig,
    PyJWTVerifier,
    UnverifiedJWTRoute,
    parse_unverified_jwt_route,
)

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
_JWT_ISSUER = "https://issuer.example"
_JWT_AUDIENCE = "litestar-security"


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
    required_claims: frozenset[str] = frozenset({"iss", "sub", "aud", "exp", "iat"}),
    maximum_lifetime: timedelta | None = timedelta(hours=1),
) -> JWTValidationConfig:
    return JWTValidationConfig(
        issuer=_JWT_ISSUER,
        audiences=frozenset({_JWT_AUDIENCE}),
        algorithms=frozenset({algorithm}),
        required_claims=required_claims,
        access_token_profile=access_token_profile,
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
        (lambda: security(cast("AuthenticationPolicy", object())), "policy helper"),
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


def test_required_without_arguments_is_the_implicit_secure_default() -> None:
    config = SecurityConfig()

    assert isinstance(config.default_policy, AuthenticationPolicy)
    assert config.default_policy == required()
    assert config.default_policy != public()
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


@pytest.mark.parametrize("limit", [0, -1])
def test_security_config_requires_positive_openapi_combination_limit(limit: int) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=r"max_openapi_combinations.*positive"):
        SecurityConfig(max_openapi_combinations=limit)


@pytest.mark.parametrize("case", [(None,), (True,), (False,)])
def test_security_returns_fresh_route_metadata_without_changing_policy(case: tuple[bool | None]) -> None:
    csrf_required = case[0]
    policy = optional(required(mechanism("oidc", "profile")))

    first = security(policy, csrf_required=csrf_required)
    second = security(policy, csrf_required=csrf_required)
    first_declaration = next(iter(first.values()))
    second_declaration = next(iter(second.values()))

    assert first is not second
    assert first == second
    assert first_declaration.policy is policy
    assert first_declaration.csrf_required is csrf_required
    assert first_declaration == second_declaration
    with pytest.raises(FrozenInstanceError):
        first_declaration.csrf_required = not csrf_required  # type: ignore[misc]


@pytest.mark.anyio
async def test_composite_bearer_dispatcher_selects_only_one_verifier() -> None:
    calls: list[tuple[str, str]] = []

    class _CompositeBearer(_Authenticator):
        async def authenticate(self, credential: str, _connection: object) -> Authenticated[str]:
            issuer, claims = credential.split(":", maxsplit=1)
            calls.append((issuer, claims))
            return Authenticated(
                claims=claims,
                evidence=AuthenticationEvidence(
                    mechanism=f"bearer:{issuer}",
                    slot=self.slot,
                    authenticated_at=datetime(2026, 7, 26, tzinfo=timezone.utc),
                ),
            )

    authenticator = _CompositeBearer("bearer", "authorization.bearer")
    registry = AuthenticationRegistry(
        slots=[_Slot("authorization.bearer")],  # type: ignore[list-item]
        mechanisms=[AuthenticationMechanism(authenticator=authenticator, resolver=_Resolver())],
    )

    outcome = await registry.get_mechanism("bearer").authenticator.authenticate(
        "local:user-1",
        None,  # type: ignore[arg-type]
    )

    assert isinstance(outcome, Authenticated)
    assert calls == [("local", "user-1")]


@pytest.mark.parametrize(
    ("algorithm", "require_key_id"), [("EdDSA", True), ("ES256", True), ("RS256", True), ("HS256", False)]
)
@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_supported_algorithms_and_normalizes_claims(
    algorithm: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]], *, require_key_id: bool
) -> None:
    signing_key, verification_key = jwt_key_material[algorithm]
    token = _encode_jwt(signing_key, algorithm, claims=_jwt_claims(sub="user-\u0430"), include_key_id=require_key_id)
    verifier = PyJWTVerifier(config=_jwt_config(algorithm), key=verification_key, require_key_id=require_key_id)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)
    claims = outcome.claims
    assert isinstance(claims, JWTClaims)
    assert claims.issuer == _JWT_ISSUER
    assert claims.subject == "user-\u0430"
    assert claims.audiences == frozenset({_JWT_AUDIENCE})
    assert claims.scopes == frozenset({"reports:read", "profile"})
    assert claims.client_id == "client-1"
    assert claims.token_id == "token-1"  # noqa: S105 - public token identifier, not a credential
    assert claims.expires_at == _JWT_NOW + timedelta(minutes=10)


@pytest.mark.parametrize(
    ("scope_claims", "expected"),
    [
        ({"scope": "reports:read profile"}, frozenset({"reports:read", "profile"})),
        ({"scp": ["reports:read", "profile"]}, frozenset({"reports:read", "profile"})),
        ({"aud": [_JWT_AUDIENCE]}, frozenset()),
    ],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_only_documented_scope_shapes(
    scope_claims: dict[str, object], expected: frozenset[str], jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    claims = _jwt_claims()
    claims.pop("scope")
    claims.update(scope_claims)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=claims, include_key_id=False), now=_JWT_NOW
    )

    assert isinstance(outcome, Authenticated)
    assert outcome.claims.scopes == expected


def test_unverified_jwt_route_is_explicit_and_immutable() -> None:
    token = _compact_jwt(
        json.dumps({"alg": "HS256", "typ": "at+jwt"}, separators=(",", ":")).encode(),
        json.dumps({"iss": _JWT_ISSUER, "aud": [_JWT_AUDIENCE]}, separators=(",", ":")).encode(),
    )

    route = parse_unverified_jwt_route(token)

    assert isinstance(route, UnverifiedJWTRoute)
    assert route.header == {"alg": "HS256", "typ": "at+jwt"}
    assert route.payload == {"iss": _JWT_ISSUER, "aud": (_JWT_AUDIENCE,)}
    with pytest.raises(TypeError):
        route.header["alg"] = "none"  # type: ignore[index]


@pytest.mark.parametrize(
    "token",
    [
        "",
        "one.two",
        "one.two.three.four",
        "one..three",
        _compact_jwt(b"[]", b"{}"),
        _compact_jwt(b"{}", b"[]"),
        _compact_jwt(b"\xff", b"{}"),
        _compact_jwt(b'{"alg":"HS256","alg":"none"}', b"{}"),
        _compact_jwt(b"{}", b'{"iss":"one","iss":"two"}'),
        _compact_jwt(b"{}", b'{"value":NaN}'),
        _compact_jwt(b"{}", (b'{"nested":' * 33) + b"null" + (b"}" * 33)),
        _compact_jwt(b"{}", json.dumps({"value": "x" * 16_384}).encode()),
        "*.e30.c2ln",
        "é.e30.c2ln",
        "e30.e30.A",
        "e30.e30.AB",
    ],
    ids=[
        "empty",
        "two-segments",
        "four-segments",
        "empty-segment",
        "header-not-object",
        "payload-not-object",
        "invalid-utf8",
        "duplicate-header-member",
        "duplicate-payload-member",
        "non-finite-number",
        "excessive-json-depth",
        "excessive-token-size",
        "invalid-base64url",
        "non-ascii",
        "invalid-base64url-length",
        "non-canonical-base64url",
    ],
)
def test_unverified_jwt_route_rejects_malformed_or_ambiguous_json(token: str) -> None:
    assert parse_unverified_jwt_route(token) == InvalidCredentials()


@pytest.mark.parametrize("limits", [{"maximum_token_bytes": 0}, {"maximum_json_depth": 0}])
def test_unverified_jwt_route_rejects_invalid_parser_limits(limits: dict[str, int]) -> None:
    assert parse_unverified_jwt_route("e30.e30.c2ln", **limits) == InvalidCredentials()  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "protected_header",
    [
        {"crit": ["unknown"]},
        {"b64": True},
        {"jwk": {"kty": "oct", "k": "embedded"}},
        {"jku": "https://attacker.invalid/jwks"},
        {"x5u": "https://attacker.invalid/certificate"},
        {"x5c": ["certificate"]},
        {"x5t": "certificate-thumbprint"},
        {"x5t#S256": "certificate-thumbprint"},
    ],
    ids=["crit", "b64", "jwk", "jku", "x5u", "x5c", "x5t", "x5t-s256"],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_forbidden_jose_headers(
    protected_header: dict[str, object], jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)
    if "b64" in protected_header:
        header = {"alg": "HS256", "typ": "at+jwt", **protected_header}
        token = _compact_jwt(
            json.dumps(header, separators=(",", ":")).encode(),
            json.dumps(_jwt_claims(), separators=(",", ":")).encode(),
        )
    else:
        token = _encode_jwt(signing_key, "HS256", headers=protected_header, include_key_id=False)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("header", "algorithm"),
    [
        ({"alg": "none", "typ": "at+jwt"}, "none"),
        ({"typ": "at+jwt"}, "missing"),
        ({"alg": "HS256", "typ": "JWT"}, "HS256"),
        ({"alg": "HS256"}, "HS256"),
        ({"alg": "RS256", "typ": "at+jwt"}, "RS256"),
        ({"alg": "HS256", "typ": "at+jwt", "kid": 7}, "HS256"),
    ],
    ids=["none", "missing-alg", "id-token-type", "missing-type", "missing-asymmetric-kid", "malformed-key-id"],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_algorithm_type_and_key_id_confusion(
    header: dict[str, object], algorithm: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    verification_algorithm = "RS256" if algorithm == "RS256" else "HS256"
    verification_key = jwt_key_material[verification_algorithm][1]
    verifier = PyJWTVerifier(
        config=_jwt_config(verification_algorithm),
        key=verification_key,
        require_key_id=verification_algorithm == "RS256",
    )
    token = _compact_jwt(
        json.dumps(header, separators=(",", ":")).encode(), json.dumps(_jwt_claims(), separators=(",", ":")).encode()
    )

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_hmac_rsa_algorithm_confusion(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    token = _encode_jwt(jwt_key_material["HS256"][0], "HS256", include_key_id=False)
    verifier = PyJWTVerifier(config=_jwt_config("RS256"), key=jwt_key_material["RS256"][1], require_key_id=True)

    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("overrides", "removed"),
    [
        ({"iss": "https://issuer.examp\u043be"}, frozenset()),
        ({"aud": "another-service"}, frozenset()),
        ({"aud": []}, frozenset()),
        ({"aud": 7}, frozenset()),
        ({"aud": [_JWT_AUDIENCE, 7]}, frozenset()),
        ({"aud": [_JWT_AUDIENCE, " "]}, frozenset()),
        ({"aud": [_JWT_AUDIENCE, _JWT_AUDIENCE]}, frozenset()),
        ({"exp": int((_JWT_NOW - timedelta(seconds=31)).timestamp())}, frozenset()),
        ({"nbf": int((_JWT_NOW + timedelta(seconds=31)).timestamp())}, frozenset()),
        ({"iat": int((_JWT_NOW + timedelta(seconds=31)).timestamp())}, frozenset()),
        (
            {
                "nbf": int((_JWT_NOW + timedelta(seconds=5)).timestamp()),
                "exp": int((_JWT_NOW + timedelta(seconds=5)).timestamp()),
            },
            frozenset(),
        ),
        ({"exp": True}, frozenset()),
        ({"iat": 1.5}, frozenset()),
        ({"exp": 10**100}, frozenset()),
        (
            {
                "iat": int((_JWT_NOW - timedelta(hours=2)).timestamp()),
                "exp": int((_JWT_NOW + timedelta(minutes=1)).timestamp()),
            },
            frozenset(),
        ),
        ({"sub": ""}, frozenset()),
        ({"client_id": ""}, frozenset()),
        ({"jti": ""}, frozenset()),
        ({"scope": 7}, frozenset()),
        ({"scope": "reports:read reports:read"}, frozenset()),
        ({"scp": "reports:read"}, frozenset({"scope"})),
        ({"scp": ["reports:read", 7]}, frozenset({"scope"})),
        ({"scp": ["reports:read"], "scope": "profile"}, frozenset()),
        ({}, frozenset({"iss"})),
        ({}, frozenset({"sub"})),
        ({}, frozenset({"exp"})),
        ({}, frozenset({"iat"})),
    ],
    ids=[
        "issuer-unicode-lookalike",
        "audience-mismatch",
        "audience-empty",
        "audience-malformed",
        "audience-member-malformed",
        "audience-member-blank",
        "audience-duplicate",
        "expired",
        "not-before-in-future",
        "issued-at-in-future",
        "not-before-at-expiry",
        "boolean-numeric-date",
        "float-numeric-date",
        "numeric-date-overflow",
        "excessive-lifetime",
        "empty-subject",
        "empty-client-id",
        "empty-token-id",
        "scalar-scope",
        "duplicate-scope",
        "string-scp",
        "mixed-scp",
        "ambiguous-scope-claims",
        "missing-issuer",
        "missing-subject",
        "missing-expiry",
        "missing-issued-at",
    ],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_invalid_rfc_9068_claims(
    overrides: dict[str, object], removed: frozenset[str], jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    claims = _jwt_claims(**overrides)
    for claim in removed:
        claims.pop(claim)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=claims, include_key_id=False), now=_JWT_NOW
    )

    assert outcome == InvalidCredentials()


@pytest.mark.anyio
async def test_pyjwt_verifier_enforces_explicit_non_access_token_required_claims(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    verifier = PyJWTVerifier(
        config=_jwt_config(
            "HS256",
            access_token_profile=False,
            required_claims=frozenset({"iss", "sub", "aud", "exp", "iat", "tenant"}),
        ),
        key=verification_key,
        require_key_id=False,
    )

    outcome = await verifier.verify(_encode_jwt(signing_key, "HS256", include_key_id=False), now=_JWT_NOW)

    assert outcome == InvalidCredentials()


@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_non_access_profile_without_optional_access_claims(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    claims = _jwt_claims()
    claims.pop("client_id")
    claims.pop("jti")
    verifier = PyJWTVerifier(
        config=_jwt_config("HS256", access_token_profile=False, maximum_lifetime=None),
        key=verification_key,
        require_key_id=False,
    )

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=claims, include_key_id=False), now=_JWT_NOW
    )

    assert isinstance(outcome, Authenticated)
    assert outcome.claims.client_id is None
    assert outcome.claims.token_id is None


@pytest.mark.parametrize("claim", ["client_id", "jti"])
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_malformed_optional_access_claims_in_non_access_profiles(
    claim: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    verifier = PyJWTVerifier(
        config=_jwt_config("HS256", access_token_profile=False), key=verification_key, require_key_id=False
    )

    outcome = await verifier.verify(
        _encode_jwt(signing_key, "HS256", claims=_jwt_claims(**{claim: 7}), include_key_id=False), now=_JWT_NOW
    )

    assert outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("token", "now"),
    [("malformed", _JWT_NOW), ("malformed", _JWT_NOW.replace(tzinfo=None))],
    ids=["malformed-compact", "naive-now"],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_rejects_invalid_verification_inputs(
    token: str, now: datetime, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=jwt_key_material["HS256"][1], require_key_id=False)

    assert await verifier.verify(token, now=now) == InvalidCredentials()


@pytest.mark.anyio
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


@pytest.mark.parametrize(
    ("algorithm", "key_name", "key"),
    [
        ("HS256", None, b"short"),
        ("EdDSA", None, b"not-an-ed25519-key"),
        ("ES256", "ES384", None),
        ("RS256", "RS1024", None),
        ("RS256", "ES256", None),
    ],
    ids=["short-hmac", "invalid-ed25519", "wrong-ec-curve", "weak-rsa", "algorithm-key-mismatch"],
)
def test_pyjwt_verifier_validates_fixed_keys_at_startup_without_secret_repr(
    algorithm: str, key_name: str | None, key: bytes | None, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    verification_key = key if key is not None else jwt_key_material[cast("str", key_name)][1]

    with pytest.raises(ImproperlyConfiguredException, match=algorithm):
        PyJWTVerifier(config=_jwt_config(algorithm), key=verification_key, require_key_id=algorithm != "HS256")


@pytest.mark.parametrize(
    ("algorithm", "key"),
    [
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "sig", "d": "private"}),
        ("RS256", {"kty": "RSA", "alg": "ES256", "use": "sig"}),
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "enc"}),
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "sig", "key_ops": ["sign"]}),
        ("RS256", {"kty": "RSA", "alg": "RS256", "use": "sig", "key_ops": ["verify", "sign"]}),
        ("ES256", {"kty": "RSA", "alg": "ES256", "use": "sig"}),
        ("HS256", {"kty": "oct", "alg": "HS256", "use": "sig"}),
    ],
    ids=[
        "private-member",
        "alg-mismatch",
        "wrong-use",
        "wrong-key-op",
        "mixed-key-ops",
        "wrong-key-type",
        "remote-hmac",
    ],
)
def test_pyjwt_verifier_rejects_untrusted_or_incompatible_jwk_metadata(algorithm: str, key: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=algorithm):
        PyJWTVerifier(
            config=_jwt_config(algorithm),
            key=key,  # type: ignore[arg-type]
            require_key_id=algorithm != "HS256",
        )


@pytest.mark.anyio
async def test_pyjwt_verifier_accepts_valid_public_jwk(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    signing_key, verification_key = jwt_key_material["RS256"]
    public_key = serialization.load_pem_public_key(verification_key)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    public_jwk.update({"alg": "RS256", "use": "sig"})
    verifier = PyJWTVerifier(config=_jwt_config("RS256"), key=public_jwk)

    outcome = await verifier.verify(_encode_jwt(signing_key, "RS256"), now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)


@pytest.mark.parametrize(
    ("algorithm", "prepared_key"),
    [
        ("ES256", ec.generate_private_key(ec.SECP384R1()).public_key()),
        ("EdDSA", ec.generate_private_key(ec.SECP256R1()).public_key()),
    ],
)
def test_pyjwt_verifier_rejects_incompatible_prepared_backend_keys(
    algorithm: str, prepared_key: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Algorithm:
        @staticmethod
        def prepare_key(_key: object) -> object:
            return prepared_key

    monkeypatch.setattr(jwt, "get_algorithm_by_name", lambda _algorithm: _Algorithm())

    with pytest.raises(ImproperlyConfiguredException, match=algorithm):
        PyJWTVerifier(config=_jwt_config(algorithm), key=b"configured-key")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer": " "},
        {"audiences": frozenset()},
        {"algorithms": frozenset()},
        {"algorithms": frozenset({"none"})},
        {"clock_skew": timedelta(seconds=-1)},
        {"maximum_lifetime": timedelta(0)},
        {"required_claims": frozenset({" "})},
        {"token_types": frozenset()},
    ],
)
def test_jwt_validation_config_rejects_unsafe_or_ambiguous_values(kwargs: dict[str, object]) -> None:
    values: dict[str, object] = {
        "issuer": _JWT_ISSUER,
        "audiences": frozenset({_JWT_AUDIENCE}),
        "algorithms": frozenset({"HS256"}),
    }
    values.update(kwargs)

    with pytest.raises(ImproperlyConfiguredException):
        JWTValidationConfig(**values)  # type: ignore[arg-type]


def test_pyjwt_verifier_rejects_non_positive_token_limit(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="maximum token bytes"):
        PyJWTVerifier(
            config=_jwt_config("HS256"), key=jwt_key_material["HS256"][1], require_key_id=False, maximum_token_bytes=0
        )


@pytest.mark.parametrize(
    ("error", "outcome_type"),
    [
        (jwt.InvalidTokenError("provider detail must not escape"), InvalidCredentials),
        (OSError("worker detail must not escape"), VerificationUnavailable),
    ],
)
@pytest.mark.anyio
async def test_pyjwt_verifier_maps_and_sanitizes_verification_failures(
    error: Exception,
    outcome_type: type[InvalidCredentials] | type[VerificationUnavailable],
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signing_key, verification_key = jwt_key_material["HS256"]
    token = _encode_jwt(signing_key, "HS256", include_key_id=False)
    verifier = PyJWTVerifier(config=_jwt_config("HS256"), key=verification_key, require_key_id=False)

    def fail_verification(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(jwt, "decode_complete", fail_verification)
    outcome = await verifier.verify(token, now=_JWT_NOW)

    assert isinstance(outcome, outcome_type)
    assert "provider detail" not in repr(outcome)
    assert "worker detail" not in repr(outcome)
