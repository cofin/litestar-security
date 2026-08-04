"""Unit tests for external service JWT and Keycloak/RPT claim profiles."""

from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, cast

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import Authenticated, InvalidCredentials, VerificationUnavailable
from litestar_security.config import WorkerLimits
from litestar_security.context import Principal, ResourcePermission
from litestar_security.providers.jwt import JWTClaims, VerificationKey
from litestar_security.providers.oidc import KeycloakClaims, ServiceTokenConfig, map_keycloak_claims

_NOW = datetime(2026, 7, 28, 20, tzinfo=timezone.utc)
_ISSUER = "https://id.example.com"
_AUDIENCE = "service-api"
_JWKS_URI = "https://id.example.com/jwks"


class _JWKS:
    def __init__(self, key: VerificationKey) -> None:
        self.outcome: object = key
        self.expected_algorithm = key.algorithm
        self.calls = 0

    async def select_key(self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime) -> object:
        assert (issuer, jwks_uri, kid, algorithm, now) == (
            _ISSUER,
            _JWKS_URI,
            "service-key",
            self.expected_algorithm,
            _NOW,
        )
        self.calls += 1
        return self.outcome

    async def warmup(self, *, now: datetime) -> None:
        del now

    async def aclose(self) -> None:
        return None


@pytest.fixture(scope="module")
def service_key_material() -> tuple[bytes, VerificationKey]:
    private = ec.generate_private_key(ec.SECP256R1())
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, VerificationKey(key_id="service-key", algorithm="ES256", key=public_pem)


def _service_claims(**overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": _ISSUER,
        "sub": "service-1",
        "aud": _AUDIENCE,
        "iat": int(_NOW.timestamp()),
        "exp": int((_NOW + timedelta(minutes=5)).timestamp()),
        "client_id": "report-worker",
        "jti": "service-token-1",
        "scope": "reports:read reports:write",
        "acr": "urn:service",
        "amr": ["private_key_jwt"],
    }
    claims.update(overrides)
    return claims


def _service_token(private: bytes, **overrides: object) -> str:
    return jwt.encode(
        _service_claims(**overrides), private, algorithm="ES256", headers={"kid": "service-key", "typ": "at+jwt"}
    )


def _service_runtime(key: VerificationKey) -> tuple[object, object, _JWKS]:
    jwks = _JWKS(key)
    slot, mechanism = ServiceTokenConfig(
        issuer=_ISSUER,
        audiences=frozenset({_AUDIENCE}),
        allowed_algorithms=frozenset({"ES256"}),
        jwks=jwks,
        jwks_uri=_JWKS_URI,
    ).build(clock=lambda: _NOW)
    return slot, mechanism, jwks


@pytest.mark.anyio
async def test_service_jwt_builds_userless_principal_and_scope_restrictions(
    service_key_material: tuple[bytes, VerificationKey],
) -> None:
    private, key = service_key_material
    slot, mechanism, jwks = _service_runtime(key)

    outcome = await mechanism.authenticator.authenticate(
        _service_token(private, aud=[_AUDIENCE, "secondary"]), type("Connection", (), {"scope": {"headers": []}})()
    )

    assert isinstance(outcome, Authenticated)
    assert outcome.restrictions.scopes == frozenset({"reports:read", "reports:write"})
    assert outcome.evidence.traits == frozenset({"service"})
    assert outcome.evidence.acr == "urn:service"
    assert outcome.evidence.amr == ("private_key_jwt",)
    principal = await mechanism.resolver.resolve(outcome.claims)
    assert principal == Principal(id="service-1", display_name="report-worker", user=None)
    assert principal.user is None
    assert slot.name == "authorization.bearer"
    assert mechanism.scheme_name == "service-jwt"
    assert mechanism.security_scheme is not None
    assert mechanism.security_scheme.bearer_format == "JWT"
    assert jwks.calls == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://wrong.example.com"},
        {"aud": "wrong"},
        {"exp": int((_NOW - timedelta(minutes=1)).timestamp())},
        {"iat": int((_NOW + timedelta(minutes=1)).timestamp())},
        {"sub": None},
        {"acr": []},
        {"amr": "wrong"},
    ],
)
async def test_service_jwt_rejects_invalid_trust_and_evidence_claims(
    service_key_material: tuple[bytes, VerificationKey], overrides: dict[str, object]
) -> None:
    private, key = service_key_material
    _, mechanism, _ = _service_runtime(key)

    outcome = await mechanism.authenticator.authenticate(
        _service_token(private, **overrides), type("Connection", (), {"scope": {"headers": []}})()
    )

    assert isinstance(outcome, InvalidCredentials)


@pytest.mark.anyio
@pytest.mark.parametrize("provider_outcome", [InvalidCredentials(), VerificationUnavailable()])
async def test_service_jwt_preserves_unknown_key_and_outage(
    service_key_material: tuple[bytes, VerificationKey], provider_outcome: object
) -> None:
    private, key = service_key_material
    _, mechanism, jwks = _service_runtime(key)
    jwks.outcome = provider_outcome

    outcome = await mechanism.authenticator.authenticate(
        _service_token(private), type("Connection", (), {"scope": {"headers": []}})()
    )

    assert outcome == provider_outcome


@pytest.mark.anyio
async def test_service_jwt_accepts_rotated_jwks_key(service_key_material: tuple[bytes, VerificationKey]) -> None:
    _, first_key = service_key_material
    _, mechanism, jwks = _service_runtime(first_key)
    rotated_private = ec.generate_private_key(ec.SECP256R1())
    rotated_public = rotated_private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwks.outcome = VerificationKey(key_id="service-key", algorithm="ES256", key=rotated_public)

    outcome = await mechanism.authenticator.authenticate(
        jwt.encode(
            _service_claims(), rotated_private, algorithm="ES256", headers={"kid": "service-key", "typ": "at+jwt"}
        ),
        type("Connection", (), {"scope": {"headers": []}})(),
    )

    assert isinstance(outcome, Authenticated)


@pytest.mark.anyio
async def test_service_jwt_multi_algorithm_config_uses_only_the_verified_header_algorithm() -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwks = _JWKS(VerificationKey(key_id="service-key", algorithm="RS256", key=public_pem))
    _, mechanism = ServiceTokenConfig(
        issuer=_ISSUER,
        audiences=frozenset({_AUDIENCE}),
        allowed_algorithms=frozenset({"ES256", "RS256"}),
        jwks=jwks,
        jwks_uri=_JWKS_URI,
    ).build(clock=lambda: _NOW)
    token = jwt.encode(_service_claims(), private, algorithm="RS256", headers={"kid": "service-key", "typ": "at+jwt"})

    outcome = await mechanism.authenticator.authenticate(token, type("Connection", (), {"scope": {"headers": []}})())

    assert isinstance(outcome, Authenticated)


@pytest.mark.anyio
async def test_service_jwt_reuses_a_cached_verifier_with_the_shared_worker_limiter(
    service_key_material: tuple[bytes, VerificationKey],
) -> None:
    private, key = service_key_material
    jwks = _JWKS(key)
    config = ServiceTokenConfig(
        issuer=_ISSUER,
        audiences=frozenset({_AUDIENCE}),
        allowed_algorithms=frozenset({"ES256"}),
        jwks=jwks,
        jwks_uri=_JWKS_URI,
        worker_limits=WorkerLimits(crypto_tokens=1),
    )
    _, mechanism = config.build(clock=lambda: _NOW)
    verifier = cast("Any", mechanism.authenticator).config.slots[0].verifier
    token = _service_token(private)

    first = await mechanism.authenticator.authenticate(token, type("Connection", (), {"scope": {"headers": []}})())
    cached = verifier._verifiers[("service-key", "ES256")]  # noqa: SLF001 - assert the internal cache contract
    second = await mechanism.authenticator.authenticate(token, type("Connection", (), {"scope": {"headers": []}})())

    assert isinstance(first, Authenticated)
    assert isinstance(second, Authenticated)
    assert verifier._verifiers[("service-key", "ES256")] is cached  # noqa: SLF001 - assert cache reuse
    assert cached.limiter is config.worker_limits.crypto_limiter


@pytest.mark.anyio
@pytest.mark.parametrize("state", ["malformed", "wrong-algorithm", "missing-kid", "bad-provider", "bad-signature"])
async def test_service_jwt_rejects_malformed_routing_and_provider_boundaries(
    service_key_material: tuple[bytes, VerificationKey], state: str
) -> None:
    private, key = service_key_material
    _, mechanism, jwks = _service_runtime(key)
    token = _service_token(private)
    if state == "malformed":
        token = "not-a-jwt"  # noqa: S105 - intentionally malformed credential fixture
    elif state == "wrong-algorithm":
        token = jwt.encode(
            _service_claims(), b"h" * 32, algorithm="HS256", headers={"kid": "service-key", "typ": "at+jwt"}
        )
    elif state == "missing-kid":
        token = jwt.encode(_service_claims(), private, algorithm="ES256", headers={"typ": "at+jwt"})
    elif state == "bad-provider":
        jwks.outcome = object()
    else:
        other = ec.generate_private_key(ec.SECP256R1())
        token = jwt.encode(_service_claims(), other, algorithm="ES256", headers={"kid": "service-key", "typ": "at+jwt"})

    outcome = await mechanism.authenticator.authenticate(token, type("Connection", (), {"scope": {"headers": []}})())

    assert isinstance(outcome, VerificationUnavailable if state == "bad-provider" else InvalidCredentials)


@pytest.mark.anyio
async def test_service_jwt_supports_custom_actor_and_sequence_scopes(
    service_key_material: tuple[bytes, VerificationKey],
) -> None:
    private, key = service_key_material
    jwks = _JWKS(key)
    _, mechanism = ServiceTokenConfig(
        issuer=_ISSUER,
        audiences=frozenset({_AUDIENCE}),
        allowed_algorithms=frozenset({"ES256"}),
        jwks=jwks,
        jwks_uri=_JWKS_URI,
        scopes_claim="permissions",
        actor_id_claim="actor",
    ).build(clock=lambda: _NOW)
    token = jwt.encode(
        _service_claims(actor="actor-1", permissions=["read", "write"], acr=None, amr=None),
        private,
        algorithm="ES256",
        headers={"kid": "service-key", "typ": "at+jwt"},
    )

    outcome = await mechanism.authenticator.authenticate(token, type("Connection", (), {"scope": {"headers": []}})())

    assert isinstance(outcome, Authenticated)
    assert outcome.restrictions.scopes == frozenset({"read", "write"})
    assert outcome.evidence.acr is None
    assert outcome.evidence.amr == ()
    assert await mechanism.resolver.resolve(outcome.claims) == Principal(
        id="actor-1", display_name="report-worker", user=None
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("claim", "value"), [("permissions", None), ("permissions", [""]), ("actor", 1), ("amr", [""])]
)
async def test_service_jwt_rejects_invalid_custom_claim_shapes(
    service_key_material: tuple[bytes, VerificationKey], claim: str, value: object
) -> None:
    private, key = service_key_material
    jwks = _JWKS(key)
    _, mechanism = ServiceTokenConfig(
        issuer=_ISSUER,
        audiences=frozenset({_AUDIENCE}),
        allowed_algorithms=frozenset({"ES256"}),
        jwks=jwks,
        jwks_uri=_JWKS_URI,
        scopes_claim="permissions",
        actor_id_claim="actor",
    ).build(clock=lambda: _NOW)
    claims = _service_claims(actor="actor-1", permissions=["read"])
    claims[claim] = value
    token = jwt.encode(claims, private, algorithm="ES256", headers={"kid": "service-key", "typ": "at+jwt"})

    outcome = await mechanism.authenticator.authenticate(token, type("Connection", (), {"scope": {"headers": []}})())
    if claim == "actor" and isinstance(outcome, Authenticated):
        outcome = await mechanism.resolver.resolve(outcome.claims)

    assert isinstance(outcome, InvalidCredentials)


@pytest.mark.parametrize(
    "overrides",
    [
        {"jwks_uri": "http://insecure.example.com"},
        {"scopes_claim": "bad-name"},
        {"actor_id_claim": ""},
        {"jwks": object()},
        {"worker_limits": object()},
    ],
)
def test_service_token_config_rejects_invalid_boundaries(
    service_key_material: tuple[bytes, VerificationKey], overrides: dict[str, object]
) -> None:
    values: dict[str, object] = {
        "issuer": _ISSUER,
        "audiences": frozenset({_AUDIENCE}),
        "allowed_algorithms": frozenset({"ES256"}),
        "jwks": _JWKS(service_key_material[1]),
        "jwks_uri": _JWKS_URI,
    }
    values.update(overrides)

    with pytest.raises(ImproperlyConfiguredException):
        ServiceTokenConfig(**values)  # type: ignore[arg-type]


def _verified(raw: dict[str, object]) -> JWTClaims:
    return JWTClaims(
        issuer="https://id.example.com",
        subject="service-1",
        audiences=frozenset({"api"}),
        expires_at=_NOW + timedelta(minutes=5),
        issued_at=_NOW,
        not_before=None,
        token_id="token-1",  # noqa: S106 - non-secret JWT identifier fixture
        client_id="client-1",
        scopes=frozenset(),
        raw=raw,  # type: ignore[arg-type]
    )


def test_keycloak_maps_roles_scopes_and_issued_rpt_without_io() -> None:
    claims = map_keycloak_claims(
        _verified({
            "realm_access": {"roles": ["admin", "reader"]},
            "resource_access": {"billing": {"roles": ["reader"]}, "reports": {"roles": ["reader", "writer"]}},
            "scope": "openid reports:read",
            "authorization": {
                "permissions": [
                    {"rsid": "resource-1", "rsname": "ignored", "scopes": ["read", "write"]},
                    {"rsname": "named-resource", "scopes": ["view"]},
                ]
            },
        })
    )

    assert claims == KeycloakClaims(
        realm_roles=frozenset({"admin", "reader"}),
        client_roles=MappingProxyType({"billing": frozenset({"reader"}), "reports": frozenset({"reader", "writer"})}),
        scopes=frozenset({"openid", "reports:read"}),
        permissions=frozenset({
            ResourcePermission(resource="resource-1", scopes=frozenset({"read", "write"})),
            ResourcePermission(resource="named-resource", scopes=frozenset({"view"})),
        }),
    )


def test_keycloak_maps_scp_and_ordinary_access_token_defaults() -> None:
    with_scp = map_keycloak_claims(_verified({"scp": ["profile", "email"]}))
    ordinary = map_keycloak_claims(_verified({}))

    assert isinstance(with_scp, KeycloakClaims)
    assert with_scp.scopes == frozenset({"profile", "email"})
    assert ordinary == KeycloakClaims()


@pytest.mark.parametrize(
    "raw",
    [
        {"realm_access": []},
        {"realm_access": {"roles": "admin"}},
        {"resource_access": []},
        {"resource_access": {"client": []}},
        {"resource_access": {"client": {"roles": "reader"}}},
        {"scope": ["wrong"]},
        {"scp": "wrong"},
        {"authorization": []},
        {"authorization": {"permissions": "wrong"}},
        {"authorization": {"permissions": ["wrong"]}},
        {"authorization": {"permissions": [{}]}},
        {"authorization": {"permissions": [{"rsid": "id", "scopes": "read"}]}},
        {"authorization": {"permissions": [{"rsid": "id", "scopes": [""]}]}},
    ],
)
def test_keycloak_rejects_malformed_nested_claims(raw: dict[str, object]) -> None:
    assert isinstance(map_keycloak_claims(_verified(raw)), InvalidCredentials)
