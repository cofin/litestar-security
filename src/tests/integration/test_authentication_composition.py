"""Request-level authentication composition and trust-domain isolation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import jwt
import pytest
from litestar import Litestar, Request, get
from litestar.openapi.config import OpenAPIConfig
from litestar.status_codes import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_503_SERVICE_UNAVAILABLE
from litestar.testing import TestClient

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security.authentication import (
    InvalidCredentials,
    NoCredentials,
    VerificationUnavailable,
    any_of,
    required,
)
from litestar_security.context import Principal
from litestar_security.providers.api_key import APIKeyClaims, APIKeyConfig
from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JWTClaims,
    JWTValidationConfig,
    PyJWTVerifier,
    VerificationKey,
    extend_composite_bearer,
)
from litestar_security.providers.oidc import ServiceTokenConfig
from tests.fixtures.collaborators import AsyncRecordingJWTVerifier, build_api_key_store

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar_security.authentication import Authenticated

_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
_PROFILES = {"external": ("https://external.example", "external-api"), "local": ("https://local.example", "local-api")}


class _Resolver:
    def __init__(self, participant: str) -> None:
        self.participant = participant
        self.calls: list[str] = []

    async def resolve(self, claims: JWTClaims) -> Principal[object]:
        self.calls.append(claims.subject)
        return Principal(id=f"{self.participant}:{claims.subject}")


@dataclass
class _RecordingVerifier:
    verifier: PyJWTVerifier

    def __post_init__(self) -> None:
        self.config = self.verifier.config
        self.calls: list[str] = []

    async def verify(self, token: str, *, now: datetime) -> Authenticated[JWTClaims] | InvalidCredentials:
        self.calls.append(token)
        return await self.verifier.verify(token, now=now)


@dataclass
class _UnavailableVerifier:
    config: JWTValidationConfig

    def __post_init__(self) -> None:
        self.calls: list[str] = []

    async def verify(self, token: str, *, now: datetime) -> VerificationUnavailable:
        del now
        self.calls.append(token)
        return VerificationUnavailable(code="provider_unavailable", retry_after=2)


class _StaticJWKS:
    def __init__(self, key: VerificationKey) -> None:
        self.key = key

    async def select_key(
        self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime
    ) -> VerificationKey:
        del issuer, jwks_uri, kid, algorithm, now
        return self.key

    async def warmup(self, *, now: datetime) -> None:
        del now

    async def aclose(self) -> None:
        return None


def _claims(issuer: str, audience: str, *, subject: str = "user-1") -> dict[str, object]:
    return {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": int((_NOW + timedelta(minutes=5)).timestamp()),
        "iat": int(_NOW.timestamp()),
        "nbf": int((_NOW - timedelta(seconds=1)).timestamp()),
        "client_id": "client-1",
        "jti": "token-1",
        "scope": "read",
    }


def _token(key: bytes, issuer: str, audience: str) -> str:
    encoded = jwt.encode(_claims(issuer, audience), key, algorithm="RS256", headers={"kid": "shared", "typ": "at+jwt"})
    return encoded.decode() if isinstance(encoded, bytes) else encoded


def _app(external_verifier: object, local_verifier: object) -> tuple[Litestar, _Resolver, _Resolver]:
    external_issuer, external_audience = _PROFILES["external"]
    local_issuer, local_audience = _PROFILES["local"]
    external_resolver = _Resolver("external")
    local_resolver = _Resolver("local")
    physical_slot, mechanism = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="external",
                selector=BearerSlotSelector(
                    issuers=frozenset({external_issuer}), audiences=frozenset({external_audience})
                ),
                verifier=external_verifier,  # type: ignore[arg-type]
            ),
        ),
    ).build(external_resolver, clock=lambda: _NOW)
    mechanism = extend_composite_bearer(
        mechanism,
        BearerTokenSlot(
            name="local",
            selector=BearerSlotSelector(issuers=frozenset({local_issuer}), audiences=frozenset({local_audience})),
            verifier=local_verifier,  # type: ignore[arg-type]
        ),
        local_resolver,
    )

    @get("/", auth=required("bearer"))
    async def handler(request: Request) -> dict[str, object]:
        return {
            "id": request.user.id,
            "mechanism": request.auth.evidence[0].mechanism,
            "slot": request.auth.evidence[0].slot,
        }

    app = Litestar(
        route_handlers=[handler],
        openapi_config=None,
        plugins=[SecurityPlugin(SecurityConfig(slots=(physical_slot,), mechanisms=(mechanism,)))],
    )
    return app, external_resolver, local_resolver


@pytest.mark.parametrize("participant", ["external", "local"])
def test_request_dispatch_selects_one_trust_slot_and_identity_resolver(
    participant: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    external_signing, external_verification = jwt_key_material["RS256"]
    local_signing, local_verification = jwt_key_material["RS256_ALT"]
    keys = {"external": external_signing, "local": local_signing}
    verifiers = {
        name: _RecordingVerifier(
            PyJWTVerifier(
                config=JWTValidationConfig(
                    issuer=issuer, audiences=frozenset({audience}), algorithms=frozenset({"RS256"})
                ),
                key=external_verification if name == "external" else local_verification,
                require_key_id=True,
            )
        )
        for name, (issuer, audience) in _PROFILES.items()
    }
    app, external_resolver, local_resolver = _app(verifiers["external"], verifiers["local"])
    issuer, audience = _PROFILES[participant]
    token = _token(keys[participant], issuer, audience)

    with TestClient(app) as client:
        response = client.get("/", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"id": f"{participant}:user-1", "mechanism": "bearer", "slot": participant}
    assert [len(verifiers["external"].calls), len(verifiers["local"].calls)] == (
        [1, 0] if participant == "external" else [0, 1]
    )
    assert (external_resolver.calls, local_resolver.calls) == (
        (["user-1"], []) if participant == "external" else ([], ["user-1"])
    )


def test_identical_key_ids_remain_isolated_across_request_trust_domains(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    external_signing, external_verification = jwt_key_material["RS256"]
    _, local_verification = jwt_key_material["RS256_ALT"]
    external_issuer, _ = _PROFILES["external"]
    local_issuer, local_audience = _PROFILES["local"]
    external = _RecordingVerifier(
        PyJWTVerifier(
            config=JWTValidationConfig(
                issuer=external_issuer, audiences=frozenset({_PROFILES["external"][1]}), algorithms=frozenset({"RS256"})
            ),
            key=external_verification,
            require_key_id=True,
        )
    )
    local = _RecordingVerifier(
        PyJWTVerifier(
            config=JWTValidationConfig(
                issuer=local_issuer, audiences=frozenset({local_audience}), algorithms=frozenset({"RS256"})
            ),
            key=local_verification,
            require_key_id=True,
        )
    )
    app, _, _ = _app(external, local)
    cross_domain_token = _token(external_signing, local_issuer, local_audience)

    with TestClient(app) as client:
        response = client.get("/", headers={"Authorization": f"Bearer {cross_domain_token}"})

    assert response.status_code == HTTP_401_UNAUTHORIZED
    assert [len(external.calls), len(local.calls)] == [0, 1]


def test_unknown_and_ambiguous_request_routes_perform_zero_verification(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["RS256"]
    config = JWTValidationConfig(
        issuer="https://issuer.example", audiences=frozenset({"one", "two"}), algorithms=frozenset({"RS256"})
    )
    verifiers = [
        _RecordingVerifier(PyJWTVerifier(config=config, key=verification_key, require_key_id=True)) for _ in range(2)
    ]
    resolver = _Resolver("unused")
    physical_slot, mechanism = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="one",
                selector=BearerSlotSelector(issuers=frozenset({config.issuer}), audiences=frozenset({"one", "two"})),
                verifier=verifiers[0],
            ),
            BearerTokenSlot(
                name="two",
                selector=BearerSlotSelector(issuers=frozenset({config.issuer}), audiences=frozenset({"one"})),
                verifier=verifiers[1],
            ),
        ),
    ).build(resolver, clock=lambda: _NOW)

    @get("/", auth=required("bearer"))
    async def handler() -> None:
        return None

    app = Litestar(
        route_handlers=[handler],
        openapi_config=None,
        plugins=[SecurityPlugin(SecurityConfig(slots=(physical_slot,), mechanisms=(mechanism,)))],
    )
    tokens = (_token(signing_key, "https://unknown.example", "one"), _token(signing_key, config.issuer, "one"))

    with TestClient(app) as client:
        responses = [client.get("/", headers={"Authorization": f"Bearer {token}"}) for token in tokens]

    assert [response.status_code for response in responses] == [HTTP_401_UNAUTHORIZED, HTTP_401_UNAUTHORIZED]
    assert [len(verifier.calls) for verifier in verifiers] == [0, 0]
    assert resolver.calls == []


@pytest.mark.parametrize(
    ("outcome", "expected_status"),
    [
        (InvalidCredentials(code="provider_invalid"), HTTP_401_UNAUTHORIZED),
        (NoCredentials(), HTTP_401_UNAUTHORIZED),
        ("unavailable", HTTP_503_SERVICE_UNAVAILABLE),
    ],
    ids=["invalid", "selected-no-credentials", "unavailable"],
)
def test_selected_terminal_outcomes_survive_framework_mapping(
    outcome: InvalidCredentials | NoCredentials | str,
    expected_status: int,
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, _ = jwt_key_material["RS256"]
    external_issuer, external_audience = _PROFILES["external"]
    config = JWTValidationConfig(
        issuer=external_issuer, audiences=frozenset({external_audience}), algorithms=frozenset({"RS256"})
    )
    external: object = (
        _UnavailableVerifier(config) if outcome == "unavailable" else AsyncRecordingJWTVerifier(outcome, config)
    )
    local = _RecordingVerifier(
        PyJWTVerifier(
            config=JWTValidationConfig(
                issuer=_PROFILES["local"][0],
                audiences=frozenset({_PROFILES["local"][1]}),
                algorithms=frozenset({"RS256"}),
            ),
            key=jwt_key_material["RS256_ALT"][1],
            require_key_id=True,
        )
    )
    app, _, _ = _app(external, local)
    token = _token(signing_key, external_issuer, external_audience)

    with TestClient(app) as client:
        response = client.get("/", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == expected_status
    assert len(external.calls) == 1  # type: ignore[attr-defined]
    assert local.calls == []


class _APIKeyResolver:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def resolve(self, claims: APIKeyClaims) -> Principal[object]:
        self.calls.append(claims.subject_id)
        return Principal(id=f"api-key:{claims.subject_id}")


async def test_api_key_authorization_bearer_coexists_with_composite_bearer_and_projects_openapi(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["RS256"]
    issuer, audience = _PROFILES["external"]
    jwt_verifier = _RecordingVerifier(
        PyJWTVerifier(
            config=JWTValidationConfig(issuer=issuer, audiences=frozenset({audience}), algorithms=frozenset({"RS256"})),
            key=verification_key,
            require_key_id=True,
        )
    )
    jwt_resolver = _Resolver("bearer")
    bearer_slot, bearer_mechanism = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="external",
                selector=BearerSlotSelector(issuers=frozenset({issuer}), audiences=frozenset({audience})),
                verifier=jwt_verifier,
            ),
        ),
    ).build(jwt_resolver, clock=lambda: _NOW)

    api_key_store = build_api_key_store()
    api_key_resolver = _APIKeyResolver()
    api_key_slot, api_key_mechanism, api_key_service = APIKeyConfig(
        store=api_key_store, pepper=b"p" * 32, accept_authorization_bearer=True
    ).build(api_key_resolver, clock=lambda: _NOW)
    issued = await api_key_service.issue(subject_id="machine-1")

    @get("/items", auth=any_of("api-key", "bearer"))
    async def items(request: Request) -> dict[str, object]:
        return {
            "id": request.user.id,
            "mechanism": request.auth.evidence[0].mechanism,
            "slot": request.auth.evidence[0].slot,
        }

    app = Litestar(
        route_handlers=[items],
        openapi_config=OpenAPIConfig(title="API", version="1.0.0"),
        plugins=[
            SecurityPlugin(
                SecurityConfig(slots=(api_key_slot, bearer_slot), mechanisms=(api_key_mechanism, bearer_mechanism))
            )
        ],
    )
    jwt_token = _token(signing_key, issuer, audience)

    with TestClient(app) as client:
        api_key_bearer_response = client.get("/items", headers={"Authorization": f"Bearer {issued.value}"})
        api_key_header_response = client.get("/items", headers={"X-API-Key": issued.value})
        jwt_response = client.get("/items", headers={"Authorization": f"Bearer {jwt_token}"})
        invalid_api_key_response = client.get("/items", headers={"Authorization": f"Bearer lsk_{'A' * 16}_{'B' * 43}"})
        schema = client.get("/schema/openapi.json").json()

    assert api_key_bearer_response.status_code == HTTP_200_OK
    assert api_key_bearer_response.json() == {"id": "api-key:machine-1", "mechanism": "api-key", "slot": "api-key"}
    assert api_key_header_response.status_code == HTTP_200_OK
    assert api_key_header_response.json() == {"id": "api-key:machine-1", "mechanism": "api-key", "slot": "api-key"}
    assert jwt_response.status_code == HTTP_200_OK
    assert jwt_response.json() == {"id": "bearer:user-1", "mechanism": "bearer", "slot": "external"}
    assert invalid_api_key_response.status_code == HTTP_401_UNAUTHORIZED
    assert len(jwt_verifier.calls) == 1
    assert schema["paths"]["/items"]["get"]["security"] == [{"APIKey": []}, {"APIKeyBearer": []}, {"bearer": []}]
    assert "APIKey" in schema["components"]["securitySchemes"]
    assert "APIKeyBearer" in schema["components"]["securitySchemes"]


async def test_api_key_authorization_bearer_coexists_with_service_token_config(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    signing_key, verification_key = jwt_key_material["RS256"]
    issuer, audience = _PROFILES["external"]
    jwks = _StaticJWKS(VerificationKey(key_id="shared", algorithm="RS256", key=verification_key))
    api_key_store = build_api_key_store()
    api_key_resolver = _APIKeyResolver()
    api_key_config = APIKeyConfig(
        store=api_key_store, identity_resolver=api_key_resolver, pepper=b"p" * 32, accept_authorization_bearer=True
    )
    service_token_config = ServiceTokenConfig(
        issuer=issuer,
        audiences=frozenset({audience}),
        allowed_algorithms=frozenset({"RS256"}),
        jwks=jwks,
        jwks_uri=f"{issuer}/.well-known/jwks.json",
    )

    @get("/workload", auth=any_of("api-key", "service-jwt"))
    async def workload(request: Request) -> dict[str, object]:
        return {"id": request.user.id, "mechanism": request.auth.evidence[0].mechanism}

    plugin = SecurityPlugin(SecurityConfig(api_key=api_key_config, service_token=service_token_config))
    app = Litestar(route_handlers=[workload], openapi_config=None, plugins=[plugin])
    _, _, api_key_service = api_key_config.build()
    issued = await api_key_service.issue(subject_id="cli-1")
    now = datetime.now(timezone.utc)
    jwt_claims = {
        "iss": issuer,
        "sub": "user-1",
        "aud": audience,
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "iat": int(now.timestamp()),
        "nbf": int((now - timedelta(seconds=1)).timestamp()),
        "client_id": "client-1",
        "jti": "token-1",
        "scope": "read",
    }
    encoded = jwt.encode(jwt_claims, signing_key, algorithm="RS256", headers={"kid": "shared", "typ": "at+jwt"})
    jwt_token = encoded.decode() if isinstance(encoded, bytes) else encoded

    with TestClient(app) as client:
        api_key_response = client.get("/workload", headers={"Authorization": f"Bearer {issued.value}"})
        jwt_response = client.get("/workload", headers={"Authorization": f"Bearer {jwt_token}"})

    assert api_key_response.status_code == HTTP_200_OK
    assert api_key_response.json() == {"id": "api-key:cli-1", "mechanism": "api-key"}
    assert jwt_response.status_code == HTTP_200_OK
    assert jwt_response.json() == {"id": "user-1", "mechanism": "service-jwt"}
