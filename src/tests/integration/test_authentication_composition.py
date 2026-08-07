"""Request-level authentication composition and trust-domain isolation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import jwt
import pytest
from litestar import Litestar, Request, get
from litestar.status_codes import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_503_SERVICE_UNAVAILABLE
from litestar.testing import TestClient

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security.authentication import InvalidCredentials, NoCredentials, VerificationUnavailable, required
from litestar_security.context import Principal
from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JWTClaims,
    JWTValidationConfig,
    PyJWTVerifier,
    extend_composite_bearer,
)
from tests.fixtures.collaborators import AsyncRecordingJWTVerifier

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
