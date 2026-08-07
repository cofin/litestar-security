"""JWT access-claim tests."""

import importlib
import json
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from math import inf, nan
from typing import cast

import pytest

from litestar_security.authentication import InvalidCredentials
from litestar_security.providers.jwt import _capabilities as jwt_capabilities
from litestar_security.providers.jwt import build_access_token_claims

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)

_JWT_ISSUER = "https://issuer.example"

_JWT_AUDIENCE = "litestar-security"


def test_access_token_claim_builder_is_deterministic_minimal_and_validated() -> None:
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=7,
        scopes=frozenset({"z:write", "a:read"}),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=5),
        jti="token-1",
        not_before=_JWT_NOW + timedelta(seconds=2),
    )

    assert dict(claims) == {
        "iss": _JWT_ISSUER,
        "sub": "user-1",
        "aud": _JWT_AUDIENCE,
        "exp": int((_JWT_NOW + timedelta(minutes=5)).timestamp()),
        "iat": int(_JWT_NOW.timestamp()),
        "nbf": int((_JWT_NOW + timedelta(seconds=2)).timestamp()),
        "client_id": "client-1",
        "jti": "token-1",
        "scope": "a:read z:write",
        "se": 7,
    }
    assert not {"email", "password", "roles", "teams", "user"}.intersection(claims)
    with pytest.raises(TypeError):
        claims["sub"] = "changed"  # type: ignore[index]
    random_one = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=0,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=1),
    )
    random_two = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=0,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=1),
    )
    assert random_one["jti"] != random_two["jti"]
    assert "scope" not in random_one


def test_capability_claims_reject_reserved_claim_names() -> None:
    capabilities = importlib.import_module("litestar_security.providers.jwt._capabilities")

    with pytest.raises(ValueError, match="reserved"):
        capabilities.build_capability_claims(
            issuer=_JWT_ISSUER,
            purpose="download",
            subject="user-1",
            audience="files",
            lifetime=timedelta(minutes=5),
            claims={"aud": "hijack"},
            now=_JWT_NOW,
        )


def test_capability_claim_builder_returns_detached_json_payload() -> None:
    capabilities = importlib.import_module("litestar_security.providers.jwt._capabilities")
    application_claims = {"resource": {"parts": ["one"]}, "weight": 1.5}

    payload = capabilities.build_capability_claims(
        issuer=_JWT_ISSUER,
        purpose="download",
        subject="user-1",
        audience="files",
        lifetime=timedelta(minutes=5),
        claims=application_claims,
        now=_JWT_NOW,
    )
    application_claims["resource"]["parts"].append("two")

    assert isinstance(payload, dict)
    assert payload["resource"] == {"parts": ["one"]}
    assert payload["weight"] == 1.5
    assert json.loads(json.dumps(payload))["resource"] == {"parts": ["one"]}


def test_capability_claim_builder_rejects_non_json_application_values() -> None:
    capabilities = importlib.import_module("litestar_security.providers.jwt._capabilities")

    with pytest.raises(ValueError, match="JSON"):
        capabilities.build_capability_claims(
            issuer=_JWT_ISSUER,
            purpose="download",
            subject="user-1",
            audience="files",
            lifetime=timedelta(minutes=5),
            claims={"created_at": _JWT_NOW},
            now=_JWT_NOW,
        )


@pytest.mark.parametrize(
    ("claims", "lifetime", "match"),
    [
        ({1: "value"}, timedelta(minutes=5), "object keys"),
        ({"nested": {1: "value"}}, timedelta(minutes=5), "object keys"),
        ({"value": nan}, timedelta(minutes=5), "finite"),
        ({"value": inf}, timedelta(minutes=5), "finite"),
        ({}, timedelta(milliseconds=500), "whole second"),
    ],
)
def test_capability_claim_builder_rejects_noncanonical_json_values(
    claims: Mapping[object, object], lifetime: timedelta, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        jwt_capabilities.build_capability_claims(
            issuer=_JWT_ISSUER,
            purpose="download",
            subject="user-1",
            audience="files",
            lifetime=lifetime,
            claims=cast("Mapping[str, jwt_capabilities.JSONValue]", claims),
            now=_JWT_NOW,
        )


def test_capability_claim_builder_rejects_excessive_json_depth() -> None:
    nested: object = "value"
    for _ in range(33):
        nested = [nested]

    with pytest.raises(ValueError, match="bounded"):
        jwt_capabilities.build_capability_claims(
            issuer=_JWT_ISSUER,
            purpose="download",
            subject="user-1",
            audience="files",
            lifetime=timedelta(minutes=5),
            claims={"nested": cast("jwt_capabilities.JSONValue", nested)},
            now=_JWT_NOW,
        )


@pytest.mark.parametrize(
    ("mutation", "now"),
    [
        ("missing", _JWT_NOW),
        ("invalid-numeric", _JWT_NOW),
        ("overflow-numeric", _JWT_NOW),
        ("expired-lifetime", _JWT_NOW),
        ("not-before-after-expiry", _JWT_NOW),
        ("invalid-now", cast("datetime", None)),
    ],
)
def test_normalize_capability_claims_rejects_malformed_temporal_claims(mutation: str, now: datetime) -> None:
    payload: dict[str, jwt_capabilities.JSONValue] = {
        "iss": _JWT_ISSUER,
        "sub": "user-1",
        "aud": "files",
        "purpose": "download",
        "jti": "capability-1",
        "iat": int(_JWT_NOW.timestamp()),
        "exp": int((_JWT_NOW + timedelta(minutes=5)).timestamp()),
    }
    if mutation == "missing":
        del payload["jti"]
    elif mutation == "invalid-numeric":
        payload["iat"] = True
    elif mutation == "overflow-numeric":
        payload["exp"] = inf
    elif mutation == "expired-lifetime":
        payload["exp"] = payload["iat"]
    elif mutation == "not-before-after-expiry":
        payload["nbf"] = payload["exp"]

    assert (
        jwt_capabilities.normalize_capability_claims(
            payload, purpose="download", audience="files", issuer=_JWT_ISSUER, now=now
        )
        == InvalidCredentials()
    )
