"""JWT capability tests."""

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import jwt
import pytest

from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.providers.jwt import (
    JWTValidationConfig,
    LocalKeyRing,
    SigningKey,
    VerificationKey,
    build_access_token_claims,
)
from litestar_security.providers.jwt import _capabilities as jwt_capabilities
from litestar_security.providers.jwt import _keyring as jwt_keyring

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)

_NAIVE_JWT_NOW = datetime(2026, 7, 26)  # noqa: DTZ001 - explicit rejection fixture

_JWT_ISSUER = "https://issuer.example"

_JWT_AUDIENCE = "litestar-security"


async def test_mint_capability_header_is_never_accepted_by_the_access_verifier(local_key_ring: LocalKeyRing) -> None:
    with pytest.raises(ValueError, match="24 hours"):
        await local_key_ring.mint_capability(
            purpose="download", subject="user-1", audience="files", lifetime=timedelta(hours=25)
        )

    token = await local_key_ring.mint_capability(
        purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=5)
    )

    assert jwt.get_unverified_header(token)["typ"] == "capability+jwt"
    verifier = local_key_ring.build_verifier(
        JWTValidationConfig(
            issuer=local_key_ring.issuer,
            audiences=frozenset({"files"}),
            algorithms=frozenset(key.algorithm for key in local_key_ring.all_verification_keys),
        )
    )
    assert isinstance(await verifier.verify(token, now=_JWT_NOW), InvalidCredentials)


@pytest.mark.parametrize("case", ["access-token", "purpose", "audience", "expired", "naive-now"])
async def test_verify_capability_rejects_untrusted_or_mismatched_tokens_as_one_outcome(
    case: str, local_key_ring: LocalKeyRing
) -> None:
    now = datetime.now(timezone.utc)
    capability = await local_key_ring.mint_capability(
        purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=1)
    )
    if case == "access-token":
        token = await local_key_ring.build_signer().sign(
            build_access_token_claims(
                issuer=local_key_ring.issuer,
                audience="files",
                subject="user-1",
                client_id="client-1",
                security_epoch=0,
                scopes=frozenset(),
                now=now,
                lifetime=timedelta(minutes=1),
                jti="access-token-1",
            ),
            now=now,
        )
        purpose, audience, verification_now = "download", "files", now
    elif case == "purpose":
        token, purpose, audience, verification_now = capability, "upload", "files", now
    elif case == "audience":
        token, purpose, audience, verification_now = capability, "download", "images", now
    elif case == "expired":
        token, purpose, audience, verification_now = (
            capability,
            "download",
            "files",
            now + timedelta(minutes=1, seconds=31),
        )
    else:
        token, purpose, audience, verification_now = capability, "download", "files", _NAIVE_JWT_NOW

    assert (
        await local_key_ring.verify_capability(token, purpose=purpose, audience=audience, now=verification_now)
        == InvalidCredentials()
    )


async def test_verify_capability_accepts_a_retained_rotation_key(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    old_private, old_public = jwt_key_material["RS256"]
    new_private, _new_public = jwt_key_material["RS256_ALT"]
    old_ring = LocalKeyRing(
        issuer=_JWT_ISSUER, active_signing_key=SigningKey(key_id="old", algorithm="RS256", private_key=old_private)
    )
    token = await old_ring.mint_capability(
        purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=5)
    )
    rotated_ring = LocalKeyRing(
        issuer=_JWT_ISSUER,
        active_signing_key=SigningKey(key_id="new", algorithm="RS256", private_key=new_private),
        verification_keys=(VerificationKey(key_id="old", algorithm="RS256", key=old_public),),
    )

    result = await rotated_ring.verify_capability(
        token, purpose="download", audience="files", now=datetime.now(timezone.utc)
    )

    assert isinstance(result, jwt_capabilities.VerifiedCapability)
    assert result.subject == "user-1"


async def test_capability_worker_failures_are_sanitized(
    local_key_ring: LocalKeyRing, monkeypatch: pytest.MonkeyPatch
) -> None:
    capability = await local_key_ring.mint_capability(
        purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=5)
    )

    async def failure(*_args: object, **_kwargs: object) -> object:
        message = "internal failure"
        raise OSError(message)

    monkeypatch.setattr(jwt_keyring, "run_worker", failure)
    with pytest.raises(RuntimeError, match="Capability minting unavailable") as exc_info:
        await local_key_ring.mint_capability(
            purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=5)
        )
    assert "internal failure" not in str(exc_info.value)

    outcome = await local_key_ring.verify_capability(
        capability, purpose="download", audience="files", now=datetime.now(timezone.utc)
    )

    assert isinstance(outcome, VerificationUnavailable)


@pytest.mark.parametrize(
    ("raw", "failure", "outcome_type"),
    [("not-a-jwt", None, InvalidCredentials), (None, jwt.InvalidTokenError(), InvalidCredentials)],
)
async def test_verify_capability_sanitizes_untrusted_routes_and_crypto_failures(
    raw: str | None,
    failure: Exception | None,
    outcome_type: type[InvalidCredentials],
    local_key_ring: LocalKeyRing,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if raw is None:
        raw = await local_key_ring.mint_capability(
            purpose="download", subject="user-1", audience="files", lifetime=timedelta(minutes=5)
        )

        async def fail_worker(*_args: object, **_kwargs: object) -> object:
            raise cast("Exception", failure)

        monkeypatch.setattr(jwt_keyring, "run_worker", fail_worker)

    outcome = await local_key_ring.verify_capability(
        raw, purpose="download", audience="files", now=datetime.now(timezone.utc)
    )

    assert isinstance(outcome, outcome_type)


async def test_verify_capability_rejects_an_unknown_key_id(local_key_ring: LocalKeyRing) -> None:
    now = datetime.now(timezone.utc)
    payload = jwt_capabilities.build_capability_claims(
        issuer=local_key_ring.issuer,
        purpose="download",
        subject="user-1",
        audience="files",
        lifetime=timedelta(minutes=5),
        claims={},
        now=now,
    )
    raw = jwt.encode(
        dict(payload),
        cast("Any", local_key_ring.active_signing_key)._prepared_key,  # noqa: SLF001 - exercise untrusted key routing
        algorithm=local_key_ring.active_signing_key.algorithm,
        headers={"kid": "unknown", "typ": jwt_capabilities.CAPABILITY_TOKEN_TYPE},
    )

    outcome = await local_key_ring.verify_capability(raw, purpose="download", audience="files", now=now)

    assert isinstance(outcome, InvalidCredentials)


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"issuer": " "}, "identifier"),
        ({"audience": " "}, "identifier"),
        ({"subject": " "}, "identifier"),
        ({"client_id": " "}, "identifier"),
        ({"security_epoch": -1}, "security epoch"),
        ({"security_epoch": True}, "security epoch"),
        ({"lifetime": timedelta(0)}, "lifetime"),
        ({"lifetime": timedelta(milliseconds=500)}, "whole second"),
        ({"now": _NAIVE_JWT_NOW}, "timezone-aware"),
        ({"not_before": _NAIVE_JWT_NOW}, "timezone-aware"),
        ({"not_before": _JWT_NOW + timedelta(minutes=6)}, "expiry"),
        ({"jti": " "}, "identifier"),
        ({"scopes": frozenset({" "})}, "scope"),
    ],
)
def test_access_token_claim_builder_rejects_invalid_inputs(overrides: dict[str, object], match: str) -> None:
    kwargs: dict[str, object] = {
        "issuer": _JWT_ISSUER,
        "audience": _JWT_AUDIENCE,
        "subject": "user-1",
        "client_id": "client-1",
        "security_epoch": 0,
        "scopes": frozenset({"profile"}),
        "now": _JWT_NOW,
        "lifetime": timedelta(minutes=5),
        "jti": "token-1",
    }
    kwargs.update(overrides)

    with pytest.raises(ValueError, match=match):
        build_access_token_claims(**kwargs)  # type: ignore[arg-type]
