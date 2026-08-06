"""JWT key and keyring tests; key values are coherent with their owning ring."""

import base64
import json
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import jwt
import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import Authenticated, InvalidCredentials
from litestar_security.providers.jwt import (
    JWTValidationConfig,
    LocalKeyRing,
    SigningKey,
    VerificationKey,
    VerificationKeySet,
    build_access_token_claims,
)

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)

_JWT_ISSUER = "https://issuer.example"

_JWT_AUDIENCE = "litestar-security"


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


def _jwt_segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _compact_jwt(header: bytes, payload: bytes, signature: bytes = b"signature") -> str:
    return ".".join((_jwt_segment(header), _jwt_segment(payload), _jwt_segment(signature)))


@pytest.mark.parametrize("algorithm", ["EdDSA", "ES256", "RS256", "HS256"])
async def test_local_key_ring_signs_and_verifies_every_supported_algorithm(
    algorithm: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    private_key, _public_key = jwt_key_material[algorithm]
    signing_key = SigningKey(key_id=f"{algorithm.lower()}-active", algorithm=algorithm, private_key=private_key)
    ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=signing_key)
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=3,
        scopes=frozenset({"profile", "reports:read"}),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=10),
        jti="token-1",
        not_before=_JWT_NOW - timedelta(seconds=1),
    )

    token = await ring.build_signer().sign(claims, now=_JWT_NOW)
    outcome = await ring.build_verifier(_jwt_config(algorithm)).verify(token, now=_JWT_NOW)

    assert jwt.get_unverified_header(token) == {"alg": algorithm, "kid": f"{algorithm.lower()}-active", "typ": "at+jwt"}
    assert isinstance(outcome, Authenticated)
    assert outcome.claims.raw["se"] == 3
    assert outcome.claims.scopes == frozenset({"profile", "reports:read"})
    assert (
        signing_key.public_jwk is None if algorithm == "HS256" else signing_key.public_jwk["kid"] == signing_key.key_id
    )


async def test_local_key_ring_rotation_accepts_retained_keys_and_rejects_removed_keys(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    old_private, old_public = jwt_key_material["RS256"]
    new_private, _new_public = jwt_key_material["RS256_ALT"]
    old_ring = LocalKeyRing(
        issuer=_JWT_ISSUER, active_signing_key=SigningKey(key_id="old", algorithm="RS256", private_key=old_private)
    )
    new_active = SigningKey(key_id="new", algorithm="RS256", private_key=new_private)
    retained = VerificationKey(key_id="old", algorithm="RS256", key=old_public)
    rotated_ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=new_active, verification_keys=(retained,))
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=1,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=10),
        jti="rotation-token",
    )
    old_token = await old_ring.build_signer().sign(claims, now=_JWT_NOW)
    new_token = await rotated_ring.build_signer().sign(claims, now=_JWT_NOW)
    config = _jwt_config("RS256")

    assert isinstance(await rotated_ring.build_verifier(config).verify(old_token, now=_JWT_NOW), Authenticated)
    assert isinstance(await rotated_ring.build_verifier(config).verify(new_token, now=_JWT_NOW), Authenticated)
    assert rotated_ring.verification_key_set.keys == rotated_ring.all_verification_keys
    replacement_without_old = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=new_active)
    assert await replacement_without_old.build_verifier(config).verify(old_token, now=_JWT_NOW) == InvalidCredentials()
    verifier = rotated_ring.build_verifier(config)
    assert await verifier.verify("malformed", now=_JWT_NOW) == InvalidCredentials()
    missing_algorithm = _compact_jwt(
        b'{"kid":"old","typ":"at+jwt"}', json.dumps(dict(claims), separators=(",", ":")).encode()
    )
    assert await verifier.verify(missing_algorithm, now=_JWT_NOW) == InvalidCredentials()


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("blank-kid", "key id"),
        ("public-signing-key", "signing key"),
        ("weak-rsa", "RS256"),
        ("wrong-curve", "ES256"),
        ("wrong-ed-key", "EdDSA"),
        ("short-hmac", "HS256"),
        ("short-hmac-verification", "HS256"),
        ("mismatched-jwk", "correspond"),
        ("private-jwk", "public JWK"),
        ("wrong-jwk-alg", "public JWK"),
        ("wrong-jwk-use", "public JWK"),
        ("wrong-jwk-ops", "public JWK"),
        ("private-verification-key", "verification key"),
        ("wrong-verification-type", "verification key"),
        ("non-bytes-signing-key", "signing key"),
        ("non-bytes-verification-key", "verification key"),
        ("unsupported-signing-algorithm", "Unsupported local signing algorithm"),
        ("unsupported-verification-algorithm", "Unsupported local verification algorithm"),
        ("empty-key-set", "at least one key"),
        ("hmac-public-jwk", "public JWK"),
        ("mismatched-jwk-kid", "public JWK"),
        ("duplicate-kid", "Duplicate local key id"),
        ("issuer-mismatch", "issuer"),
        ("active-algorithm-excluded", "active signing algorithm"),
        ("no-compatible-key-set", "no key accepted"),
    ],
)
def test_local_key_ring_rejects_unsafe_startup_configuration(  # noqa: C901
    case: str, match: str, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    rsa_private, rsa_public = jwt_key_material["RS256"]
    alt_private, _alt_public = jwt_key_material["RS256_ALT"]
    valid = SigningKey(key_id="valid", algorithm="RS256", private_key=rsa_private)
    public_jwk = dict(cast("Mapping[str, object]", valid.public_jwk))

    def build_invalid() -> object:  # noqa: C901, PLR0911, PLR0912
        if case == "blank-kid":
            return SigningKey(key_id=" ", algorithm="RS256", private_key=rsa_private)
        if case == "public-signing-key":
            return SigningKey(key_id="public", algorithm="RS256", private_key=rsa_public)
        if case == "weak-rsa":
            return SigningKey(key_id="weak", algorithm="RS256", private_key=jwt_key_material["RS1024"][0])
        if case == "wrong-curve":
            return SigningKey(key_id="curve", algorithm="ES256", private_key=jwt_key_material["ES384"][0])
        if case == "wrong-ed-key":
            return SigningKey(key_id="wrong-ed", algorithm="EdDSA", private_key=rsa_private)
        if case == "short-hmac":
            return SigningKey(key_id="short", algorithm="HS256", private_key=b"too-short")
        if case == "short-hmac-verification":
            return VerificationKey(key_id="short", algorithm="HS256", key=b"too-short")
        if case == "mismatched-jwk":
            return SigningKey(key_id="valid", algorithm="RS256", private_key=alt_private, public_jwk=public_jwk)
        if case == "private-jwk":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "d": "secret"}
            )
        if case == "wrong-jwk-alg":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "alg": "ES256"}
            )
        if case == "wrong-jwk-use":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "use": "enc"}
            )
        if case == "wrong-jwk-ops":
            return SigningKey(
                key_id="valid",
                algorithm="RS256",
                private_key=rsa_private,
                public_jwk={**public_jwk, "key_ops": ["sign"]},
            )
        if case == "private-verification-key":
            return VerificationKey(key_id="private", algorithm="RS256", key=rsa_private)
        if case == "wrong-verification-type":
            return VerificationKey(key_id="wrong-type", algorithm="ES256", key=rsa_public)
        if case == "non-bytes-signing-key":
            return SigningKey(key_id="type", algorithm="RS256", private_key=cast("Any", "not-bytes"))
        if case == "non-bytes-verification-key":
            return VerificationKey(key_id="type", algorithm="RS256", key=cast("Any", "not-bytes"))
        if case == "unsupported-signing-algorithm":
            return SigningKey(key_id="unsupported", algorithm=cast("Any", "ES384"), private_key=rsa_private)
        if case == "unsupported-verification-algorithm":
            return VerificationKey(key_id="unsupported", algorithm=cast("Any", "ES384"), key=rsa_public)
        if case == "empty-key-set":
            return VerificationKeySet(issuer=_JWT_ISSUER, keys=())
        if case == "hmac-public-jwk":
            return SigningKey(
                key_id="hmac", algorithm="HS256", private_key=jwt_key_material["HS256"][0], public_jwk=public_jwk
            )
        if case == "mismatched-jwk-kid":
            return SigningKey(
                key_id="valid", algorithm="RS256", private_key=rsa_private, public_jwk={**public_jwk, "kid": "other"}
            )
        if case == "duplicate-kid":
            return LocalKeyRing(
                issuer=_JWT_ISSUER,
                active_signing_key=valid,
                verification_keys=(VerificationKey(key_id="valid", algorithm="RS256", key=rsa_public),),
            )
        ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=valid)
        if case == "issuer-mismatch":
            return ring.build_verifier(
                JWTValidationConfig(
                    issuer="https://other.example",
                    audiences=frozenset({_JWT_AUDIENCE}),
                    algorithms=frozenset({"RS256"}),
                )
            )
        if case == "active-algorithm-excluded":
            retained = VerificationKey(key_id="retained-ec", algorithm="ES256", key=jwt_key_material["ES256"][1])
            return LocalKeyRing(
                issuer=_JWT_ISSUER, active_signing_key=valid, verification_keys=(retained,)
            ).build_verifier(_jwt_config("ES256"))
        return VerificationKeySet(
            issuer=_JWT_ISSUER, keys=(VerificationKey(key_id="rsa-only", algorithm="RS256", key=rsa_public),)
        ).build_verifier(_jwt_config("ES256"))

    with pytest.raises(ImproperlyConfiguredException, match=match):
        build_invalid()
