"""JWT signing and worker tests; worker behavior is observed through signing."""

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, cast

import jwt
import pytest

from litestar_security.authentication import Authenticated
from litestar_security.providers.jwt import (
    JWTValidationConfig,
    LocalKeyRing,
    SigningKey,
    TokenSigner,
    VerificationKey,
    VerificationKeySet,
    build_access_token_claims,
)
from litestar_security.providers.jwt import _workers as jwt_workers

if TYPE_CHECKING:
    from anyio import CapacityLimiter

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


async def test_local_signer_runs_crypto_in_a_worker_and_supports_custom_signers(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []
    observations: list[str] = []

    async def run_sync(function: Callable[[], object], **kwargs: object) -> object:
        calls.append(kwargs)
        return function()

    class Metrics:
        def increment(self, name: str, *, attributes: Mapping[str, str] = {}) -> None:
            del name, attributes

        def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = {}) -> None:
            del value, attributes
            observations.append(name)

    monkeypatch.setattr(jwt_workers.to_thread, "run_sync", run_sync)
    ring = LocalKeyRing(
        issuer=_JWT_ISSUER,
        active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=jwt_key_material["EdDSA"][0]),
        metrics=Metrics(),
    )
    claims = build_access_token_claims(
        issuer=_JWT_ISSUER,
        audience=_JWT_AUDIENCE,
        subject="user-1",
        client_id="client-1",
        security_epoch=0,
        scopes=frozenset(),
        now=_JWT_NOW,
        lifetime=timedelta(minutes=5),
        jti="worker-token",
    )

    token = await ring.build_signer().sign(claims, now=_JWT_NOW)

    class _CustomSigner:
        async def sign(self, custom_claims: Mapping[str, object], *, now: datetime) -> str:
            assert custom_claims is claims
            assert now is _JWT_NOW
            encoded = jwt.encode(
                dict(custom_claims),
                jwt_key_material["EdDSA"][0],
                algorithm="EdDSA",
                headers={"kid": "kms", "typ": "at+jwt"},
            )
            return encoded.decode() if isinstance(encoded, bytes) else encoded

    custom_signer: TokenSigner = _CustomSigner()  # type: ignore[assignment]
    custom_token = await custom_signer.sign(claims, now=_JWT_NOW)  # type: ignore[arg-type]
    custom_keys = VerificationKeySet(
        issuer=_JWT_ISSUER, keys=(VerificationKey(key_id="kms", algorithm="EdDSA", key=jwt_key_material["EdDSA"][1]),)
    )

    assert token.count(".") == 2
    assert len(calls) == 1
    assert calls[0]["abandon_on_cancel"] is True
    assert cast("CapacityLimiter", calls[0]["limiter"]).total_tokens == 32
    assert isinstance(await ring.build_verifier(_jwt_config("EdDSA")).verify(token, now=_JWT_NOW), Authenticated)
    assert {"security.jwt.sign_duration", "security.jwt.verify_duration"} <= set(observations)
    assert isinstance(custom_signer, TokenSigner)
    assert isinstance(
        await custom_keys.build_verifier(_jwt_config("EdDSA")).verify(custom_token, now=_JWT_NOW), Authenticated
    )

    async def unavailable(_function: Callable[[], object], **_kwargs: object) -> object:
        message = "private failure detail"
        raise OSError(message)

    monkeypatch.setattr(jwt_workers.to_thread, "run_sync", unavailable)
    with pytest.raises(RuntimeError, match="Token signing unavailable") as exc_info:
        await ring.build_signer().sign(claims, now=_JWT_NOW)
    assert "private failure detail" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("missing", "sub"),
        ("forbidden", ("email", "private@example.com")),
        ("issuer", "https://other.example"),
        ("issued_at", int(_JWT_NOW.timestamp()) + 1),
        ("not_before", int((_JWT_NOW + timedelta(hours=1)).timestamp())),
        ("scope", "profile  reports:read"),
    ],
)
async def test_local_signer_rejects_nonconforming_access_claims(
    mutation: str, value: object, jwt_key_material: Mapping[str, tuple[bytes, bytes]]
) -> None:
    ring = LocalKeyRing(
        issuer=_JWT_ISSUER,
        active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=jwt_key_material["EdDSA"][0]),
    )
    claims = dict(
        build_access_token_claims(
            issuer=_JWT_ISSUER,
            audience=_JWT_AUDIENCE,
            subject="user-1",
            client_id="client-1",
            security_epoch=0,
            scopes=frozenset({"profile"}),
            now=_JWT_NOW,
            lifetime=timedelta(minutes=5),
            jti="invalid-shape",
        )
    )
    if mutation == "missing":
        claims.pop(cast("str", value))
    elif mutation == "forbidden":
        key, item = cast("tuple[str, object]", value)
        claims[key] = item
    elif mutation == "issuer":
        claims["iss"] = value
    elif mutation == "issued_at":
        claims["iat"] = value
    elif mutation == "not_before":
        claims["nbf"] = value
    else:
        claims["scope"] = value

    with pytest.raises(ValueError, match="Invalid local access-token claims"):
        await ring.build_signer().sign(cast("Mapping[str, object]", claims), now=_JWT_NOW)  # type: ignore[arg-type]


def test_local_key_material_is_secret_safe(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    private_key, public_key = jwt_key_material["RS256"]
    signing_key = SigningKey(key_id="active", algorithm="RS256", private_key=private_key)
    verification_key = VerificationKey(key_id="retained", algorithm="RS256", key=public_key)
    ring = LocalKeyRing(issuer=_JWT_ISSUER, active_signing_key=signing_key, verification_keys=(verification_key,))

    assert all(
        private_key.decode() not in repr(value) and public_key.decode() not in repr(value)
        for value in (signing_key, verification_key, ring, ring.build_signer())
    )
    for public_jwk in (signing_key.public_jwk, verification_key.public_jwk):
        assert public_jwk is not None
        assert not {"d", "dp", "dq", "k", "oth", "p", "q", "qi"}.intersection(public_jwk)


def test_local_keys_canonicalize_null_public_jwk_metadata(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    private_key, public_key = jwt_key_material["RS256"]
    generated = SigningKey(key_id="generated", algorithm="RS256", private_key=private_key)
    null_metadata = {
        **dict(cast("Mapping[str, object]", generated.public_jwk)),
        "alg": None,
        "key_ops": None,
        "kid": None,
        "use": None,
    }

    signing_key = SigningKey(
        key_id="active", algorithm="RS256", private_key=private_key, public_jwk=cast("Any", null_metadata)
    )
    verification_key = VerificationKey(
        key_id="retained", algorithm="RS256", key=public_key, public_jwk=cast("Any", null_metadata)
    )

    for public_jwk, key_id in ((signing_key.public_jwk, "active"), (verification_key.public_jwk, "retained")):
        assert public_jwk is not None
        assert public_jwk["alg"] == "RS256"
        assert public_jwk["key_ops"] == ("verify",)
        assert public_jwk["kid"] == key_id
        assert public_jwk["use"] == "sig"
