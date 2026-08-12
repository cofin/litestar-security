"""Unit tests for authoritative Google IAP assertion authentication."""

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.authentication import (
    Authenticated,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
)
from litestar_security.config import WorkerLimits
from litestar_security.context import Principal
from litestar_security.providers.iap import GoogleIAPClaims, GoogleIAPConfig, GoogleIAPExternalIdentity
from litestar_security.providers.jwt import VerificationKey

_NOW = datetime(2026, 7, 28, 20, tzinfo=timezone.utc)
_ISSUER = "https://cloud.google.com/iap"
_AUDIENCE = "/projects/123/global/backendServices/456"
_JWKS_URI = "https://www.gstatic.com/iap/verify/public_key-jwk"


class _JWKS:
    def __init__(self, key: VerificationKey) -> None:
        self.key = key
        self.outcome: object = key
        self.calls: list[tuple[str, str, str, str, datetime]] = []

    async def select_key(self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime) -> object:
        self.calls.append((issuer, jwks_uri, kid, algorithm, now))
        return self.outcome

    async def warmup(self, *, now: datetime) -> None:
        del now

    async def aclose(self) -> None:
        return None


class _Resolver:
    def __init__(self) -> None:
        self.claims: list[GoogleIAPClaims] = []

    async def resolve(self, claims: GoogleIAPClaims) -> Principal[str]:
        self.claims.append(claims)
        return Principal(id=claims.subject, display_name=claims.email, user=claims.subject)


@pytest.fixture(scope="module")
def iap_key_material() -> tuple[bytes, VerificationKey]:
    private = ec.generate_private_key(ec.SECP256R1())
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, VerificationKey(key_id="iap-key", algorithm="ES256", key=public_pem)


def _claims(**overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": _ISSUER,
        "sub": "accounts.google.com:subject-1",
        "aud": _AUDIENCE,
        "iat": int(_NOW.timestamp()),
        "exp": int((_NOW + timedelta(minutes=10)).timestamp()),
        "email": "person@example.com",
        "azp": "iap-client",
    }
    claims.update(overrides)
    return claims


def _token(private_key: bytes, *, claims: Mapping[str, object] | None = None, algorithm: str = "ES256") -> str:
    return jwt.encode(
        dict(_claims() if claims is None else claims),
        private_key,
        algorithm=algorithm,
        headers={"kid": "iap-key", "typ": "JWT"},
    )


def _runtime(key: VerificationKey) -> tuple[object, object, _JWKS, _Resolver]:
    jwks = _JWKS(key)
    resolver = _Resolver()
    slot, mechanism = GoogleIAPConfig(audience=_AUDIENCE, identity_resolver=resolver, jwks=jwks).build(
        clock=lambda: _NOW
    )
    return slot, mechanism, jwks, resolver


def test_iap_slot_ignores_unsigned_identity_headers_and_rejects_duplicates(
    iap_key_material: tuple[bytes, VerificationKey],
) -> None:
    slot, _, _, _ = _runtime(iap_key_material[1])

    absent = slot.extract(
        type("Connection", (), {"scope": {"headers": [(b"x-goog-authenticated-user-email", b"person@example.com")]}})()
    )
    duplicate = slot.extract(
        type(
            "Connection",
            (),
            {"scope": {"headers": [(b"x-goog-iap-jwt-assertion", b"one"), (b"X-Goog-IAP-JWT-Assertion", b"two")]}},
        )()
    )

    assert isinstance(absent, NoCredentials)
    assert isinstance(duplicate, InvalidCredentials)


@pytest.mark.parametrize(
    ("value", "outcome"), [(b"signed", PresentedCredential), (b"\xff", InvalidCredentials), (b"", InvalidCredentials)]
)
def test_iap_slot_parses_only_one_ascii_assertion(
    iap_key_material: tuple[bytes, VerificationKey], value: bytes, outcome: type[object]
) -> None:
    slot, _, _, _ = _runtime(iap_key_material[1])

    extraction = slot.extract(type("Connection", (), {"scope": {"headers": [(b"x-goog-iap-jwt-assertion", value)]}})())

    assert isinstance(extraction, outcome)


@pytest.mark.parametrize(
    "claims",
    [
        _claims(exp=int((_NOW - timedelta(minutes=1)).timestamp())),
        _claims(iat=int((_NOW + timedelta(minutes=1)).timestamp())),
        _claims(iss="https://example.com"),
        _claims(aud="wrong"),
        {key: value for key, value in _claims().items() if key != "sub"},
        _claims(email=["wrong"]),
        _claims(azp=1),
        _claims(exp=int((_NOW + timedelta(minutes=11, seconds=1)).timestamp())),
        _claims(gcip={"sub": "external", "email_verified": "yes"}),
    ],
)
async def test_iap_rejects_invalid_claims(
    iap_key_material: tuple[bytes, VerificationKey], claims: Mapping[str, object]
) -> None:
    private, key = iap_key_material
    _, mechanism, _, _ = _runtime(key)

    outcome = await mechanism.authenticator.authenticate(
        _token(private, claims=claims), type("Connection", (), {"scope": {"headers": []}})()
    )

    assert isinstance(outcome, InvalidCredentials)


@pytest.mark.parametrize("state", ["malformed", "wrong-algorithm", "missing-kid", "naive-clock", "bad-provider"])
async def test_iap_rejects_malformed_routes_and_invalid_runtime_boundaries(
    iap_key_material: tuple[bytes, VerificationKey], state: str
) -> None:
    private, key = iap_key_material
    slot, mechanism, jwks, resolver = _runtime(key)
    token = _token(private)
    if state == "malformed":
        token = "not-a-jwt"  # noqa: S105 - intentionally malformed credential fixture
    elif state == "wrong-algorithm":
        token = jwt.encode(_claims(), b"h" * 32, algorithm="HS256", headers={"kid": "iap-key", "typ": "JWT"})
    elif state == "missing-kid":
        token = jwt.encode(_claims(), private, algorithm="ES256", headers={"typ": "JWT"})
    elif state == "naive-clock":
        _, mechanism = GoogleIAPConfig(audience=_AUDIENCE, identity_resolver=resolver, jwks=jwks).build(
            clock=lambda: datetime(2026, 7, 28)  # noqa: DTZ001 - intentional naive rejection fixture
        )
    else:
        jwks.outcome = object()

    outcome = await mechanism.authenticator.authenticate(token, type("Connection", (), {"scope": {"headers": []}})())

    assert isinstance(outcome, VerificationUnavailable if state == "bad-provider" else InvalidCredentials)
    assert slot.name == "google-iap"


async def test_iap_valid_assertion_uses_pinned_jwks_and_preserves_identity_evidence(
    iap_key_material: tuple[bytes, VerificationKey],
) -> None:
    private, key = iap_key_material
    _, mechanism, jwks, resolver = _runtime(key)
    token = _token(private)

    outcome = await mechanism.authenticator.authenticate(token, type("Connection", (), {"scope": {"headers": []}})())

    assert isinstance(outcome, Authenticated)
    assert outcome.claims == GoogleIAPClaims(
        subject="accounts.google.com:subject-1", email="person@example.com", authorized_party="iap-client"
    )
    assert outcome.evidence.mechanism == "google-iap"
    assert outcome.evidence.methods == frozenset({"iap"})
    assert mechanism.scheme_name == "GoogleIAP"
    assert mechanism.security_scheme is not None
    assert mechanism.security_scheme.name == "X-Goog-IAP-JWT-Assertion"
    assert jwks.calls == [(_ISSUER, _JWKS_URI, "iap-key", "ES256", _NOW)]
    assert await mechanism.resolver.resolve(outcome.claims) == Principal(
        id=outcome.claims.subject, display_name=outcome.claims.email, user=outcome.claims.subject
    )
    assert resolver.claims == [outcome.claims]
    assert token not in repr(outcome)


async def test_iap_projects_typed_google_and_external_identity_claims(
    iap_key_material: tuple[bytes, VerificationKey],
) -> None:
    private, key = iap_key_material
    _, mechanism, _, _ = _runtime(key)
    claims = _claims(
        hd="example.com",
        google={"access_levels": ["accessPolicies/1/accessLevels/staff"], "device_id": "device-1"},
        gcip={
            "sub": "external-subject",
            "email": "external@example.com",
            "email_verified": True,
            "sign_in_provider": "google.com",
            "tenant": "tenant-1",
            "sign_in_attributes": {"department": "security"},
        },
    )

    outcome = await mechanism.authenticator.authenticate(
        _token(private, claims=claims), type("Connection", (), {"scope": {"headers": []}})()
    )

    assert isinstance(outcome, Authenticated)
    assert outcome.claims.hosted_domain == "example.com"
    assert outcome.claims.access_levels == ("accessPolicies/1/accessLevels/staff",)
    assert outcome.claims.device_id == "device-1"
    assert outcome.claims.external_identity == GoogleIAPExternalIdentity(
        subject="external-subject",
        email="external@example.com",
        email_verified=True,
        sign_in_provider="google.com",
        tenant="tenant-1",
        sign_in_attributes={"department": "security"},
    )
    assert outcome.claims.subject == "accounts.google.com:subject-1"


async def test_iap_reuses_a_cached_verifier_with_the_shared_worker_limiter(
    iap_key_material: tuple[bytes, VerificationKey],
) -> None:
    private, key = iap_key_material
    jwks = _JWKS(key)
    config = GoogleIAPConfig(
        audience=_AUDIENCE, identity_resolver=_Resolver(), jwks=jwks, worker_limits=WorkerLimits(crypto_tokens=1)
    )
    _, mechanism = config.build(clock=lambda: _NOW)
    authenticator = cast("Any", mechanism.authenticator)
    token = _token(private)

    first = await authenticator.authenticate(token, type("Connection", (), {"scope": {"headers": []}})())
    cached = authenticator._verifiers._entries[("iap-key", "ES256")][1]  # noqa: SLF001 - cache contract
    second = await authenticator.authenticate(token, type("Connection", (), {"scope": {"headers": []}})())

    assert isinstance(first, Authenticated)
    assert isinstance(second, Authenticated)
    assert authenticator._verifiers._entries[("iap-key", "ES256")][1] is cached  # noqa: SLF001 - cache reuse
    assert cached.limiter is config.worker_limits.crypto_limiter


async def test_iap_replaces_same_kid_verifier_when_selected_key_rotates(
    iap_key_material: tuple[bytes, VerificationKey],
) -> None:
    old_private, old_key = iap_key_material
    new_private_key = ec.generate_private_key(ec.SECP256R1())
    new_private = new_private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    new_public = new_private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    new_key = VerificationKey(key_id="iap-key", algorithm="ES256", key=new_public)
    _, mechanism, jwks, _ = _runtime(old_key)

    first = await mechanism.authenticator.authenticate(
        _token(old_private), type("Connection", (), {"scope": {"headers": []}})()
    )
    jwks.outcome = new_key
    second = await mechanism.authenticator.authenticate(
        _token(new_private), type("Connection", (), {"scope": {"headers": []}})()
    )

    assert isinstance(first, Authenticated)
    assert isinstance(second, Authenticated)


async def test_iap_optional_evidence_claims_default_to_none(iap_key_material: tuple[bytes, VerificationKey]) -> None:
    private, key = iap_key_material
    _, mechanism, _, _ = _runtime(key)
    claims = _claims()
    claims.pop("email")
    claims.pop("azp")

    outcome = await mechanism.authenticator.authenticate(
        _token(private, claims=claims), type("Connection", (), {"scope": {"headers": []}})()
    )

    assert isinstance(outcome, Authenticated)
    assert outcome.claims.email is None
    assert outcome.claims.authorized_party is None


@pytest.mark.parametrize("jwks_outcome", [InvalidCredentials(), VerificationUnavailable()])
async def test_iap_preserves_jwks_structured_outcomes(
    iap_key_material: tuple[bytes, VerificationKey], jwks_outcome: object
) -> None:
    private, key = iap_key_material
    _, mechanism, jwks, _ = _runtime(key)
    jwks.outcome = jwks_outcome

    outcome = await mechanism.authenticator.authenticate(
        _token(private), type("Connection", (), {"scope": {"headers": []}})()
    )

    assert outcome == jwks_outcome


@pytest.mark.parametrize(
    "arguments",
    [
        {"audience": ""},
        {"audience": frozenset()},
        {"audience": frozenset({""})},
        {"issuer": "http://not-google"},
        {"header_name": "bad header"},
        {"header_name": 1},
        {"clock_skew": timedelta(microseconds=-1)},
        {"worker_limits": object()},
    ],
)
def test_iap_config_rejects_unsafe_trust_profiles(
    iap_key_material: tuple[bytes, VerificationKey], arguments: dict[str, object]
) -> None:
    values: dict[str, object] = {
        "audience": _AUDIENCE,
        "identity_resolver": _Resolver(),
        "jwks": _JWKS(iap_key_material[1]),
    }
    values.update(arguments)

    with pytest.raises(ImproperlyConfiguredException):
        GoogleIAPConfig(**values)  # type: ignore[arg-type]


def test_iap_build_rejects_non_callable_clock_and_accepts_audience_set(
    iap_key_material: tuple[bytes, VerificationKey],
) -> None:
    config = GoogleIAPConfig(
        audience=frozenset({_AUDIENCE}), identity_resolver=_Resolver(), jwks=_JWKS(iap_key_material[1])
    )

    with pytest.raises(ImproperlyConfiguredException, match="clock"):
        config.build(clock=None)  # type: ignore[arg-type]
