"""Unit tests for authentication outcomes and registry compilation."""

import base64
import json
from collections.abc import Callable, Mapping
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, cast

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
from litestar_security.context import AuthenticationEvidence, AuthorizationSnapshot, CredentialRestrictions, Principal
from litestar_security.providers import jwt as jwt_provider
from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JWTClaims,
    JWTValidationConfig,
    LocalKeyRing,
    PyJWTVerifier,
    SigningKey,
    TokenSigner,
    UnverifiedJWTRoute,
    VerificationKey,
    VerificationKeySet,
    build_access_token_claims,
    parse_unverified_jwt_route,
)

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
_NAIVE_JWT_NOW = datetime(2026, 7, 26)  # noqa: DTZ001 - explicit rejection fixture
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
    ("headers", "expected_type", "expected_value"),
    [
        ([], NoCredentials, None),
        ([(b"authorization", b"Bearer compact.jwt.value")], PresentedCredential, "compact.jwt.value"),
        ([(b"authorization", b"bEaReR compact.jwt.value")], PresentedCredential, "compact.jwt.value"),
        (
            [(b"authorization", b"Bearer one.two.three"), (b"Authorization", b"Bearer four.five.six")],
            InvalidCredentials,
            None,
        ),
        ([(b"authorization", b"")], InvalidCredentials, None),
        ([(b"authorization", b"Basic credential")], InvalidCredentials, None),
        ([(b"authorization", b" Bearer one.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer  one.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer\tone.two.three")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer one.two.three\x7f")], InvalidCredentials, None),
        ([(b"authorization", b"Bearer \xff")], InvalidCredentials, None),
    ],
    ids=[
        "absent",
        "bearer",
        "case-insensitive-scheme",
        "duplicate",
        "empty",
        "wrong-scheme",
        "leading-space",
        "double-space",
        "tab",
        "control",
        "non-ascii",
    ],
)
def test_composite_bearer_extracts_the_raw_authorization_namespace_once(
    headers: list[tuple[bytes, bytes]],
    expected_type: type[NoCredentials] | type[PresentedCredential[object]] | type[InvalidCredentials],
    expected_value: str | None,
) -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    )
    physical_slot, _ = composite.build(_Resolver())

    extraction = physical_slot.extract(SimpleNamespace(scope={"headers": headers}))  # type: ignore[arg-type]

    assert isinstance(extraction, expected_type)
    assert getattr(extraction, "value", None) == expected_value


def test_composite_bearer_rejects_oversized_credentials_during_extraction() -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
        maximum_token_bytes=5,
    )
    physical_slot, _ = composite.build(_Resolver())

    extraction = physical_slot.extract(
        SimpleNamespace(scope={"headers": [(b"authorization", b"Bearer longer")]})  # type: ignore[arg-type]
    )

    assert extraction == InvalidCredentials()


def _routing_token(*, issuer: str, audiences: str | list[str], token_type: str | None = None) -> str:
    return _compact_jwt(
        json.dumps({"alg": "RS256", "kid": "shared", "typ": token_type or "at+jwt"}, separators=(",", ":")).encode(),
        json.dumps({"iss": issuer, "aud": audiences}, separators=(",", ":")).encode(),
    )


@pytest.mark.parametrize(
    ("issuer", "audience", "selected_name"),
    [("https://local.example", "local-api", "local"), ("https://oidc.example", "oidc-api", "oidc")],
)
@pytest.mark.anyio
async def test_composite_bearer_selects_exactly_one_trust_slot(issuer: str, audience: str, selected_name: str) -> None:
    grants = AuthorizationSnapshot(
        scopes=frozenset({"reports:read"}),
        roles=frozenset({"analyst"}),
        capabilities=frozenset({"reports"}),
        team_roles={"team-1": frozenset({"viewer"})},
        tenant_ids=frozenset({"tenant-1"}),
        attributes={"region": "north"},
    )
    restrictions = CredentialRestrictions(
        scopes=frozenset({"reports:read"}), roles=frozenset({"analyst"}), tenant_ids=frozenset({"tenant-1"})
    )
    authenticated = Authenticated(
        claims="user-1",
        evidence=AuthenticationEvidence(
            mechanism="provider",
            slot="provider-slot",
            authenticated_at=_JWT_NOW,
            expires_at=_JWT_NOW + timedelta(1),
            methods=frozenset({"jwt"}),
            traits=frozenset({"phishing-resistant"}),
            acr="urn:example:acr:2",
            amr=("pwd", "otp"),
        ),
        grants=grants,
        restrictions=restrictions,
    )
    local = _recording_jwt_verifier(authenticated, issuer="https://local.example", audiences=frozenset({"local-api"}))
    oidc = _recording_jwt_verifier(authenticated, issuer="https://oidc.example", audiences=frozenset({"oidc-api"}))
    token = _routing_token(issuer=issuer, audiences=audience)
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(
                    issuers=frozenset({"https://local.example"}), audiences=frozenset({"local-api"})
                ),
                verifier=local,  # type: ignore[arg-type]
            ),
            BearerTokenSlot(
                name="oidc",
                selector=BearerSlotSelector(
                    issuers=frozenset({"https://oidc.example"}), audiences=frozenset({"oidc-api"})
                ),
                verifier=oidc,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

    assert isinstance(outcome, Authenticated)
    assert outcome.evidence.mechanism == "bearer"
    assert outcome.evidence.slot == selected_name
    assert outcome.evidence == AuthenticationEvidence(
        mechanism="bearer",
        slot=selected_name,
        authenticated_at=_JWT_NOW,
        expires_at=_JWT_NOW + timedelta(1),
        methods=frozenset({"jwt"}),
        traits=frozenset({"phishing-resistant"}),
        acr="urn:example:acr:2",
        amr=("pwd", "otp"),
    )
    assert outcome.grants == grants
    assert outcome.restrictions == restrictions
    assert len(local.calls) + len(oidc.calls) == 1
    assert (local.calls if selected_name == "local" else oidc.calls) == [(token, _JWT_NOW)]


@pytest.mark.anyio
async def test_composite_bearer_cryptographically_isolates_same_kid_trust_domains(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    local_signing_key, local_verification_key = jwt_key_material["RS256"]
    oidc_signing_key, oidc_verification_key = jwt_key_material["RS256_ALT"]
    profiles = (
        ("local", "https://local.example", "local-api", local_signing_key, local_verification_key),
        ("oidc", "https://oidc.example", "oidc-api", oidc_signing_key, oidc_verification_key),
    )
    slots = tuple(
        BearerTokenSlot(
            name=name,
            selector=BearerSlotSelector(issuers=frozenset({issuer}), audiences=frozenset({audience})),
            verifier=PyJWTVerifier(
                config=JWTValidationConfig(
                    issuer=issuer, audiences=frozenset({audience}), algorithms=frozenset({"RS256"})
                ),
                key=verification_key,
                require_key_id=True,
            ),
        )
        for name, issuer, audience, _signing_key, verification_key in profiles
    )
    _, mechanism_value = CompositeBearerConfig(mechanism_name="bearer", slots=slots).build(
        _Resolver(), clock=lambda: _JWT_NOW
    )

    for name, issuer, audience, signing_key, _verification_key in profiles:
        token = _encode_jwt(signing_key, "RS256", claims=_jwt_claims(iss=issuer, aud=audience))
        outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

        assert isinstance(outcome, Authenticated)
        assert outcome.claims.issuer == issuer
        assert outcome.evidence.slot == name

    cross_domain_token = _encode_jwt(
        local_signing_key, "RS256", claims=_jwt_claims(iss="https://oidc.example", aud="oidc-api")
    )
    cross_domain_outcome = await mechanism_value.authenticator.authenticate(
        cross_domain_token,
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert cross_domain_outcome == InvalidCredentials()


@pytest.mark.parametrize(
    ("selectors", "audiences"),
    [
        (
            (
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"one", "two"})),
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"one"})),
            ),
            "one",
        ),
        (
            (
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"one"})),
                BearerSlotSelector(issuers=frozenset({"https://issuer.example"}), audiences=frozenset({"two"})),
            ),
            ["one", "two"],
        ),
        (
            (
                BearerSlotSelector(issuers=frozenset({"https://one.example"})),
                BearerSlotSelector(issuers=frozenset({"https://other.example"})),
            ),
            "unknown",
        ),
    ],
    ids=["overlapping-audience-ambiguity", "multi-audience-ambiguity", "unknown"],
)
@pytest.mark.anyio
async def test_composite_bearer_rejects_unknown_or_ambiguous_routes_without_verification(
    selectors: tuple[BearerSlotSelector, BearerSlotSelector], audiences: str | list[str]
) -> None:
    verifiers = tuple(
        _recording_jwt_verifier(
            InvalidCredentials(),
            issuer=next(iter(selector.issuers)),
            audiences=selector.audiences
            or (frozenset({audiences}) if isinstance(audiences, str) else frozenset(audiences)),
        )
        for selector in selectors
    )
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=tuple(
            BearerTokenSlot(name=f"slot-{index}", selector=selector, verifier=verifiers[index])  # type: ignore[arg-type]
            for index, selector in enumerate(selectors)
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate(
        _routing_token(issuer="https://issuer.example", audiences=audiences),
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert outcome == InvalidCredentials(code="unknown_or_ambiguous_bearer_slot")
    assert not verifiers[0].calls
    assert not verifiers[1].calls


@pytest.mark.parametrize(
    ("verifier_outcome", "expected"),
    [
        (InvalidCredentials(code="provider_invalid"), InvalidCredentials(code="provider_invalid")),
        (
            VerificationUnavailable(code="provider_unavailable", retry_after=2),
            VerificationUnavailable(code="provider_unavailable", retry_after=2),
        ),
        (NoCredentials(), InvalidCredentials()),
    ],
    ids=["invalid", "unavailable", "unexpected-no-credentials"],
)
@pytest.mark.anyio
async def test_composite_bearer_preserves_selected_terminal_outcomes(
    verifier_outcome: InvalidCredentials | VerificationUnavailable | NoCredentials,
    expected: InvalidCredentials | VerificationUnavailable,
) -> None:
    verifier = _recording_jwt_verifier(verifier_outcome)
    token = _routing_token(issuer=_JWT_ISSUER, audiences=_JWT_AUDIENCE)
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

    assert outcome == expected
    assert verifier.calls == [(token, _JWT_NOW)]


@pytest.mark.anyio
async def test_composite_bearer_rejects_malformed_routes_before_verification() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)

    outcome = await mechanism_value.authenticator.authenticate("malformed", SimpleNamespace())  # type: ignore[arg-type]

    assert outcome == InvalidCredentials()
    assert not verifier.calls


@pytest.mark.anyio
async def test_composite_bearer_uses_an_aware_utc_clock_by_default() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    _, mechanism_value = composite.build(_Resolver())

    await mechanism_value.authenticator.authenticate(
        _routing_token(issuer=_JWT_ISSUER, audiences=_JWT_AUDIENCE),
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert verifier.calls[0][1].tzinfo is timezone.utc


def test_composite_bearer_builds_one_native_registry_mechanism() -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    )

    physical_slot, mechanism_value = composite.build(_Resolver())
    registry = AuthenticationRegistry(slots=(physical_slot,), mechanisms=(mechanism_value,))  # type: ignore[arg-type]

    assert registry.slot_names == ("authorization.bearer",)
    assert registry.mechanism_names == ("bearer",)
    assert mechanism_value.scheme_name == "bearer"
    assert mechanism_value.security_scheme == SecurityScheme(type="http", scheme="bearer", bearer_format="JWT")


@pytest.mark.anyio
async def test_composite_bearer_never_retains_or_represents_the_raw_token() -> None:
    verifier = _recording_jwt_verifier(InvalidCredentials())
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=verifier,  # type: ignore[arg-type]
            ),
        ),
    )
    physical_slot, mechanism_value = composite.build(_Resolver(), clock=lambda: _JWT_NOW)
    token = _routing_token(issuer=_JWT_ISSUER, audiences=_JWT_AUDIENCE)
    extraction = physical_slot.extract(
        SimpleNamespace(scope={"headers": [(b"authorization", f"Bearer {token}".encode())]})  # type: ignore[arg-type]
    )
    outcome = await mechanism_value.authenticator.authenticate(token, SimpleNamespace())  # type: ignore[arg-type]

    assert isinstance(extraction, PresentedCredential)
    assert outcome == InvalidCredentials()
    assert all(
        token not in repr(value)
        for value in (composite, physical_slot, mechanism_value, mechanism_value.authenticator, extraction, outcome)
    )


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: BearerSlotSelector(issuers=frozenset()), "issuer"),
        (lambda: BearerSlotSelector(issuers=frozenset({_JWT_ISSUER}), token_types=frozenset()), "token types"),
        (lambda: CompositeBearerConfig(mechanism_name="bearer", slots=()), "at least one"),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=(
                    BearerTokenSlot(
                        name="duplicate",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    ),
                    BearerTokenSlot(
                        name="duplicate",
                        selector=BearerSlotSelector(issuers=frozenset({"https://other.example"})),
                        verifier=_recording_jwt_verifier(InvalidCredentials(), issuer="https://other.example"),  # type: ignore[arg-type]
                    ),
                ),
            ),
            "Duplicate bearer slot",
        ),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=tuple(
                    BearerTokenSlot(
                        name=f"slot-{index}",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    )
                    for index in range(2)
                ),
            ),
            "identical selector",
        ),
        (
            lambda: CompositeBearerConfig(
                mechanism_name="bearer",
                slots=(
                    BearerTokenSlot(
                        name="local",
                        selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                        verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
                    ),
                ),
                maximum_token_bytes=0,
            ),
            "maximum token bytes",
        ),
        (
            lambda: BearerTokenSlot(
                name="missing-config",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=cast("Any", SimpleNamespace()),
            ),
            "must expose JWTValidationConfig",
        ),
        (
            lambda: BearerTokenSlot(
                name="issuer-mismatch",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials(), issuer="https://other.example"),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
        (
            lambda: BearerTokenSlot(
                name="audience-mismatch",
                selector=BearerSlotSelector(
                    issuers=frozenset({_JWT_ISSUER}), audiences=frozenset({"another-audience"})
                ),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
        (
            lambda: BearerTokenSlot(
                name="type-mismatch",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER}), token_types=frozenset({"id+jwt"})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
            "does not match verifier",
        ),
    ],
)
def test_composite_bearer_configuration_rejects_ambiguous_or_unsafe_values(
    factory: Callable[[], object], match: str
) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        factory()


def test_composite_bearer_requires_a_callable_clock() -> None:
    composite = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    )

    with pytest.raises(ImproperlyConfiguredException, match="clock must be callable"):
        composite.build(_Resolver(), clock=None)  # type: ignore[arg-type]


@pytest.mark.parametrize("algorithm", ["EdDSA", "ES256", "RS256", "HS256"])
@pytest.mark.anyio
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


@pytest.mark.anyio
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
        ({"scopes": frozenset({" "})}, "identifier"),
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


@pytest.mark.anyio
async def test_local_signer_runs_crypto_in_a_worker_and_supports_custom_signers(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []

    async def run_sync(function: Callable[[], object], **kwargs: object) -> object:
        calls.append(kwargs)
        return function()

    monkeypatch.setattr(jwt_provider.to_thread, "run_sync", run_sync)
    ring = LocalKeyRing(
        issuer=_JWT_ISSUER,
        active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=jwt_key_material["EdDSA"][0]),
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
    assert calls == [{"abandon_on_cancel": True, "limiter": None}]
    assert isinstance(custom_signer, TokenSigner)
    assert isinstance(
        await custom_keys.build_verifier(_jwt_config("EdDSA")).verify(custom_token, now=_JWT_NOW), Authenticated
    )

    async def unavailable(_function: Callable[[], object], **_kwargs: object) -> object:
        message = "private failure detail"
        raise OSError(message)

    monkeypatch.setattr(jwt_provider.to_thread, "run_sync", unavailable)
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
@pytest.mark.anyio
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
