"""Unit tests for authentication outcomes and registry compilation."""

from collections.abc import Callable
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from typing import Any, cast

import pytest
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
)
from litestar_security.config import ExternalCSRF, SecurityConfig
from litestar_security.context import AuthenticationEvidence, Principal
from litestar_security.providers.api_key import APIKeyConfig
from litestar_security.providers.jwt import (
    BearerSlotSelector,
    BearerTokenSlot,
    CompositeBearerConfig,
    JWTValidationConfig,
)
from tests.fixtures.collaborators import build_api_key_store

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
_JWT_ISSUER = "https://issuer.example"
_JWT_AUDIENCE = "litestar-security"


class _Slot:
    def __init__(self, name: str) -> None:
        self.name = name

    def extract(self, _connection: object) -> NoCredentials:
        return NoCredentials()


class _CustomBearerSlot:
    name = "authorization.bearer"

    def extract(self, connection: Any) -> NoCredentials | InvalidCredentials | PresentedCredential[str]:
        values = [value for header, value in connection.scope["headers"] if header.lower() == b"authorization"]
        if not values:
            return NoCredentials()
        if len(values) != 1 or not values[0].isascii():
            return InvalidCredentials()
        scheme, separator, token = values[0].decode("ascii").partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token or " " in token:
            return InvalidCredentials()
        return PresentedCredential(token)


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
        (lambda: optional(object()), "policy helper"),  # type: ignore[arg-type]
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


def test_required_without_arguments_is_the_implicit_secure_policy() -> None:
    config = SecurityConfig()

    assert not hasattr(config, "default_policy")
    assert not hasattr(config, "openapi_policy")
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
    with pytest.raises(ImproperlyConfiguredException, match="name must be text"):
        ExternalCSRF(name=cast("Any", object()), validate=lambda _path, _method, _policy: True)
    with pytest.raises(ImproperlyConfiguredException, match="hook must be callable"):
        ExternalCSRF(name="edge", validate=cast("Any", object()))

    async def validate(_path: str, _method: str, _policy: AuthenticationPolicy) -> bool:
        return True

    with pytest.raises(ImproperlyConfiguredException, match="hook must be synchronous"):
        ExternalCSRF(name="edge", validate=cast("Any", validate))


@pytest.mark.parametrize("limit", [0, -1])
def test_security_config_requires_positive_openapi_combination_limit(limit: int) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=r"max_openapi_combinations.*positive"):
        SecurityConfig(max_openapi_combinations=limit)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        (
            {"additional_security_schemes": {"APIKeyBearer": SecurityScheme(type="http", scheme="bearer")}},
            "configured together",
        ),
        (
            {
                "scheme_name": "APIKey",
                "security_scheme": SecurityScheme(type="apiKey", name="X-API-Key", security_scheme_in="header"),
                "additional_security_schemes": {" ": SecurityScheme(type="http", scheme="bearer")},
            },
            "must not be blank",
        ),
        (
            {
                "scheme_name": "APIKey",
                "security_scheme": SecurityScheme(type="apiKey", name="X-API-Key", security_scheme_in="header"),
                "additional_security_schemes": {"APIKey": SecurityScheme(type="http", scheme="bearer")},
            },
            "Duplicate OpenAPI security scheme name",
        ),
        (
            {
                "scheme_name": "APIKey",
                "security_scheme": SecurityScheme(type="apiKey", name="X-API-Key", security_scheme_in="header"),
                "additional_security_schemes": {"APIKeyBearer": cast("Any", object())},
            },
            "must be a SecurityScheme",
        ),
    ],
)
def test_authentication_mechanism_validates_additional_security_schemes(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        AuthenticationMechanism(
            authenticator=_Authenticator("a", "slot-a"),  # type: ignore[arg-type]
            resolver=_Resolver(),
            **kwargs,  # type: ignore[arg-type]
        )


def test_registry_coordinates_api_key_bearer_prefix_with_composite_bearer_slot() -> None:
    api_key_slot, api_key_mechanism, _ = APIKeyConfig(
        store=build_api_key_store(), pepper=b"p" * 32, accept_authorization_bearer=True
    ).build(_Resolver(), clock=lambda: _JWT_NOW)
    bearer_slot, bearer_mechanism = CompositeBearerConfig(
        mechanism_name="bearer",
        slots=(
            BearerTokenSlot(
                name="local",
                selector=BearerSlotSelector(issuers=frozenset({_JWT_ISSUER})),
                verifier=_recording_jwt_verifier(InvalidCredentials()),  # type: ignore[arg-type]
            ),
        ),
    ).build(_Resolver(), clock=lambda: _JWT_NOW)

    registry = AuthenticationRegistry(
        slots=(api_key_slot, bearer_slot),
        mechanisms=(api_key_mechanism, bearer_mechanism),  # type: ignore[arg-type]
    )

    compiled_api_key_slot = registry.get_slot("api-key")
    compiled_bearer_slot = registry.get_slot("authorization.bearer")
    assert getattr(compiled_api_key_slot, "coexists_with_bearer_slot", False) is True
    assert getattr(compiled_bearer_slot, "excluded_prefixes", ()) == ("lsk_",)
    assert (
        compiled_bearer_slot.extract(
            type("Connection", (), {"scope": {"headers": [(b"authorization", b"Bearer lsk_key_secret")]}})()
        )
        == NoCredentials()
    )
    assert compiled_bearer_slot.extract(
        type("Connection", (), {"scope": {"headers": [(b"authorization", b"Bearer compact.jwt.token")]}})()
    ) == PresentedCredential("compact.jwt.token")


def test_registry_coordinates_api_key_bearer_prefix_with_custom_bearer_slot() -> None:
    api_key_slot, api_key_mechanism, _ = APIKeyConfig(
        store=build_api_key_store(), pepper=b"p" * 32, accept_authorization_bearer=True
    ).build(_Resolver(), clock=lambda: _JWT_NOW)
    custom_bearer_mechanism = AuthenticationMechanism(
        authenticator=_Authenticator("custom-bearer", "authorization.bearer"),  # type: ignore[arg-type]
        resolver=_Resolver(),
    )

    registry = AuthenticationRegistry(
        slots=(api_key_slot, _CustomBearerSlot()),  # type: ignore[arg-type]
        mechanisms=(api_key_mechanism, custom_bearer_mechanism),  # type: ignore[arg-type]
    )

    compiled_api_key_slot = registry.get_slot("api-key")
    compiled_bearer_slot = registry.get_slot("authorization.bearer")
    assert getattr(compiled_api_key_slot, "coexists_with_bearer_slot", False) is True
    assert compiled_bearer_slot.name == "authorization.bearer"
    assert (
        compiled_bearer_slot.extract(
            type("Connection", (), {"scope": {"headers": [(b"authorization", b"Bearer lsk_key_secret")]}})()
        )
        == NoCredentials()
    )
    assert compiled_bearer_slot.extract(
        type("Connection", (), {"scope": {"headers": [(b"authorization", b"Bearer custom-token")]}})()
    ) == PresentedCredential("custom-token")
    assert compiled_bearer_slot.extract(type("Connection", (), {"scope": {"headers": []}})()) == NoCredentials()
    assert isinstance(
        compiled_bearer_slot.extract(
            type("Connection", (), {"scope": {"headers": [(b"authorization", b"Bearer lsk_bad extra")]}})()
        ),
        InvalidCredentials,
    )
