"""Unit tests for pure OpenAPI configuration projection."""

from types import MappingProxyType

import pytest
from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi.config import OpenAPIConfig
from litestar.openapi.spec import Components, SecurityScheme, Tag

from litestar_security._openapi import OpenAPISchemeSet, merge_openapi_tags, prepare_openapi_config
from litestar_security.authentication import (
    AuthenticationMechanism,
    AuthenticationRegistry,
    MechanismRequirement,
    NoCredentials,
    SecurityRuntimePlan,
)
from litestar_security.context import Principal


def _scheme_set(*, scheme: SecurityScheme | None = None) -> OpenAPISchemeSet:
    scheme = scheme or SecurityScheme(type="http", scheme="bearer")
    return OpenAPISchemeSet(
        by_mechanism=MappingProxyType({"token": ("Token", scheme)}), unique_schemes=MappingProxyType({"Token": scheme})
    )


def test_openapi_scheme_projection_preserves_public_optional_and_required_shapes() -> None:
    schemes = _scheme_set()

    assert schemes.project(SecurityRuntimePlan(authenticate=False)) == [{}]
    required = SecurityRuntimePlan(
        authenticate=True, required=True, alternatives=((MechanismRequirement(name="token"),),)
    )
    optional = SecurityRuntimePlan(authenticate=True, alternatives=required.alternatives, allow_anonymous=True)
    assert schemes.project(required) == [{"Token": []}]
    assert schemes.project(optional) == [{}, {"Token": []}]


def test_openapi_scheme_projection_rejects_scopes_for_non_oauth_scheme() -> None:
    plan = SecurityRuntimePlan(
        authenticate=True,
        required=True,
        alternatives=((MechanismRequirement(name="token", scopes=frozenset({"read"})),),),
    )

    with pytest.raises(ImproperlyConfiguredException, match="does not support OAuth or OIDC scopes"):
        _scheme_set().project(plan)


def test_prepare_openapi_config_adds_only_missing_compatible_schemes() -> None:
    config = OpenAPIConfig(title="Example", version="1.0")
    prepared = prepare_openapi_config(config, _scheme_set())

    assert prepared is not config
    assert prepared.components[-1].security_schemes == {"Token": SecurityScheme(type="http", scheme="bearer")}
    assert prepare_openapi_config(prepared, _scheme_set()) is prepared


def test_prepare_openapi_config_rejects_conflicting_scheme() -> None:
    config = OpenAPIConfig(
        title="Example",
        version="1.0",
        components=[
            Components(
                security_schemes={"Token": SecurityScheme(type="apiKey", name="token", security_scheme_in="header")}
            )
        ],
    )

    with pytest.raises(ImproperlyConfiguredException, match="Conflicting native OpenAPI security scheme"):
        prepare_openapi_config(config, _scheme_set())


def test_merge_openapi_tags_preserves_declared_tags_and_stably_deduplicates() -> None:
    owned = Tag(name="accounts", description="Application wording")
    config = OpenAPIConfig(title="Example", version="1.0", tags=[owned])

    merged = merge_openapi_tags(
        config,
        [Tag(name="accounts", description="Generated wording"), Tag(name="security", description="Security routes")],
    )

    assert merged.tags == [owned, Tag(name="security", description="Security routes")]
    assert merge_openapi_tags(merged, [Tag(name="accounts"), Tag(name="security")]) is merged


class _OpenAPISlot:
    def __init__(self, name: str) -> None:
        self.name = name

    def extract(self, _connection: object) -> NoCredentials:
        return NoCredentials()


class _OpenAPIAuthenticator:
    def __init__(self, name: str, slot: str) -> None:
        self.name = name
        self.slot = slot
        self.participates_by_default = True

    async def authenticate(self, _credential: str, _connection: object) -> NoCredentials:
        return NoCredentials()


class _OpenAPIResolver:
    async def resolve(self, claims: str) -> Principal[object]:
        return Principal(id=claims)


def test_openapi_scheme_set_projects_additional_security_schemes_and_rejects_conflicts() -> None:
    header_scheme = SecurityScheme(type="apiKey", name="X-API-Key", security_scheme_in="header")
    bearer_scheme = SecurityScheme(type="http", scheme="bearer", bearer_format="lsk_<key_id>_<secret>")
    api_key_mechanism = AuthenticationMechanism(
        authenticator=_OpenAPIAuthenticator("api-key", "api-key"),  # type: ignore[arg-type]
        resolver=_OpenAPIResolver(),
        scheme_name="APIKey",
        security_scheme=header_scheme,
        additional_security_schemes={"APIKeyBearer": bearer_scheme},
    )
    registry = AuthenticationRegistry(slots=(_OpenAPISlot("api-key"),), mechanisms=(api_key_mechanism,))  # type: ignore[arg-type]
    schemes = OpenAPISchemeSet.from_registry(registry)

    assert schemes.unique_schemes == {"APIKey": header_scheme, "APIKeyBearer": bearer_scheme}
    required_plan = SecurityRuntimePlan(
        authenticate=True, required=True, alternatives=((MechanismRequirement(name="api-key"),),)
    )
    optional_plan = SecurityRuntimePlan(
        authenticate=True, alternatives=required_plan.alternatives, allow_anonymous=True
    )
    assert schemes.project(required_plan) == [{"APIKey": []}, {"APIKeyBearer": []}]
    assert schemes.project(optional_plan) == [{}, {"APIKey": []}, {"APIKeyBearer": []}]

    conflicting_mechanism = AuthenticationMechanism(
        authenticator=_OpenAPIAuthenticator("bearer", "bearer"),  # type: ignore[arg-type]
        resolver=_OpenAPIResolver(),
        scheme_name="APIKeyBearer",
        security_scheme=SecurityScheme(type="http", scheme="bearer", bearer_format="JWT"),
    )
    conflicting_registry = AuthenticationRegistry(
        slots=(_OpenAPISlot("api-key"), _OpenAPISlot("bearer")),
        mechanisms=(api_key_mechanism, conflicting_mechanism),  # type: ignore[arg-type]
    )
    with pytest.raises(ImproperlyConfiguredException, match="Conflicting native OpenAPI security scheme: APIKeyBearer"):
        OpenAPISchemeSet.from_registry(conflicting_registry)
