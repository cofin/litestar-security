"""Integration contracts for the published RFC 9728 metadata document."""

import json
from datetime import datetime, timezone
from typing import Any, cast

import pytest
from litestar import Litestar, get
from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi.spec import SecurityScheme
from litestar.status_codes import HTTP_200_OK, HTTP_304_NOT_MODIFIED, HTTP_401_UNAUTHORIZED
from litestar.testing import create_test_client

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security.authentication import (
    Authenticated,
    AuthenticationEvidence,
    AuthenticationMechanism,
    NoCredentials,
    PresentedCredential,
)
from litestar_security.context import Principal
from litestar_security.providers.oauth import ProtectedResourceConfig, build_protected_resource_handler

METADATA_PATH = "/.well-known/oauth-protected-resource"


class _HeaderSlot:
    name = "slot-api-key"

    def extract(self, connection: Any) -> object:
        value = cast("str | None", connection.headers.get("x-api-key"))
        if value is None:
            return NoCredentials()
        return PresentedCredential("user")


class _HeaderAuthenticator:
    participates_by_default = True
    name = "api-key"
    slot = "slot-api-key"

    async def authenticate(self, credential: object, _connection: object) -> Authenticated[str]:
        return Authenticated(
            claims=cast("str", credential),
            evidence=AuthenticationEvidence(
                mechanism=self.name, slot=self.slot, authenticated_at=datetime(2026, 8, 4, tzinfo=timezone.utc)
            ),
        )


class _HeaderResolver:
    async def resolve(self, claims: str) -> Principal[object]:
        return Principal(id=claims)


def _app_config(**kwargs: object) -> SecurityConfig[object]:
    return SecurityConfig(protected_resource=ProtectedResourceConfig(**kwargs))  # type: ignore[arg-type]


def test_metadata_is_served_at_the_well_known_path() -> None:
    config = _app_config(
        resource="https://api.example.com",
        authorization_servers=("https://issuer.example.com",),
        scopes_supported=("read", "write"),
        resource_documentation="https://docs.example.com",
    )

    with create_test_client([], plugins=[SecurityPlugin(config)]) as client:
        response = client.get(METADATA_PATH)

    assert response.status_code == HTTP_200_OK
    assert response.json() == {
        "authorization_servers": ["https://issuer.example.com"],
        "bearer_methods_supported": ["header"],
        "resource": "https://api.example.com",
        "resource_documentation": "https://docs.example.com",
        "scopes_supported": ["read", "write"],
    }


def test_rfc9728_member_names_are_specification_defined_and_must_not_be_renamed() -> None:
    """Lock the wire member names of the RFC 9728 metadata document.

    These names are defined by RFC 9728 section 2 and are read by authorization
    servers and clients that never see this codebase. They are **not** an
    application casing preference and must never be routed through a
    rename strategy, a DTO, or any other field-naming policy.

    If a change makes this test fail, the change is wrong. Do not update the
    expected names to match it, and do not delete this test.
    """
    config = _app_config(
        resource="https://api.example.com",
        authorization_servers=("https://issuer.example.com",),
        scopes_supported=("read",),
        resource_documentation="https://docs.example.com",
    )
    plugin = SecurityPlugin(config)

    with create_test_client([], plugins=[plugin]) as client:
        response = client.get(METADATA_PATH)
        handler = client.app.route_handler_method_map[METADATA_PATH]["GET"]

    assert sorted(json.loads(response.content)) == [
        "authorization_servers",
        "bearer_methods_supported",
        "resource",
        "resource_documentation",
        "scopes_supported",
    ]
    # No DTO may sit between the precomputed document and the wire.
    assert handler.resolve_data_dto() is None
    assert handler.resolve_return_dto() is None


def test_absent_optional_members_are_omitted() -> None:
    config = _app_config(resource="https://api.example.com", bearer_methods_supported=())

    with create_test_client([], plugins=[SecurityPlugin(config)]) as client:
        response = client.get(METADATA_PATH)

    assert response.json() == {"resource": "https://api.example.com"}


def test_metadata_path_follows_the_resource_path_component() -> None:
    config = _app_config(resource="https://api.example.com/mcp")

    with create_test_client([], plugins=[SecurityPlugin(config)]) as client:
        response = client.get(f"{METADATA_PATH}/mcp")

    assert response.status_code == HTTP_200_OK
    assert response.json()["resource"] == "https://api.example.com/mcp"


def test_route_prefix_mounts_the_document_under_a_path() -> None:
    config = _app_config(resource="https://api.example.com", route_prefix="/api")

    with create_test_client([], plugins=[SecurityPlugin(config)]) as client:
        response = client.get(f"/api{METADATA_PATH}")

    assert response.status_code == HTTP_200_OK


@pytest.mark.parametrize(
    "resource",
    [
        "https://api.example.com/{tenant}",
        "https://api.example.com/a b",
        "https://api.example.com/a//b",
        "https://api.example.com/../etc",
        "https://api.example.com/a\\b",
    ],
)
def test_resource_paths_that_cannot_be_mounted_are_rejected(resource: str) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(resource=resource)


def test_document_is_public_even_when_the_application_requires_authentication() -> None:
    @get("/private")
    async def private() -> str:  # pragma: no cover - the request never reaches the handler
        return "private"

    config = SecurityConfig[object](
        slots=(_HeaderSlot(),),  # type: ignore[arg-type]
        mechanisms=(
            AuthenticationMechanism(
                authenticator=_HeaderAuthenticator(),  # type: ignore[arg-type]
                resolver=_HeaderResolver(),
                scheme_name="api-key",
                security_scheme=SecurityScheme(type="http", scheme="bearer"),
            ),
        ),
        require_default=True,
        protected_resource=ProtectedResourceConfig(resource="https://api.example.com"),
    )

    with create_test_client([private], plugins=[SecurityPlugin(config)]) as client:
        assert client.get("/private").status_code == HTTP_401_UNAUTHORIZED
        assert client.get(METADATA_PATH).status_code == HTTP_200_OK


def test_conditional_requests_answer_not_modified() -> None:
    config = _app_config(resource="https://api.example.com")

    with create_test_client([], plugins=[SecurityPlugin(config)]) as client:
        first = client.get(METADATA_PATH)
        etag = first.headers["etag"]
        conditional = client.get(METADATA_PATH, headers={"If-None-Match": etag})
        wildcard = client.get(METADATA_PATH, headers={"If-None-Match": "*"})
        weak = client.get(METADATA_PATH, headers={"If-None-Match": f"W/{etag}"})
        other = client.get(METADATA_PATH, headers={"If-None-Match": '"other"'})

    assert first.headers["cache-control"] == "public, max-age=300"
    assert first.headers["content-type"].startswith("application/json")
    assert conditional.status_code == HTTP_304_NOT_MODIFIED
    assert wildcard.status_code == HTTP_304_NOT_MODIFIED
    assert weak.status_code == HTTP_304_NOT_MODIFIED
    assert other.status_code == HTTP_200_OK


def test_cache_max_age_is_configurable() -> None:
    config = _app_config(resource="https://api.example.com", cache_max_age=0)

    with create_test_client([], plugins=[SecurityPlugin(config)]) as client:
        response = client.get(METADATA_PATH)

    assert response.headers["cache-control"] == "public, max-age=0"


@pytest.mark.parametrize("cache_max_age", [-1, 86_401, True, "300"])
def test_cache_max_age_is_bounded(cache_max_age: object) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(resource="https://api.example.com", cache_max_age=cache_max_age)  # type: ignore[arg-type]


def test_etag_is_stable_across_equal_configurations() -> None:
    first = ProtectedResourceConfig(resource="https://api.example.com", scopes_supported=("read",))
    second = ProtectedResourceConfig(resource="https://api.example.com", scopes_supported=("read",))
    different = ProtectedResourceConfig(resource="https://api.example.com", scopes_supported=("write",))

    assert first.etag == second.etag
    assert first.etag != different.etag


def test_handler_can_be_mounted_without_the_plugin() -> None:
    config = ProtectedResourceConfig(resource="https://api.example.com")
    app = Litestar([build_protected_resource_handler(config)])

    with create_test_client([], plugins=[]) as _client:
        pass

    assert config.path in {route.path for route in app.routes}


def test_no_document_is_registered_when_the_feature_is_unconfigured() -> None:
    with create_test_client([], plugins=[SecurityPlugin(SecurityConfig[object]())]) as client:
        assert client.get(METADATA_PATH).status_code != HTTP_200_OK
