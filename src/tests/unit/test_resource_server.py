"""Unit contracts for the RFC 9728 protected-resource configuration."""

import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security import SecurityConfig
from litestar_security.providers.oauth import ProtectedResourceConfig


def test_defaults_advertise_only_the_bearer_header_method() -> None:
    config = ProtectedResourceConfig(resource="https://api.example.com")

    assert config.resource == "https://api.example.com"
    assert config.authorization_servers == ()
    assert config.scopes_supported == ()
    assert config.bearer_methods_supported == ("header",)
    assert config.resource_documentation is None
    assert config.route_prefix == ""


def test_sequences_freeze_to_tuples() -> None:
    config = ProtectedResourceConfig(
        resource="https://api.example.com",
        authorization_servers=["https://issuer.example.com"],
        scopes_supported=["read", "write"],
        bearer_methods_supported=["header", "body"],
    )

    assert config.authorization_servers == ("https://issuer.example.com",)
    assert config.scopes_supported == ("read", "write")
    assert config.bearer_methods_supported == ("header", "body")


@pytest.mark.parametrize(
    "resource",
    [
        "",
        "   ",
        "/mcp",
        "api.example.com",
        "https:///mcp",
        "https://api.example.com/mcp#section",
        "https://api.example.com/mcp?tenant=1",
        " https://api.example.com",
    ],
)
def test_resource_must_be_an_absolute_uri(resource: str) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(resource=resource)


def test_resource_must_be_text() -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(resource=object())  # type: ignore[arg-type]


@pytest.mark.parametrize("authorization_server", ["", "not-a-uri", "https://issuer.example.com#f"])
def test_authorization_servers_must_be_absolute_uris(authorization_server: str) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(resource="https://api.example.com", authorization_servers=(authorization_server,))


def test_authorization_servers_reject_duplicates() -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(
            resource="https://api.example.com",
            authorization_servers=("https://issuer.example.com", "https://issuer.example.com"),
        )


@pytest.mark.parametrize("scope", ["", "read write", 'read"', "read\\"])
def test_scopes_must_be_single_scope_tokens(scope: str) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(resource="https://api.example.com", scopes_supported=(scope,))


def test_scopes_reject_duplicates() -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(resource="https://api.example.com", scopes_supported=("read", "read"))


@pytest.mark.parametrize("method", ["Header", "cookie", "", "header body"])
def test_bearer_methods_are_restricted_to_the_registered_values(method: str) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(resource="https://api.example.com", bearer_methods_supported=(method,))


def test_bearer_methods_reject_duplicates() -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(resource="https://api.example.com", bearer_methods_supported=("header", "header"))


def test_bearer_methods_may_be_empty() -> None:
    config = ProtectedResourceConfig(resource="https://api.example.com", bearer_methods_supported=())

    assert config.bearer_methods_supported == ()


def test_resource_documentation_must_be_an_absolute_uri() -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(resource="https://api.example.com", resource_documentation="/docs")


def test_resource_documentation_accepts_an_absolute_uri() -> None:
    config = ProtectedResourceConfig(
        resource="https://api.example.com", resource_documentation="https://docs.example.com/api"
    )

    assert config.resource_documentation == "https://docs.example.com/api"


def test_route_prefix_defaults_to_the_application_root() -> None:
    assert ProtectedResourceConfig(resource="https://api.example.com").route_prefix == ""


def test_route_prefix_accepts_a_mount_point() -> None:
    config = ProtectedResourceConfig(resource="https://api.example.com", route_prefix="/api/")

    assert config.route_prefix == "/api"


@pytest.mark.parametrize("route_prefix", ["api", "/", "//api", "/a b", "/api\n", 1])
def test_route_prefix_rejects_relative_and_malformed_mounts(route_prefix: object) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        ProtectedResourceConfig(resource="https://api.example.com", route_prefix=route_prefix)  # type: ignore[arg-type]


def test_config_is_frozen() -> None:
    config = ProtectedResourceConfig(resource="https://api.example.com")

    with pytest.raises(AttributeError):
        config.resource = "https://other.example.com"  # type: ignore[misc]


def test_security_config_accepts_a_protected_resource() -> None:

    config = ProtectedResourceConfig(resource="https://api.example.com")

    assert SecurityConfig[object](protected_resource=config).protected_resource is config


def test_security_config_rejects_a_foreign_protected_resource() -> None:

    with pytest.raises(ImproperlyConfiguredException):
        SecurityConfig[object](protected_resource=object())  # type: ignore[arg-type]
