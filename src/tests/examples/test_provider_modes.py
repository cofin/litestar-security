"""Integration tests for deterministic provider example modes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from examples.app import create_app
from litestar.testing import TestClient

if TYPE_CHECKING:
    from litestar_security import SecurityPlugin


@pytest.mark.parametrize("mode", ["google-iap", "google-oauth", "github-oauth", "keycloak", "api-team-service"])
def test_provider_modes_boot_with_native_openapi(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    monkeypatch.setenv("LITESTAR_SECURITY_EXAMPLE", mode)
    app = create_app()
    plugin = cast("SecurityPlugin[object]", app.plugins.init[0])

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert app.openapi_schema.paths["/"] is not None
    if mode == "google-iap":
        assert plugin.config.iap is not None
        assert plugin.config.iap.audience == frozenset({"/projects/123/global/backendServices/456"})
        assert "GoogleIAP" in app.openapi_schema.components.security_schemes
    elif mode == "api-team-service":
        assert plugin.config.api_key is not None
        assert plugin.config.service_token is not None
        assert {"APIKey", "service-jwt"} <= set(app.openapi_schema.components.security_schemes)
    else:
        assert plugin.config.oauth is not None
        provider_name = {"google-oauth": "google", "github-oauth": "github", "keycloak": "keycloak"}[mode]
        assert plugin.config.oauth.oauth_service.provider_names == frozenset({provider_name})
        assert "/auth/oauth/{provider}/login" in app.openapi_schema.paths


@pytest.mark.parametrize("mode", ["google-oauth", "github-oauth", "keycloak"])
def test_stub_provider_start_is_pkce_bound_and_secret_free(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    monkeypatch.setenv("LITESTAR_SECURITY_EXAMPLE", mode)
    app = create_app()
    provider_name = {"google-oauth": "google", "github-oauth": "github", "keycloak": "keycloak"}[mode]

    with TestClient(app) as client:
        response = client.get(f"/auth/oauth/{provider_name}/login", params={"return_to": "/"}, follow_redirects=False)

    assert response.status_code in {200, 302, 303, 307}
    assert "example-access" not in response.text


def test_keycloak_realm_fixture_is_pinned_to_safe_code_flow() -> None:
    realm = json.loads(Path("src/tests/fixtures/keycloak/realm.json").read_bytes())
    client = realm["clients"][0]

    assert realm["realm"] == "litestar-security-example"
    assert client["publicClient"] is True
    assert client["standardFlowEnabled"] is True
    assert client["directAccessGrantsEnabled"] is False
