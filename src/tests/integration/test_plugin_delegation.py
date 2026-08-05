"""Integration contracts for the surface another plugin delegates authentication to.

These prove the claims made in ``docs/resource-server.rst``. The whole point of
that page is that a second plugin can be written against the published surface
without reading this package's internals, so nothing here touches a private
name.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import jwt.algorithms
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from litestar import get
from litestar.config.app import AppConfig
from litestar.di import NamedDependency
from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi.spec import SecurityScheme
from litestar.plugins import InitPlugin
from litestar.status_codes import HTTP_200_OK, HTTP_401_UNAUTHORIZED
from litestar.testing import create_test_client

from litestar_security import SecurityConfig, SecurityPlugin, required
from litestar_security.authentication import AuthenticationMechanism
from litestar_security.context import Principal, SecurityContext
from litestar_security.providers.jwks import (
    CachedJWKSProvider,
    InMemoryJWKSCache,
    JWKSCacheEntry,
    JWKSFetchRequest,
    JWKSFetchResponse,
)
from litestar_security.providers.oauth import ProtectedResourceConfig
from litestar_security.providers.oidc import ServiceTokenConfig

ISSUER = "https://issuer.example.com"
JWKS_URI = "https://issuer.example.com/jwks.json"
RESOURCE = "https://api.example.com"
AUDIENCE = "team-api"
KEY_ID = "workload-key"


class _CountingFetcher:
    def __init__(self, document: bytes) -> None:
        self.document = document
        self.calls = 0

    async def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResponse:
        del request
        self.calls += 1
        return JWKSFetchResponse(status_code=200, headers={"cache-control": "max-age=600"}, body=self.document)


class _CompanionPlugin(InitPlugin):
    """A second plugin that registers routes and delegates their authentication.

    It builds no verifier, owns no key cache, and declares its policy the same
    way an application route does.
    """

    __slots__ = ("security",)

    def __init__(self) -> None:
        self.security: SecurityConfig[Any] | None = None

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        security_plugin = next(plugin for plugin in app_config.plugins if isinstance(plugin, SecurityPlugin))
        self.security = security_plugin.config
        app_config.route_handlers.append(_companion_route)
        return app_config


@get("/companion/reports", auth=required("service-jwt"), sync_to_thread=False)
def _companion_route(
    principal: NamedDependency[Principal[object]], security_context: NamedDependency[SecurityContext]
) -> dict[str, object]:
    presented = frozenset[str]().union(*(value.scopes for value in security_context.restrictions))
    return {
        "actor": principal.id,
        "mechanisms": sorted(evidence.mechanism for evidence in security_context.evidence),
        "scopes": sorted(presented),
    }


@pytest.fixture(scope="module")
def workload_key() -> tuple[bytes, bytes]:
    private = ec.generate_private_key(ec.SECP256R1())
    return (
        private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
    )


def _jwks_document(public_pem: bytes) -> bytes:
    public_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(serialization.load_pem_public_key(public_pem)))
    public_jwk.update({"kid": KEY_ID, "alg": "ES256", "use": "sig"})
    return json.dumps({"keys": [public_jwk]}).encode()


def _workload_token(private_pem: bytes) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "iss": ISSUER,
            "sub": "report-worker",
            "aud": AUDIENCE,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "jti": "workload-token-1",
            "client_id": "report-worker",
            "scope": "reports:read reports:write",
        },
        private_pem,
        algorithm="ES256",
        headers={"kid": KEY_ID, "typ": "at+jwt"},
    )


def _delegating_config(provider: CachedJWKSProvider) -> SecurityConfig[object]:
    slot, mechanism = ServiceTokenConfig(
        issuer=ISSUER,
        audiences=frozenset({AUDIENCE}),
        allowed_algorithms=frozenset({"ES256"}),
        jwks=provider,
        jwks_uri=JWKS_URI,
    ).build()
    return SecurityConfig(
        slots=(slot,),
        mechanisms=(mechanism,),
        jwks_providers=(provider,),
        protected_resource=ProtectedResourceConfig(
            resource=RESOURCE, authorization_servers=(ISSUER,), scopes_supported=("reports:read", "reports:write")
        ),
    )


def test_a_second_plugin_delegates_bearer_validation(workload_key: tuple[bytes, bytes]) -> None:
    private_pem, public_pem = workload_key
    fetcher = _CountingFetcher(_jwks_document(public_pem))
    provider = CachedJWKSProvider(
        (JWKSCacheEntry(issuer=ISSUER, jwks_uri=JWKS_URI, algorithms=frozenset({"ES256"})),),
        fetcher,
        cache=InMemoryJWKSCache(),
    )
    companion = _CompanionPlugin()
    config = _delegating_config(provider)

    with create_test_client([], plugins=[SecurityPlugin(config), companion]) as client:
        anonymous = client.get("/companion/reports")
        authorized = client.get(
            "/companion/reports", headers={"Authorization": f"Bearer {_workload_token(private_pem)}"}
        )
        repeated = client.get("/companion/reports", headers={"Authorization": f"Bearer {_workload_token(private_pem)}"})
        manifest = client.get("/.well-known/oauth-protected-resource")

    assert companion.security is config
    assert anonymous.status_code == HTTP_401_UNAUTHORIZED
    assert authorized.status_code == HTTP_200_OK
    assert authorized.json() == {
        "actor": "report-worker",
        "mechanisms": ["service-jwt"],
        "scopes": ["reports:read", "reports:write"],
    }
    assert repeated.status_code == HTTP_200_OK
    # One key set, fetched once, however many components verify against it.
    assert fetcher.calls == 1
    assert manifest.json()["authorization_servers"] == [ISSUER]


def test_the_configured_provider_is_reachable_from_the_built_application(workload_key: tuple[bytes, bytes]) -> None:
    _private_pem, public_pem = workload_key
    provider = CachedJWKSProvider(
        (JWKSCacheEntry(issuer=ISSUER, jwks_uri=JWKS_URI, algorithms=frozenset({"ES256"})),),
        _CountingFetcher(_jwks_document(public_pem)),
    )
    config = _delegating_config(provider)

    with create_test_client([], plugins=[SecurityPlugin(config)]) as client:
        found = client.app.plugins.get(SecurityPlugin)

    assert found.config is config
    assert found.config.jwks_providers == (provider,)


def test_a_conflicting_security_scheme_is_rejected_at_startup(workload_key: tuple[bytes, bytes]) -> None:
    _private_pem, public_pem = workload_key
    provider = CachedJWKSProvider(
        (JWKSCacheEntry(issuer=ISSUER, jwks_uri=JWKS_URI, algorithms=frozenset({"ES256"})),),
        _CountingFetcher(_jwks_document(public_pem)),
    )
    slot, mechanism = ServiceTokenConfig(
        issuer=ISSUER,
        audiences=frozenset({AUDIENCE}),
        allowed_algorithms=frozenset({"ES256"}),
        jwks=provider,
        jwks_uri=JWKS_URI,
    ).build()

    class _CompanionSlot:
        name = "x-companion"

        def extract(self, connection: Any) -> object:
            del connection
            raise NotImplementedError

    class _CompanionAuthenticator:
        participates_by_default = True
        name = "companion"
        slot = "x-companion"

        async def authenticate(self, credential: object, connection: object) -> object:
            del credential, connection
            raise NotImplementedError

    class _CompanionResolver:
        async def resolve(self, claims: object) -> object:
            del claims
            raise NotImplementedError

    companion_mechanism = AuthenticationMechanism(
        authenticator=_CompanionAuthenticator(),  # type: ignore[arg-type]
        resolver=_CompanionResolver(),  # type: ignore[arg-type]
        scheme_name="service-jwt",
        security_scheme=SecurityScheme(type="apiKey", name="x-companion", security_scheme_in="header"),
    )
    config = SecurityConfig[object](
        slots=(slot, _CompanionSlot()),  # type: ignore[arg-type]
        mechanisms=(mechanism, companion_mechanism),
    )

    with (
        pytest.raises(ImproperlyConfiguredException, match="Conflicting native OpenAPI security scheme"),
        create_test_client([], plugins=[SecurityPlugin(config)]),
    ):
        pass  # pragma: no cover - startup raises before the client is usable
