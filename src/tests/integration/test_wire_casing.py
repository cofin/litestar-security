"""Integration tests for the wire convention the generated routes are spelled in."""

import re
from datetime import datetime, timezone
from typing import Any, cast

import pytest
from litestar import Litestar, get
from litestar.config.csrf import CSRFConfig
from litestar.enums import ScopeType
from litestar.middleware.session.client_side import CookieBackendConfig
from litestar.status_codes import HTTP_200_OK, HTTP_202_ACCEPTED, HTTP_400_BAD_REQUEST
from litestar.testing import TestClient, create_test_client

from litestar_security import SecurityConfig, SecurityPlugin
from litestar_security.accounts import (
    LocalAuth,
    LocalAuthSecrets,
    PurposeTokenCodec,
    RefreshReceiptKey,
    RefreshReceiptSealer,
    RefreshTokenCodec,
    RegistrationPolicy,
    SessionBindingConfig,
)
from litestar_security.authentication import public
from litestar_security.providers import LocalKeyRing, SigningKey
from litestar_security.providers.oauth import ProtectedResourceConfig
from litestar_security.schema import WirePolicy
from tests.fixtures.collaborators import NotifyingLocalAccountStore
from tests.integration.test_openapi_document import build_documented_app

SNAKE = WirePolicy()
CAMEL = WirePolicy(rename="camel")
SHOUTED = WirePolicy(rename=str.upper)
LENIENT = WirePolicy(rename="camel", forbid_unknown_fields=False)

# The three schemas that declare their member names are not this library's to
# rename: two are specification-defined and one is rendered by Litestar.
_EXEMPT_SCHEMAS = frozenset({"OIDCBackchannelLogout", "RouteError", "TokenPair"})

_SNAKE_MEMBER = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)+$")
_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_PASSWORD = "correct horse battery staple"  # noqa: S105 - a fixed test password


def _schemas(document: dict[str, Any]) -> dict[str, Any]:
    return cast("dict[str, Any]", document["components"]["schemas"])


def _members(document: dict[str, Any], name: str) -> set[str]:
    return set(_schemas(document)[name].get("properties", {}))


@pytest.fixture(scope="module")
def documents(jwt_key_material: "dict[str, tuple[bytes, bytes]]") -> dict[str, dict[str, Any]]:
    """Return the document the whole generated tree emits under each policy."""
    private_key, _public_key = jwt_key_material["EdDSA"]
    return {
        name: cast("dict[str, Any]", build_documented_app(private_key, wire=policy).openapi_schema.to_schema())
        for name, policy in (("snake", SNAKE), ("camel", CAMEL), ("shouted", SHOUTED))
    }


def test_component_keys_are_the_same_under_every_casing(documents: dict[str, dict[str, Any]]) -> None:
    """A casing change moves members, never the type names a client is generated from."""
    keys = {name: set(_schemas(document)) for name, document in documents.items()}

    assert keys["camel"] == keys["snake"]
    assert keys["shouted"] == keys["snake"]
    assert len(keys["snake"]) > 1


def test_paths_and_operations_are_the_same_under_every_casing(documents: dict[str, dict[str, Any]]) -> None:
    assert set(documents["camel"]["paths"]) == set(documents["snake"]["paths"])
    assert set(documents["shouted"]["paths"]) == set(documents["snake"]["paths"])


def test_no_renameable_component_keeps_a_snake_case_member(documents: dict[str, dict[str, Any]]) -> None:
    """The one assertion that generalizes over schemas nobody thought to enumerate."""
    offenders = {
        name: sorted(member for member in schema.get("properties", {}) if _SNAKE_MEMBER.match(member))
        for name, schema in _schemas(documents["camel"]).items()
        if name not in _EXEMPT_SCHEMAS
    }

    assert not {name: members for name, members in offenders.items() if members}


def test_every_exempt_schema_is_present_and_still_spelled_its_own_way(documents: dict[str, dict[str, Any]]) -> None:
    """A schema opting out is only meaningful if it is in the document to opt out of."""
    for name in _EXEMPT_SCHEMAS:
        assert _members(documents["camel"], name) == _members(documents["snake"], name)
    assert _members(documents["camel"], "TokenPair") == {"access_token", "refresh_token", "expires_in", "token_type"}


def test_the_nested_session_schema_is_renamed_at_every_level(documents: dict[str, dict[str, Any]]) -> None:
    """Nesting is where a rename bug hides and where the depth limit truncates."""
    listed = _schemas(documents["camel"])["LocalSessionList"]["properties"]

    assert set(listed) == {"sessions"}
    assert listed["sessions"]["items"]["$ref"].endswith("/LocalSession")
    assert _members(documents["camel"], "LocalSession") == {
        "sessionId",
        "current",
        "createdAt",
        "lastSeenAt",
        "expiresAt",
        "displayMetadata",
    }
    assert _members(documents["shouted"], "LocalSession") == {
        "SESSION_ID",
        "CURRENT",
        "CREATED_AT",
        "LAST_SEEN_AT",
        "EXPIRES_AT",
        "DISPLAY_METADATA",
    }


def test_the_union_login_routes_document_both_arms(documents: dict[str, dict[str, Any]]) -> None:
    """Both login routes return one of two bodies, and both bodies are renamed."""
    session_login = documents["camel"]["paths"]["/auth/login"]["post"]["responses"]
    token_login = documents["camel"]["paths"]["/auth/token"]["post"]["responses"]

    assert _members(documents["camel"], "LocalAccount") == {"accountId", "displayName"}
    assert "accountId" in _members(documents["camel"], "LocalMFAChallenge")
    assert session_login["200"]["content"]["application/json"]["schema"]["$ref"].endswith("/LocalAccount")
    assert session_login["403"]["content"]["application/json"]["schema"]["$ref"].endswith("/LocalMFAChallenge")
    assert token_login["200"]["content"]["application/json"]["schema"]["$ref"].endswith("/TokenPair")


def test_a_documented_returned_body_is_the_one_the_route_sends(documents: dict[str, dict[str, Any]]) -> None:
    """A response specification and the handler's own body are one component."""
    paths = documents["camel"]["paths"]
    logout = paths["/auth/oauth/{provider}/logout"]["post"]["responses"]["200"]
    link = paths["/auth/oauth/{provider}/links/{provider_account_id}/unlink"]["post"]["responses"]["200"]
    arms = logout["content"]["application/json"]["schema"]["oneOf"]

    assert any(arm.get("$ref", "").endswith("/OAuthOperationSummary") for arm in arms)
    assert link["content"]["application/json"]["schema"]["$ref"].endswith("/OAuthOperationSummary")
    assert "providerAccountId" in _members(documents["camel"], "OAuthOperationSummary")


def test_a_documented_raised_body_still_describes_what_litestar_sends(documents: dict[str, dict[str, Any]]) -> None:
    """A denial is rendered by exception handling, so no casing policy reaches it."""
    denial = documents["camel"]["paths"]["/auth/login"]["post"]["responses"]["400"]

    assert denial["content"]["application/json"]["schema"]["$ref"].endswith("/RouteError")
    assert _members(documents["camel"], "RouteError") == {"status_code", "detail", "extra"}


def test_no_documented_response_publishes_an_empty_media_type(documents: dict[str, dict[str, Any]]) -> None:
    """Litestar leaves the media type unset on a DTO'd `Response[X]` unless it is pinned."""
    empty = [
        (path, method, status)
        for document in documents.values()
        for path, path_item in document["paths"].items()
        for method, operation in path_item.items()
        if isinstance(operation, dict)
        for status, response in (operation.get("responses") or {}).items()
        if "" in (response.get("content") or {})
    ]

    assert not empty


@get("/csrf", auth=public(), csrf_required=True)
async def _csrf_seed() -> None:
    """Establish the CSRF cookie a session-establishing route requires."""
    return


def _runtime_app(policy: WirePolicy, accounts: NotifyingLocalAccountStore, private_key: bytes) -> Litestar:
    local_auth = LocalAuth.hybrid(
        accounts=cast("Any", accounts),
        secrets=LocalAuthSecrets(
            purpose_tokens=PurposeTokenCodec(pepper=b"p" * 32),
            refresh_codec=RefreshTokenCodec(pepper=b"q" * 32),
            refresh_receipts=RefreshReceiptSealer(active_key=RefreshReceiptKey("wire", b"r" * 32)),
        ),
        binding=SessionBindingConfig(
            pepper=b"b" * 32, cookie_name="binding", max_age=600, secure=False, allow_insecure=True
        ),
        key_ring=LocalKeyRing(
            issuer="https://local.example",
            active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=private_key),
        ),
        token_audience="local-client",  # noqa: S106 - a public JWT audience
        registration=RegistrationPolicy.public(),
    )
    return Litestar(
        route_handlers=[_csrf_seed],
        csrf_config=CSRFConfig(secret="wire-casing-csrf-secret"),  # noqa: S106 - a fixed test secret
        middleware=[
            CookieBackendConfig(
                secret=bytes(range(16)),
                key="native-session",
                max_age=600,
                scopes={ScopeType.HTTP, ScopeType.WEBSOCKET},
                secure=False,
            ).middleware
        ],
        openapi_config=None,
        plugins=[
            SecurityPlugin(
                SecurityConfig(
                    local_auth=local_auth,
                    wire_rename=policy.rename,
                    wire_forbid_unknown_fields=policy.forbid_unknown_fields,
                )
            )
        ],
    )


@pytest.fixture
def private_key(jwt_key_material: "dict[str, tuple[bytes, bytes]]") -> bytes:
    """Return the signing key the runtime application issues access tokens with."""
    return jwt_key_material["EdDSA"][0]


@pytest.mark.parametrize(
    ("policy", "identifier", "accepted", "rejected"),
    [
        (SNAKE, "identifier", "display_name", "displayName"),
        (CAMEL, "identifier", "displayName", "display_name"),
        (SHOUTED, "IDENTIFIER", "DISPLAY_NAME", "display_name"),
    ],
)
def test_a_generated_route_decodes_the_configured_casing_and_rejects_the_other(
    policy: WirePolicy, identifier: str, accepted: str, rejected: str, private_key: bytes
) -> None:
    accounts = NotifyingLocalAccountStore(
        _discard, clock=lambda: _NOW, identifiers=str.casefold, entropy=lambda size: b"e" * size
    )

    with TestClient(_runtime_app(policy, accounts, private_key)) as client:
        body = {identifier: "person@example.com", "PASSWORD" if policy is SHOUTED else "password": _PASSWORD}
        assert client.post("/auth/register", json={**body, accepted: "Person"}).status_code == HTTP_202_ACCEPTED
        assert client.post("/auth/register", json={**body, rejected: "Person"}).status_code == HTTP_400_BAD_REQUEST


@pytest.mark.parametrize(("policy", "expected"), [(CAMEL, HTTP_400_BAD_REQUEST), (LENIENT, HTTP_202_ACCEPTED)])
def test_an_unknown_member_is_rejected_only_when_the_policy_forbids_it(
    policy: WirePolicy, expected: int, private_key: bytes
) -> None:
    accounts = NotifyingLocalAccountStore(
        _discard, clock=lambda: _NOW, identifiers=str.casefold, entropy=lambda size: b"e" * size
    )

    with TestClient(_runtime_app(policy, accounts, private_key)) as client:
        response = client.post(
            "/auth/register", json={"identifier": "person@example.com", "password": _PASSWORD, "nickname": "Person"}
        )

    assert response.status_code == expected


def test_a_generated_response_and_its_nested_members_encode_in_the_configured_casing(private_key: bytes) -> None:
    accounts = NotifyingLocalAccountStore(
        _discard, clock=lambda: _NOW, identifiers=str.casefold, entropy=lambda size: b"e" * size
    )

    with TestClient(_runtime_app(CAMEL, accounts, private_key)) as client:
        registration = client.post(
            "/auth/register", json={"identifier": "person@example.com", "password": _PASSWORD, "displayName": "Person"}
        )
        assert registration.status_code == HTTP_202_ACCEPTED
        confirmation = client.post("/auth/verification/confirm", json={"token": accounts.token_for("local.verify")})
        assert confirmation.status_code == HTTP_200_OK
        assert client.get("/csrf").status_code == HTTP_200_OK
        csrf_headers = {"x-csrftoken": cast("str", client.cookies.get("csrftoken"))}
        login = client.post(
            "/auth/login", json={"identifier": "person@example.com", "password": _PASSWORD}, headers=csrf_headers
        )
        assert login.status_code == HTTP_200_OK, login.text
        sessions = client.get("/auth/sessions")
        assert sessions.status_code == HTTP_200_OK, sessions.text

    assert set(login.json()) == {"accountId", "displayName"}
    assert login.json()["displayName"] == "Person"
    listed = sessions.json()["sessions"]
    assert set(listed[0]) == {"sessionId", "current", "createdAt", "lastSeenAt", "expiresAt", "displayMetadata"}


def test_the_token_response_keeps_its_specification_member_names(private_key: bytes) -> None:
    """RFC 6749 names every member of the token response, so no policy renames them."""
    accounts = NotifyingLocalAccountStore(
        _discard, clock=lambda: _NOW, identifiers=str.casefold, entropy=lambda size: b"e" * size
    )

    with TestClient(_runtime_app(CAMEL, accounts, private_key)) as client:
        assert (
            client.post(
                "/auth/register",
                json={"identifier": "person@example.com", "password": _PASSWORD, "displayName": "Person"},
            ).status_code
            == HTTP_202_ACCEPTED
        )
        assert (
            client.post("/auth/verification/confirm", json={"token": accounts.token_for("local.verify")}).status_code
            == HTTP_200_OK
        )
        issued = client.post("/auth/token", json={"identifier": "person@example.com", "password": _PASSWORD})

    assert issued.status_code == HTTP_200_OK, issued.text
    assert set(issued.json()) == {"access_token", "refresh_token", "expires_in", "token_type"}


async def _discard(*_args: object, **_kwargs: object) -> None:
    return None


def test_the_protected_resource_metadata_is_unaffected_by_the_casing_policy() -> None:
    """RFC 9728 names every member of this document, and no policy reaches it."""
    config = SecurityConfig(
        protected_resource=ProtectedResourceConfig(
            resource="https://api.example.com",
            authorization_servers=("https://issuer.example.com",),
            scopes_supported=("read",),
        ),
        wire_rename="camel",
    )

    with create_test_client([], plugins=[SecurityPlugin(config)]) as client:
        response = client.get("/.well-known/oauth-protected-resource")
        handler = client.app.route_handler_method_map["/.well-known/oauth-protected-resource"]["GET"]

    assert sorted(response.json()) == [
        "authorization_servers",
        "bearer_methods_supported",
        "resource",
        "scopes_supported",
    ]
    assert handler.resolve_return_dto() is None
