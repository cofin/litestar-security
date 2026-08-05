"""Golden-file guard for the OpenAPI document the generated routes emit.

``src/tests/fixtures/openapi_document.json`` is the committed document for one
application that turns on every generated route family at once: local auth in
hybrid mode with public registration, MFA, passkeys, OAuth, and OIDC logout.

The fixture is a **canonical** rendering: ``json.dumps`` with sorted object keys
and two-space indentation. Sorting is required, not cosmetic — Litestar derives
some response-header maps from sets, so the natural key order of the emitted
document changes with ``PYTHONHASHSEED`` while the sorted order does not.

**Updating the fixture is a deliberate act.** Regenerate it with::

    uv run python -m tests.integration.test_openapi_document

then read the resulting git diff and confirm every changed line is a change the
work in hand intended. The five tests below are ordered so an accidental drift
names itself: the path set, the operation-id set, the tag groups, and the
component-schema member names are each compared on their own before the whole
document is compared byte for byte. A failure in one of the first four says
exactly what moved; a failure in only the last one says something changed that
none of those four describes.

The member-name comparison is what makes a **casing** change legible. Member
names are the wire contract the generated client's field names come from, so a
rename that reaches them is the largest change this document can carry and the
easiest to make by accident. Compared on its own it reports the schemas and the
members that moved; folded into the byte comparison it would report only that
several thousand lines differ.
"""

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest
from litestar import Litestar
from litestar.config.csrf import CSRFConfig
from litestar.datastructures import Cookie
from litestar.exceptions import ImproperlyConfiguredException
from litestar.middleware.session.client_side import CookieBackendConfig
from litestar.openapi.config import OpenAPIConfig
from litestar.openapi.spec import Tag

from litestar_security import ROUTE_TAGS, RouteDocs, SecurityConfig, SecurityPlugin
from litestar_security._openapi import merge_openapi_tags
from litestar_security.accounts import (
    AESGCMSecretProtector,
    LocalAuth,
    LocalAuthSecrets,
    PurposeTokenCodec,
    RecoveryCodePepper,
    RefreshReceiptKey,
    RefreshReceiptSealer,
    RefreshTokenCodec,
    RegistrationPolicy,
    SecretProtectorKey,
    SessionBindingConfig,
)
from litestar_security.config import MFAConfig, PasskeyConfig
from litestar_security.providers import LocalKeyRing, SigningKey
from litestar_security.providers.oauth import (
    OAuthAuthorization,
    OAuthConfig,
    OAuthLogout,
    OAuthRouteStatus,
    OIDCLogoutIdentity,
    OIDCLogoutLifecycleService,
)
from litestar_security.testing import (
    InMemoryLocalAccountStore,
    InMemoryMFAStore,
    InMemoryOIDCSessionLogoutStore,
    InMemoryPasskeyStore,
    InMemoryStepUpStore,
    InMemoryWebAuthnChallengeStore,
)

GOLDEN_DOCUMENT = Path(__file__).resolve().parents[1] / "fixtures" / "openapi_document.json"

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


async def _observe(*_args: object, **_kwargs: object) -> None:
    return None


class _Provider:
    name = "example"


class _OAuthRouteService:
    """Route-shaped OAuth service: the document depends on signatures, not behavior."""

    provider_names = frozenset({"example"})

    async def begin(self, **kwargs: object) -> OAuthAuthorization:
        del kwargs
        return OAuthAuthorization(
            url="https://issuer.example/authorize",
            binding_cookie=Cookie(key="__Host-litestar-security-oauth", value="binding", path="/"),
        )

    async def callback(self, **kwargs: object) -> OAuthRouteStatus:
        del kwargs
        return OAuthRouteStatus(detail="Authenticated.")

    async def unlink(self, **kwargs: object) -> OAuthRouteStatus:
        del kwargs
        return OAuthRouteStatus(detail="Unlinked.")

    async def revoke(self, **kwargs: object) -> OAuthRouteStatus:
        del kwargs
        return OAuthRouteStatus(detail="Revoked.")

    async def logout(self, **kwargs: object) -> OAuthLogout:
        del kwargs
        return OAuthLogout(detail="Logged out.")


class _LogoutTokenConsumer:
    async def consume(self, provider: str, logout_token: str, *, now: datetime) -> OIDCLogoutIdentity:
        del logout_token, now
        return OIDCLogoutIdentity(
            provider=provider,
            issuer="https://issuer.example",
            token_id="jti",  # noqa: S106 - the OIDC logout token identifier is not a secret
            subject="subject",
        )


def build_documented_app(
    private_key: bytes, *, docs: RouteDocs | None = None, passkey_docs: RouteDocs | None = None
) -> Litestar:
    """Build the application every generated route family is documented from.

    Args:
        private_key: PKCS8 PEM signing material for the local token issuer.
        docs: Documentation metadata applied to every configured feature.
        passkey_docs: Documentation metadata for the passkey feature alone, so a
            test can make the MFA and passkey configurations disagree.

    Returns:
        One application with local auth, MFA, passkeys, OAuth, and OIDC logout.
    """
    docs = RouteDocs() if docs is None else docs
    accounts = InMemoryLocalAccountStore(
        _observe, clock=lambda: _NOW, identifiers=str.casefold, entropy=lambda size: b"e" * size
    )
    local_auth = LocalAuth.hybrid(
        accounts=cast("Any", accounts),
        secrets=LocalAuthSecrets(
            purpose_tokens=PurposeTokenCodec(pepper=b"p" * 32),
            refresh_codec=RefreshTokenCodec(pepper=b"q" * 32),
            refresh_receipts=RefreshReceiptSealer(active_key=RefreshReceiptKey("golden", b"r" * 32)),
        ),
        binding=SessionBindingConfig(pepper=b"b" * 32, max_age=600),
        key_ring=LocalKeyRing(
            issuer="https://local.example",
            active_signing_key=SigningKey(key_id="active", algorithm="EdDSA", private_key=private_key),
        ),
        token_audience="local-client",  # noqa: S106 - public JWT audience
        registration=RegistrationPolicy.public(),
        docs=docs,
    )
    step_up_store = InMemoryStepUpStore()
    mfa = MFAConfig(
        store=InMemoryMFAStore(),
        secret_protector=AESGCMSecretProtector(active_key=SecretProtectorKey("v1", b"s" * 32)),
        recovery_peppers=(RecoveryCodePepper("v1", b"p" * 32),),
        login_methods=cast("Any", accounts),
        step_up_store=step_up_store,
        docs=docs,
    )
    passkeys = PasskeyConfig(
        store=InMemoryPasskeyStore(),
        challenge_store=InMemoryWebAuthnChallengeStore(),
        rp_id="example.com",
        origins=("https://example.com",),
        login_methods=cast("Any", accounts),
        step_up_store=step_up_store,
        docs=docs if passkey_docs is None else passkey_docs,
    )
    oauth = OAuthConfig(
        oauth_service=cast("Any", _OAuthRouteService()),
        providers=(_Provider(),),
        oidc_service=OIDCLogoutLifecycleService(
            provider_issuers={"example": "https://issuer.example"},
            consumer=cast("Any", _LogoutTokenConsumer()),
            sessions=InMemoryOIDCSessionLogoutStore(session_mappings={}, frontchannel_bindings={}),
            clock=lambda: _NOW,
        ),
        docs=docs,
    )
    return Litestar(
        route_handlers=[],
        csrf_config=CSRFConfig(secret="golden-file-csrf-secret"),  # noqa: S106 - fixed test secret
        middleware=[CookieBackendConfig(secret=bytes(range(16)), secure=True, httponly=True).middleware],
        openapi_config=OpenAPIConfig(title="Litestar Security", version="0.0.0"),
        plugins=[SecurityPlugin(SecurityConfig(local_auth=local_auth, mfa=mfa, passkeys=passkeys, oauth=oauth))],
    )


def canonical(document: Mapping[str, Any]) -> str:
    """Render one OpenAPI document as the fixture's stable canonical text."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def emitted_document(private_key: bytes, *, docs: RouteDocs | None = None) -> dict[str, Any]:
    """Return the OpenAPI document the documented application emits."""
    return cast("dict[str, Any]", build_documented_app(private_key, docs=docs).openapi_schema.to_schema())


def _operation_ids(document: Mapping[str, Any]) -> set[str]:
    return {
        operation["operationId"]
        for path_item in document["paths"].values()
        for method, operation in path_item.items()
        if isinstance(operation, dict) and "operationId" in operation and method != "parameters"
    }


def _tag_groups(document: Mapping[str, Any]) -> dict[str, str | None]:
    return {tag["name"]: tag.get("description") for tag in document.get("tags", ())}


def schema_members(document: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """Return the declared member names of every component schema, by schema name."""
    schemas = cast("Mapping[str, Mapping[str, Any]]", document.get("components", {}).get("schemas", {}))
    return {name: tuple(sorted(schema.get("properties", {}))) for name, schema in schemas.items()}


@pytest.fixture(scope="module")
def golden() -> dict[str, Any]:
    """Return the committed document."""
    return cast("dict[str, Any]", json.loads(GOLDEN_DOCUMENT.read_text(encoding="utf-8")))


@pytest.fixture(scope="module")
def emitted(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> dict[str, Any]:
    """Return the freshly emitted document."""
    return emitted_document(jwt_key_material["EdDSA"][0])


def test_documented_paths_match_the_golden_file(emitted: Mapping[str, Any], golden: Mapping[str, Any]) -> None:
    """No generated route appears or disappears without a deliberate fixture update."""
    assert sorted(emitted["paths"]) == sorted(golden["paths"])


def test_documented_operation_ids_match_the_golden_file(emitted: Mapping[str, Any], golden: Mapping[str, Any]) -> None:
    """Operation IDs become generated client function names, so they are a public surface."""
    assert sorted(_operation_ids(emitted)) == sorted(_operation_ids(golden))


def test_documented_tag_groups_match_the_golden_file(emitted: Mapping[str, Any], golden: Mapping[str, Any]) -> None:
    """Every declared tag group keeps its name and its description."""
    assert _tag_groups(emitted) == _tag_groups(golden)


def test_documented_schema_members_match_the_golden_file(emitted: Mapping[str, Any], golden: Mapping[str, Any]) -> None:
    """Member names are the wire contract, so a casing change must be a deliberate one."""
    assert schema_members(emitted) == schema_members(golden)


def test_openapi_document_is_byte_identical_to_the_golden_file(
    emitted: Mapping[str, Any], golden: Mapping[str, Any]
) -> None:
    """Catch every drift the four narrower comparisons above do not describe."""
    assert canonical(emitted) == canonical(golden)


def test_the_golden_file_is_stored_in_canonical_form(golden: Mapping[str, Any]) -> None:
    """A hand-edited fixture would make the byte comparison meaningless."""
    assert GOLDEN_DOCUMENT.read_text(encoding="utf-8") == canonical(golden)


if __name__ == "__main__":  # pragma: no cover - deliberate fixture regeneration
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    _key = ed25519.Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    GOLDEN_DOCUMENT.write_text(canonical(emitted_document(_key)), encoding="utf-8")


def _used_tags(document: Mapping[str, Any]) -> set[str]:
    return {
        tag
        for path_item in document["paths"].values()
        for method, operation in path_item.items()
        if isinstance(operation, dict) and method != "parameters"
        for tag in operation.get("tags", ())
    }


def test_every_tag_group_the_routes_use_is_declared_and_described(emitted: Mapping[str, Any]) -> None:
    """All ten groups reach the OpenAPI config, not only the five local-auth ones."""
    declared = _tag_groups(emitted)

    assert set(declared) == _used_tags(emitted)
    assert len(declared) == len(ROUTE_TAGS)
    assert all(description for description in declared.values())


def test_renaming_a_tag_group_regroups_its_routes(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    """An application renames a built-in group and its routes move with the name."""
    docs = RouteDocs(
        tags={"mfa": "Two-factor", "oidc.logout": "Single sign-out"},
        tag_descriptions={"mfa": "How this deployment does second factors."},
    )
    document = emitted_document(jwt_key_material["EdDSA"][0], docs=docs)
    declared = _tag_groups(document)

    assert "Multi-factor authentication" not in declared
    assert "OIDC logout" not in declared
    assert declared["Two-factor"] == "How this deployment does second factors."
    assert declared["Single sign-out"] == ROUTE_TAGS["oidc.logout"].description
    assert set(declared) == _used_tags(document)
    assert document["paths"]["/auth/mfa/totp/enroll"]["post"]["tags"] == ["Two-factor"]


def test_two_groups_renamed_to_one_name_become_one_group(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    """Merging two built-in groups is a legitimate rename, not an error."""
    docs = RouteDocs(tags={"mfa": "Second factors", "passkeys": "Second factors"})
    document = emitted_document(jwt_key_material["EdDSA"][0], docs=docs)
    declared = _tag_groups(document)

    assert declared["Second factors"] == ROUTE_TAGS["mfa"].description
    assert len(declared) == len(ROUTE_TAGS) - 1
    assert document["paths"]["/auth/passkeys"]["get"]["tags"] == ["Second factors"]


def test_an_application_declared_tag_still_wins(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    """A description the application pre-declared is documentation it already owns."""
    caller = Tag(name="Passkeys", description="Caller owns this description.")
    app = build_documented_app(jwt_key_material["EdDSA"][0])
    openapi_config = OpenAPIConfig(title="Litestar Security", version="0.0.0", tags=[caller])
    declared = {tag.name: tag for tag in merge_openapi_tags(openapi_config, ROUTE_TAGS.values()).tags or ()}

    assert declared["Passkeys"] is caller
    assert app.openapi_schema is not None


def test_mfa_and_passkey_documentation_must_agree(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    """One router serves both features, so two disagreeing configurations cannot both apply."""
    with pytest.raises(ImproperlyConfiguredException, match="documentation"):
        build_documented_app(
            jwt_key_material["EdDSA"][0],
            docs=RouteDocs(tags={"step_up": "Re-authentication"}),
            passkey_docs=RouteDocs(tags={"step_up": "Confirmation"}),
        )


def test_one_transform_renames_every_generated_operation_id(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    """An application wanting camelCase supplies one callable, not thirty-five overrides."""
    docs = RouteDocs(operation_id=lambda value: value[0].lower() + value[1:])
    document = emitted_document(jwt_key_material["EdDSA"][0], docs=docs)

    assert document["paths"]["/auth/login"]["post"]["operationId"] == "localSessionLogin"
    assert document["paths"]["/auth/passkeys"]["get"]["operationId"] == "passkeyList"
    assert all(operation_id[0].islower() for operation_id in _operation_ids(document))


def test_one_transform_renames_every_generated_route_name(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    """Route names are what ``route_reverse`` resolves, so a transform must reach them too."""
    app = build_documented_app(jwt_key_material["EdDSA"][0], docs=RouteDocs(route_name="app.".__add__))

    assert app.route_reverse("app.local.session.login") == "/auth/login"
    assert app.route_reverse("app.oidc.logout.frontchannel", provider="example") == (
        "/auth/oidc/example/frontchannel-logout"
    )


def test_colliding_operation_ids_after_a_transform_raise(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    """A transform that flattens two operations together would produce a broken client."""
    with pytest.raises(ImproperlyConfiguredException, match="operation_id"):
        build_documented_app(jwt_key_material["EdDSA"][0], docs=RouteDocs(operation_id=lambda _value: "Operation"))


def test_colliding_route_names_after_a_transform_raise(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> None:
    """Litestar indexes handlers by name, so a collision silently misdirects ``route_reverse``."""
    with pytest.raises(ImproperlyConfiguredException, match="route name"):
        build_documented_app(jwt_key_material["EdDSA"][0], docs=RouteDocs(route_name=lambda _value: "route"))
