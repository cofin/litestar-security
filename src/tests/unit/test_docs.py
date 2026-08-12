"""Unit contracts for the generated-route documentation registry and metadata type."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, cast

import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security._docs import ROUTE_TAGS, RouteDocs
from litestar_security.accounts import (
    AESGCMSecretProtector,
    LocalAuth,
    LocalAuthSecrets,
    PurposeTokenCodec,
    RefreshReceiptKey,
    RefreshReceiptSealer,
    RefreshTokenCodec,
    SecretProtectorKey,
    SessionBindingConfig,
)
from litestar_security.config import MFAConfig, PasskeyConfig
from litestar_security.providers import LocalKeyRing, SigningKey
from litestar_security.providers.oauth import OAuthConfig
from litestar_security.testing import (
    InMemoryLocalAccountStore,
    InMemoryMFAStore,
    InMemoryPasskeyStore,
    InMemoryWebAuthnChallengeStore,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


async def _observe(*_args: object, **_kwargs: object) -> None:
    return None


def test_every_generated_tag_group_has_a_stable_key() -> None:
    """The stable keys are the public override surface and must not drift."""
    assert tuple(ROUTE_TAGS) == (
        "local.sessions",
        "local.tokens",
        "local.registration",
        "local.passwords",
        "local.verification",
        "mfa",
        "passkeys",
        "step_up",
        "oauth.providers",
        "oidc.logout",
    )


def test_every_registered_tag_carries_a_name_and_a_description() -> None:
    """A group with no description is the defect this registry exists to remove."""
    assert all(tag.name and tag.description for tag in ROUTE_TAGS.values())


def test_display_names_are_unique() -> None:
    """Two keys sharing a display name would silently merge two route groups."""
    names = [tag.name for tag in ROUTE_TAGS.values()]
    assert len(set(names)) == len(names)


def test_the_registry_is_read_only() -> None:
    """The registry is a shared default, so no caller may mutate it in place."""
    assert not hasattr(ROUTE_TAGS, "__setitem__")


def test_the_controllers_file_their_routes_under_registered_display_names() -> None:
    """Every tag a generated controller declares resolves to a registry entry."""
    from litestar_security.accounts.controllers._local import (  # noqa: PLC0415 - private import under test
        LOCAL_AUTH_TAGS,
    )
    from litestar_security.accounts.controllers._mfa import _MFA_TAG, _PASSKEY_TAG, _STEP_UP_TAG  # noqa: PLC0415
    from litestar_security.providers.oauth._routes import _OAUTH_PROVIDERS_TAG, _OIDC_LOGOUT_TAG  # noqa: PLC0415

    declared = {*(tag.name for tag in LOCAL_AUTH_TAGS), _MFA_TAG, _PASSKEY_TAG, _STEP_UP_TAG}
    declared |= {_OAUTH_PROVIDERS_TAG, _OIDC_LOGOUT_TAG}
    assert declared == {tag.name for tag in ROUTE_TAGS.values()}


def test_local_auth_tags_keep_their_registry_order() -> None:
    """Declaration order is display order, and the local groups still come first."""
    from litestar_security.accounts.controllers._local import LOCAL_AUTH_TAGS  # noqa: PLC0415

    local_tags = tuple(ROUTE_TAGS[key] for key in ROUTE_TAGS if key.startswith("local."))
    assert local_tags == LOCAL_AUTH_TAGS


def test_the_registry_is_part_of_the_public_surface() -> None:
    """An application discovers the valid override keys from the package itself."""
    import litestar_security  # noqa: PLC0415 - asserts the package export directly

    assert litestar_security.ROUTE_TAGS is ROUTE_TAGS
    assert "ROUTE_TAGS" in litestar_security.__all__


def test_route_docs_defaults_override_nothing() -> None:
    """A default instance is the documented no-op an unconfigured feature carries."""
    docs = RouteDocs()

    assert docs.tags == {}
    assert docs.tag_descriptions == {}
    assert docs.operation_id is None
    assert docs.route_name is None


def test_route_docs_freezes_the_mappings_it_is_given() -> None:
    """A caller keeping a reference to its own dict cannot mutate the config later."""
    supplied = {"mfa": "Two-factor"}
    docs = RouteDocs(tags=supplied)
    supplied["mfa"] = "changed"

    assert docs.tags == {"mfa": "Two-factor"}
    assert not hasattr(docs.tags, "__setitem__")
    assert not hasattr(docs.tag_descriptions, "__setitem__")


def test_an_unknown_tag_override_key_raises() -> None:
    """A typo'd override must not silently do nothing."""
    with pytest.raises(ImproperlyConfiguredException, match=r"local\.session"):
        RouteDocs(tags={"local.session": "Sessions"})


def test_an_unknown_tag_description_key_raises() -> None:
    """Descriptions are addressed by the same stable keys as names."""
    with pytest.raises(ImproperlyConfiguredException, match="passkey"):
        RouteDocs(tag_descriptions={"passkey": "WebAuthn."})


@pytest.mark.parametrize("tags", [{"mfa": ""}, {"mfa": "   "}, {"mfa": cast("Any", 1)}])
def test_a_tag_override_must_be_a_non_blank_name(tags: dict[str, str]) -> None:
    """An empty display name would file the routes under a nameless group."""
    with pytest.raises(ImproperlyConfiguredException, match="display name"):
        RouteDocs(tags=tags)


@pytest.mark.parametrize("descriptions", [{"mfa": ""}, {"mfa": "  "}, {"mfa": cast("Any", 1)}])
def test_a_tag_description_override_must_be_non_blank(descriptions: dict[str, str]) -> None:
    """A blank description is worse than the default one it replaces."""
    with pytest.raises(ImproperlyConfiguredException, match="description"):
        RouteDocs(tag_descriptions=descriptions)


@pytest.mark.parametrize("field_name", ["operation_id", "route_name"])
def test_a_transform_must_be_callable(field_name: str) -> None:
    """A non-callable transform would fail deep inside route construction."""
    with pytest.raises(ImproperlyConfiguredException, match="callable"):
        RouteDocs(**{field_name: cast("Any", "camelCase")})


def test_route_docs_accepts_every_registered_key() -> None:
    """Every group the registry names is overridable."""
    docs = RouteDocs(
        tags={key: f"Group {index}" for index, key in enumerate(ROUTE_TAGS)},
        tag_descriptions={key: f"Description {index}." for index, key in enumerate(ROUTE_TAGS)},
        operation_id=str.lower,
        route_name=str.upper,
    )

    assert set(docs.tags) == set(ROUTE_TAGS)
    assert set(docs.tag_descriptions) == set(ROUTE_TAGS)


def test_route_docs_is_part_of_the_public_surface() -> None:
    """An application constructs this type, so it is imported from the package root."""
    import litestar_security  # noqa: PLC0415 - asserts the package export directly

    assert litestar_security.RouteDocs is RouteDocs
    assert "RouteDocs" in litestar_security.__all__


def _local_auth_kwargs(*, refresh: bool = False) -> "dict[str, Any]":
    accounts = InMemoryLocalAccountStore(
        _observe,
        clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
        identifiers=str.casefold,
        entropy=lambda size: b"e" * size,
    )
    return {
        "accounts": cast("Any", accounts),
        "secrets": LocalAuthSecrets(
            purpose_tokens=PurposeTokenCodec(pepper=b"p" * 32),
            refresh_codec=RefreshTokenCodec(pepper=b"q" * 32) if refresh else None,
            refresh_receipts=(RefreshReceiptSealer(active_key=RefreshReceiptKey("k", b"r" * 32)) if refresh else None),
        ),
        "binding": SessionBindingConfig(pepper=b"b" * 32, max_age=600),
    }


def _mfa_kwargs() -> "dict[str, Any]":
    return {
        "store": InMemoryMFAStore(),
        "secret_protector": AESGCMSecretProtector(active_key=SecretProtectorKey("v1", b"s" * 32)),
        "register_routes": False,
    }


def _passkey_kwargs() -> "dict[str, Any]":
    return {
        "store": InMemoryPasskeyStore(),
        "challenge_store": InMemoryWebAuthnChallengeStore(),
        "rp_id": "example.com",
        "origins": ("https://example.com",),
        "register_routes": False,
    }


def _oauth_kwargs() -> "dict[str, Any]":
    class _Service:
        provider_names = frozenset({"example"})

        async def begin(self, **kwargs: object) -> None:
            del kwargs

        async def complete_callback(self, **kwargs: object) -> None:
            del kwargs

        async def establish_login(self, **kwargs: object) -> None:
            del kwargs

        async def unlink(self, **kwargs: object) -> None:
            del kwargs

        async def revoke(self, **kwargs: object) -> None:
            del kwargs

        async def logout(self, **kwargs: object) -> None:
            del kwargs

    return {"oauth_service": cast("Any", _Service()), "register_routes": False}


def test_every_feature_config_carries_documentation_metadata_by_default() -> None:
    """An unconfigured feature documents its routes exactly as it always has."""
    configs = (
        LocalAuth.session(**_local_auth_kwargs(), register_routes=False),
        MFAConfig(**_mfa_kwargs()),
        PasskeyConfig(**_passkey_kwargs()),
        OAuthConfig(**_oauth_kwargs()),
    )

    assert all(config.docs == RouteDocs() for config in configs)


@pytest.mark.parametrize("profile", ["session", "tokens", "hybrid"])
def test_every_local_auth_profile_threads_documentation_metadata_through(
    profile: str, jwt_key_material: "Mapping[str, tuple[bytes, bytes]]"
) -> None:
    """``docs`` travels beside ``route_prefix`` on all three profile constructors."""
    docs = RouteDocs(tags={"local.sessions": "Sessions"})
    kwargs = _local_auth_kwargs(refresh=profile != "session")
    if profile != "session":
        kwargs |= {
            "key_ring": LocalKeyRing(
                issuer="https://local.example",
                active_signing_key=SigningKey(
                    key_id="active", algorithm="EdDSA", private_key=jwt_key_material["EdDSA"][0]
                ),
            ),
            "token_audience": "local-client",
        }
    if profile == "tokens":
        del kwargs["binding"]

    config = getattr(LocalAuth, profile)(**kwargs, register_routes=False, docs=docs)

    assert config.docs is docs


@pytest.mark.parametrize(
    ("factory", "kwargs"), [(MFAConfig, _mfa_kwargs), (PasskeyConfig, _passkey_kwargs), (OAuthConfig, _oauth_kwargs)]
)
def test_every_feature_config_preserves_supplied_documentation_metadata(factory: "Any", kwargs: "Any") -> None:
    """The configured object is preserved by identity, not rebuilt."""
    docs = RouteDocs(tag_descriptions={"mfa": "How this deployment does second factors."})

    assert factory(**kwargs(), docs=docs).docs is docs


@pytest.mark.parametrize(
    ("factory", "kwargs"),
    [
        (LocalAuth.session, _local_auth_kwargs),
        (MFAConfig, _mfa_kwargs),
        (PasskeyConfig, _passkey_kwargs),
        (OAuthConfig, _oauth_kwargs),
    ],
)
def test_documentation_metadata_must_be_route_docs(factory: "Any", kwargs: "Any") -> None:
    """A mapping passed where a RouteDocs belongs is rejected at configuration time."""
    with pytest.raises(ImproperlyConfiguredException, match="documentation"):
        factory(**kwargs(), docs=cast("Any", {"mfa": "Two-factor"}))


def test_local_auth_reports_its_effective_tags_for_a_custom_controller_mount() -> None:
    """A profile that generates no routes contributes no tags; one that does reports its own."""
    silent = LocalAuth.session(**_local_auth_kwargs(), register_routes=False)
    documented = LocalAuth.session(**_local_auth_kwargs(), docs=RouteDocs(tags={"local.sessions": "Sessions"}))

    assert silent.openapi_tags() == ()
    assert [tag.name for tag in documented.openapi_tags()] == [
        "Sessions",
        "Local tokens",
        "Local registration",
        "Local passwords",
        "Local verification",
    ]
