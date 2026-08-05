"""Unit contracts for the generated-route documentation registry and metadata type."""

from litestar_security._docs import ROUTE_TAGS


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
