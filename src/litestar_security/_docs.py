"""Application-owned OpenAPI documentation metadata for generated routes.

Every generated route is filed under one tag group. A group is addressed by a
stable key rather than by its display name, so an application that renames a
group keeps addressing it by the same key. Declaration order below is display
order in the emitted document.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi.spec import Tag

__all__ = ("ROUTE_TAGS", "RouteDocs")


ROUTE_TAGS: Mapping[str, Tag] = MappingProxyType({
    # A reader meets the two ways to log in before the flows that repair an
    # account they cannot log in to.
    "local.sessions": Tag(
        name="Local sessions",
        description=(
            "Cookie-based login for browser clients, plus the caller's own session inventory. "
            "Every route here is scoped to the authenticated caller: there is no administrative view."
        ),
    ),
    "local.tokens": Tag(
        name="Local tokens",
        description=(
            "Bearer login for non-browser clients. Refresh tokens rotate strictly, so replaying a "
            "consumed token revokes its whole family rather than returning a new pair."
        ),
    ),
    "local.registration": Tag(
        name="Local registration",
        description=(
            "Self-service account creation under the configured registration policy. The response is "
            "identical whether or not the identifier was already taken, so it never confirms an account."
        ),
    ),
    "local.passwords": Tag(
        name="Local passwords",
        description=(
            "Password change for an authenticated caller and the recovery flow for one who cannot sign in. "
            "Both raise the account security epoch, which invalidates credentials issued before the change."
        ),
    ),
    "local.verification": Tag(
        name="Local verification",
        description=(
            "Account-verification token issue and consumption. Requesting a token returns the same response "
            "for every identifier, so it never confirms an account."
        ),
    ),
    "mfa": Tag(
        name="Multi-factor authentication",
        description=(
            "Enrollment and removal of time-based codes and recovery codes. Changing how an account is "
            "protected consumes a fresh step-up grant, so a stolen session cannot weaken it silently."
        ),
    ),
    "passkeys": Tag(
        name="Passkeys",
        description=(
            "WebAuthn credential registration and assertion. Each challenge is single-use and bound to the "
            "browser that requested it, and the credential's private key never leaves the authenticator."
        ),
    ),
    "step_up": Tag(
        name="Step-up authentication",
        description=(
            "Re-proof of a strong factor immediately before a sensitive operation. A grant is bound to one "
            "purpose at one security epoch and is consumed on first use, so it cannot be replayed or reused."
        ),
    ),
    "oauth.providers": Tag(
        name="OAuth providers",
        description=(
            "Interactive provider login, account linking, scope upgrades, and token revocation. Every "
            "authorization round trip is bound to a cookie the same browser must present at the callback."
        ),
    ),
    "oidc.logout": Tag(
        name="OIDC logout",
        description=(
            "Provider-initiated front- and back-channel logout. A logout token is verified against the "
            "configured issuer and its identifier is consumed once, so a replayed notification revokes nothing."
        ),
    ),
})


def _no_overrides() -> "dict[str, str]":
    return {}


def _frozen_overrides(values: "Mapping[str, str]", *, subject: str) -> "Mapping[str, str]":
    unknown = sorted(set(values) - set(ROUTE_TAGS))
    if unknown:
        message = f"Unknown generated-route tag group: {', '.join(unknown)}"
        raise ImproperlyConfiguredException(detail=message)
    blank = sorted(key for key, value in values.items() if value.__class__ is not str or not value.strip())
    if blank:
        message = f"Generated-route tag {subject} must be a non-blank string: {', '.join(blank)}"
        raise ImproperlyConfiguredException(detail=message)
    return MappingProxyType(dict(values))


@dataclass(frozen=True, slots=True)
class RouteDocs:
    """Application-owned OpenAPI documentation for generated routes.

    Tag groups are addressed by the stable keys of :data:`ROUTE_TAGS`, never by
    their display names, so an application that renames a group keeps addressing
    it by the key it already used. None of this is security policy: an
    application cannot change what a route requires by documenting it
    differently.
    """

    tags: Mapping[str, str] = field(default_factory=_no_overrides)
    """Replacement display name per stable tag-group key."""
    tag_descriptions: Mapping[str, str] = field(default_factory=_no_overrides)
    """Replacement description per stable tag-group key."""
    operation_id: Callable[[str], str] | None = None
    """Rewrite every generated ``operation_id``, which names the generated client function."""
    route_name: Callable[[str], str] | None = None
    """Rewrite every generated route ``name``, which ``route_reverse`` resolves."""

    def __post_init__(self) -> None:
        """Freeze the supplied mappings and reject an override nothing can apply to.

        Raises:
            ImproperlyConfiguredException: If a key names no generated tag group,
                an override is blank, or a transform is not callable.
        """
        object.__setattr__(self, "tags", _frozen_overrides(self.tags, subject="display name"))
        object.__setattr__(self, "tag_descriptions", _frozen_overrides(self.tag_descriptions, subject="description"))
        for name in ("operation_id", "route_name"):
            transform: object = getattr(self, name)
            if transform is not None and not callable(transform):
                message = f"Generated-route {name} transform must be callable"
                raise ImproperlyConfiguredException(detail=message)
