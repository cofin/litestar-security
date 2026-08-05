"""Application-owned OpenAPI documentation metadata for generated routes.

Every generated route is filed under one tag group. A group is addressed by a
stable key rather than by its display name, so an application that renames a
group keeps addressing it by the same key. Declaration order below is display
order in the emitted document.
"""

from collections.abc import Mapping
from types import MappingProxyType

from litestar.openapi.spec import Tag

__all__ = ("ROUTE_TAGS",)


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
