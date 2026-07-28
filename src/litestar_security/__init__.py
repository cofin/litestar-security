"""Public package exports for Litestar Security."""

from typing import TYPE_CHECKING, Any

from litestar_security.__metadata__ import __project__, __version__
from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationOutcome,
    AuthenticationPolicy,
    AuthenticationRegistry,
    CredentialExtraction,
    CredentialSlot,
    IdentityResolution,
    IdentityResolver,
    InvalidCredentials,
    MechanismRequirement,
    NoCredentials,
    PresentedCredential,
    RequestAuthenticator,
    VerificationUnavailable,
    all_of,
    any_of,
    at_least,
    mechanism,
    optional,
    public,
    required,
    security,
)
from litestar_security.config import ExternalCSRF, MFAConfig, PasskeyConfig, SecurityConfig
from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    CredentialRestrictions,
    LitestarSessionHandle,
    NullSessionHandle,
    Principal,
    ResourcePermission,
    SecurityContext,
    SessionHandle,
    SessionPersistenceUnavailableError,
    SessionUnavailableError,
)
from litestar_security.guards import (
    AssuranceRequirement,
    AssuranceTrait,
    AuthorizationDecision,
    AuthorizationPredicate,
    requires_assurance,
    requires_authenticated,
    requires_capability,
    requires_role,
    requires_scope,
    requires_team_role,
    requires_tenant,
)
from litestar_security.guards import all_of as guard_all_of
from litestar_security.guards import any_of as guard_any_of
from litestar_security.guards import at_least as guard_at_least
from litestar_security.guards import one_of as guard_one_of
from litestar_security.plugin import CurrentUser, PrincipalDependency, SecurityContextDependency, SecurityPlugin

if TYPE_CHECKING:
    from litestar_security.providers.oauth import (
        GitHubOAuthProvider,
        OAuthAccountService,
        OAuthAccountStore,
        OAuthConfig,
        OAuthProvider,
        OAuthRouteService,
        TokenVault,
    )

__all__ = (
    "AssuranceRequirement",
    "AssuranceTrait",
    "Authenticated",
    "AuthenticationEvidence",
    "AuthenticationMechanism",
    "AuthenticationOutcome",
    "AuthenticationPolicy",
    "AuthenticationRegistry",
    "AuthorizationDecision",
    "AuthorizationPredicate",
    "AuthorizationSnapshot",
    "CredentialExtraction",
    "CredentialRestrictions",
    "CredentialSlot",
    "CurrentUser",
    "ExternalCSRF",
    "GitHubOAuthProvider",
    "IdentityResolution",
    "IdentityResolver",
    "InvalidCredentials",
    "LitestarSessionHandle",
    "MFAConfig",
    "MechanismRequirement",
    "NoCredentials",
    "NullSessionHandle",
    "OAuthAccountService",
    "OAuthAccountStore",
    "OAuthConfig",
    "OAuthProvider",
    "OAuthRouteService",
    "PasskeyConfig",
    "PresentedCredential",
    "Principal",
    "PrincipalDependency",
    "RequestAuthenticator",
    "ResourcePermission",
    "SecurityConfig",
    "SecurityContext",
    "SecurityContextDependency",
    "SecurityPlugin",
    "SessionHandle",
    "SessionPersistenceUnavailableError",
    "SessionUnavailableError",
    "TokenVault",
    "VerificationUnavailable",
    "__project__",
    "__version__",
    "all_of",
    "any_of",
    "at_least",
    "guard_all_of",
    "guard_any_of",
    "guard_at_least",
    "guard_one_of",
    "mechanism",
    "optional",
    "public",
    "required",
    "requires_assurance",
    "requires_authenticated",
    "requires_capability",
    "requires_role",
    "requires_scope",
    "requires_team_role",
    "requires_tenant",
    "security",
)

_OAUTH_EXPORTS = frozenset({
    "GitHubOAuthProvider",
    "OAuthAccountService",
    "OAuthAccountStore",
    "OAuthConfig",
    "OAuthProvider",
    "OAuthRouteService",
    "TokenVault",
})


def __getattr__(name: str) -> Any:  # noqa: ANN401 - module lazy-export hooks are dynamically typed
    """Resolve curated OAuth exports without loading providers at root import."""
    if name in _OAUTH_EXPORTS:
        from litestar_security import providers  # noqa: PLC0415 - preserve lightweight package-root imports

        return getattr(providers, name)
    message = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(message)
