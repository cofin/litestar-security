"""Public package exports for Litestar Security."""

from typing import TYPE_CHECKING, Any

from litestar_security.__metadata__ import __project__, __version__
from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationOutcome,
    AuthenticationPolicy,
    AuthenticationRegistry,
    AuthorizationResolver,
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
from litestar_security.config import BlockingIntegration, ExternalCSRF, MFAConfig, PasskeyConfig, SecurityConfig
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
    intersect_authorization,
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
from litestar_security.headers import ContentSecurityPolicy, CSPMode, SecurityHeadersConfig, csp_nonce
from litestar_security.plugin import CurrentUser, PrincipalDependency, SecurityContextDependency, SecurityPlugin
from litestar_security.websocket import (
    AuthorizationSnapshotRefresher,
    InMemoryWebSocketTicketStore,
    IssuedWebSocketTicket,
    WebSocketBinding,
    WebSocketCloseCodes,
    WebSocketRevocationSource,
    WebSocketSecurityConfig,
    WebSocketTicketRecord,
    WebSocketTicketService,
    WebSocketTicketStore,
    issue_websocket_ticket,
    websocket_policy_fingerprint,
)

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
    "AuthorizationResolver",
    "AuthorizationSnapshot",
    "AuthorizationSnapshotRefresher",
    "BlockingIntegration",
    "CSPMode",
    "ContentSecurityPolicy",
    "CredentialExtraction",
    "CredentialRestrictions",
    "CredentialSlot",
    "CurrentUser",
    "ExternalCSRF",
    "GitHubOAuthProvider",
    "IdentityResolution",
    "IdentityResolver",
    "InMemoryWebSocketTicketStore",
    "InvalidCredentials",
    "IssuedWebSocketTicket",
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
    "SecurityHeadersConfig",
    "SecurityPlugin",
    "SessionHandle",
    "SessionPersistenceUnavailableError",
    "SessionUnavailableError",
    "TokenVault",
    "VerificationUnavailable",
    "WebSocketBinding",
    "WebSocketCloseCodes",
    "WebSocketRevocationSource",
    "WebSocketSecurityConfig",
    "WebSocketTicketRecord",
    "WebSocketTicketService",
    "WebSocketTicketStore",
    "__project__",
    "__version__",
    "all_of",
    "any_of",
    "at_least",
    "csp_nonce",
    "guard_all_of",
    "guard_any_of",
    "guard_at_least",
    "guard_one_of",
    "intersect_authorization",
    "issue_websocket_ticket",
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
    "websocket_policy_fingerprint",
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
