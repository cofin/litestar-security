"""Public package exports for Litestar Security."""

from litestar_security.__metadata__ import __project__, __version__
from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationOutcome,
    AuthenticationRegistry,
    CredentialExtraction,
    CredentialSlot,
    IdentityResolver,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    RequestAuthenticator,
    VerificationUnavailable,
)
from litestar_security.config import SecurityConfig
from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    CredentialRestrictions,
    LitestarSessionHandle,
    NullSessionHandle,
    Principal,
    SecurityContext,
    SessionHandle,
    SessionPersistenceUnavailableError,
    SessionUnavailableError,
)
from litestar_security.plugin import CurrentUser, PrincipalDependency, SecurityContextDependency, SecurityPlugin

__all__ = (
    "Authenticated",
    "AuthenticationEvidence",
    "AuthenticationMechanism",
    "AuthenticationOutcome",
    "AuthenticationRegistry",
    "AuthorizationSnapshot",
    "CredentialExtraction",
    "CredentialRestrictions",
    "CredentialSlot",
    "CurrentUser",
    "IdentityResolver",
    "InvalidCredentials",
    "LitestarSessionHandle",
    "NoCredentials",
    "NullSessionHandle",
    "PresentedCredential",
    "Principal",
    "PrincipalDependency",
    "RequestAuthenticator",
    "SecurityConfig",
    "SecurityContext",
    "SecurityContextDependency",
    "SecurityPlugin",
    "SessionHandle",
    "SessionPersistenceUnavailableError",
    "SessionUnavailableError",
    "VerificationUnavailable",
    "__project__",
    "__version__",
)
