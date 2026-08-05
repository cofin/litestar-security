"""Configuration for the Litestar Security plugin."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import timedelta
from inspect import iscoroutinefunction
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeVar, cast

from litestar.exceptions import ImproperlyConfiguredException

from litestar_security._docs import RouteDocs
from litestar_security.authentication import (
    AuthenticationMechanism,
    AuthenticationPolicy,
    AuthorizationResolver,
    CredentialSlot,
)
from litestar_security.headers import SecurityHeadersConfig
from litestar_security.websocket import WebSocketSecurityConfig
from litestar_security.workers import BlockingIntegration, NoOpSecurityMetrics, SecurityMetrics, WorkerLimits

if TYPE_CHECKING:
    from litestar_security.accounts import (
        AttestationTrustMapper,
        LocalAuthConfig,
        LoginMethodStore,
        RecoveryCodePepper,
        SecurityEventSink,
        TOTPPolicy,
    )
    from litestar_security.providers.api_key import APIKeyConfig
    from litestar_security.providers.iap import GoogleIAPConfig
    from litestar_security.providers.jwks import JWKSProvider
    from litestar_security.providers.jwt import LocalJWKSConfig
    from litestar_security.providers.oauth import OAuthConfig, ProtectedResourceConfig
    from litestar_security.providers.oidc import ServiceTokenConfig

__all__ = (
    "BlockingIntegration",
    "ExternalCSRF",
    "MFAConfig",
    "NoOpSecurityMetrics",
    "PasskeyConfig",
    "SecurityConfig",
    "SecurityMetrics",
    "WorkerLimits",
)

UserT = TypeVar("UserT")
SyncT = TypeVar("SyncT")
ResultT = TypeVar("ResultT")
_EMPTY_METRIC_ATTRIBUTES: Mapping[str, str] = MappingProxyType({})
_MAXIMUM_WORKER_TOKENS = 1_024
_ASCII_CONTROL_LIMIT = 32


@dataclass(frozen=True, slots=True)
class ExternalCSRF:
    """Declare a named application-owned CSRF coverage validator."""

    name: str
    validate: Callable[[str, str, AuthenticationPolicy], bool] = field(repr=False)

    def __post_init__(self) -> None:
        """Normalize the integration name."""
        name_value = cast("object", self.name)
        if name_value.__class__ is not str:
            message = "External CSRF integration name must be text"
            raise ImproperlyConfiguredException(detail=message)
        name = cast("str", name_value).strip()  # type: ignore[redundant-cast]  # mypy narrows this; pyright does not
        if not name:
            message = "External CSRF integration name must not be blank"
            raise ImproperlyConfiguredException(detail=message)
        validator = cast("object", self.validate)
        if not callable(validator):
            message = "External CSRF validation hook must be callable"
            raise ImproperlyConfiguredException(detail=message)
        if iscoroutinefunction(validator):
            message = "External CSRF validation hook must be synchronous"
            raise ImproperlyConfiguredException(detail=message)
        object.__setattr__(self, "name", name)


@dataclass(frozen=True, slots=True)
class MFAConfig:
    """Configure MFA capabilities without selecting a persistence technology."""

    store: object
    secret_protector: object = field(repr=False)
    policy: "TOTPPolicy | None" = None
    recovery_peppers: "Sequence[RecoveryCodePepper]" = field(default=(), repr=False)
    login_methods: "LoginMethodStore | None" = field(default=None, repr=False)
    events: "SecurityEventSink | None" = field(default=None, repr=False)
    step_up_store: object | None = field(default=None, repr=False)
    require_at_login: bool = False
    login_challenge_store: object | None = field(default=None, repr=False)
    route_prefix: str = "/auth"
    issuer: str = "Litestar Security"
    register_routes: bool = True
    docs: RouteDocs = field(default_factory=RouteDocs, repr=False)
    mfa_service: object = field(init=False, repr=False, compare=False)
    step_up_service: object | None = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Build project-owned services from explicit application ports."""
        from litestar_security.accounts import (  # noqa: PLC0415 - account services load only when configured
            MFALoginChallengeStore,
            MFAService,
            StepUpService,
            StepUpStore,
        )

        mfa_service_kwargs: dict[str, object] = {
            "store": self.store,
            "secret_protector": self.secret_protector,
            "issuer": self.issuer,
            "recovery_peppers": tuple(self.recovery_peppers),
            "login_methods": self.login_methods,
        }
        if self.policy is not None:
            mfa_service_kwargs["policy"] = self.policy
        if self.events is not None:
            mfa_service_kwargs["events"] = self.events
        object.__setattr__(self, "mfa_service", MFAService(**cast("Any", mfa_service_kwargs)))
        step_up_store = self.step_up_store if self.step_up_store is not None else self.store
        object.__setattr__(
            self,
            "step_up_service",
            StepUpService(cast("Any", step_up_store)) if isinstance(step_up_store, StepUpStore) else None,
        )
        object.__setattr__(self, "route_prefix", _feature_route_prefix(self.route_prefix))
        register_routes_value = cast("object", self.register_routes)
        if register_routes_value.__class__ is not bool:
            msg = "MFA route registration must be boolean"
            raise ImproperlyConfiguredException(detail=msg)
        if self.docs.__class__ is not RouteDocs:
            msg = "MFA documentation metadata must be RouteDocs"
            raise ImproperlyConfiguredException(detail=msg)
        require_at_login_value = cast("object", self.require_at_login)
        if require_at_login_value.__class__ is not bool:
            msg = "MFA require_at_login must be boolean"
            raise ImproperlyConfiguredException(detail=msg)
        login_challenge_store = self.login_challenge_store if self.login_challenge_store is not None else self.store
        if self.require_at_login and not isinstance(login_challenge_store, MFALoginChallengeStore):
            msg = "MFA login challenge store must implement MFALoginChallengeStore"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "login_challenge_store", login_challenge_store)
        if (self.register_routes or self.require_at_login) and (
            not self.recovery_peppers or self.login_methods is None
        ):
            msg = "Generated MFA routes require recovery-code peppers and a login-method store"
            raise ImproperlyConfiguredException(detail=msg)


@dataclass(frozen=True, slots=True)
class PasskeyConfig:
    """Configure exact WebAuthn relying-party and persistence boundaries."""

    store: object
    challenge_store: object
    rp_id: str
    origins: Sequence[str]
    rp_name: str = "Litestar Security"
    algorithms: Sequence[int] = (-8, -7, -257)
    challenge_ttl: timedelta = timedelta(minutes=5)
    allow_insecure_localhost: bool = False
    worker_timeout: float = 10.0
    attestation_trust: "AttestationTrustMapper | None" = field(default=None, repr=False)
    login_methods: "LoginMethodStore | None" = field(default=None, repr=False)
    events: "SecurityEventSink | None" = field(default=None, repr=False)
    step_up_store: object | None = field(default=None, repr=False)
    route_prefix: str = "/auth"
    register_routes: bool = True
    docs: RouteDocs = field(default_factory=RouteDocs, repr=False)
    passkey_service: object = field(init=False, repr=False, compare=False)
    step_up_service: object | None = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Freeze relying-party origins and build the project-owned service."""
        from litestar_security.accounts import (  # noqa: PLC0415 - account services load only when configured
            PasskeyService,
            StepUpService,
            StepUpStore,
        )

        object.__setattr__(self, "origins", tuple(self.origins))
        object.__setattr__(self, "algorithms", tuple(self.algorithms))
        passkey_service_kwargs = {
            "store": self.store,
            "challenge_store": self.challenge_store,
            "rp_id": self.rp_id,
            "rp_name": self.rp_name,
            "origins": self.origins,
            "algorithms": self.algorithms,
            "challenge_ttl": self.challenge_ttl,
            "allow_insecure_localhost": self.allow_insecure_localhost,
            "worker_timeout": self.worker_timeout,
            "attestation_trust": self.attestation_trust,
            "login_methods": self.login_methods,
        }
        if self.events is not None:
            passkey_service_kwargs["events"] = self.events
        object.__setattr__(self, "passkey_service", PasskeyService(**cast("Any", passkey_service_kwargs)))
        object.__setattr__(
            self,
            "step_up_service",
            StepUpService(cast("Any", self.step_up_store)) if isinstance(self.step_up_store, StepUpStore) else None,
        )
        object.__setattr__(self, "route_prefix", _feature_route_prefix(self.route_prefix))
        register_routes_value = cast("object", self.register_routes)
        if register_routes_value.__class__ is not bool:
            msg = "Passkey route registration must be boolean"
            raise ImproperlyConfiguredException(detail=msg)
        if self.docs.__class__ is not RouteDocs:
            msg = "Passkey documentation metadata must be RouteDocs"
            raise ImproperlyConfiguredException(detail=msg)
        if self.register_routes and self.login_methods is None:
            msg = "Generated passkey routes require a login-method store"
            raise ImproperlyConfiguredException(detail=msg)


def _feature_route_prefix(value: object) -> str:
    if not isinstance(value, str):
        msg = "MFA and passkey route prefixes must be absolute non-root paths"
        raise ImproperlyConfiguredException(detail=msg)
    normalized = value.rstrip("/")
    if (
        not normalized.startswith("/")
        or normalized == ""
        or "//" in normalized
        or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in normalized)
    ):
        msg = "MFA and passkey route prefixes must be absolute non-root paths"
        raise ImproperlyConfiguredException(detail=msg)
    return normalized


def _exclude_patterns(value: object) -> tuple[str, ...] | str | None:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, Sequence):
        given = tuple(cast("Sequence[object]", value))
        patterns = tuple(pattern for pattern in given if isinstance(pattern, str))
        if len(patterns) == len(given):
            return patterns
    msg = "Route exclusion patterns must be text or a sequence of text"
    raise ImproperlyConfiguredException(detail=msg)


@dataclass(slots=True)
class SecurityConfig(Generic[UserT]):
    """Configure the per-application security runtime."""

    slots: Sequence[CredentialSlot[Any]] = ()
    mechanisms: Sequence[AuthenticationMechanism[Any, Any, UserT]] = ()
    max_openapi_combinations: int = 32
    external_csrf: ExternalCSRF | None = None
    exclude: Sequence[str] | str | None = None
    """Regular expressions matched against a route path to exclude it from security.

    Mirrors ``JWTAuth.exclude``: a single pattern or a sequence of patterns,
    joined into one expression and compiled with :mod:`re`. A pattern is
    anchored at the start of the route path, so ``"^/static"`` and ``"/static"``
    both exclude ``/static/{file_path:path}`` while a bare ``"static"`` does not.

    Exclusion is total and applies when the route is compiled, not per request:
    an excluded route is never authenticated, carries no principal, and
    contributes an anonymous security requirement to OpenAPI rather than the
    configured schemes. A route that declares its own ``auth=`` and also matches
    a pattern is a contradiction and is rejected at startup.
    """
    require_default: bool = False
    local_auth: "LocalAuthConfig[UserT] | None" = None
    local_jwks: "LocalJWKSConfig | None" = None
    oauth: "OAuthConfig | None" = None
    protected_resource: "ProtectedResourceConfig | None" = None
    """Describe this application as an OAuth 2.1 protected resource.

    When set, the plugin publishes the RFC 9728 metadata document at
    ``/.well-known/oauth-protected-resource`` so an authorization server or a
    client can discover which issuers this resource trusts, which scopes it
    understands, and how a bearer token may be presented to it. The route is
    unauthenticated, as the specification requires.
    """
    mfa: MFAConfig | None = None
    passkeys: PasskeyConfig | None = None
    api_key: "APIKeyConfig | None" = None
    iap: "GoogleIAPConfig[UserT] | None" = None
    service_token: "ServiceTokenConfig | None" = None
    headers: SecurityHeadersConfig | None = None
    websocket: WebSocketSecurityConfig = field(default_factory=WebSocketSecurityConfig)
    authorization_resolver: AuthorizationResolver[UserT] | None = field(default=None, repr=False)
    jwks_providers: Sequence["JWKSProvider"] = ()
    jwks_warmup_failure: Literal["fail_startup", "lazy"] = "fail_startup"

    def __post_init__(self) -> None:
        """Freeze ordered authentication collections."""
        if self.max_openapi_combinations < 1:
            msg = "max_openapi_combinations must be positive"
            raise ImproperlyConfiguredException(detail=msg)
        external_csrf = cast("object | None", self.external_csrf)
        if external_csrf is not None and not isinstance(external_csrf, ExternalCSRF):
            msg = "External CSRF configuration must be an ExternalCSRF assertion"
            raise ImproperlyConfiguredException(detail=msg)
        headers = cast("object | None", self.headers)
        if headers is not None and not isinstance(headers, SecurityHeadersConfig):
            msg = "Browser security headers must be a SecurityHeadersConfig"
            raise ImproperlyConfiguredException(detail=msg)
        self._validate_protected_resource()
        self.exclude = _exclude_patterns(self.exclude)
        self.slots = tuple(self.slots)
        self.mechanisms = tuple(self.mechanisms)
        local_accounts = getattr(self.local_auth, "accounts", None)
        local_epoch = getattr(local_accounts, "current_epoch", None)
        if self.websocket.current_security_epoch is None and callable(local_epoch):
            self.websocket = replace(self.websocket, current_security_epoch=local_epoch)
        jwks_providers = list(self.jwks_providers)
        for provider in (
            None if self.iap is None else self.iap.jwks,
            None if self.service_token is None else self.service_token.jwks,
        ):
            if provider is not None and all(existing is not provider for existing in jwks_providers):
                jwks_providers.append(provider)
        self.jwks_providers = tuple(jwks_providers)
        if self.jwks_warmup_failure not in {"fail_startup", "lazy"}:
            msg = "JWKS warmup failure mode must be 'fail_startup' or 'lazy'"
            raise ImproperlyConfiguredException(detail=msg)

    def _validate_protected_resource(self) -> None:
        if self.protected_resource is None:
            return
        from litestar_security.providers.oauth import (  # noqa: PLC0415 - the OAuth tree loads only when configured
            ProtectedResourceConfig,
        )

        if not isinstance(cast("object", self.protected_resource), ProtectedResourceConfig):
            msg = "Protected resource metadata must be a ProtectedResourceConfig"
            raise ImproperlyConfiguredException(detail=msg)
