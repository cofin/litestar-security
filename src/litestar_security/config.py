"""Configuration for the Litestar Security plugin."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from functools import partial
from inspect import iscoroutinefunction
from math import isfinite
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic, Literal, Protocol, TypeVar, cast, runtime_checkable

from anyio import CapacityLimiter, to_thread
from litestar.config.csrf import CSRFConfig
from litestar.exceptions import ImproperlyConfiguredException
from litestar.middleware.session.base import BaseSessionBackend

from litestar_security.authentication import (
    AuthenticationMechanism,
    AuthenticationPolicy,
    AuthorizationResolver,
    CredentialSlot,
    required,
)
from litestar_security.headers import SecurityHeadersConfig
from litestar_security.websocket import WebSocketSecurityConfig

if TYPE_CHECKING:
    from litestar_security.accounts import (
        AttestationTrustMapper,
        LoginMethodStore,
        RecoveryCodePepper,
        SecurityEventSink,
        TOTPPolicy,
    )
    from litestar_security.accounts._profiles import LocalAuthConfig
    from litestar_security.providers.api_key import APIKeyConfig
    from litestar_security.providers.iap import GoogleIAPConfig
    from litestar_security.providers.jwks import JWKSProvider
    from litestar_security.providers.jwt import LocalJWKSConfig
    from litestar_security.providers.oauth import OAuthConfig
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
class BlockingIntegration(Generic[SyncT]):
    """Mark one explicitly synchronous application integration for startup normalization.

    Args:
        implementation: The complete synchronous feature protocol.
    """

    implementation: SyncT = field(repr=False)


@dataclass(slots=True)
class BlockingCallRunner:
    """Submit explicit blocking feature operations through one finite worker budget."""

    limiter: CapacityLimiter = field(default_factory=lambda: CapacityLimiter(8), repr=False)

    async def run(self, function: Callable[..., ResultT], /, *args: object, **kwargs: object) -> ResultT:
        """Run one complete blocking operation without abandoning an in-flight mutation.

        Args:
            function: The synchronous atomic operation.
            *args: Positional arguments forwarded to the operation.
            **kwargs: Keyword arguments forwarded to the operation.

        Returns:
            The operation result after its worker job completes.
        """
        call = partial(function, *args, **kwargs)
        return await to_thread.run_sync(call, abandon_on_cancel=False, limiter=self.limiter)


@runtime_checkable
class SecurityMetrics(Protocol):
    """Vendor-neutral synchronous metric sink that must not block."""

    def increment(self, name: str, *, attributes: Mapping[str, str] = _EMPTY_METRIC_ATTRIBUTES) -> None:
        """Increment one security counter.

        Args:
            name: The counter name.
            attributes: Dimensions to record with the increment.
        """
        ...  # pragma: no cover

    def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = _EMPTY_METRIC_ATTRIBUTES) -> None:
        """Observe one security duration or size.

        Args:
            name: The measurement name.
            value: The observed value.
            attributes: Dimensions to record with the observation.
        """
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class NoOpSecurityMetrics:
    """Default metric sink with zero vendor or runtime overhead."""

    def increment(self, name: str, *, attributes: Mapping[str, str] = _EMPTY_METRIC_ATTRIBUTES) -> None:
        """Ignore a counter.

        Args:
            name: The counter name.
            attributes: Dimensions to record with the increment.
        """

    def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = _EMPTY_METRIC_ATTRIBUTES) -> None:
        """Ignore an observation.

        Args:
            name: The measurement name.
            value: The observed value.
            attributes: Dimensions to record with the observation.
        """


@dataclass(frozen=True, slots=True)
class WorkerLimits:
    """Paired dedicated limiters that components may share as one worker budget."""

    network_tokens: int = 8
    crypto_tokens: int = 32
    timeout: float = 10.0
    network_limiter: CapacityLimiter = field(init=False, repr=False, compare=False)
    crypto_limiter: CapacityLimiter = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Build dedicated limiters once after validating finite bounds."""
        for value in (self.network_tokens, self.crypto_tokens):
            if value.__class__ is not int or not 1 <= value <= _MAXIMUM_WORKER_TOKENS:
                msg = "Security worker limits must be positive bounded integers"
                raise ImproperlyConfiguredException(detail=msg)
        if self.timeout.__class__ not in {int, float} or not isfinite(self.timeout) or self.timeout <= 0:
            msg = "Security worker timeout must be finite and positive"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "timeout", float(self.timeout))
        object.__setattr__(self, "network_limiter", CapacityLimiter(self.network_tokens))
        object.__setattr__(self, "crypto_limiter", CapacityLimiter(self.crypto_tokens))


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
    route_prefix: str = "/auth"
    issuer: str = "Litestar Security"
    register_routes: bool = True
    service: object = field(init=False, repr=False, compare=False)
    step_up_service: object | None = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Build project-owned services from explicit application ports."""
        from litestar_security.accounts import (  # noqa: PLC0415 - avoids the accounts profile/config cycle
            MFAService,
            StepUpService,
            StepUpStore,
        )

        service_kwargs: dict[str, object] = {
            "store": self.store,
            "secret_protector": self.secret_protector,
            "issuer": self.issuer,
            "recovery_peppers": tuple(self.recovery_peppers),
            "login_methods": self.login_methods,
        }
        if self.policy is not None:
            service_kwargs["policy"] = self.policy
        if self.events is not None:
            service_kwargs["events"] = self.events
        object.__setattr__(self, "service", MFAService(**cast("Any", service_kwargs)))
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
        if self.register_routes and (not self.recovery_peppers or self.login_methods is None):
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
    service: object = field(init=False, repr=False, compare=False)
    step_up_service: object | None = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Freeze relying-party origins and build the project-owned service."""
        from litestar_security.accounts import (  # noqa: PLC0415 - avoids the accounts profile/config cycle
            PasskeyService,
            StepUpService,
            StepUpStore,
        )

        object.__setattr__(self, "origins", tuple(self.origins))
        object.__setattr__(self, "algorithms", tuple(self.algorithms))
        service_kwargs = {
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
            service_kwargs["events"] = self.events
        object.__setattr__(self, "service", PasskeyService(**cast("Any", service_kwargs)))
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


@dataclass(slots=True)
class SecurityConfig(Generic[UserT]):
    """Configure the per-application security runtime."""

    slots: Sequence[CredentialSlot[Any]] = ()
    mechanisms: Sequence[AuthenticationMechanism[Any, Any, UserT]] = ()
    default_policy: AuthenticationPolicy = field(default_factory=required)
    openapi_policy: AuthenticationPolicy | None = None
    max_openapi_combinations: int = 32
    csrf_config: CSRFConfig | None = None
    external_csrf: ExternalCSRF | None = None
    require_default: bool = False
    session_backend: BaseSessionBackend[Any] | None = None
    local_auth: "LocalAuthConfig[UserT] | None" = None
    local_jwks: "LocalJWKSConfig | None" = None
    oauth: "OAuthConfig | None" = None
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
        csrf_config = cast("object | None", self.csrf_config)
        external_csrf = cast("object | None", self.external_csrf)
        if csrf_config is not None and not isinstance(csrf_config, CSRFConfig):
            msg = "Native CSRF configuration must be a Litestar CSRFConfig"
            raise ImproperlyConfiguredException(detail=msg)
        if external_csrf is not None and not isinstance(external_csrf, ExternalCSRF):
            msg = "External CSRF configuration must be an ExternalCSRF assertion"
            raise ImproperlyConfiguredException(detail=msg)
        headers = cast("object | None", self.headers)
        if headers is not None and not isinstance(headers, SecurityHeadersConfig):
            msg = "Browser security headers must be a SecurityHeadersConfig"
            raise ImproperlyConfiguredException(detail=msg)
        if csrf_config is not None and external_csrf is not None:
            msg = "Security configuration cannot combine native and external CSRF enforcement"
            raise ImproperlyConfiguredException(detail=msg)
        self.slots = tuple(self.slots)
        self.mechanisms = tuple(self.mechanisms)
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
