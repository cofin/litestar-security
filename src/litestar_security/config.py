"""Configuration for the Litestar Security plugin."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from inspect import iscoroutinefunction
from math import isfinite
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Generic, Literal, Protocol, TypeVar, cast, runtime_checkable

from anyio import CapacityLimiter
from litestar.config.csrf import CSRFConfig
from litestar.exceptions import ImproperlyConfiguredException
from litestar.middleware.session.base import BaseSessionBackend

from litestar_security.authentication import AuthenticationMechanism, AuthenticationPolicy, CredentialSlot, required

if TYPE_CHECKING:
    from litestar_security.accounts._profiles import LocalAuthConfig
    from litestar_security.providers.jwks import JWKSProvider
    from litestar_security.providers.jwt import LocalJWKSConfig

__all__ = ("ExternalCSRF", "NoOpSecurityMetrics", "SecurityConfig", "SecurityMetrics", "WorkerLimits")

UserT = TypeVar("UserT")
_EMPTY_METRIC_ATTRIBUTES: Mapping[str, str] = MappingProxyType({})
_MAXIMUM_WORKER_TOKENS = 1_024


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
        if csrf_config is not None and external_csrf is not None:
            msg = "Security configuration cannot combine native and external CSRF enforcement"
            raise ImproperlyConfiguredException(detail=msg)
        self.slots = tuple(self.slots)
        self.mechanisms = tuple(self.mechanisms)
        self.jwks_providers = tuple(self.jwks_providers)
        if self.jwks_warmup_failure not in {"fail_startup", "lazy"}:
            msg = "JWKS warmup failure mode must be 'fail_startup' or 'lazy'"
            raise ImproperlyConfiguredException(detail=msg)
