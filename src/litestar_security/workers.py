"""Runtime execution ports shared by the security components.

These are service ports rather than configuration: a worker budget, a metrics
sink, and the bridge that runs an application's blocking implementation off the
event loop. They live below `config` so that the account services and the token
providers can depend on them without depending on configuration, which in turn
lets configuration reach the account services without a cycle.

`litestar_security.config` re-exports every name here, which is the documented
import path.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import partial
from math import isfinite
from types import MappingProxyType
from typing import Generic, Protocol, TypeVar, runtime_checkable

from anyio import CapacityLimiter, to_thread
from litestar.exceptions import ImproperlyConfiguredException

__all__ = ("BlockingCallRunner", "BlockingIntegration", "NoOpSecurityMetrics", "SecurityMetrics", "WorkerLimits")

SyncT = TypeVar("SyncT")
ResultT = TypeVar("ResultT")
_EMPTY_METRIC_ATTRIBUTES: Mapping[str, str] = MappingProxyType({})
_MAXIMUM_WORKER_TOKENS = 1_024


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
