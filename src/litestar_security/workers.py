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
from contextlib import suppress
from dataclasses import dataclass, field
from functools import partial
from math import isfinite
from time import perf_counter
from types import MappingProxyType
from typing import Generic, Protocol, TypeVar, runtime_checkable

from anyio import CapacityLimiter, fail_after, to_thread
from litestar.exceptions import ImproperlyConfiguredException

__all__ = (
    "BlockingCallRunner",
    "BlockingIntegration",
    "NoOpSecurityMetrics",
    "SecurityMetrics",
    "WorkerLimits",
    "metric_sink",
    "run_in_cpu_worker",
    "run_in_io_worker",
    "safe_increment",
    "safe_observe",
)

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
        ...

    def observe(self, name: str, value: float, *, attributes: Mapping[str, str] = _EMPTY_METRIC_ATTRIBUTES) -> None:
        """Observe one security duration or size.

        Args:
            name: The measurement name.
            value: The observed value.
            attributes: Dimensions to record with the observation.
        """
        ...


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


def metric_sink(metrics: SecurityMetrics | None) -> SecurityMetrics:
    """Return the given metric sink or a NoOpSecurityMetrics instance."""
    return NoOpSecurityMetrics() if metrics is None else metrics


def safe_increment(metrics: SecurityMetrics, name: str) -> None:
    """Safely increment a counter without propagating metric errors."""
    with suppress(Exception):
        metrics.increment(name)


def safe_observe(metrics: SecurityMetrics, name: str, value: float) -> None:
    """Safely observe a measurement without propagating metric errors."""
    with suppress(Exception):
        metrics.observe(name, value)


async def run_in_cpu_worker(
    operation: Callable[[], ResultT],
    *,
    limiter: CapacityLimiter,
    worker_timeout: float = 10.0,
    metrics: SecurityMetrics | None = None,
    operation_metric: str = "security.worker.cpu_duration",
) -> ResultT:
    """Run a CPU-bound operation off the event loop inside a bounded limiter."""
    sink = metric_sink(metrics)
    if limiter.borrowed_tokens >= limiter.total_tokens:
        safe_increment(sink, "security.worker.saturation")
    queued_at = perf_counter()

    def run() -> ResultT:
        started = perf_counter()
        safe_observe(sink, "security.worker.wait", started - queued_at)
        try:
            return operation()
        finally:
            elapsed = perf_counter() - started
            safe_observe(sink, "security.worker.duration", elapsed)
            safe_observe(sink, operation_metric, elapsed)

    with fail_after(worker_timeout):
        return await to_thread.run_sync(run, abandon_on_cancel=True, limiter=limiter)


async def run_in_io_worker(
    operation: Callable[[], ResultT],
    *,
    limiter: CapacityLimiter,
    worker_timeout: float = 10.0,
    metrics: SecurityMetrics | None = None,
    operation_metric: str = "security.worker.io_duration",
) -> ResultT:
    """Run an I/O-bound operation off the event loop inside a bounded limiter."""
    sink = metric_sink(metrics)
    if limiter.borrowed_tokens >= limiter.total_tokens:
        safe_increment(sink, "security.worker.saturation")
    queued_at = perf_counter()

    def run() -> ResultT:
        started = perf_counter()
        safe_observe(sink, "security.worker.wait", started - queued_at)
        try:
            return operation()
        finally:
            elapsed = perf_counter() - started
            safe_observe(sink, "security.worker.duration", elapsed)
            safe_observe(sink, operation_metric, elapsed)

    with fail_after(worker_timeout):
        return await to_thread.run_sync(run, abandon_on_cancel=False, limiter=limiter)


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
            if type(value) is not int or not 1 <= value <= _MAXIMUM_WORKER_TOKENS:
                msg = "Security worker limits must be positive bounded integers"
                raise ImproperlyConfiguredException(detail=msg)
        if type(self.timeout) not in {int, float} or not isfinite(self.timeout) or self.timeout <= 0:
            msg = "Security worker timeout must be finite and positive"
            raise ImproperlyConfiguredException(detail=msg)
        object.__setattr__(self, "timeout", float(self.timeout))
        object.__setattr__(self, "network_limiter", CapacityLimiter(self.network_tokens))
        object.__setattr__(self, "crypto_limiter", CapacityLimiter(self.crypto_tokens))
