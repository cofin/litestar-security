"""Bounded worker offload for synchronous signer and verifier customization.

Sync callables are shared, so they run through an explicit finite capacity limiter
rather than the default thread pool. Metric sinks are isolated here because a
failing sink must never change the outcome of a sign or verify call.
"""

from collections.abc import Callable
from time import perf_counter
from typing import TypeVar

from anyio import CapacityLimiter, fail_after, to_thread

from litestar_security.config import NoOpSecurityMetrics, SecurityMetrics
from litestar_security.providers._internal import raise_config, safe_increment, safe_observe

ResultT = TypeVar("ResultT")
_MAXIMUM_WORKER_TOKENS = 1_024


def metric_sink(metrics: SecurityMetrics | None) -> SecurityMetrics:
    sink = NoOpSecurityMetrics() if metrics is None else metrics
    if not callable(getattr(sink, "increment", None)) or not callable(getattr(sink, "observe", None)):
        raise_config("JWT metrics must implement SecurityMetrics")
    return sink


def validate_limiter(limiter: object) -> CapacityLimiter:
    total_tokens: object = getattr(limiter, "total_tokens", None)
    if (
        not isinstance(limiter, CapacityLimiter)
        or not isinstance(total_tokens, int)
        or isinstance(total_tokens, bool)
        or not 1 <= total_tokens <= _MAXIMUM_WORKER_TOKENS
    ):
        raise_config("JWT worker limiter must have finite bounded capacity")
    return limiter


async def run_worker(
    operation: Callable[[], ResultT],
    *,
    limiter: CapacityLimiter,
    worker_timeout: float,
    metrics: SecurityMetrics,
    operation_metric: str,
) -> ResultT:
    if limiter.borrowed_tokens >= limiter.total_tokens:
        safe_increment(metrics, "security.worker.saturation")
    queued_at = perf_counter()

    def run() -> ResultT:
        started = perf_counter()
        safe_observe(metrics, "security.worker.wait", started - queued_at)
        try:
            return operation()
        finally:
            elapsed = perf_counter() - started
            safe_observe(metrics, "security.worker.duration", elapsed)
            safe_observe(metrics, operation_metric, elapsed)

    with fail_after(worker_timeout):
        return await to_thread.run_sync(run, abandon_on_cancel=True, limiter=limiter)
