"""Token signer protocols and normalization of sync or async customization.

This module owns only the protocol surface. Concrete local signing lives with the
key ring, which is what actually holds private key material.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from inspect import iscoroutinefunction
from typing import Protocol, cast, runtime_checkable

from litestar_security.providers._internal import JSONValue, raise_config
from litestar_security.providers.jwt._workers import metric_sink, run_worker
from litestar_security.workers import SecurityMetrics, WorkerLimits

__all__ = ("SyncTokenSigner", "TokenSigner", "normalize_signer")


@runtime_checkable
class TokenSigner(Protocol):
    """Sign caller-built local claims without owning application persistence.

    Implementations emit access JWTs whose protected header has a non-empty
    ``kid``, a supported non-``none`` ``alg``, and ``typ="at+jwt"``. Untrusted
    caller claims must not choose those headers.
    """

    async def sign(self, claims: Mapping[str, JSONValue], *, now: datetime) -> str:
        """Return one compact signed access token.

        Args:
            claims: The claim set to sign.
            now: The signing timestamp.

        Returns:
            A compact access JWT with the required protected-header profile.

        Raises:
            Exception: When signing cannot produce that access JWT.
        """
        ...  # pragma: no cover


@runtime_checkable
class SyncTokenSigner(Protocol):
    """Blocking custom access-JWT signer normalized once into the crypto worker.

    Implementations emit access JWTs whose protected header has a non-empty
    ``kid``, a supported non-``none`` ``alg``, and ``typ="at+jwt"``. Untrusted
    caller claims must not choose those headers.
    """

    def sign(self, claims: Mapping[str, JSONValue], *, now: datetime) -> str:
        """Return one compact signed access token.

        Args:
            claims: The claim set to sign.
            now: The signing timestamp.

        Returns:
            A compact access JWT with the required protected-header profile.

        Raises:
            Exception: When signing cannot produce that access JWT.
        """
        ...  # pragma: no cover


def normalize_signer(
    signer: TokenSigner | SyncTokenSigner,
    *,
    worker_limits: WorkerLimits | None = None,
    metrics: SecurityMetrics | None = None,
) -> TokenSigner:
    """Normalize one custom signer once without blocking the event loop.

    Args:
        signer: The application's signer, blocking or async.
        worker_limits: The shared crypto-worker budget a blocking signer runs inside.
        metrics: The sink offered signing measurements.

    Returns:
        An async signer.
    """
    sign_method = getattr(signer, "sign", None)
    if not callable(sign_method):
        raise_config("Token signer must define sign")
    workers = WorkerLimits() if worker_limits is None else worker_limits
    if not isinstance(workers, WorkerLimits):  # pyright: ignore[reportUnnecessaryIsInstance] - defend runtime port boundary
        raise_config("Token signer worker limits must be WorkerLimits")
    sink = metric_sink(metrics)
    if iscoroutinefunction(sign_method):
        return cast("TokenSigner", signer)
    return _WorkerTokenSigner(sign_sync=cast("Callable[..., str]", sign_method), workers=workers, metrics=sink)


@dataclass(frozen=True, slots=True)
class _WorkerTokenSigner:
    sign_sync: Callable[..., str] = field(repr=False)
    workers: WorkerLimits = field(repr=False)
    metrics: SecurityMetrics = field(repr=False)

    async def sign(self, claims: Mapping[str, JSONValue], *, now: datetime) -> str:
        try:
            return await run_worker(
                partial(self.sign_sync, claims, now=now),
                limiter=self.workers.crypto_limiter,
                worker_timeout=self.workers.timeout,
                metrics=self.metrics,
                operation_metric="security.jwt.sign_duration",
            )
        except Exception:  # noqa: BLE001 - application-supplied code may raise anything; fail closed
            message = "Token signing unavailable"
            raise RuntimeError(message) from None
