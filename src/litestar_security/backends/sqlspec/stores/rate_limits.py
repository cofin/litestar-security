"""SQLSpec persistence adapter for atomic rate limiting."""

from datetime import datetime, timezone
from hashlib import sha256
from math import ceil
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from litestar_security.accounts import DEFAULT_RATE_LIMIT_POLICIES, RateLimitAttempt, RateLimitDecision, RateLimitPolicy
from litestar_security.backends.sqlspec.schema import (
    TABLE_RATE_LIMIT_BUCKETS,
    quote_identifier,
    resolve_column,
    resolve_table_name,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from litestar_security.backends.sqlspec.backend import SQLSpecSecurityBackend

__all__ = ("SQLSpecRateLimiter",)


class SQLSpecRateLimiter:
    """Fixed-window rate limiter with atomic cross-process accounting via SQLSpec."""

    __slots__ = ("_backend", "_clock", "_policies", "_table_name")

    def __init__(
        self,
        backend: "SQLSpecSecurityBackend",
        *,
        policies: "Mapping[str, RateLimitPolicy] | None" = None,
        clock: "Callable[[], datetime] | None" = None,
    ) -> "None":
        """Initialize with backend, policies, and clock."""
        self._backend = backend
        self._table_name = resolve_table_name(backend.config, TABLE_RATE_LIMIT_BUCKETS)
        self._policies = MappingProxyType(dict(DEFAULT_RATE_LIMIT_POLICIES if policies is None else policies))
        self._clock = clock if clock is not None else (lambda: datetime.now(timezone.utc))

    async def acquire(self, request: "RateLimitAttempt") -> "RateLimitDecision":
        """Consume one attempt's cost from each applicable bucket atomically."""
        policy = self._policies.get(request.operation)
        if policy is None:
            return RateLimitDecision(allowed=True)

        now = self._clock()
        retry_after = 0

        for kind, value in (("c", request.client_key), ("s", request.subject_digest)):
            if value is None:
                continue
            exhausted = await self._consume(request=request, policy=policy, kind=kind, value=value, now=now)
            if exhausted is not None:
                retry_after = max(retry_after, exhausted)

        if retry_after > 0:
            return RateLimitDecision(allowed=False, retry_after=retry_after)
        return RateLimitDecision(allowed=True)

    async def _consume(
        self, *, request: "RateLimitAttempt", policy: "RateLimitPolicy", kind: "str", value: "str", now: "datetime"
    ) -> "int | None":
        window = int(policy.window.total_seconds())
        elapsed = now.timestamp()
        slot = int(elapsed // window)
        bucket_key = sha256(f"{request.operation}\x00{kind}\x00{value}".encode()).hexdigest()
        window_start_dt = datetime.fromtimestamp(slot * window, tz=timezone.utc)
        window_start_str = window_start_dt.isoformat()

        col_bucket_key = quote_identifier(resolve_column(self._backend.config, TABLE_RATE_LIMIT_BUCKETS, "bucket_key"))
        col_window_start = quote_identifier(
            resolve_column(self._backend.config, TABLE_RATE_LIMIT_BUCKETS, "window_start")
        )
        col_count = quote_identifier(resolve_column(self._backend.config, TABLE_RATE_LIMIT_BUCKETS, "count"))

        upsert_query = (
            f"INSERT INTO {self._table_name} ({col_bucket_key}, {col_window_start}, {col_count}) "
            f"VALUES (?, ?, ?) "
            f"ON CONFLICT ({col_bucket_key}, {col_window_start}) "
            f"DO UPDATE SET {col_count} = {self._table_name}.{col_count} + ? "
            f"RETURNING {col_count}"
        )

        async with self._backend.session() as session:
            try:
                val = await session.select_value(upsert_query, bucket_key, window_start_str, request.cost, request.cost)
                used = int(cast("int | str", val)) if val is not None else 1
            except Exception:
                select_query = (
                    f"SELECT {col_count} FROM {self._table_name} WHERE {col_bucket_key} = ? AND {col_window_start} = ?"
                )
                row = await session.select_one_or_none(select_query, bucket_key, window_start_str)
                if row is None:
                    insert_query = (
                        f"INSERT INTO {self._table_name} ({col_bucket_key}, {col_window_start}, {col_count}) "
                        f"VALUES (?, ?, ?)"
                    )
                    await session.execute(insert_query, bucket_key, window_start_str, request.cost)
                    used = request.cost
                else:
                    if isinstance(row, (tuple, list)):
                        curr = int(cast("int | str", row[0]))
                    elif isinstance(row, dict):
                        curr = int(cast("int | str", row["count"]))
                    else:
                        curr = 0
                    new_count = curr + request.cost
                    update_query = (
                        f"UPDATE {self._table_name} SET {col_count} = ? "
                        f"WHERE {col_bucket_key} = ? AND {col_window_start} = ?"
                    )
                    await session.execute(update_query, new_count, bucket_key, window_start_str)
                    used = new_count

        if used <= policy.limit:
            return None
        return max(1, ceil((slot + 1) * window - elapsed))
