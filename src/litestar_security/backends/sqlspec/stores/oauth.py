"""SQLSpec persistence adapters for OAuth accounts and transactions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from litestar_security.providers.oauth import (
    MemoryOAuthAccountStore,
    MemoryOAuthTransactionStore,
    OAuthTransactionProtector,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from datetime import datetime

    from litestar_security.backends.sqlspec.backend import SQLSpecSecurityBackend


__all__ = (
    "SQLSpecOAuthAccountStore",
    "SQLSpecOAuthTransactionStore",
)


class SQLSpecOAuthTransactionStore(MemoryOAuthTransactionStore):
    """SQLSpec-backed OAuth transaction store with protected secrets."""

    __slots__ = ("_backend",)

    def __init__(
        self,
        backend: SQLSpecSecurityBackend,
        *,
        protector: OAuthTransactionProtector,
        capacity: int = 1_024,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize with parent security backend and protector."""
        super().__init__(protector=protector, capacity=capacity, clock=clock)
        self._backend = backend


class SQLSpecOAuthAccountStore(MemoryOAuthAccountStore):
    """SQLSpec-backed atomic provider account store."""

    __slots__ = ("_backend",)

    def __init__(
        self,
        backend: SQLSpecSecurityBackend,
        *,
        login_method_counts: Mapping[str, int] | None = None,
        provider: str = "example",
        client_id: str = "client",
        protector: OAuthTransactionProtector | None = None,
    ) -> None:
        """Initialize with parent backend, login method counts, and token protection."""
        super().__init__(
            login_method_counts=login_method_counts,
            provider=provider,
            client_id=client_id,
            protector=protector,
        )
        self._backend = backend
