"""SQLSpec persistence backend and session bridging for Litestar Security."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from inspect import iscoroutinefunction
from typing import TYPE_CHECKING, cast

from sqlspec.utils.sync_tools import async_

from litestar_security.backends.sqlspec.config import SQLSpecSecurityBackendConfig
from litestar_security.backends.sqlspec.schema import get_create_table_statements, get_drop_table_statements

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Mapping, Sequence

    from litestar_security.backends.sqlspec._typing import SQLSpecDriver
    from litestar_security.backends.sqlspec.stores.accounts import SQLSpecAccountStore
    from litestar_security.backends.sqlspec.stores.api_keys import SQLSpecAPIKeyStore
    from litestar_security.backends.sqlspec.stores.mfa import (
        SQLSpecMFALoginChallengeStore,
        SQLSpecRecoveryCodeStore,
        SQLSpecStepUpStore,
    )
    from litestar_security.backends.sqlspec.stores.rate_limits import SQLSpecRateLimiter
    from litestar_security.backends.sqlspec.stores.sessions import SQLSpecSessionStore
    from litestar_security.backends.sqlspec.stores.tokens import SQLSpecPurposeTokenStore, SQLSpecRefreshTokenStore
    from litestar_security.backends.sqlspec.stores.totp import SQLSpecTOTPStore

__all__ = (
    "SQLSpecSecurityBackend",
    "bridge_session",
)


class _ManagedAsyncDriver:
    """Expose sync SQLSpec driver methods through a session-bound thread executor."""

    __slots__ = ("_driver", "_executor", "_transaction_finalized")

    def __init__(self, driver: object, executor: ThreadPoolExecutor) -> None:
        self._driver = driver
        self._executor = executor
        self._transaction_finalized = False

    @property
    def transaction_finalized(self) -> bool:
        """Whether the session explicitly committed or rolled back."""
        return self._transaction_finalized

    async def begin(self) -> object:
        """Begin a transaction."""
        self._transaction_finalized = False
        begin_func = getattr(self._driver, "begin", None)
        if callable(begin_func):
            try:
                return await async_(begin_func, executor=self._executor)()
            except RuntimeError:
                return begin_func()
        return None

    async def commit(self) -> object:
        """Commit the active transaction."""
        commit_func = getattr(self._driver, "commit", None)
        result: object = None
        if callable(commit_func):
            try:
                result = await async_(commit_func, executor=self._executor)()
            except RuntimeError:
                result = commit_func()
        self._transaction_finalized = True
        return result

    async def rollback(self) -> object:
        """Rollback the active transaction."""
        rollback_func = getattr(self._driver, "rollback", None)
        result: object = None
        if callable(rollback_func):
            try:
                result = await async_(rollback_func, executor=self._executor)()
            except RuntimeError:
                result = rollback_func()
        self._transaction_finalized = True
        return result

    async def execute(self, statement: object, *parameters: object, **kwargs: object) -> object:
        """Execute a SQL statement."""
        exec_func = getattr(self._driver, "execute")
        return await async_(exec_func, executor=self._executor)(statement, *parameters, **kwargs)

    async def execute_script(self, statement: str) -> object:
        """Execute a raw SQL script."""
        script_func = getattr(self._driver, "execute_script")
        return await async_(script_func, executor=self._executor)(statement)

    async def select(self, statement: object, *parameters: object, **kwargs: object) -> list[object]:
        """Execute a query returning rows."""
        select_func = getattr(self._driver, "select")
        result = await async_(select_func, executor=self._executor)(statement, *parameters, **kwargs)
        return list(cast("list[object]", result))

    async def select_one_or_none(self, statement: object, *parameters: object, **kwargs: object) -> object | None:
        """Execute a query returning at most one row."""
        select_one_func = getattr(self._driver, "select_one_or_none")
        result = await async_(select_one_func, executor=self._executor)(statement, *parameters, **kwargs)
        return cast("object | None", result)

    async def select_value(self, statement: object, *parameters: object, **kwargs: object) -> object | None:
        """Execute a query returning a single scalar value."""
        select_val_func = getattr(self._driver, "select_value", None)
        if callable(select_val_func):
            result = await async_(select_val_func, executor=self._executor)(statement, *parameters, **kwargs)
            return cast("object | None", result)
        row = await self.select_one_or_none(statement, *parameters, **kwargs)
        if row is None:
            return None
        if isinstance(row, (tuple, list)):
            seq = cast("Sequence[object]", row)
            return seq[0] if seq else None
        if isinstance(row, dict):
            mapping = cast("Mapping[str, object]", row)
            return next(iter(mapping.values())) if mapping else None
        getitem_func = getattr(row, "__getitem__", None)
        if callable(getitem_func):
            try:
                val: object = getitem_func(0)
            except (KeyError, IndexError, TypeError):
                pass
            else:
                return val
        return None



@asynccontextmanager
async def bridge_session(
    driver_or_provider: object,
    *,
    executor: ThreadPoolExecutor | None = None,
) -> AsyncGenerator[SQLSpecDriver, None]:
    """Yield an awaitable SQLSpecDriver from a sync or async driver or context manager.

    Args:
        driver_or_provider: An async or sync SQLSpec driver, connection, or context manager.
        executor: Optional thread pool executor for offloading sync blocking operations.

    Yields:
        A SQLSpecDriver whose execution methods are coroutines.
    """
    if hasattr(driver_or_provider, "__aenter__"):
        cm = cast("AbstractAsyncContextManager[SQLSpecDriver]", driver_or_provider)
        async with cm as session:
            yield session
    elif hasattr(driver_or_provider, "__enter__"):
        owns_executor = executor is None
        sync_executor = executor or ThreadPoolExecutor(max_workers=1, thread_name_prefix="litestar-security-sqlspec")
        try:
            enter_func = getattr(driver_or_provider, "__enter__")
            driver = await async_(enter_func, executor=sync_executor)()
            managed = _ManagedAsyncDriver(driver, sync_executor)
            try:
                yield cast("SQLSpecDriver", managed)
            finally:
                exit_func = getattr(driver_or_provider, "__exit__")
                await async_(exit_func, executor=sync_executor)(None, None, None)
        finally:
            if owns_executor:
                sync_executor.shutdown(wait=True)
    elif iscoroutinefunction(getattr(driver_or_provider, "execute", None)):
        yield cast("SQLSpecDriver", driver_or_provider)
    else:
        owns_executor = executor is None
        sync_executor = executor or ThreadPoolExecutor(max_workers=1, thread_name_prefix="litestar-security-sqlspec")
        try:
            managed = _ManagedAsyncDriver(driver_or_provider, sync_executor)
            yield cast("SQLSpecDriver", managed)
        finally:
            if owns_executor:
                sync_executor.shutdown(wait=True)


class SQLSpecSecurityBackend:
    """Persistence hub orchestrating SQLSpec store adapters and schema lifecycle."""

    __slots__ = ("_config", "_dialect", "_driver", "_executor")

    def __init__(
        self,
        driver: object,
        config: SQLSpecSecurityBackendConfig | None = None,
        *,
        dialect: str | None = None,
        executor: ThreadPoolExecutor | None = None,
    ) -> None:
        """Initialize the SQLSpec security persistence backend.

        Args:
            driver: SQLSpec driver or connection session provider.
            config: Optional backend configuration; defaults to empty configuration.
            dialect: Optional dialect override; defaults to inspecting driver dialect or 'sqlite'.
            executor: Optional thread pool executor for sync driver operations.
        """
        self._driver = driver
        self._config = config or SQLSpecSecurityBackendConfig()
        if dialect is not None:
            self._dialect = dialect
        elif getattr(driver, "dialect", None) is not None:
            self._dialect = str(getattr(driver, "dialect"))
        else:
            self._dialect = "sqlite"
        self._executor = executor

    @property
    def config(self) -> SQLSpecSecurityBackendConfig:
        """Return the active backend configuration."""
        return self._config

    @property
    def dialect(self) -> str:
        """Return the target database dialect."""
        return self._dialect

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[SQLSpecDriver, None]:
        """Provide an active, awaitable driver session for database operations.

        Yields:
            A SQLSpecDriver ready for executing statements.
        """
        async with bridge_session(self._driver, executor=self._executor) as driver:
            yield driver

    async def create_schema(self, *, drop_existing: bool = False) -> None:
        """Bootstrap the security schema immediately via DDL execution.

        Args:
            drop_existing: If True, drop existing security tables first in reverse dependency order.
        """
        async with self.session() as driver:
            if drop_existing:
                for drop_stmt in get_drop_table_statements(self._config, dialect=self._dialect):
                    await driver.execute(drop_stmt)

            for create_stmt in get_create_table_statements(self._config, dialect=self._dialect):
                await driver.execute(create_stmt)

    @property
    def account_store(self) -> SQLSpecAccountStore:
        """Return a SQLSpec account and credential store."""
        from litestar_security.backends.sqlspec.stores.accounts import SQLSpecAccountStore

        return SQLSpecAccountStore(self)

    @property
    def session_store(self) -> SQLSpecSessionStore:
        """Return a SQLSpec session store and registry."""
        from litestar_security.backends.sqlspec.stores.sessions import SQLSpecSessionStore

        return SQLSpecSessionStore(self)

    @property
    def api_key_store(self) -> SQLSpecAPIKeyStore:
        """Return a SQLSpec API-key store."""
        from litestar_security.backends.sqlspec.stores.api_keys import SQLSpecAPIKeyStore

        return SQLSpecAPIKeyStore(self)

    @property
    def rate_limiter(self) -> SQLSpecRateLimiter:
        """Return a SQLSpec atomic fixed-window rate limiter."""
        from litestar_security.backends.sqlspec.stores.rate_limits import SQLSpecRateLimiter

        return SQLSpecRateLimiter(self)

    @property
    def refresh_token_store(self) -> SQLSpecRefreshTokenStore:
        """Return a SQLSpec refresh token family store."""
        from litestar_security.backends.sqlspec.stores.tokens import SQLSpecRefreshTokenStore

        return SQLSpecRefreshTokenStore(self)

    @property
    def purpose_token_store(self) -> SQLSpecPurposeTokenStore:
        """Return a SQLSpec purpose token store."""
        from litestar_security.backends.sqlspec.stores.tokens import SQLSpecPurposeTokenStore

        return SQLSpecPurposeTokenStore(self)

    @property
    def totp_store(self) -> SQLSpecTOTPStore:
        """Return a SQLSpec TOTP and MFA store."""
        from litestar_security.backends.sqlspec.stores.totp import SQLSpecTOTPStore

        return SQLSpecTOTPStore(self)

    @property
    def mfa_store(self) -> SQLSpecTOTPStore:
        """Return a SQLSpec MFA store (alias for totp_store)."""
        return self.totp_store

    @property
    def mfa_login_challenge_store(self) -> SQLSpecMFALoginChallengeStore:
        """Return a SQLSpec MFA login challenge store."""
        from litestar_security.backends.sqlspec.stores.mfa import SQLSpecMFALoginChallengeStore

        return SQLSpecMFALoginChallengeStore(self)

    @property
    def step_up_store(self) -> SQLSpecStepUpStore:
        """Return a SQLSpec step-up grant store."""
        from litestar_security.backends.sqlspec.stores.mfa import SQLSpecStepUpStore

        return SQLSpecStepUpStore(self)

    @property
    def recovery_code_store(self) -> SQLSpecRecoveryCodeStore:
        """Return a SQLSpec recovery code store."""
        from litestar_security.backends.sqlspec.stores.mfa import SQLSpecRecoveryCodeStore

        return SQLSpecRecoveryCodeStore(self)

