"""Internal typing definitions for the SQLSpec security backend."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

__all__ = (
    "SQLSpecConfig",
    "SQLSpecDriver",
)


class SQLSpecConfig(Protocol):
    """Structural protocol for SQLSpec adapter configuration."""

    extension_config: Mapping[str, object] | None

    def add_extension_migrations(
        self,
        name: str,
        migrations_path: str | Path,
        settings: Mapping[str, object] | None = None,
    ) -> None:
        """Register packaged migrations with SQLSpec."""
        ...

    def remove_extension_migrations(self, name: str) -> bool | None:
        """Remove previously registered extension migrations."""
        ...


class SQLSpecDriver(Protocol):
    """Awaitable driver surface used by the security backend."""

    async def execute(self, statement: object, *parameters: object, **kwargs: object) -> object:
        """Execute a SQL statement."""
        ...

    async def execute_script(self, statement: str) -> object:
        """Execute a raw SQL script containing multiple statements."""
        ...

    async def select(self, statement: object, *parameters: object, **kwargs: object) -> list[object]:
        """Execute a query returning all rows."""
        ...

    async def select_one_or_none(self, statement: object, *parameters: object, **kwargs: object) -> object | None:
        """Execute a query returning at most one row."""
        ...

    async def select_value(self, statement: object, *parameters: object, **kwargs: object) -> object | None:
        """Execute a query returning a single scalar value."""
        ...

