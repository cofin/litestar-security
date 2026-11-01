"""Native Litestar controllers for the generated local-auth and MFA routes.

These modules are the top of the `accounts` graph: they consume the account
services and wire schemas and nothing in the package depends back on them.
"""

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from litestar_security.accounts.controllers._local import (
        LOCAL_AUTH_TAGS,
        build_local_auth_routes,
        require_local_bearer,
    )
    from litestar_security.accounts.controllers._mfa import build_mfa_routes

__all__ = ("LOCAL_AUTH_TAGS", "build_local_auth_routes", "build_mfa_routes", "require_local_bearer")

_LOCAL_EXPORTS = frozenset({"LOCAL_AUTH_TAGS", "build_local_auth_routes", "require_local_bearer"})


def __getattr__(name: str) -> Any:  # noqa: ANN401 - module lazy-export hook is dynamically typed
    """Resolve generated controller exports without loading route trees at root import."""
    if name in _LOCAL_EXPORTS:
        return getattr(import_module("litestar_security.accounts.controllers._local"), name)
    if name == "build_mfa_routes":
        return getattr(import_module("litestar_security.accounts.controllers._mfa"), name)
    message = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(message)
