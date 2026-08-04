"""Native Litestar controllers for the generated local-auth and MFA routes.

These modules are the top of the `accounts` graph: they consume the account
services and wire schemas and nothing in the package depends back on them.
"""

from typing import TYPE_CHECKING, Any

from litestar_security._lazy import import_optional_attribute

if TYPE_CHECKING:
    from litestar_security.accounts.controllers._local import (
        LOCAL_AUTH_TAGS,
        build_local_auth_routes,
        requires_local_bearer,
    )
    from litestar_security.accounts.controllers._mfa import build_mfa_routes

__all__ = ("LOCAL_AUTH_TAGS", "build_local_auth_routes", "build_mfa_routes", "requires_local_bearer")

_LOCAL_EXPORTS = frozenset({"LOCAL_AUTH_TAGS", "build_local_auth_routes", "requires_local_bearer"})


def __getattr__(name: str) -> Any:  # noqa: ANN401 - module lazy-export hook is dynamically typed
    """Resolve generated controller exports when their optional features are installed."""
    if name in _LOCAL_EXPORTS:
        return import_optional_attribute(
            "litestar_security.accounts.controllers._local",
            name,
            extras="argon2,mfa",
            dependencies=frozenset({"argon2", "pyotp"}),
        )
    if name == "build_mfa_routes":
        return import_optional_attribute(
            "litestar_security.accounts.controllers._mfa",
            name,
            extras="mfa,passkeys",
            dependencies=frozenset({"pyotp", "webauthn"}),
        )
    message = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(message)
