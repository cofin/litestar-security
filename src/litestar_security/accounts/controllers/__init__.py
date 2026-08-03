"""Native Litestar controllers for the generated local-auth and MFA routes.

These modules are the top of the `accounts` graph: they consume the account
services and wire schemas and nothing in the package depends back on them.
"""

from litestar_security.accounts.controllers._local import (
    LOCAL_AUTH_TAGS,
    build_local_auth_routes,
    requires_local_bearer,
)
from litestar_security.accounts.controllers._mfa import build_mfa_routes

__all__ = ("LOCAL_AUTH_TAGS", "build_local_auth_routes", "build_mfa_routes", "requires_local_bearer")
