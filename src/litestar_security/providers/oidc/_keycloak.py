"""Compatibility shim for oidc keycloak claims.

All Keycloak definitions have been consolidated into litestar_security.providers.oidc._provider.
"""

import sys
from types import ModuleType

from litestar_security.providers.oidc import _provider as _canonical_module
from litestar_security.providers.oidc._provider import KeycloakClaims, map_keycloak_claims

__all__ = ("KeycloakClaims", "map_keycloak_claims")


class _ShimModule(ModuleType):
    """Module proxy forwarding attribute mutations to the canonical module."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if hasattr(_canonical_module, name):
            setattr(_canonical_module, name, value)

    def __getattr__(self, name: str) -> object:
        return getattr(_canonical_module, name)


sys.modules[__name__].__class__ = _ShimModule
