"""Typing helpers and dependency-availability aliases.

This module is the supported import surface for the typing utilities. The
implementation lives in :mod:`litestar_security._typing`, which stays private so
the shims for dependencies an install may omit can evolve without widening the
public API.

The ``*_INSTALLED`` flags resolve when they are read rather than when they are
built, so importing this module never imports the dependency it describes::

    from litestar_security.typing import WEBAUTHN_INSTALLED, require_dependency

    if WEBAUTHN_INSTALLED:
        ...

    webauthn = require_dependency("webauthn")
"""

from litestar_security._typing import (
    ARGON2_INSTALLED,
    CRYPTOGRAPHY_INSTALLED,
    HTTPX_INSTALLED,
    JWT_INSTALLED,
    MSGSPEC_INSTALLED,
    PYOTP_INSTALLED,
    WEBAUTHN_INSTALLED,
    MissingDependencyError,
    OptionalDependencyFlag,
    dependency_flag,
    import_optional,
    import_optional_attr,
    module_available,
    require_dependency,
    reset_dependency_cache,
    resolve_optional_attr,
)

__all__ = (
    "ARGON2_INSTALLED",
    "CRYPTOGRAPHY_INSTALLED",
    "HTTPX_INSTALLED",
    "JWT_INSTALLED",
    "MSGSPEC_INSTALLED",
    "PYOTP_INSTALLED",
    "WEBAUTHN_INSTALLED",
    "MissingDependencyError",
    "OptionalDependencyFlag",
    "dependency_flag",
    "import_optional",
    "import_optional_attr",
    "module_available",
    "require_dependency",
    "reset_dependency_cache",
    "resolve_optional_attr",
)
