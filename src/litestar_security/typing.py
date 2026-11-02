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

from typing import TYPE_CHECKING, Any

from litestar_security import _typing
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
    ensure_argon2,
    ensure_pyotp,
    ensure_webauthn,
    import_optional,
    import_optional_attr,
    module_available,
    require_dependency,
    reset_dependency_cache,
    resolve_optional_attr,
)

if TYPE_CHECKING:
    from litestar_security._typing import (
        Argon2Error,
        Argon2Parameters,
        Argon2PasswordHasherEngine,
        Argon2Type,
        AttestationConveyancePreference,
        AttestationFormat,
        AuthenticatorSelectionCriteria,
        COSEAlgorithmIdentifier,
        CredentialDeviceType,
        InvalidHashError,
        UserVerificationRequirement,
        VerificationError,
        VerifyMismatchError,
        extract_parameters,
        generate_authentication_options,
        generate_registration_options,
        options_to_json,
        parse_attestation_object,
        parse_authentication_credential_json,
        parse_client_data_json,
        parse_registration_credential_json,
        pyotp,
        verify_authentication_response,
        verify_registration_response,
    )

__all__ = (
    "ARGON2_INSTALLED",
    "CRYPTOGRAPHY_INSTALLED",
    "HTTPX_INSTALLED",
    "JWT_INSTALLED",
    "MSGSPEC_INSTALLED",
    "PYOTP_INSTALLED",
    "WEBAUTHN_INSTALLED",
    "Argon2Error",
    "Argon2Parameters",
    "Argon2PasswordHasherEngine",
    "Argon2Type",
    "AttestationConveyancePreference",
    "AttestationFormat",
    "AuthenticatorSelectionCriteria",
    "COSEAlgorithmIdentifier",
    "CredentialDeviceType",
    "InvalidHashError",
    "MissingDependencyError",
    "OptionalDependencyFlag",
    "UserVerificationRequirement",
    "VerificationError",
    "VerifyMismatchError",
    "dependency_flag",
    "ensure_argon2",
    "ensure_pyotp",
    "ensure_webauthn",
    "extract_parameters",
    "generate_authentication_options",
    "generate_registration_options",
    "import_optional",
    "import_optional_attr",
    "module_available",
    "options_to_json",
    "parse_attestation_object",
    "parse_authentication_credential_json",
    "parse_client_data_json",
    "parse_registration_credential_json",
    "pyotp",
    "require_dependency",
    "reset_dependency_cache",
    "resolve_optional_attr",
    "verify_authentication_response",
    "verify_registration_response",
)


def __getattr__(name: str) -> Any:  # noqa: ANN401 - dynamic optional-dependency export resolution
    """Delegate lazy optional-dependency lookups to ``litestar_security._typing``."""
    if name in __all__:
        value = getattr(_typing, name)
        globals()[name] = value
        return value
    msg = f"module '{__name__}' has no attribute '{name}'"
    raise AttributeError(msg)


def __dir__() -> list[str]:
    """List all public attributes exposed by ``litestar_security.typing``."""
    return sorted(set(globals()).union(__all__))
