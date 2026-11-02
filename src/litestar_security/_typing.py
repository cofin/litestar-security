"""Foundational shims for dependencies that an install may omit.

This module is the single source of truth for the ``*_INSTALLED`` flags and for
resolving a name out of a dependency that may be absent. It stays private so the
shims can grow as capabilities move behind extras, without widening the public
API every time. Public re-exports live in :mod:`litestar_security.typing`.

Availability is resolved with :func:`importlib.util.find_spec` rather than an
import, so asking whether a dependency exists never executes it. The answers are
cached for the interpreter session; a test that manipulates ``sys.path`` calls
:func:`reset_dependency_cache` to invalidate them.
"""

import sys
from dataclasses import dataclass
from importlib import import_module
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any, TypeVar, cast

if TYPE_CHECKING:
    from types import ModuleType

    import pyotp
    from argon2 import Parameters as Argon2Parameters
    from argon2 import PasswordHasher as Argon2PasswordHasherEngine
    from argon2 import extract_parameters
    from argon2.exceptions import Argon2Error, InvalidHashError, VerificationError, VerifyMismatchError
    from argon2.low_level import Type as Argon2Type
    from webauthn import (
        generate_authentication_options,
        generate_registration_options,
        options_to_json,
        verify_authentication_response,
        verify_registration_response,
    )
    from webauthn.helpers import (
        parse_attestation_object,
        parse_authentication_credential_json,
        parse_client_data_json,
        parse_registration_credential_json,
    )
    from webauthn.helpers.cose import COSEAlgorithmIdentifier
    from webauthn.helpers.structs import (
        AttestationConveyancePreference,
        AttestationFormat,
        AuthenticatorSelectionCriteria,
        CredentialDeviceType,
        UserVerificationRequirement,
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

T = TypeVar("T")

_dependency_cache: "dict[str, bool]" = {}
_optional_module_cache: "dict[str, ModuleType | None]" = {}

_DISTRIBUTIONS = {"argon2": "argon2-cffi", "jwt": "PyJWT", "pyotp": "PyOTP", "webauthn": "webauthn"}
_EXTRAS = {"argon2": "argon2", "pyotp": "mfa", "webauthn": "passkeys"}


class MissingDependencyError(ImportError):
    """A capability was used without the dependency that implements it."""

    def __init__(self, package: str, install_package: str | None = None) -> None:
        """Record which distribution to install and why.

        Args:
            package: The importable module that could not be resolved.
            install_package: The distribution to install, when it differs from
                the module name.
        """
        target = install_package or _DISTRIBUTIONS.get(package, package)
        extra = _EXTRAS.get(package)
        install_hint = (
            f"Install it with 'pip install litestar-security[{extra}]' or 'pip install {target}'."
            if extra is not None
            else f"Install it with 'pip install {target}'."
        )
        super().__init__(f"Package {package!r} is not installed but is required for this feature. {install_hint}")


def module_available(module_name: str) -> bool:
    """Report whether a module can be resolved without importing it.

    Args:
        module_name: Dotted module path to check.

    Returns:
        True when the import system can locate the module, False otherwise.
    """
    if _module_blocked(module_name):
        return False
    cached = _dependency_cache.get(module_name)
    if cached is not None:
        return cached
    try:
        available = find_spec(module_name) is not None
    except (ImportError, ValueError):
        available = False
    _dependency_cache[module_name] = available
    return available


def reset_dependency_cache(module_name: str | None = None) -> None:
    """Discard cached availability answers.

    Args:
        module_name: The single module to forget, or None to forget every
            cached answer.
    """
    if module_name is None:
        _dependency_cache.clear()
        _optional_module_cache.clear()
        return
    _dependency_cache.pop(module_name, None)
    _optional_module_cache.pop(module_name, None)


def import_optional(module_name: str) -> "ModuleType | None":
    """Import a module that an install may omit.

    Args:
        module_name: Dotted module path to import.

    Returns:
        The imported module, or None when it is not installed.
    """
    if _module_blocked(module_name):
        return None
    if module_name in _optional_module_cache:
        return _optional_module_cache[module_name]
    try:
        module = import_module(module_name)
    except ImportError:
        module = None
    _optional_module_cache[module_name] = module
    return module


def import_optional_attr(module_name: str, attr: str) -> Any:  # noqa: ANN401 - the value is whatever the module defines
    """Resolve one name out of a module that an install may omit.

    Args:
        module_name: Dotted module path to import.
        attr: Attribute to read from the imported module.

    Returns:
        The resolved attribute, or None when either the module or the attribute
        is unavailable.
    """
    module = import_optional(module_name)
    if module is None:
        return None
    return getattr(module, attr, None)


def resolve_optional_attr(module_name: str, attr: "str | None", fallback: T) -> T:
    """Resolve a name, falling back to a stable stub when it is unavailable.

    Unlike `import_optional_attr` this returns the caller's stub rather than
    None, so a module-level cache keeps one identity for the missing case.

    Args:
        module_name: Dotted module path to import.
        attr: Attribute to read from the module, or None to return the module.
        fallback: The stub to return when the module or attribute is missing.

    Returns:
        The resolved module or attribute, or the fallback stub.
    """
    module = import_optional(module_name)
    if module is None:
        return fallback
    if attr is None:
        return cast("T", module)
    resolved = getattr(module, attr, None)
    return fallback if resolved is None else resolved


def require_dependency(module_name: str, install_package: str | None = None) -> "ModuleType":
    """Import a dependency, failing with an actionable message when it is absent.

    Use this at the point a capability is actually exercised, so an install that
    omits the extra fails where the feature is used rather than at import.

    Args:
        module_name: Dotted module path to import.
        install_package: The distribution to name in the error, when it differs
            from the module name.

    Returns:
        The imported module.

    Raises:
        MissingDependencyError: When the module cannot be imported.
    """
    module = import_optional(module_name)
    if module is None:
        raise MissingDependencyError(module_name, install_package)
    return module


def ensure_argon2() -> None:
    """Ensure the optional ``[argon2]`` extra is installed."""
    if import_optional("argon2") is None:
        msg = "litestar-security feature requires the [argon2] extra: pip install 'litestar-security[argon2]'"
        raise ImportError(msg)


def ensure_pyotp() -> None:
    """Ensure the optional ``[mfa]`` extra is installed."""
    if import_optional("pyotp") is None:
        msg = "litestar-security feature requires the [mfa] extra: pip install 'litestar-security[mfa]'"
        raise ImportError(msg)


def ensure_webauthn() -> None:
    """Ensure the optional ``[passkeys]`` extra is installed."""
    if import_optional("webauthn") is None:
        msg = "litestar-security feature requires the [passkeys] extra: pip install 'litestar-security[passkeys]'"
        raise ImportError(msg)


@dataclass(frozen=True, slots=True)
class OptionalDependencyFlag:
    """A dependency check that resolves when it is read, not when it is built.

    Reading the flag in a boolean context answers the availability question, so
    a module-level constant costs nothing at import time.
    """

    module_name: str

    def __bool__(self) -> bool:
        """Report whether the tracked module can be resolved.

        Returns:
            True when the module is importable.
        """
        return module_available(self.module_name)

    def __repr__(self) -> str:
        """Describe the tracked module and its current availability.

        Returns:
            A representation naming the module and whether it resolves.
        """
        status = "available" if module_available(self.module_name) else "missing"
        return f"OptionalDependencyFlag(module={self.module_name!r}, status={status!r})"


def dependency_flag(module_name: str) -> OptionalDependencyFlag:
    """Build a lazily evaluated availability flag for a module.

    Args:
        module_name: Dotted module path to track.

    Returns:
        A flag that resolves the module the first time it is read.
    """
    return OptionalDependencyFlag(module_name)


ARGON2_INSTALLED = dependency_flag("argon2")
CRYPTOGRAPHY_INSTALLED = dependency_flag("cryptography")
HTTPX_INSTALLED = dependency_flag("httpx")
JWT_INSTALLED = dependency_flag("jwt")
MSGSPEC_INSTALLED = dependency_flag("msgspec")
PYOTP_INSTALLED = dependency_flag("pyotp")
WEBAUTHN_INSTALLED = dependency_flag("webauthn")


class _Argon2ParametersShim:  # pragma: no cover
    """Fallback shim for ``argon2.Parameters`` when ``argon2-cffi`` is absent."""

    __slots__ = ()


class _Argon2EngineShim:  # pragma: no cover
    """Fallback shim for ``argon2.PasswordHasher`` when ``argon2-cffi`` is absent."""

    __slots__ = ()

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        ensure_argon2()

    def hash(self, *_args: object, **_kwargs: object) -> str:
        ensure_argon2()
        raise RuntimeError

    def verify(self, *_args: object, **_kwargs: object) -> bool:
        ensure_argon2()
        raise RuntimeError


class _Argon2TypeShim:  # pragma: no cover
    """Fallback shim for ``argon2.low_level.Type`` when ``argon2-cffi`` is absent."""

    __slots__ = ()
    ID = "ID"


class _PyOTPShim:  # pragma: no cover
    """Fallback shim for ``pyotp`` when ``PyOTP`` is absent."""

    __slots__ = ()

    @staticmethod
    def random_base32(*_args: object, **_kwargs: object) -> str:
        ensure_pyotp()
        raise RuntimeError

    @staticmethod
    def TOTP(*_args: object, **_kwargs: object) -> object:  # noqa: N802
        ensure_pyotp()
        raise RuntimeError


class _WebAuthnAttestationConveyanceShim:  # pragma: no cover
    """Fallback shim for ``AttestationConveyancePreference`` when ``webauthn`` is absent."""

    __slots__ = ()
    DIRECT = "direct"
    NONE = "none"


class _WebAuthnAttestationFormatShim:  # pragma: no cover
    """Fallback shim for ``AttestationFormat`` when ``webauthn`` is absent."""

    __slots__ = ("value",)
    FIDO_U2F = "fido-u2f"
    PACKED = "packed"
    TPM = "tpm"

    def __init__(self, value: str) -> None:
        self.value = value


class _WebAuthnAuthenticatorSelectionShim:  # pragma: no cover
    """Fallback shim for ``AuthenticatorSelectionCriteria`` when ``webauthn`` is absent."""

    __slots__ = ()

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        ensure_webauthn()


class _WebAuthnCOSEAlgorithmShim:  # pragma: no cover
    """Fallback shim for ``COSEAlgorithmIdentifier`` when ``webauthn`` is absent."""

    __slots__ = ()

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        ensure_webauthn()


class _WebAuthnCredentialDeviceTypeShim:  # pragma: no cover
    """Fallback shim for ``CredentialDeviceType`` when ``webauthn`` is absent."""

    __slots__ = ()
    MULTI_DEVICE = "multi_device"


class _WebAuthnUserVerificationShim:  # pragma: no cover
    """Fallback shim for ``UserVerificationRequirement`` when ``webauthn`` is absent."""

    __slots__ = ()

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        ensure_webauthn()


def _module_blocked(module_name: str) -> bool:
    root_name = module_name.partition(".")[0]
    return (root_name in sys.modules and sys.modules.get(root_name) is None) or (
        module_name in sys.modules and sys.modules.get(module_name) is None
    )


def _unavailable_argon2(*_args: object, **_kwargs: object) -> object:  # pragma: no cover
    ensure_argon2()
    raise RuntimeError


def _unavailable_webauthn(*_args: object, **_kwargs: object) -> object:  # pragma: no cover
    ensure_webauthn()
    raise RuntimeError


_LAZY_EXPORTS: dict[str, tuple[str, str | None, object]] = {
    "Argon2Error": ("argon2.exceptions", "Argon2Error", Exception),
    "Argon2Parameters": ("argon2", "Parameters", _Argon2ParametersShim),
    "Argon2PasswordHasherEngine": ("argon2", "PasswordHasher", _Argon2EngineShim),
    "Argon2Type": ("argon2.low_level", "Type", _Argon2TypeShim),
    "AttestationConveyancePreference": (
        "webauthn.helpers.structs",
        "AttestationConveyancePreference",
        _WebAuthnAttestationConveyanceShim,
    ),
    "AttestationFormat": ("webauthn.helpers.structs", "AttestationFormat", _WebAuthnAttestationFormatShim),
    "AuthenticatorSelectionCriteria": (
        "webauthn.helpers.structs",
        "AuthenticatorSelectionCriteria",
        _WebAuthnAuthenticatorSelectionShim,
    ),
    "COSEAlgorithmIdentifier": ("webauthn.helpers.cose", "COSEAlgorithmIdentifier", _WebAuthnCOSEAlgorithmShim),
    "CredentialDeviceType": ("webauthn.helpers.structs", "CredentialDeviceType", _WebAuthnCredentialDeviceTypeShim),
    "InvalidHashError": ("argon2.exceptions", "InvalidHashError", Exception),
    "UserVerificationRequirement": (
        "webauthn.helpers.structs",
        "UserVerificationRequirement",
        _WebAuthnUserVerificationShim,
    ),
    "VerificationError": ("argon2.exceptions", "VerificationError", Exception),
    "VerifyMismatchError": ("argon2.exceptions", "VerifyMismatchError", Exception),
    "extract_parameters": ("argon2", "extract_parameters", _unavailable_argon2),
    "generate_authentication_options": ("webauthn", "generate_authentication_options", _unavailable_webauthn),
    "generate_registration_options": ("webauthn", "generate_registration_options", _unavailable_webauthn),
    "options_to_json": ("webauthn", "options_to_json", _unavailable_webauthn),
    "parse_attestation_object": ("webauthn.helpers", "parse_attestation_object", _unavailable_webauthn),
    "parse_authentication_credential_json": (
        "webauthn.helpers",
        "parse_authentication_credential_json",
        _unavailable_webauthn,
    ),
    "parse_client_data_json": ("webauthn.helpers", "parse_client_data_json", _unavailable_webauthn),
    "parse_registration_credential_json": (
        "webauthn.helpers",
        "parse_registration_credential_json",
        _unavailable_webauthn,
    ),
    "pyotp": ("pyotp", None, _PyOTPShim),
    "verify_authentication_response": ("webauthn", "verify_authentication_response", _unavailable_webauthn),
    "verify_registration_response": ("webauthn", "verify_registration_response", _unavailable_webauthn),
}


def __getattr__(name: str) -> Any:  # noqa: ANN401 - dynamic optional-dependency export resolution
    """Resolve optional dependency exports lazily on first access."""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        msg = f"module '{__name__}' has no attribute '{name}'"
        raise AttributeError(msg)
    module_name, attr_name, fallback = target
    value = resolve_optional_attr(module_name, attr_name, fallback)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """List eager and lazy exports available on the module."""
    return sorted(set(globals()).union(_LAZY_EXPORTS))
