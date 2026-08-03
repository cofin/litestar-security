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

from dataclasses import dataclass
from importlib import import_module
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any, TypeVar, cast

if TYPE_CHECKING:
    from types import ModuleType

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

T = TypeVar("T")

_dependency_cache: "dict[str, bool]" = {}
_optional_module_cache: "dict[str, ModuleType | None]" = {}

# The distribution that supplies each importable module, where the two names
# differ. A missing entry means the module and the distribution share a name.
_DISTRIBUTIONS = {"argon2": "argon2-cffi", "jwt": "PyJWT", "pyotp": "PyOTP"}


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
        super().__init__(
            f"Package {package!r} is not installed but is required for this feature. "
            f"Install it with 'pip install litestar-security[{target}]' or 'pip install {target}'."
        )


def module_available(module_name: str) -> bool:
    """Report whether a module can be resolved without importing it.

    Args:
        module_name: Dotted module path to check.

    Returns:
        True when the import system can locate the module, False otherwise.
    """
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
