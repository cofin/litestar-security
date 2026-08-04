"""Private helpers for optional-feature lazy exports."""

from importlib import import_module
from typing import Any

__all__ = ()


def import_optional_attribute(
    module_name: str, attribute_name: str, *, extras: str, dependencies: frozenset[str]
) -> Any:  # noqa: ANN401 - package lazy-export hooks resolve arbitrary public objects
    """Import one optional-feature attribute without masking unrelated failures."""
    try:
        module = import_module(module_name)
    except ModuleNotFoundError as error:
        if error.name not in dependencies:
            raise
        message = f"litestar-security feature requires the [{extras}] extra: pip install 'litestar-security[{extras}]'"
        raise ImportError(message) from None
    return getattr(module, attribute_name)
