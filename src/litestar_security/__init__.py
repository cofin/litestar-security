"""Public package exports for Litestar Security."""

from litestar_security.__metadata__ import __project__, __version__
from litestar_security.config import SecurityConfig
from litestar_security.plugin import SecurityPlugin

__all__ = ("SecurityConfig", "SecurityPlugin", "__project__", "__version__")
