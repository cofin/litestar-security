"""Package metadata."""

from importlib.metadata import PackageNotFoundError, metadata, version

__all__ = ("__project__", "__version__")

try:
    __version__ = version("litestar-security")
    __project__ = metadata("litestar-security")["Name"]
except PackageNotFoundError:  # pragma: no cover
    __version__ = "1.0.0"
    __project__ = "litestar-security"
