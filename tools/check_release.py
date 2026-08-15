"""Build and verify release archives across every supported Python version."""

import os
import subprocess
import tempfile
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).parents[1]
EXPECTED_VERSION = "0.5.0"
SUPPORTED_PYTHONS = ("3.10", "3.11", "3.12", "3.13", "3.14")
DIRECT_DEPENDENCIES = frozenset({"argon2-cffi", "httpx", "litestar", "pyotp", "pyjwt", "webauthn"})
FORBIDDEN_DEPENDENCIES = frozenset({"advanced-alchemy", "litestar-mcp", "sqlalchemy", "sqlspec"})
SMOKE_SCRIPT = r"""
import asyncio
import importlib
import sys
from importlib.resources import files
from pkgutil import walk_packages

from litestar import Litestar, get
from litestar.di import NamedDependency
from litestar.openapi.config import OpenAPIConfig
from litestar.testing import TestClient

import litestar_security
from litestar_security import Principal, SecurityConfig, SecurityPlugin
from litestar_security.providers.api_key import APIKeyClaims, APIKeyConfig
from litestar_security.testing import (
    InMemorySecurityBackend,
    StoreConformanceFactories,
    assert_security_backend_conformance,
)

for module in walk_packages(litestar_security.__path__, "litestar_security."):
    if not any(part.startswith("_") for part in module.name.split(".")):
        importlib.import_module(module.name)

assert "pytest" not in sys.modules
assert litestar_security.__version__ == "0.5.0"
assert files("litestar_security").joinpath("py.typed").is_file()
assert StoreConformanceFactories is not None
assert assert_security_backend_conformance is not None

class Resolver:
    async def resolve(self, claims: APIKeyClaims) -> Principal[object]:
        return Principal(id=claims.subject_id, user=object())

backend = InMemorySecurityBackend()
api_key = APIKeyConfig(store=backend.api_keys, pepper=b"p" * 32, identity_resolver=Resolver())
issued = asyncio.run(api_key.build()[2].issue(subject_id="release-actor"))

@get("/protected")
async def protected(principal: NamedDependency[Principal[object]]) -> dict[str, str]:
    return {"principal": principal.id or ""}

app = Litestar(
    route_handlers=[protected],
    openapi_config=OpenAPIConfig(title="Release smoke", version="0.5.0"),
    plugins=[SecurityPlugin(SecurityConfig(api_key=api_key))],
)
with TestClient(app) as client:
    response = client.get("/protected", headers={"X-API-Key": issued.value})

assert response.status_code == 200, response.text
assert response.json() == {"principal": "release-actor"}
assert app.openapi_schema.paths["/protected"].get.security == [{"APIKey": []}]
"""


def require(*, condition: bool, detail: object) -> None:
    """Fail one release invariant with actionable detail.

    Args:
        condition: Whether the release invariant holds.
        detail: Evidence included when it does not.
    """
    if not condition:
        raise RuntimeError(str(detail))


def run(*command: str, cwd: Path = ROOT, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run one fixed release verification command.

    Args:
        *command: Repository-owned command and arguments.
        cwd: Working directory isolated from repository imports when required.
        env: Optional sanitized process environment.

    Returns:
        The completed process.
    """
    try:
        return subprocess.run(  # noqa: S603 - every executable and argument is repository-controlled
            command, cwd=cwd, env=env, check=True, text=True, capture_output=True
        )
    except subprocess.CalledProcessError as error:
        message = f"Command failed: {' '.join(command)}\n{error.stdout}\n{error.stderr}"
        raise RuntimeError(message) from error


def dependency_name(requirement: str) -> str:
    """Extract a normalized distribution name from one metadata requirement.

    Args:
        requirement: One ``Requires-Dist`` metadata value.

    Returns:
        The normalized distribution name.
    """
    head = requirement.split(";", 1)[0].strip()
    name = head.split("[", 1)[0].split(" ", 1)[0]
    for operator in ("<", ">", "=", "!", "~"):
        name = name.split(operator, 1)[0]
    return name.lower().replace("_", "-")


def inspect_wheel(wheel: Path) -> None:
    """Validate package contents and dependency metadata.

    Args:
        wheel: Built wheel archive.
    """
    with ZipFile(wheel) as archive:
        names = tuple(archive.namelist())
        metadata_path = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = BytesParser(policy=compat32).parsebytes(archive.read(metadata_path))
    require(condition="litestar_security/py.typed" in names, detail="wheel is missing litestar_security/py.typed")
    forbidden_assets = tuple(
        name
        for name in names
        if name.startswith(("tests/", "examples/", ".agents/")) or "/tests/" in name or "/fixtures/" in name
    )
    require(condition=not forbidden_assets, detail=forbidden_assets)
    require(condition=metadata["Name"] == "litestar-security", detail=metadata["Name"])
    require(condition=metadata["Version"] == EXPECTED_VERSION, detail=metadata["Version"])
    requirements = tuple(metadata.get_all("Requires-Dist", []))
    dependencies = frozenset(dependency_name(requirement) for requirement in requirements)
    require(condition=dependencies == DIRECT_DEPENDENCIES, detail=requirements)
    require(condition=dependencies.isdisjoint(FORBIDDEN_DEPENDENCIES), detail=requirements)


def smoke_wheel(
    wheel: Path, python_version: str, workspace: Path, clean_environment: dict[str, str], *, lower_bound: bool = False
) -> None:
    """Install and exercise one wheel in an isolated environment.

    Args:
        wheel: Built wheel archive.
        python_version: Interpreter version managed by uv.
        workspace: Temporary release workspace.
        clean_environment: Environment without repository import overrides.
        lower_bound: Pin the supported Litestar lower bound before installation.
    """
    suffix = "-lower-bound" if lower_bound else ""
    environment = workspace / f"python-{python_version}{suffix}"
    run("uv", "venv", "--python", python_version, str(environment))
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if lower_bound:
        run("uv", "pip", "install", "--python", str(python), "litestar==2.24.0")
    run("uv", "pip", "install", "--python", str(python), f"{wheel}[all]")
    run(str(python), "-I", "-c", SMOKE_SCRIPT, cwd=workspace, env=clean_environment)
    cli = environment / ("Scripts/litestar.exe" if os.name == "nt" else "bin/litestar")
    result = run(str(cli), "security", "--version", cwd=workspace, env=clean_environment)
    require(condition=result.stdout.strip() == f"litestar-security, version {EXPECTED_VERSION}", detail=result.stdout)


def main() -> None:
    """Build archives and execute the complete isolated release smoke matrix."""
    requested_pythons = tuple(
        version.strip() for version in os.environ.get("RELEASE_PYTHONS", ",".join(SUPPORTED_PYTHONS)).split(",")
    )
    if not requested_pythons or not set(requested_pythons).issubset(SUPPORTED_PYTHONS):
        message = f"RELEASE_PYTHONS must select from {', '.join(SUPPORTED_PYTHONS)}"
        raise ValueError(message)
    with tempfile.TemporaryDirectory(prefix="litestar-security-release-") as temporary:
        workspace = Path(temporary)
        distributions = workspace / "dist"
        run("uv", "build", "--wheel", "--sdist", "--out-dir", str(distributions))
        wheels = tuple(distributions.glob("litestar_security-*.whl"))
        source_archives = tuple(distributions.glob("litestar_security-*.tar.gz"))
        require(condition=len(wheels) == 1, detail=wheels)
        require(condition=len(source_archives) == 1, detail=source_archives)
        wheel = wheels[0]
        inspect_wheel(wheel)
        clean_environment = dict(os.environ)
        clean_environment.pop("PYTHONPATH", None)
        for python_version in requested_pythons:
            smoke_wheel(wheel, python_version, workspace, clean_environment)
        smoke_wheel(wheel, "3.10", workspace, clean_environment, lower_bound=True)


if __name__ == "__main__":
    main()
