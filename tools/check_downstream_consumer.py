"""Build and verify the isolated downstream-consumer fixture."""

import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "src" / "tests" / "fixtures" / "downstream_consumer"
# The same 13 roots as [tool.ruff.lint.flake8-tidy-imports.banned-api] in
# pyproject.toml, in distribution rather than module spelling. Ruff keeps them out
# of the source; this keeps them out of the wheel's Requires-Dist.
FORBIDDEN_DEPENDENCIES = (
    "advanced-alchemy",
    "aioboto3",
    "aiomysql",
    "aiosqlite",
    "asyncpg",
    "boto3",
    "google-cloud",
    "litestar-mcp",
    "motor",
    "pymongo",
    "redis",
    "sqlalchemy",
    "sqlspec",
)


def run(*command: str, cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
    """Run one checked downstream verification command."""
    subprocess.run(command, cwd=cwd, env=env, check=True)  # noqa: S603 - fixed repository-owned command arguments


def main() -> None:
    """Build the wheel and test the consumer without repository source imports."""
    with tempfile.TemporaryDirectory(prefix="litestar-security-downstream-") as temporary:
        workspace = Path(temporary)
        distributions = workspace / "dist"
        environment = workspace / ".venv"
        run("uv", "build", "--wheel", "--out-dir", str(distributions))
        wheel = next(distributions.glob("litestar_security-*.whl"))
        run("uv", "venv", "--python", os.environ.get("PYTHON_VERSION", "3.10"), str(environment))
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run(
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            f"{wheel}[argon2,mfa,oauth,passkeys]",
            "pytest",
            "mypy",
            "pyright",
        )
        run("uv", "pip", "install", "--python", str(python), "--no-deps", str(FIXTURE))
        clean_environment = dict(os.environ)
        clean_environment.pop("PYTHONPATH", None)
        run(str(python), "-m", "pytest", cwd=FIXTURE, env=clean_environment)
        run(str(python), "-m", "mypy", cwd=FIXTURE, env=clean_environment)
        run(str(python), "-m", "pyright", cwd=FIXTURE, env=clean_environment)
        metadata_check = (
            "from importlib.metadata import distributions, metadata;"
            "d=[x.metadata['Name'] for x in distributions() "
            "if x.metadata['Name'].lower().startswith('litestar-security')];"
            "assert d == ['litestar-security'], d;"
            "r=metadata('litestar-security').get_all('Requires-Dist') or [];"
            f"assert not any(x.lower().startswith({FORBIDDEN_DEPENDENCIES!r}) for x in r), r"
        )
        run(str(python), "-I", "-c", metadata_check, cwd=workspace, env=clean_environment)


if __name__ == "__main__":
    main()
