"""Enforce the import boundaries ruff cannot express.

Ruff owns the flat rules: no runtime module imports ``litestar_security.testing``
or any storage adapter (``[tool.ruff.lint.flake8-tidy-imports.banned-api]``), and
no relative import can route around them (``ban-relative-imports``). Two rules are
left over:

R4  Runtime source carries no per-call awaitability branch. Expressible in ruff,
    but ``banned-api`` has no per-key ``per-file-ignores``, so the single
    exemption below would un-ban every other entry for that file.
R5  ``import litestar_security`` loads neither the test kit nor its exports.
    A runtime property of the import graph; no linter can observe it.

Run by ``make import-boundaries``, which ``make lint`` depends on. ``--self-test``
proves both checks fail on a deliberate violation.
"""

import ast
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

PACKAGE_ROOT = Path(__file__).parents[1] / "src" / "litestar_security"

# R4 exemptions, by path relative to PACKAGE_ROOT. Each entry states why the
# branch is still there. An empty dict is the goal.
AWAITABILITY_EXEMPTIONS: dict[str, str] = {
    "providers/jwks/_provider.py": "Closes an owned fetcher whose aclose() may be sync or async."
}

R5_SCRIPT = (
    "import sys; import litestar_security; "
    "assert 'litestar_security.testing' not in sys.modules; "
    "assert not hasattr(litestar_security, 'InMemorySecurityBackend')"
)


def _inspect_aliases(tree: ast.Module) -> tuple[frozenset[str], frozenset[str]]:
    """Collect the names an ``inspect`` import binds in one module.

    Args:
        tree: Parsed module to scan.

    Returns:
        Names bound to the ``inspect`` module, and names bound straight to
        ``inspect.isawaitable`` by a from-import, whatever they were renamed to.
    """
    modules: set[str] = set()
    directs: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name for alias in node.names if alias.name == "inspect")
        elif isinstance(node, ast.ImportFrom) and node.module == "inspect":
            directs.update(alias.asname or alias.name for alias in node.names if alias.name == "isawaitable")
    return frozenset(modules), frozenset(directs)


def _module_violations(source: Path, label: str) -> list[str]:
    """Find every per-call awaitability reference in one module.

    Args:
        source: Module to parse.
        label: Path to name the module by in a violation message.

    Returns:
        One ``path:line`` string per reference, ordered by line.
    """
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    modules, directs = _inspect_aliases(tree)
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "inspect":
            lines.update(node.lineno for alias in node.names if alias.name == "isawaitable")
        elif isinstance(node, ast.Attribute) and node.attr == "isawaitable":
            if isinstance(node.value, ast.Name) and node.value.id in modules:
                lines.add(node.lineno)
        elif isinstance(node, ast.Name) and node.id in directs and isinstance(node.ctx, ast.Load):
            lines.add(node.lineno)
    return [f"{label}:{line}" for line in sorted(lines)]


def awaitability_violations(root: Path, exemptions: Mapping[str, str]) -> list[str]:
    """Check R4 across a package tree.

    Args:
        root: Package directory to walk.
        exemptions: Reason per exempted path, relative to ``root``.

    Returns:
        One ``path:line`` string per unexempted reference.
    """
    violations: list[str] = []
    for source in sorted(root.rglob("*.py")):
        label = source.relative_to(root).as_posix()
        if label in exemptions:
            continue
        violations.extend(_module_violations(source, label))
    return violations


def eager_import_failure(prelude: str = "") -> str:
    """Check R5 in an interpreter that carries nothing from this shell.

    Args:
        prelude: Statements to run before the check, used by ``--self-test`` to
            put a stub package on the path that ``-I`` would otherwise exclude.

    Returns:
        The child's diagnostic output, or an empty string when R5 holds.
    """
    result = subprocess.run(  # noqa: S603 - fixed interpreter, repository-owned script
        [sys.executable, "-I", "-c", prelude + R5_SCRIPT], check=False, capture_output=True, text=True
    )
    return "" if result.returncode == 0 else (result.stderr or "R5 check failed without output")


def _write(path: Path, body: str) -> None:
    """Write one module, creating its parent directories.

    Args:
        path: File to write.
        body: Source text to write into it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _self_test_r4(workspace: Path) -> list[str]:
    """Prove R4 catches both spellings and honours an exemption.

    Args:
        workspace: Temporary directory to build the fixture packages in.

    Returns:
        One message per deliberate violation that went undetected.
    """
    failures: list[str] = []
    package = workspace / "both_spellings"
    _write(package / "from_import.py", "from inspect import isawaitable as maybe\n\n\ndef f(x):\n    return maybe(x)\n")
    _write(package / "attribute.py", "import inspect\n\n\ndef f(x):\n    return inspect.isawaitable(x)\n")
    _write(package / "clean.py", "def f(x):\n    return x\n")

    found = awaitability_violations(package, {})
    failures.extend(
        f"R4 missed the {spelling} spelling; reported {found}"
        for spelling in ("from_import.py", "attribute.py")
        if not any(violation.startswith(spelling) for violation in found)
    )
    if any(violation.startswith("clean.py") for violation in found):
        failures.append(f"R4 flagged a clean module; reported {found}")
    print(f"  R4 both spellings: {found}")

    exempted = workspace / "exempted"
    _write(exempted / "providers" / "jwks" / "_provider.py", "from inspect import isawaitable\n")
    still_found = awaitability_violations(exempted, {"providers/jwks/_provider.py": "self-test"})
    if still_found:
        failures.append(f"R4 ignored its exemption table; reported {still_found}")
    print(f"  R4 exemption honoured: {still_found == []}")
    return failures


def _self_test_r5(workspace: Path) -> list[str]:
    """Prove R5 fails against a package that eagerly imports its test kit.

    Args:
        workspace: Temporary directory to build the stub package in.

    Returns:
        One message if the deliberate violation went undetected.
    """
    stub = workspace / "stub"
    _write(stub / "litestar_security" / "testing.py", "InMemorySecurityBackend = object\n")
    _write(
        stub / "litestar_security" / "__init__.py",
        "from litestar_security.testing import InMemorySecurityBackend\n\n__all__ = ('InMemorySecurityBackend',)\n",
    )
    prelude = f"import sys; sys.path.insert(0, {str(stub)!r}); "
    failure = eager_import_failure(prelude)
    print(f"  R5 catches an eager test-kit import: {bool(failure)}")
    return [] if failure else ["R5 passed against a stub that eagerly imports its testing surface"]


def self_test() -> int:
    """Prove every check fails on a deliberate violation.

    Returns:
        ``0`` when all three deliberate violations were caught, ``1`` otherwise.
    """
    print("Self-test: each case below is a deliberate violation that must be caught.")
    with tempfile.TemporaryDirectory(prefix="litestar-security-boundaries-") as temporary:
        failures = _self_test_r4(Path(temporary)) + _self_test_r5(Path(temporary))
    if failures:
        sys.stderr.write("Self-test FAILED - a deliberate violation was not caught:\n")
        for failure in failures:
            sys.stderr.write(f" - {failure}\n")
        return 1
    print("Self-test passed: 3 deliberate violations caught.")
    return 0


def main(argv: list[str]) -> int:
    """Run the import-boundary checks ruff cannot express.

    Args:
        argv: Process arguments; ``--self-test`` runs the deliberate-violation
            suite instead of checking the repository.

    Returns:
        ``0`` when every boundary holds, ``1`` otherwise.
    """
    if "--self-test" in argv[1:]:
        return self_test()

    for path, reason in sorted(AWAITABILITY_EXEMPTIONS.items()):
        print(f"INFO: R4 exempts {path}: {reason}")

    failed = False
    violations = awaitability_violations(PACKAGE_ROOT, AWAITABILITY_EXEMPTIONS)
    if violations:
        failed = True
        sys.stderr.write("R4: runtime source must carry no per-call awaitability branch. Found:\n")
        for violation in violations:
            sys.stderr.write(f" - {violation}\n")

    failure = eager_import_failure()
    if failure:
        failed = True
        sys.stderr.write("R5: `import litestar_security` must not load the test kit or its exports:\n")
        sys.stderr.write(f"{failure}\n")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
