"""Disallow postponed evaluation of annotations in source code."""

import ast
import sys
from pathlib import Path


def _has_future_annotations(path: Path) -> bool:
    """Check whether a python file imports __future__.annotations."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return False
    try:
        tree = ast.parse(content, filename=str(path))
    except SyntaxError:
        return "from __future__ import annotations" in content

    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )


def main(argv: list[str]) -> int:
    """Scan given files for forbidden future annotations imports."""
    bad_files: list[str] = [
        str(path) for raw in argv[1:] if (path := Path(raw)).suffix == ".py" and _has_future_annotations(path)
    ]

    if not bad_files:
        return 0

    sys.stderr.write("Disallowed future import found. Remove `from __future__ import annotations` from:\n")
    for file_name in bad_files:
        sys.stderr.write(f" - {file_name}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
