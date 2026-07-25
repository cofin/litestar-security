"""Reject postponed annotations in package modules."""

import ast
import sys
from pathlib import Path


def main(paths: list[str]) -> int:
    """Return a non-zero status when a file imports future annotations."""
    invalid: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
            and any(alias.name == "annotations" for alias in node.names)
            for node in tree.body
        ):
            invalid.append(path)

    for path in invalid:
        print(f"{path}: from __future__ import annotations is not allowed")
    return int(bool(invalid))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
