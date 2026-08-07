"""Importable test fixture package.

Not collected: ``norecursedirs`` in ``pyproject.toml`` excludes this directory,
which keeps ``downstream_consumer/tests/`` -- a second package named ``tests`` --
off ``sys.path``. Exclusion from collection does not affect importability; test
modules import from here as ``tests.fixtures.<module>``.
"""
