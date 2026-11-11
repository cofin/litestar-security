Contributing
============

Litestar Security uses test-driven development and Conventional Commits. Keep
changes focused on an approved contract.

Development installation
------------------------

The project uses ``uv`` for dependency management. Install ``uv`` and a
supported Python version (``3.10`` through ``3.14``), then sync every locked
development group and optional extra from the repository root:

.. code-block:: console

   make install

``uv.lock`` remains tracked so local development and CI resolve the same
dependency graph.

Making a change
---------------

Write a failing test before changing behavior, then implement the smallest
change that makes it pass. Place isolated pure-logic tests under
``src/tests/unit/`` (without ``Litestar`` or HTTP test clients) and end-to-end
application, controller, CLI, and WebSocket tests under
``src/tests/integration/``. Preserve runtime-evaluatable type annotations (never
add ``from __future__ import annotations``) and keep runtime modules free of
storage, ORM, cache, and cloud SDK dependencies.

Run the focused checks while editing:

.. code-block:: console

   make test
   make coverage
   make type-check
   make lint
   make examples
   make docs
   make docs-linkcheck
   make build

Before handing off a change, run the complete validation surface:

.. code-block:: console

   make check-all

JWT and JWKS performance benchmarks are local-only and run separately from the
standard test suite:

.. code-block:: console

   make performance

Documentation and changelog
---------------------------

Build the Sphinx documentation and validate links locally with ``make docs`` and
``make docs-linkcheck`` (warnings are treated as errors under ``-W``).

Public changes should include an entry under the target release section in
``docs/changelog.rst``.

Commit messages and hooks
-------------------------

Use Conventional Commits, such as ``feat(providers): add bearer prefix check``
or ``docs: clarify plugin composition``. Run repository hygiene hooks locally
with ``uv run prek run --all-files`` (included inside ``make lint``).
