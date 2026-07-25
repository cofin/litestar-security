Contributing
============

Litestar Security is pre-alpha. Contributions should preserve the small public
surface until authentication or authorization behavior has an approved design.

Development installation
------------------------

The project uses ``uv`` for dependency management. From the repository root,
install every locked development group:

.. code-block:: console

   make install

The supported Python range is 3.10 through 3.14. The lockfile remains tracked
so local development and CI resolve the same dependency graph.

Making a change
---------------

Write a failing test before changing behavior, then implement the smallest
change that makes it pass. Keep plugin lifecycle concerns separate from future
authentication and authorization features.

Run the focused checks while editing:

.. code-block:: console

   make test
   make type-check
   make lint

Before proposing a change, run the complete validation surface:

.. code-block:: console

   make check-all

Documentation
-------------

Build the documentation and validate links locally:

.. code-block:: console

   make docs
   make docs-linkcheck

Public changes should include an entry under ``Unreleased`` in
``docs/changelog.rst``.

Commit messages
---------------

Use Conventional Commits, such as ``feat: add a security integration`` or
``docs: clarify plugin setup``. The repository hooks validate commit messages
and source files.
