Development installation
========================

Prerequisites
-------------

Install ``uv`` and a supported Python version (3.10 through 3.14). The
repository's lockfile records the complete development dependency graph.

Install dependencies
--------------------

From the repository root:

.. code-block:: console

   make install

This creates ``.venv`` and installs the package in editable mode.

Validate the environment
------------------------

Run the tests first:

.. code-block:: console

   make test

Run every local gate before handing off a change:

.. code-block:: console

   make check-all

The aggregate target checks hooks, tests, coverage, mypy, pyright, slots,
documentation, links, and package builds.
