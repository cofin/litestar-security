Contributing
============

Litestar Security uses test-driven development and Conventional Commits. Keep
changes focused on an approved contract.

Install ``uv`` and a supported Python version, then create the locked
development environment:

.. code-block:: console

   make install

Use the focused checks while working:

.. code-block:: console

   make test
   make coverage
   make type-check
   make lint
   make docs
   make docs-linkcheck
   make build

Run every local gate before handing off a change:

.. code-block:: console

   make check-all

JWT and JWKS performance checks are local-only and separate from the normal
test suite:

.. code-block:: console

   make performance

The complete contributor guide is in the repository's ``CONTRIBUTING.rst``
file.
