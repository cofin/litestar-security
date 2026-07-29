Getting started
===============

Choose a transport before configuring routes:

* ``LocalAuth.session`` uses a native Litestar session plus an independent
  binding cookie and requires CSRF.
* ``LocalAuth.tokens`` issues short-lived access JWTs and strict rotating opaque
  refresh families without a session.
* ``LocalAuth.hybrid`` exposes distinct browser and API routes. It never infers
  transport from middleware or request fields.

The complete tested factories are in ``examples.app``:

.. code-block:: console

   LITESTAR_SECURITY_EXAMPLE=local-session uv run litestar --app examples.app:create_app run
   LITESTAR_SECURITY_EXAMPLE=local-token uv run litestar --app examples.app:create_app run
   LITESTAR_SECURITY_EXAMPLE=local-hybrid uv run litestar --app examples.app:create_app run
   LITESTAR_SECURITY_EXAMPLE=no-session uv run litestar --app examples.app:create_app run

Configuration and admission are separate. Adding a verifier makes a mechanism
available; ``default_policy``, route ``security(...)`` metadata, and guards
decide where it is accepted. Startup rejects unknown mechanisms, duplicate
credential-slot ownership, competing session middleware, or missing CSRF
coverage.

Generated local routes are ordinary Litestar handlers with stable OpenAPI
operation identifiers. See :doc:`generated-routes` for the transport-specific
route matrix.
