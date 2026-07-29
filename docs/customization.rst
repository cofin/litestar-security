Customization and application ownership
=======================================

Core integration ports are deliberately small and atomic. Implement the
protocols needed by the selected feature, then run the matching helpers from
``litestar_security.testing``. ``InMemorySecurityBackend`` and deterministic
provider transports are references for tests and examples, not production
persistence.

Async implementations stay on the event loop. Wrap a complete synchronous port
in ``BlockingIntegration`` so the runtime can use the configured bounded worker
budget. Do not wrap individual calls or perform hidden blocking I/O in async
methods.

Litestar Security does not install a general administrator API. The
``custom-admin`` example owns a controller and applies application guards while
orchestrating disable, forced reset, and credential/factor/session/key
revocation services:

.. code-block:: console

   LITESTAR_SECURITY_EXAMPLE=custom-admin uv run litestar --app examples.app:create_app run

Provider HTTP transports, delivery commands, audit sinks, metrics, rate-limit
stores, user resolution, role/team/tenant snapshots, and key-management clients
remain application choices.
