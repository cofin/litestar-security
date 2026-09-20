Security backend upgrades
=========================

Backend adoption is opt-in. Existing application-provided stores remain
supported through the public store protocols; installing a new backend does
not replace those stores or migrate their data.

Before adopting a backend, inventory the stores configured by your application,
their table and column names, and the migration system that owns their schema.
Keep application-owned migrations authoritative for existing data. Creating a
fresh backend schema is not an upgrade procedure for an existing database.

Validate a proposed change against a copy of the application's data, including
authentication, session revocation, token reuse rejection, and authorization.
Plan data conversion and rollback before switching the configured stores.

See :doc:`../composition` for application composition and
:doc:`../reference` for the public contracts.

SQLSpec account store imports
-----------------------------

Prefer the named import
``from litestar_security.backends.sqlspec.stores import SQLSpecAccountStore``.
Wildcard imports from the implementation module
``litestar_security.backends.sqlspec.stores.accounts`` now expose only that
store class. If your application relied on incidental helper imports from that
module, import those helpers directly from their defining public modules.
Named store imports and database schemas are unchanged.
