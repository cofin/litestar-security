Introduction
============

Litestar Security will provide focused security integrations for Litestar
applications. The project is currently pre-alpha, so the first release keeps
its promises intentionally small.

What exists
-----------

The initial scaffold provides:

* an installable ``litestar-security`` distribution;
* a typed ``litestar_security`` package;
* :class:`litestar_security.SecurityConfig`;
* :class:`litestar_security.SecurityPlugin`;
* a ``litestar security`` CLI group; and
* development, test, documentation, and build automation.

What does not exist
-------------------

Authentication and authorization are not implemented. The plugin does not add
providers, middleware, guards, state, dependencies, or routes. It also makes no
claims about identity models, credentials, sessions, tokens, roles, or
permissions.

Those contracts will be designed and tested with the features that require
them. This avoids turning an empty scaffold into an accidental public security
API.
