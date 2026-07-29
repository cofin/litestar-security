Introduction
============

Litestar Security provides typed, backend-agnostic authentication and
authorization for Litestar applications. The plugin owns framework integration;
the application owns identity, persistence, key custody, delivery, and
deployment trust.

How it fits
-----------

Every request receives a typed ``Principal`` and ``SecurityContext``. Anonymous
requests get an anonymous principal. Authenticated requests carry verified
evidence and the authorization data returned by the application.

Authentication answers who presented acceptable evidence. Route policy decides
which evidence is accepted. Guards decide what that principal may do.

Litestar Security integrates with native sessions, CSRF, OpenAPI, exceptions,
dependency injection, and WebSockets. Applications supply the stores and
provider clients needed by the authentication methods they choose.
