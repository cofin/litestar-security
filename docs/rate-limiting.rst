=============
Rate limiting
=============

Local authentication routes are unauthenticated and deliberately expensive.
Password verification runs Argon2, which is correct for password storage and
also means one cheap request costs the server real CPU. Left unbounded, those
routes are both a password-guessing surface and an amplification lever, so every
abuse-prone operation consumes a budget before it does any credential work.

Limiting is on by default. You do not have to configure anything to get it.

Two tiers
=========

Litestar already ships :class:`~litestar.middleware.rate_limit.RateLimitConfig`,
a per-route middleware keyed on the client address. Use it. It is the right tool
for coarse per-address limits across your whole application, and this library
does not reimplement it.

What middleware cannot do is key a bucket on the *submitted identifier*, because
it runs before the request body is parsed. That distinction matters:

- **Address-keyed limits** stop one machine hammering your login route. They do
  not stop a botnet spreading ten thousand guesses for one account across ten
  thousand addresses, where every address looks idle.
- **Identifier-keyed limits** stop that. They do not stop one machine spraying
  one common password across ten thousand accounts, where every account sees a
  single attempt.

You need both. This library supplies the second tier, applied inside the
services, before hashing.

What is limited
===============

.. list-table::
   :header-rows: 1
   :widths: 40 20 40

   * - Operation
     - Default budget
     - Buckets
   * - ``local.login``
     - 10 / 5 min
     - client + identifier
   * - ``local.registration``
     - 5 / hour
     - client + identifier
   * - ``local.recovery``
     - 5 / hour
     - client + identifier
   * - ``local.verification.resend``
     - 5 / hour
     - client + identifier
   * - ``local.password.reset``
     - 10 / hour
     - client
   * - ``local.refresh.rotate``
     - 60 / 5 min
     - client

Session and token login share one ``local.login`` budget on purpose. They
present the same credential to the same account store, so separate budgets would
let an attacker double their allowance by alternating between ``/auth/login``
and ``/auth/token``.

Password reset and refresh rotation are keyed on the client only. The value they
present is a token, not an identifier, and digesting it into a bucket key would
let the limiter backend become a record of which tokens were attempted.

Responses
=========

A denied attempt returns ``429`` with a ``Retry-After`` header when the limiter
reports one. A limiter that raises is treated as unavailable and **fails
closed** with ``503`` — an outage must not silently remove the limit.

Both statuses appear in the generated OpenAPI document.

Making it correct across processes
==================================

The bundled limiter holds a store *name*, not a store, and resolves it from the
application store registry at startup. An unregistered name yields Litestar's
in-memory default, which is correct for a single process and multiplies by your
worker count if you do not change it.

Point the name at a shared backend and counting becomes correct everywhere:

.. code-block:: python

   from litestar import Litestar
   from litestar.stores.redis import RedisStore

   from litestar_security.accounts import RATE_LIMIT_STORE_NAME

   app = Litestar(
       route_handlers=[],
       stores={RATE_LIMIT_STORE_NAME: RedisStore.with_client("redis://localhost:6379")},
   )

The bundled limiter counts with a read-modify-write cycle, because the native
store contract exposes no compare-and-increment. Concurrent attempts can
therefore undercount slightly. Where exactness matters, supply a limiter backed
by an atomic primitive.

Trusting the right client key
=============================

The default client key is the peer address, and it deliberately does **not**
honour ``X-Forwarded-For``. Those headers are attacker-controlled unless a proxy
you operate rewrote them, so trusting them by default would let anyone mint
unlimited buckets by varying one header.

Behind a proxy, supply an extractor that knows which hops you trust:

.. code-block:: python

   from litestar_security.accounts import LocalAuth


   def client_key(connection):
       forwarded = connection.headers.get("X-Forwarded-For")
       return forwarded.split(",")[0].strip() if forwarded else None


   local_auth = LocalAuth.session(
       accounts=accounts,
       secrets=secrets,
       binding=binding,
       client_key=client_key,
   )

Only do this when a proxy you control overwrites the header. Returning ``None``
disables the client bucket and leaves the identifier bucket in force.

Supplying your own limiter
==========================

:class:`~litestar_security.accounts.RateLimiter` is a port. Implement
``acquire`` and pass it as ``rate_limiter``:

.. code-block:: python

   from litestar_security.accounts import RateLimitDecision, RateLimitRequest


   class MyLimiter:
       async def acquire(self, request: RateLimitRequest) -> RateLimitDecision:
           allowed, retry_after = await my_backend.consume(
               request.operation, request.client_key, request.subject_digest
           )
           return RateLimitDecision(allowed=allowed, retry_after=None if allowed else retry_after)

``request.subject_digest`` is a peppered HMAC of the normalized identifier, never
the identifier itself, so a limiter backend never stores email addresses. Raise
from ``acquire`` to signal an outage; the caller fails closed.

To limit only at the edge, pass
:class:`~litestar_security.accounts.UnlimitedRateLimiter`.

Tuning the budgets
==================

.. code-block:: python

   from datetime import timedelta

   from litestar_security.accounts import (
       DEFAULT_RATE_LIMIT_POLICIES,
       RateLimitPolicy,
       StoreRateLimiter,
   )

   limiter = StoreRateLimiter(
       policies={
           **DEFAULT_RATE_LIMIT_POLICIES,
           "local.login": RateLimitPolicy(limit=5, window=timedelta(minutes=15)),
       }
   )

An operation absent from the mapping is not limited by that limiter.

Audit events
============

A denial emits a :class:`~litestar_security.accounts.SecurityEvent` with outcome
``rate_limited`` to the configured ``events`` sink. The event carries no account
identifier: the denial was keyed on a digest, and resolving it back to an
account would defeat the point of digesting it.
