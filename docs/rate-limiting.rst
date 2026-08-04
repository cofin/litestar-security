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
   * - ``local.login.mfa``
     - 10 / 5 min
     - client + account
   * - ``local.registration``
     - 5 / hour
     - client + identifier
   * - ``local.recovery``
     - 5 / hour
     - client + identifier
   * - ``local.verification.resend``
     - 5 / hour
     - client + identifier
   * - ``local.verification.consume``
     - 10 / 5 min
     - client
   * - ``local.password.reset``
     - 10 / hour
     - client
   * - ``local.password.verify``
     - 10 / 5 min
     - client + account
   * - ``local.refresh.rotate``
     - 60 / 5 min
     - client
   * - ``local.mfa.totp.remove``
     - 5 / hour
     - client + account
   * - ``local.passkey.remove``
     - 5 / hour
     - client + account

Session and token login share one ``local.login`` budget on purpose. They
present the same credential to the same account store, so separate budgets would
let an attacker double their allowance by alternating between ``/auth/login``
and ``/auth/token``.

MFA-login completion uses its own ``local.login.mfa`` budget. Its challenge is
already bound to one account, so the limiter uses client and account buckets;
the password-login allowance cannot be reused to make extra factor guesses.

Password reset, verification confirmation, and refresh rotation are keyed on
the client only. The value they present is a token, not an identifier, and
digesting it into a bucket key would let the limiter backend become a record of
which tokens were attempted.

``local.password.verify`` is the step-up password factor: re-verifying the
password of an already-authenticated principal. It shares the TOTP verification
cadence because both are second-factor checks, and it is keyed on the account so
a stolen session cannot brute-force the password from many addresses. Factor
and credential removal consume a budget before the step-up grant is even
examined, so guessing at removals is bounded the same way as guessing at
credentials.

The MFA and passkey ceremonies — enrollment, verification, recovery-code
consumption and replacement, and the registration and authentication options —
carry budgets of their own under ``local.mfa.*`` and ``local.passkey.*``. Every
operation the generated routes limit appears in
:data:`~litestar_security.accounts.DEFAULT_RATE_LIMIT_POLICIES`.

Responses
=========

A denied attempt returns ``429`` with a ``Retry-After`` header when the limiter
reports one. A limiter that raises is treated as unavailable and **fails
closed** with ``503`` — an outage must not silently remove the limit.

Both statuses appear in the generated OpenAPI document.

Choosing a limiter for your deployment
=======================================

The bundled limiter holds a store *name*, not a store, and resolves it from the
application store registry at startup. An unregistered name yields Litestar's
in-memory default, which is correct for a single process and multiplies by your
worker count if you do not change it.

Point the name at a shared backend when every process must see the same bucket
values:

.. code-block:: python

   from litestar import Litestar
   from litestar.stores.redis import RedisStore

   from litestar_security.accounts import RATE_LIMIT_STORE_NAME

   app = Litestar(
       route_handlers=[],
       stores={RATE_LIMIT_STORE_NAME: RedisStore.with_client("redis://localhost:6379")},
   )

``StoreRateLimiter`` is exact across its instances and event loops *within one
process*: it serializes its complete read-modify-write operation with a
process-wide lock. A shared store makes bucket values visible to other
processes, but it cannot make that cycle atomic between processes or machines.
For a multi-process deployment, provide an application limiter backed by an
atomic backend primitive, then validate it with
:func:`~litestar_security.testing.assert_rate_limiter_conformance`.

Trusting the right client key
=============================

The default client key is the peer address, and it deliberately does **not**
honour ``X-Forwarded-For``. Those headers are attacker-controlled unless a proxy
you operate rewrote them, so trusting them by default would let anyone mint
unlimited buckets by varying one header.

Behind a proxy, use :func:`~litestar_security.accounts.forwarded_client_key`
and configure the exact CIDR ranges and number of forwarding hops that you
operate:

.. code-block:: python

   from litestar_security.accounts import LocalAuth, forwarded_client_key


   local_auth = LocalAuth.session(
       accounts=accounts,
       secrets=secrets,
       binding=binding,
       client_key=forwarded_client_key(
           trusted_proxies={"198.51.100.0/28", "2001:db8:1234:5::/64"},
           max_hops=2,
       ),
   )

Only do this when a proxy you control overwrites the header. The extractor
accepts forwarding data only from a directly connected address in those CIDRs,
then walks no more than ``max_hops`` entries from right to left and returns the
first address outside the trusted proxy ranges. An untrusted direct peer, a
missing or malformed header, or a chain whose inspected hops are all trusted
falls back to the direct peer.

Do not configure a broad network or too many hops merely to make a deployment
work. A shared-NAT proxy or an over-broad forwarding trust boundary can collapse
many unrelated clients into one client bucket, causing collateral ``429``
responses. Conversely, when ``client_key`` is absent or returns ``None`` there
is no client bucket at all; client-only operations lose their client limit and
combined operations retain only their identifier/account bucket. Do not replace
an unavailable client key with a shared sentinel value.

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

An operation absent from the mapping is not limited by that limiter. That is
why the shipped default map is provably exhaustive: an import-time assertion
requires :data:`~litestar_security.accounts.DEFAULT_RATE_LIMIT_POLICIES` to map
exactly ``RATE_LIMITED_OPERATIONS``, the canonical set of operations the
library's own routes hand to a limiter. A new library operation without a
default budget fails immediately rather than shipping unlimited. When you
replace the mapping wholesale, keep every operation you did not mean to
unlimit — starting from ``DEFAULT_RATE_LIMIT_POLICIES`` as above preserves the
guarantee.

Audit events
============

A denial emits a :class:`~litestar_security.accounts.SecurityEvent` with outcome
``rate_limited`` to the configured ``events`` sink. The event carries no account
identifier: the denial was keyed on a digest, and resolving it back to an
account would defeat the point of digesting it.
