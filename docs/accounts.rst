Accounts, factors, and recovery
===============================

Applications own the local account capability store and its transaction
boundaries. Registration, verification, password change/reset, session
inventory/revocation, refresh rotation, and login-method changes are explicit
typed operations. Enumeration-sensitive endpoints return uniform accepted
responses.

Refresh tokens are opaque, rotating, family-bound, and replay-aware. Password
or factor changes advance the authoritative security epoch so old sessions and
tokens fail closed. Idempotency receipts never store or reveal a recoverable
refresh token.

TOTP enrollment is pending until verified. Recovery codes are reveal-once,
peppered digests. Passkey challenges and step-up grants are short-lived,
purpose-bound, and one-time. Removing a password, provider identity, TOTP
factor, or passkey must preserve at least one viable login method through an
application-store atomic operation.

Generated controllers are optional. Set ``register_routes=False`` and compose
the typed services into application-owned handlers when product behavior or
administrator workflow differs. See :doc:`customization`.
