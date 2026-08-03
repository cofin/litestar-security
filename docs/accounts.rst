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

Recovery-code digests are account-bound under the current ``v2`` domain. Codes
issued by an earlier release must be replaced with
``MFAService.generate_recovery_codes()`` before they can be used.

Generated controllers are optional. Set ``register_routes=False`` and compose
the typed services into application-owned handlers when product behavior or
administrator workflow differs. See :doc:`customization`.

Require MFA after password login
================================

Set ``MFAConfig(require_at_login=True)`` to require TOTP or a recovery code
after a verified password and before a local session or token pair is issued.
The configuration requires recovery-code peppers, a login-method store, and an
atomic :class:`~litestar_security.accounts.MFALoginChallengeStore`; the explicit
``login_challenge_store`` overrides ``store`` when supplied. The store keeps
only a digest and atomically consumes a challenge exactly once.

**An account with no enrolled factor cannot complete a login.** Roll out
enrollment and retain a usable factor before enabling this deployment-wide
setting. In particular, keep the ``method_id`` returned at TOTP enrollment:
there is no factor-discovery port to recover it later.
