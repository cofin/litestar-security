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

MFA secret protection
=====================

``MFAConfig`` requires a ``SecretProtector``. Use the first-party
``AESGCMSecretProtector`` unless the application has a separate protector that
meets the same contract:

.. code-block:: python

   from litestar_security import MFAConfig
   from litestar_security.accounts import AESGCMSecretProtector, SecretProtectorKey


   # ``mfa_store`` is the application's MFAStore implementation.
   active_key = SecretProtectorKey(
       "v2",
       application_secret_store.get_bytes("mfa-secret-protector/v2"),
   )
   previous_key = SecretProtectorKey(
       "v1",
       application_secret_store.get_bytes("mfa-secret-protector/v1"),
   )
   mfa = MFAConfig(
       store=mfa_store,
       secret_protector=AESGCMSecretProtector(
           active_key=active_key,
           retained_keys=(previous_key,),
       ),
       register_routes=False,
   )

Each key is exactly 32 bytes of application-owned material obtained from a KMS
or secret store; never embed it as a source-code literal. To rotate a key, add
the old active key to ``retained_keys`` before promoting the new ``active_key``.
Retain it until every MFA secret encrypted with that version has been replaced
or is no longer usable.

Applications may provide their own protector. Verify it with
:func:`~litestar_security.testing.assert_secret_protector_conformance`, which
checks round-tripping, key-version labeling, associated-data authentication,
and non-deterministic protection.

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
setting.

Set ``require_at_login="enrolled"`` to challenge only the accounts that hold a
viable TOTP or passkey factor, so unenrolled accounts sign in directly. The
enrolled set is read from
:meth:`~litestar_security.accounts.LoginMethodStore.list_methods` on the
configured ``login_methods`` store, and binding fails when that store does not
implement it.
