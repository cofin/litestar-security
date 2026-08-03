"""Canonical operation and outcome names for local-account security events.

Every ``SecurityEvent`` an account service emits names an operation and an
outcome. Those names reach application audit sinks and durable outbox rows, so
applications match on them and a silent rename is a breaking change. Defining
them here keeps one spelling per concept instead of a literal per call site.

Operations read ``local.<area>.<verb>``. Outcomes are past-tense verbs describing
what the operation settled on, not whether the request succeeded.
"""

__all__ = (
    "LOGIN",
    "MFA_RECOVERY_CONSUME",
    "MFA_RECOVERY_REPLACE",
    "MFA_TOTP_ENROLL",
    "MFA_TOTP_REMOVE",
    "MFA_TOTP_VERIFY",
    "OUTCOME_ATTEMPTED",
    "OUTCOME_CHANGED",
    "OUTCOME_CLONE_RISK",
    "OUTCOME_CREATED",
    "OUTCOME_ISSUED",
    "OUTCOME_MALFORMED_HASH",
    "OUTCOME_RATE_LIMITED",
    "OUTCOME_REBOUND",
    "OUTCOME_RESET",
    "OUTCOME_REVOKED",
    "OUTCOME_UPDATED",
    "OUTCOME_VERIFIED",
    "PASSKEY_ASSERT",
    "PASSKEY_AUTH_OPTIONS",
    "PASSKEY_REGISTER_OPTIONS",
    "PASSKEY_REGISTER_VERIFY",
    "PASSKEY_REMOVE",
    "PASSWORD_CHANGE",
    "PASSWORD_FORCE_RESET",
    "PASSWORD_REFRESH_REVOKE",
    "PASSWORD_REHASH",
    "PASSWORD_RESET",
    "PASSWORD_SESSION_REBIND",
    "PASSWORD_SESSION_REVOKE_OTHERS",
    "PASSWORD_VERIFY",
    "RATE_LIMITED_OPERATIONS",
    "RECOVERY",
    "RECOVERY_CONSUME",
    "RECOVERY_ISSUE",
    "REFRESH_CREATE",
    "REFRESH_PREPARE",
    "REFRESH_RECEIPT",
    "REFRESH_REVOKE",
    "REFRESH_ROTATE",
    "REGISTRATION",
    "SESSION_LOGOUT",
    "SESSION_REBIND",
    "SESSION_REVOKE",
    "SESSION_REVOKE_ALL_SUFFIX",
    "VERIFICATION_CONSUME",
    "VERIFICATION_ISSUE",
    "VERIFICATION_RESEND",
)


PASSWORD_CHANGE = "local.password.change"
PASSWORD_FORCE_RESET = "local.password.force_reset"
PASSWORD_REFRESH_REVOKE = "local.password.refresh_revoke"
PASSWORD_REHASH = "local.password.rehash"
PASSWORD_SESSION_REBIND = "local.password.session_rebind"
PASSWORD_SESSION_REVOKE_OTHERS = "local.password.session_revoke_others"
PASSWORD_VERIFY = "local.password.verify"
RECOVERY = "local.recovery"
RECOVERY_CONSUME = "local.recovery.consume"
RECOVERY_ISSUE = "local.recovery.issue"
REFRESH_CREATE = "local.refresh.create"
REFRESH_PREPARE = "local.refresh.prepare"
REFRESH_RECEIPT = "local.refresh.receipt"
REFRESH_REVOKE = "local.refresh.revoke"
REFRESH_ROTATE = "local.refresh.rotate"
REGISTRATION = "local.registration"
SESSION_LOGOUT = "local.session.logout"
SESSION_REBIND = "local.session.rebind"
SESSION_REVOKE = "local.session.revoke"
VERIFICATION_CONSUME = "local.verification.consume"
VERIFICATION_ISSUE = "local.verification.issue"

# Appended to a caller-supplied operation when one request revokes every session
# an account holds, so the derived name still reports which operation caused it.
SESSION_REVOKE_ALL_SUFFIX = ".session_revoke_all"

# Rate-limited entry points. These are separate operations from the events above
# because a limiter buckets the *attempt*, which happens before any of those
# outcomes exist. Session and token login share one ``LOGIN`` budget on purpose:
# they present the same credential to the same account store, so giving them
# separate budgets would let an attacker double their allowance by alternating
# between the two routes.
LOGIN = "local.login"
MFA_RECOVERY_CONSUME = "local.mfa.recovery.consume"
MFA_RECOVERY_REPLACE = "local.mfa.recovery.replace"
MFA_TOTP_ENROLL = "local.mfa.totp.enroll"
MFA_TOTP_REMOVE = "local.mfa.totp.remove"
MFA_TOTP_VERIFY = "local.mfa.totp.verify"
PASSKEY_ASSERT = "local.passkey.assert"
PASSKEY_AUTH_OPTIONS = "local.passkey.authentication.options"
PASSKEY_REGISTER_OPTIONS = "local.passkey.registration.options"
PASSKEY_REGISTER_VERIFY = "local.passkey.registration.verify"
PASSKEY_REMOVE = "local.passkey.remove"
PASSWORD_RESET = "local.password.reset"
VERIFICATION_RESEND = "local.verification.resend"

# The exact set of operations the library's own routes/services hand to a
# RateLimiter. DEFAULT_RATE_LIMIT_POLICIES MUST map every one of these: an
# operation limited by a route but absent from the default map is silently
# unlimited (StoreRateLimiter.acquire admits unmapped operations).
RATE_LIMITED_OPERATIONS = frozenset({
    LOGIN,
    REGISTRATION,
    RECOVERY,
    PASSWORD_RESET,
    PASSWORD_VERIFY,
    VERIFICATION_RESEND,
    VERIFICATION_CONSUME,
    REFRESH_ROTATE,
    MFA_TOTP_ENROLL,
    MFA_TOTP_VERIFY,
    MFA_TOTP_REMOVE,
    MFA_RECOVERY_CONSUME,
    MFA_RECOVERY_REPLACE,
    PASSKEY_REGISTER_OPTIONS,
    PASSKEY_REGISTER_VERIFY,
    PASSKEY_AUTH_OPTIONS,
    PASSKEY_ASSERT,
    PASSKEY_REMOVE,
})

OUTCOME_ATTEMPTED = "attempted"
OUTCOME_CHANGED = "changed"
OUTCOME_CLONE_RISK = "clone_risk"
OUTCOME_CREATED = "created"
OUTCOME_ISSUED = "issued"
OUTCOME_MALFORMED_HASH = "malformed_hash"
OUTCOME_RATE_LIMITED = "rate_limited"
OUTCOME_REBOUND = "rebound"
OUTCOME_RESET = "reset"
OUTCOME_REVOKED = "revoked"
OUTCOME_UPDATED = "updated"
OUTCOME_VERIFIED = "verified"
