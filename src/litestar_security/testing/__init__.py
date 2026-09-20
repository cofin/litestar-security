"""Testing utilities, store doubles, fakes, and conformance test suites."""

from collections.abc import Mapping

from litestar_security.providers.oauth import OAuthTransactionProtector
from litestar_security.testing.conformance import (
    StoreConformanceFactories,
    assert_api_key_store_conformance,
    assert_local_account_store_conformance,
    assert_mfa_login_challenge_store_conformance,
    assert_mfa_store_conformance,
    assert_oauth_account_store_conformance,
    assert_oauth_transaction_protector_conformance,
    assert_oauth_transaction_store_conformance,
    assert_oidc_session_logout_store_conformance,
    assert_passkey_store_conformance,
    assert_rate_limiter_conformance,
    assert_refresh_family_store_conformance,
    assert_secret_protector_conformance,
    assert_security_backend_conformance,
    assert_session_registry_conformance,
    assert_step_up_store_conformance,
    assert_webauthn_challenge_store_conformance,
    assert_websocket_connect_token_store_conformance,
)
from litestar_security.testing.fakes import (
    BackendBarrier,
    BackendEvent,
    FakeClock,
    FakeOAuthHTTPTransport,
    FakeOAuthProvider,
    FakeSecurityClock,
    InMemoryWebSocketRevocationSource,
    OAuthRequestObservation,
    StaticAuthorizationResolver,
    StaticAuthorizationSnapshotRefresher,
    StaticIdentityResolver,
)
from litestar_security.testing.stores import (
    InMemoryAPIKeyStore,
    InMemoryLocalAccountStore,
    InMemoryMFALoginChallengeStore,
    InMemoryMFAStore,
    InMemoryOIDCSessionLogoutStore,
    InMemoryPasskeyStore,
    InMemorySecurityBackend,
    InMemoryStepUpStore,
    InMemoryWebAuthnChallengeStore,
    InMemoryWebSocketConnectTokenStore,
    MemoryOAuthAccountStore,
    MemoryOAuthTransactionStore,
    TTLEvictionManager,
)

__all__ = (
    "BackendBarrier",
    "BackendEvent",
    "FakeClock",
    "FakeOAuthHTTPTransport",
    "FakeOAuthProvider",
    "FakeSecurityClock",
    "InMemoryAPIKeyStore",
    "InMemoryLocalAccountStore",
    "InMemoryMFALoginChallengeStore",
    "InMemoryMFAStore",
    "InMemoryOIDCSessionLogoutStore",
    "InMemoryPasskeyStore",
    "InMemorySecurityBackend",
    "InMemoryStepUpStore",
    "InMemoryWebAuthnChallengeStore",
    "InMemoryWebSocketConnectTokenStore",
    "InMemoryWebSocketRevocationSource",
    "MemoryOAuthAccountStore",
    "MemoryOAuthTransactionStore",
    "OAuthRequestObservation",
    "OAuthTransactionProtector",
    "StaticAuthorizationResolver",
    "StaticAuthorizationSnapshotRefresher",
    "StaticIdentityResolver",
    "StoreConformanceFactories",
    "TTLEvictionManager",
    "assert_api_key_store_conformance",
    "assert_local_account_store_conformance",
    "assert_mfa_login_challenge_store_conformance",
    "assert_mfa_store_conformance",
    "assert_oauth_account_store_conformance",
    "assert_oauth_transaction_protector_conformance",
    "assert_oauth_transaction_store_conformance",
    "assert_oidc_session_logout_store_conformance",
    "assert_passkey_store_conformance",
    "assert_rate_limiter_conformance",
    "assert_refresh_family_store_conformance",
    "assert_secret_protector_conformance",
    "assert_security_backend_conformance",
    "assert_session_registry_conformance",
    "assert_step_up_store_conformance",
    "assert_webauthn_challenge_store_conformance",
    "assert_websocket_connect_token_store_conformance",
)

_OPTIONAL_TESTING_EXPORTS: Mapping[str, tuple[str, str, frozenset[str]]] = {
    "MFAStore": ("litestar_security.accounts._mfa", "mfa", frozenset({"pyotp"})),
    "MFALoginChallengeStore": ("litestar_security.accounts._mfa_login", "mfa", frozenset({"pyotp"})),
    "PasskeyStore": ("litestar_security.accounts._passkeys", "passkeys", frozenset({"webauthn"})),
    "WebAuthnChallengeStore": ("litestar_security.accounts._passkeys", "passkeys", frozenset({"webauthn"})),
    "StepUpStore": ("litestar_security.accounts._mfa", "mfa", frozenset({"pyotp"})),
    "StepUpCredential": ("litestar_security.accounts._mfa", "mfa", frozenset({"pyotp"})),
    "PasskeyCredential": ("litestar_security.accounts._passkeys", "passkeys", frozenset({"webauthn"})),
    "PasskeyAssertionStatus": ("litestar_security.accounts._passkeys", "passkeys", frozenset({"webauthn"})),
    "WebAuthnChallenge": ("litestar_security.accounts._passkeys", "passkeys", frozenset({"webauthn"})),
    "MFALoginChallenge": ("litestar_security.accounts._mfa_login", "mfa", frozenset({"pyotp"})),
    "PendingTOTPEnrollment": ("litestar_security.accounts._mfa", "mfa", frozenset({"pyotp"})),
    "ProtectedSecret": ("litestar_security.accounts._mfa", "mfa", frozenset({"pyotp"})),
    "RecoveryCodeDigest": ("litestar_security.accounts._mfa", "mfa", frozenset({"pyotp"})),
    "SecretProtector": ("litestar_security.accounts._mfa", "mfa", frozenset({"pyotp"})),
    "StepUpGrantState": ("litestar_security.accounts._mfa", "mfa", frozenset({"pyotp"})),
    "TOTPMethod": ("litestar_security.accounts._mfa", "mfa", frozenset({"pyotp"})),
    "TOTPPolicy": ("litestar_security.accounts._mfa", "mfa", frozenset({"pyotp"})),
    "UserVerification": ("litestar_security.accounts._passkeys", "passkeys", frozenset({"webauthn"})),
}


def __getattr__(name: str) -> object:
    """Resolve optional testing exports only when their feature dependencies are available."""
    if name in ("_single_winner", "_DeterministicProtector"):
        import importlib

        module_path = (
            "litestar_security.testing.conformance" if name == "_single_winner" else "litestar_security.testing.stores"
        )
        return getattr(importlib.import_module(module_path), name)

    from litestar_security._typing import import_optional_attribute

    target = _OPTIONAL_TESTING_EXPORTS.get(name)
    if target is not None:
        module_name, extras, dependencies = target
        return import_optional_attribute(module_name, name, extras=extras, dependencies=dependencies)
    message = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(message)
