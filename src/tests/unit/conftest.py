"""Session-scoped unit-test contracts."""

from collections.abc import Mapping

import pytest

import litestar_security.accounts as accounts_module
from litestar_security.context import Principal
from litestar_security.providers.jwt import LocalKeyRing, SigningKey
from litestar_security.testing import FakeClock, InMemoryOIDCSessionLogoutStore, InMemorySecurityBackend
from tests.fixtures import collaborators


@pytest.fixture(scope="session")
def anonymous_principal() -> Principal[object]:
    """Return the immutable anonymous principal shared by unit tests."""
    return Principal.anonymous()


@pytest.fixture(scope="session")
def local_key_ring(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> LocalKeyRing:
    """Return one explicit immutable local EdDSA key ring."""
    private_key, _ = jwt_key_material["EdDSA"]
    return LocalKeyRing(
        issuer="https://local.example",
        active_signing_key=SigningKey(key_id="local-key", algorithm="EdDSA", private_key=private_key),
    )


@pytest.fixture
def password_hasher() -> "accounts_module.Argon2PasswordHasher":
    """Return one request-local hasher because its limiter tracks mutable loans."""
    return accounts_module.Argon2PasswordHasher()


@pytest.fixture
def security_backend(clock: FakeClock) -> InMemorySecurityBackend:
    """Return one aggregate backend because every store it owns is mutable."""
    return InMemorySecurityBackend(clock=clock)


@pytest.fixture
def account_store(security_backend: InMemorySecurityBackend) -> object:
    """Return the backend's account store; sessions and refresh families live here too."""
    return security_backend.accounts


@pytest.fixture
def session_registry(security_backend: InMemorySecurityBackend) -> object:
    """Return the account store again, because sessions are folded into it."""
    return security_backend.accounts


@pytest.fixture
def refresh_family_store(security_backend: InMemorySecurityBackend) -> object:
    """Return the account store again, because refresh families are folded into it."""
    return security_backend.accounts


@pytest.fixture
def api_key_store(security_backend: InMemorySecurityBackend) -> object:
    """Return the backend's API-key store, which records issuance and revocation."""
    return security_backend.api_keys


@pytest.fixture
def mfa_store(security_backend: InMemorySecurityBackend) -> object:
    """Return the backend's MFA store, whose enrollments mutate."""
    return security_backend.mfa


@pytest.fixture
def mfa_login_challenge_store(security_backend: InMemorySecurityBackend) -> object:
    """Return the backend's MFA login-challenge store, which is consumed in place."""
    return security_backend.mfa_login


@pytest.fixture
def passkey_store(security_backend: InMemorySecurityBackend) -> object:
    """Return the backend's passkey store, whose credentials mutate."""
    return security_backend.passkeys


@pytest.fixture
def webauthn_challenge_store(security_backend: InMemorySecurityBackend) -> object:
    """Return the backend's WebAuthn challenge store, which is consumed in place."""
    return security_backend.challenges


@pytest.fixture
def step_up_store(security_backend: InMemorySecurityBackend) -> object:
    """Return the backend's step-up store, whose grants are consumed in place."""
    return security_backend.step_up


@pytest.fixture
def oauth_account_store(security_backend: InMemorySecurityBackend) -> object:
    """Return the backend's OAuth account store, a shipped production adapter under write."""
    return security_backend.oauth_accounts


@pytest.fixture
def oauth_transaction_store(security_backend: InMemorySecurityBackend) -> object:
    """Return the backend's OAuth transaction store, whose transactions are single-use."""
    return security_backend.oauth_transactions


@pytest.fixture
def token_vault(security_backend: InMemorySecurityBackend) -> object:
    """Return the backend's token vault, which rotates stored tokens under compare-and-swap."""
    return security_backend.oauth_tokens


@pytest.fixture
def connect_token_store(security_backend: InMemorySecurityBackend) -> object:
    """Return the backend's WebSocket connect-token store, whose tickets are consumed once."""
    return security_backend.websocket_connect_tokens


@pytest.fixture
def oidc_logout_store() -> InMemoryOIDCSessionLogoutStore:
    """Return a standalone OIDC logout store, because the aggregate backend cannot reach one.

    Use ``collaborators.build_security_environment()`` instead when a test needs
    this store and the backend to share one clock.
    """
    return InMemoryOIDCSessionLogoutStore(session_mappings=(), frontchannel_bindings={})


@pytest.fixture
def rate_limiter() -> object:
    """Return one production limiter over a fresh store because its counters mutate."""
    return collaborators.build_rate_limiter()


@pytest.fixture(scope="session")
def secret_protector() -> object:
    """Return one protector for the session because it is a frozen dataclass holding no mutable state."""
    return collaborators.build_secret_protector()
