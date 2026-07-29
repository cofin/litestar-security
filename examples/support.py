"""Deterministic local-only support objects for the runnable examples."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from litestar.datastructures import Cookie
from litestar.middleware.session.client_side import CookieBackendConfig

from litestar_security.accounts import (
    ConsumeResult,
    ConsumeStatus,
    CreateRefreshFamilyCommand,
    CreateSessionCommand,
    LocalAccount,
    LocalAccountCapabilities,
    LocalAuth,
    LocalAuthConfig,
    LocalAuthSecrets,
    NotificationCommand,
    PasswordChangeResult,
    PasswordChangeStatus,
    PasswordCredentialState,
    PasswordResetResult,
    PasswordResetStatus,
    PasswordVerificationResult,
    PasswordVerificationStatus,
    PurposeTokenCodec,
    RefreshFamilyContext,
    RefreshReceiptKey,
    RefreshReceiptSealer,
    RefreshRotationStatus,
    RefreshTokenCodec,
    RefreshTokenProof,
    RegistrationPolicy,
    RegistrationResult,
    RegistrationStatus,
    RotateRefreshCommand,
    RotateRefreshResult,
    SessionBindingConfig,
    SessionRecord,
    TokenIssue,
    TokenPurpose,
)
from litestar_security.context import AuthorizationSnapshot, Principal
from litestar_security.providers.api_key import APIKeyClaims, APIKeyConfig
from litestar_security.providers.iap import GoogleIAPClaims, GoogleIAPConfig
from litestar_security.providers.jwt import LocalKeyRing, SigningKey
from litestar_security.providers.oauth import (
    OAuthAuthorization,
    OAuthConfig,
    OAuthLogoutResult,
    OAuthOperation,
    OAuthRouteResponse,
    ProviderIdentity,
    ProviderTokenSet,
    SecretStr,
)
from litestar_security.providers.oidc import ServiceTokenConfig
from litestar_security.testing import FakeOAuthProvider, InMemorySecurityBackend
from litestar_security.websocket import WebSocketSecurityConfig

if TYPE_CHECKING:
    from litestar.connection import Request

    from litestar_security.authentication import InvalidCredentials
    from litestar_security.providers.jwks import JWKSProvider

__all__ = (
    "ExampleAccountStore",
    "build_api_team_config",
    "build_iap_config",
    "build_local_auth",
    "build_oauth_config",
    "build_websocket_config",
    "example_account_store",
    "example_session_config",
)

_PURPOSE_PEPPER = b"p" * 32
_REFRESH_PEPPER = b"r" * 32
_RECEIPT_KEY = b"k" * 32
_BINDING_PEPPER = b"b" * 32
_IAP_AUDIENCE = "/projects/123/global/backendServices/456"


class _UnavailableJWKS:
    async def select_key(
        self, issuer: str, jwks_uri: str, kid: str, algorithm: str, *, now: datetime
    ) -> InvalidCredentials:
        del issuer, jwks_uri, kid, algorithm, now
        from litestar_security.authentication import InvalidCredentials  # noqa: PLC0415 - type used on request only

        return InvalidCredentials()

    async def warmup(self, *, now: datetime) -> None:
        del now

    async def aclose(self) -> None:
        return None


class _ExampleIdentityResolver:
    async def resolve(self, claims: APIKeyClaims | GoogleIAPClaims) -> Principal[object]:
        subject = getattr(claims, "subject_id", None) or getattr(claims, "subject", None)
        return Principal(id=cast("str", subject), user=object())


class _ExampleOAuthService:
    def __init__(self, provider_name: str) -> None:
        self.provider_names = frozenset({provider_name})

    async def begin(  # noqa: PLR0913 - mirrors the public OAuth service boundary
        self,
        *,
        provider: str,
        operation: OAuthOperation,
        account_id: str | None,
        provider_account_id: str | None,
        return_to: str,
        scopes: frozenset[str] | None,
        step_up_grant: str | None,
        request: Request[Any, Any, Any],
    ) -> OAuthAuthorization:
        del operation, account_id, provider_account_id, return_to, scopes, step_up_grant, request
        return OAuthAuthorization(
            url=f"https://provider.example/authorize?provider={provider}&code_challenge=example",
            binding_cookie=Cookie(
                key="__Host-litestar-security-oauth",
                value="example-binding",
                path="/",
                secure=True,
                httponly=True,
                samesite="lax",
            ),
        )

    async def callback(
        self, *, provider: str, code: str, state: str, request: Request[Any, Any, Any]
    ) -> OAuthRouteResponse:
        del code, state, request
        return OAuthRouteResponse(detail="Authenticated.", provider_account_id=f"{provider}-account")

    async def unlink(self, **_kwargs: object) -> OAuthRouteResponse:
        return OAuthRouteResponse(detail="Unlinked.")

    async def revoke(self, **_kwargs: object) -> OAuthRouteResponse:
        return OAuthRouteResponse(detail="Revoked.")

    async def logout(self, **_kwargs: object) -> OAuthLogoutResult:
        return OAuthLogoutResult()


def build_iap_config() -> GoogleIAPConfig[object]:
    """Build the deterministic exact-audience IAP trust boundary."""
    return GoogleIAPConfig(
        audience=_IAP_AUDIENCE,
        identity_resolver=_ExampleIdentityResolver(),
        jwks=cast("JWKSProvider", _UnavailableJWKS()),
    )


def build_oauth_config(mode: str) -> OAuthConfig:
    """Build local-stub OAuth/OIDC routes for one provider mode."""
    provider_name = {"google-oauth": "google", "github-oauth": "github", "keycloak": "keycloak"}.get(mode)
    if provider_name is None:
        message = f"Unsupported OAuth example mode: {mode}"
        raise ValueError(message)
    provider = FakeOAuthProvider(
        name=provider_name,
        tokens=ProviderTokenSet(
            access_token=SecretStr("example-access"),
            token_type="Bearer",  # noqa: S106 - standardized OAuth token type
            scopes=frozenset({"openid", "profile", "email"}),
            expires_at=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(hours=1),
        ),
        identity=ProviderIdentity(
            provider=provider_name,
            issuer=f"https://{provider_name}.example",
            subject="example-subject",
            display_name="Example User",
            email="user@example.com",
            email_verified=True,
            raw_claims={},
        ),
    )
    return OAuthConfig(oauth_service=_ExampleOAuthService(provider_name), providers=(provider,))


def build_api_team_config() -> tuple[APIKeyConfig, ServiceTokenConfig]:
    """Build API-key and userless workload-JWT boundaries for the API example."""
    backend = InMemorySecurityBackend()
    jwks = cast("JWKSProvider", _UnavailableJWKS())
    return (
        APIKeyConfig(store=backend.api_keys, pepper=b"a" * 32, identity_resolver=_ExampleIdentityResolver()),
        ServiceTokenConfig(
            issuer="https://workload.example",
            audiences=frozenset({"team-api"}),
            allowed_algorithms=frozenset({"ES256"}),
            jwks=jwks,
            jwks_uri="https://workload.example/jwks",
        ),
    )


class _ExampleSnapshotRefresher:
    async def refresh(
        self, *, principal: Principal[object], previous: AuthorizationSnapshot, route_name: str
    ) -> AuthorizationSnapshot:
        del principal, route_name
        return previous


def build_websocket_config() -> WebSocketSecurityConfig:
    """Build exact-origin WebSocket policy with bounded snapshot refresh."""
    return WebSocketSecurityConfig(
        allowed_origins=frozenset({"http://testserver.local"}),
        refresh_interval=timedelta(seconds=30),
        snapshot_refresher=_ExampleSnapshotRefresher(),
    )


@dataclass(slots=True)
class _RefreshState:
    token_id: str
    token_digest: bytes
    account_id: str
    family_id: str
    security_epoch: int
    token_expires_at: datetime
    family_expires_at: datetime
    scopes: frozenset[str]
    revoked: bool = False


@dataclass(slots=True)
class ExampleAccountStore:
    """Small application-owned store used only by the local examples."""

    account: LocalAccount[object] | None = None
    password_hash: str | None = None
    sessions: dict[str, SessionRecord] = field(default_factory=lambda: cast("dict[str, SessionRecord]", {}))
    purpose_tokens: dict[str, TokenIssue] = field(default_factory=lambda: cast("dict[str, TokenIssue]", {}))
    refresh_tokens: dict[str, _RefreshState] = field(default_factory=lambda: cast("dict[str, _RefreshState]", {}))
    verification_token: str | None = None
    recovery_token: str | None = None

    async def find_for_login(self, normalized_identifier: str) -> LocalAccount[object] | None:
        """Find an account by normalized login identifier."""
        if self.account is None or self.account.normalized_identifier != normalized_identifier:
            return None
        return self.account

    async def get_by_id(self, account_id: str) -> LocalAccount[object] | None:
        """Find an account by identifier."""
        return self.account if self.account is not None and self.account.account_id == account_id else None

    async def current_epoch(self, account_id: str) -> int | None:
        """Return the authoritative security epoch."""
        account = await self.get_by_id(account_id)
        return account.security_epoch if account is not None else None

    async def get_password_state(self, account_id: str) -> PasswordCredentialState | None:
        """Return the current password state."""
        account = await self.get_by_id(account_id)
        if account is None or self.password_hash is None:
            return None
        return PasswordCredentialState(password_hash=self.password_hash, security_epoch=account.security_epoch)

    async def compare_and_replace_password(
        self, account_id: str, expected_hash: str, password_hash: str, **_kwargs: object
    ) -> bool:
        """Replace a password only when the expected digest still matches."""
        if await self.get_by_id(account_id) is None or self.password_hash != expected_hash:
            return False
        self.password_hash = password_hash
        return True

    async def replace_password_and_bump_epoch(
        self, account_id: str, password_hash: str, *, expected_epoch: int, **_kwargs: object
    ) -> PasswordChangeResult:
        """Atomically replace a password and advance the security epoch."""
        account = await self.get_by_id(account_id)
        if account is None or account.security_epoch != expected_epoch:
            return PasswordChangeResult(PasswordChangeStatus.CONFLICT)
        self.password_hash = password_hash
        self.account = replace(account, security_epoch=expected_epoch + 1)
        return PasswordChangeResult(PasswordChangeStatus.CHANGED, expected_epoch + 1)

    async def register(
        self, command: object, password_hash: str, *, verification: object | None, **_kwargs: object
    ) -> RegistrationResult[object]:
        """Create one account and optional verification issue."""
        if self.account is not None:
            return RegistrationResult(RegistrationStatus.DUPLICATE)
        registration = cast("Any", command)
        self.account = LocalAccount(
            account_id="account-1",
            normalized_identifier=registration.normalized_identifier,
            display_name=registration.display_name,
            active=True,
            verified=verification is None,
            security_epoch=1,
            user=object(),
        )
        self.password_hash = password_hash
        if verification is not None:
            issue, notification = cast("Any", verification).bind(self.account.account_id)
            await self.issue(issue, notification)
        return RegistrationResult(RegistrationStatus.CREATED, self.account)

    async def issue(self, issue: TokenIssue, notification: NotificationCommand, **_kwargs: object) -> None:
        """Store a purpose token and its development-only delivery value."""
        self.purpose_tokens[issue.token_id] = issue
        if issue.purpose is TokenPurpose.VERIFICATION:
            self.verification_token = notification.token
        elif issue.purpose is TokenPurpose.RECOVERY:
            self.recovery_token = notification.token

    async def consume_and_verify(self, token_id: str, digest: bytes, **_kwargs: object) -> ConsumeResult:
        """Consume a verification token."""
        issue = self.purpose_tokens.pop(token_id, None)
        if issue is None or issue.digest != digest or self.account is None:
            return ConsumeResult(ConsumeStatus.INVALID)
        self.account = replace(self.account, verified=True)
        return ConsumeResult(ConsumeStatus.CONSUMED, self.account.account_id, self.account.security_epoch)

    async def consume_and_reset(
        self, token_id: str, digest: bytes, new_password_hash: str, **_kwargs: object
    ) -> PasswordResetResult:
        """Consume a recovery token and reset password state."""
        issue = self.purpose_tokens.pop(token_id, None)
        if issue is None or issue.digest != digest or self.account is None:
            return PasswordResetResult(PasswordResetStatus.INVALID)
        self.password_hash = new_password_hash
        self.account = replace(self.account, security_epoch=self.account.security_epoch + 1)
        return PasswordResetResult(PasswordResetStatus.RESET, self.account.account_id, self.account.security_epoch)

    async def register_login_method(self, *_args: object, **_kwargs: object) -> None:
        """Accept the example's password login-method registration."""

    async def revoke_login_method(self, *_args: object, **_kwargs: object) -> object:
        """Return an opaque example revocation result."""
        return object()

    async def create(self, command: CreateSessionCommand, **_kwargs: object) -> SessionRecord:
        """Create a native session record."""
        record = SessionRecord(
            session_id=command.session_id,
            binding_id=command.binding_id,
            binding_digest=command.binding_digest,
            account_id=command.account_id,
            security_epoch=command.security_epoch,
            created_at=command.created_at,
            last_seen_at=command.created_at,
            expires_at=command.expires_at,
            display_metadata=command.display_metadata,
        )
        self.sessions[record.session_id] = record
        return record

    async def get(self, session_id: str) -> SessionRecord | None:
        """Get a native session record."""
        return self.sessions.get(session_id)

    async def list_for_account(self, account_id: str) -> list[SessionRecord]:
        """List one account's sessions."""
        return [record for record in self.sessions.values() if record.account_id == account_id]

    async def touch(self, session_id: str, *, now: datetime) -> SessionRecord | None:
        """Advance a session's activity time."""
        record = self.sessions.get(session_id)
        if record is None:
            return None
        touched = replace(record, last_seen_at=now)
        self.sessions[session_id] = touched
        return touched

    async def revoke_session_for_account(self, account_id: str, session_id: str, **_kwargs: object) -> bool:
        """Revoke one owned session."""
        record = self.sessions.get(session_id)
        if record is None or record.account_id != account_id:
            return False
        del self.sessions[session_id]
        return True

    async def revoke_sessions_for_account(self, account_id: str, **_kwargs: object) -> int:
        """Revoke all sessions for an account."""
        matches = tuple(key for key, record in self.sessions.items() if record.account_id == account_id)
        for key in matches:
            del self.sessions[key]
        return len(matches)

    async def revoke_other_sessions(self, account_id: str, session_id: str, **_kwargs: object) -> int:
        """Revoke every session except the named current session."""
        matches = tuple(
            key for key, record in self.sessions.items() if record.account_id == account_id and key != session_id
        )
        for key in matches:
            del self.sessions[key]
        return len(matches)

    async def rebind(
        self, prior_session_id: str, command: CreateSessionCommand, **kwargs: object
    ) -> SessionRecord | None:
        """Replace a prior session during login."""
        if prior_session_id not in self.sessions:
            return None
        del self.sessions[prior_session_id]
        return await self.create(command, **kwargs)

    async def create_family(self, command: CreateRefreshFamilyCommand, **_kwargs: object) -> bool:
        """Create a refresh-token family."""
        self.refresh_tokens[command.token_id] = _RefreshState(
            token_id=command.token_id,
            token_digest=command.token_digest,
            account_id=command.account_id,
            family_id=command.family_id,
            security_epoch=command.security_epoch,
            token_expires_at=command.token_expires_at,
            family_expires_at=command.family_expires_at,
            scopes=command.scopes,
        )
        return True

    async def prepare_rotation(
        self, proof: RefreshTokenProof, _idempotency_digest: bytes | None, **_kwargs: object
    ) -> RefreshFamilyContext:
        """Resolve the current family before a refresh rotation."""
        state = self.refresh_tokens[proof.token_id]
        return RefreshFamilyContext(
            account_id=state.account_id,
            family_id=state.family_id,
            security_epoch=state.security_epoch,
            token_expires_at=state.token_expires_at,
            family_expires_at=state.family_expires_at,
            scopes=state.scopes,
        )

    async def rotate(self, command: RotateRefreshCommand, **_kwargs: object) -> RotateRefreshResult:
        """Atomically replace a refresh token."""
        self.refresh_tokens.pop(command.token_id)
        self.refresh_tokens[command.successor_id] = _RefreshState(
            token_id=command.successor_id,
            token_digest=command.successor_digest,
            account_id=command.account_id,
            family_id=command.family_id,
            security_epoch=command.security_epoch,
            token_expires_at=command.successor_expires_at,
            family_expires_at=command.family_expires_at,
            scopes=command.scopes,
        )
        return RotateRefreshResult(RefreshRotationStatus.ROTATED, command.sealed_receipt)

    async def revoke_family(self, family_id: str, **_kwargs: object) -> bool:
        """Revoke a refresh family."""
        matches = [state for state in self.refresh_tokens.values() if state.family_id == family_id]
        for state in matches:
            state.revoked = True
        return bool(matches)

    async def revoke_token(self, token_id: str, token_digest: bytes, **_kwargs: object) -> bool:
        """Revoke a refresh token by digest."""
        state = self.refresh_tokens.get(token_id)
        if state is None or state.token_digest != token_digest:
            return False
        state.revoked = True
        return True

    async def revoke_token_for_account(
        self, account_id: str, token_id: str, token_digest: bytes, **_kwargs: object
    ) -> bool:
        """Revoke one account-owned refresh token."""
        state = self.refresh_tokens.get(token_id)
        if state is None or state.account_id != account_id or state.token_digest != token_digest:
            return False
        state.revoked = True
        return True

    async def revoke_for_account(self, account_id: str, **_kwargs: object) -> int:
        """Revoke every refresh token for an account."""
        matches = [state for state in self.refresh_tokens.values() if state.account_id == account_id]
        for state in matches:
            state.revoked = True
        return len(matches)


@dataclass(frozen=True, slots=True)
class _ExamplePasswordHasher:
    async def hash(self, password: str) -> str:
        return f"example-hash:{password}"

    async def verify(self, encoded_hash: str | None, password: str) -> PasswordVerificationResult:
        return PasswordVerificationResult(
            PasswordVerificationStatus.VERIFIED
            if encoded_hash == f"example-hash:{password}"
            else PasswordVerificationStatus.INVALID
        )


def example_account_store() -> LocalAccountCapabilities[object]:
    """Return an application-owned in-memory store.

    Returns:
        An isolated application-owned capability object.
    """
    return cast("LocalAccountCapabilities[object]", ExampleAccountStore())


def example_session_config() -> CookieBackendConfig:
    """Build the explicit insecure-loopback session configuration.

    Returns:
        A native Litestar client-side session configuration.
    """
    return CookieBackendConfig(secret=bytes(range(16)), key="example-session", max_age=600, secure=False, httponly=True)


def build_local_auth(mode: str) -> LocalAuthConfig[object]:
    """Build one explicit local-auth transport profile.

    Args:
        mode: ``local-session``, ``local-token``, or ``local-hybrid``.

    Returns:
        The selected local-auth profile.

    Raises:
        ValueError: If ``mode`` is not a local-auth example mode.
    """
    accounts = example_account_store()
    registration = RegistrationPolicy.public()
    shared: dict[str, object] = {"accounts": accounts, "registration": registration, "route_prefix": "/auth"}
    if mode == "local-session":
        return LocalAuth.session(
            **cast("Any", shared),
            secrets=LocalAuthSecrets.session(purpose_token_pepper=_PURPOSE_PEPPER),
            password_hasher=_ExamplePasswordHasher(),
            binding=SessionBindingConfig(
                pepper=_BINDING_PEPPER, cookie_name="example-binding", secure=False, allow_insecure=True, max_age=600
            ),
        )
    if mode in {"local-token", "local-hybrid"}:
        private_key = Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        secrets = LocalAuthSecrets(
            purpose_tokens=PurposeTokenCodec(pepper=_PURPOSE_PEPPER),
            refresh_codec=RefreshTokenCodec(pepper=_REFRESH_PEPPER),
            refresh_receipts=RefreshReceiptSealer(active_key=RefreshReceiptKey(key_id="example", key=_RECEIPT_KEY)),
        )
        key_ring = LocalKeyRing(
            issuer="http://127.0.0.1:8000",
            active_signing_key=SigningKey(key_id="example", algorithm="EdDSA", private_key=private_key),
        )
        if mode == "local-token":
            return LocalAuth.tokens(
                **cast("Any", shared),
                secrets=secrets,
                key_ring=key_ring,
                token_audience="litestar-security-example",  # noqa: S106 - public JWT audience identifier
                password_hasher=_ExamplePasswordHasher(),
            )
        return LocalAuth.hybrid(
            **cast("Any", shared),
            secrets=secrets,
            binding=SessionBindingConfig(
                pepper=_BINDING_PEPPER, cookie_name="example-binding", secure=False, allow_insecure=True, max_age=600
            ),
            key_ring=key_ring,
            token_audience="litestar-security-example",  # noqa: S106 - public JWT audience identifier
            password_hasher=_ExamplePasswordHasher(),
        )
    message = f"Unsupported local example mode: {mode}"
    raise ValueError(message)
