"""Source-oriented accounts unit tests."""

import sys
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from functools import partial
from importlib import import_module
from importlib.metadata import requires
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.exceptions import InvalidTag
from litestar.exceptions import ImproperlyConfiguredException
from litestar.stores.memory import MemoryStore
from litestar.stores.registry import StoreRegistry

import litestar_security.accounts as accounts_module
from litestar_security.authentication import InvalidCredentials, VerificationUnavailable
from litestar_security.providers.jwt import BearerTokenSlot, LocalKeyRing
from tests.fixtures.accounts import (
    AsyncOutcome,
    _local_auth_rate_limit_config,
    _RefreshEntropy,
    _structural_capabilities,
)

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
_NAIVE_JWT_NOW = datetime(2026, 7, 26)  # noqa: DTZ001 - explicit rejection fixture
_JWT_ISSUER = "https://issuer.example"
_JWT_AUDIENCE = "litestar-security"
_OIDC_ISSUER = "https://issuer.example/tenant"
_OIDC_DISCOVERY_URL = f"{_OIDC_ISSUER}/.well-known/openid-configuration"
_OIDC_PUBLIC_IP = "93.184.216.34"
_JWKS_URI = f"{_JWT_ISSUER}/.well-known/jwks.json"
_MFA_VECTOR_NOW = datetime.fromtimestamp(59, tz=timezone.utc)
_MFA_ENCODED_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
_MFA_POLICY = accounts_module.TOTPPolicy()


def test_package_declares_account_feature_dependencies_only_through_extras() -> None:
    declared = tuple(requirement.lower().replace(" ", "") for requirement in requires("litestar-security") or ())

    assert "argon2-cffi<26,>=25.1;extra=='argon2'" in declared
    assert "pyotp<3,>=2.10;extra=='mfa'" in declared
    assert "webauthn<4,>=3;extra=='passkeys'" in declared
    assert not any(";extra=='all'" in requirement for requirement in declared)
    assert not any(
        requirement.startswith(("argon2-cffi", "pyotp", "webauthn")) and ";extra==" not in requirement
        for requirement in declared
    )
    assert all(
        not requirement.startswith(dependency)
        for dependency in ("advanced-alchemy", "redis", "sqlalchemy", "sqlspec")
        for requirement in declared
    )
    assert import_module("argon2")
    assert import_module("litestar_security.accounts")


async def test_aesgcm_secret_protector_is_nondeterministic_and_aad_bound() -> None:
    key = accounts_module.SecretProtectorKey("v1", b"k" * 32)
    nonces = iter((b"1" * 12, b"2" * 12))
    protector = accounts_module.AESGCMSecretProtector(active_key=key, entropy=lambda _length: next(nonces))
    first = await protector.protect(b"secret", associated_data=b"account-1")
    second = await protector.protect(b"secret", associated_data=b"account-1")
    assert first.ciphertext != second.ciphertext
    assert await protector.unprotect(first, associated_data=b"account-1") == b"secret"
    with pytest.raises(InvalidTag):
        await protector.unprotect(first, associated_data=b"account-2")
    with pytest.raises(ImproperlyConfiguredException, match="32-byte"):
        accounts_module.SecretProtectorKey("v1", b"short")


def test_profiles_reaches_the_generated_controllers_at_module_scope() -> None:
    profiles = import_module("litestar_security.accounts._profiles")
    assert "litestar_security.accounts.controllers" in sys.modules
    assert (
        profiles.build_local_auth_routes
        is import_module("litestar_security.accounts.controllers").build_local_auth_routes
    )


def _local_auth_secrets(*, refresh: bool = False) -> accounts_module.LocalAuthSecrets:
    return accounts_module.LocalAuthSecrets(
        purpose_tokens=accounts_module.PurposeTokenCodec(pepper=b"p" * 32),
        refresh_codec=(accounts_module.RefreshTokenCodec(pepper=b"q" * 32) if refresh else None),
        refresh_receipts=(
            accounts_module.RefreshReceiptSealer(active_key=accounts_module.RefreshReceiptKey("test-key", b"r" * 32))
            if refresh
            else None
        ),
    )


_BASE_LOCAL_CAPABILITIES = {
    "compare_and_replace_password",
    "consume_and_reset",
    "consume_and_verify",
    "current_epoch",
    "find_for_login",
    "get_by_id",
    "get_password_state",
    "issue",
    "issue_absent",
    "list_methods",
    "register_login_method",
    "replace_password_and_bump_epoch",
    "revoke_login_method",
}
_SESSION_CAPABILITIES = {
    "create",
    "get",
    "list_for_account",
    "rebind",
    "revoke_other_sessions",
    "revoke_session_for_account",
    "revoke_sessions_for_account",
    "touch",
}
_REFRESH_CAPABILITIES = {
    "create_family",
    "prepare_rotation",
    "revoke_family",
    "revoke_for_account",
    "revoke_token",
    "revoke_token_for_account",
    "rotate",
}


def test_local_auth_profiles_validate_only_structural_enabled_capabilities(local_key_ring: LocalKeyRing) -> None:
    binding = accounts_module.SessionBindingConfig(pepper=b"p" * 32)
    key_ring = local_key_ring
    audience = "local-client"
    session_store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES))
    token_store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _REFRESH_CAPABILITIES))
    hybrid_store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES | _REFRESH_CAPABILITIES))
    registration_store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES | {"register"}))

    session = accounts_module.LocalAuth.session(
        accounts=session_store, secrets=_local_auth_secrets(), binding=binding, route_prefix="/security/"
    )
    tokens = accounts_module.LocalAuth.tokens(
        accounts=token_store,
        secrets=_local_auth_secrets(refresh=True),
        key_ring=key_ring,
        token_audience=f" {audience} ",
    )
    hybrid = accounts_module.LocalAuth.hybrid(
        accounts=hybrid_store,
        secrets=_local_auth_secrets(refresh=True),
        binding=binding,
        key_ring=key_ring,
        token_audience=audience,
    )
    registration = accounts_module.LocalAuth.session(
        accounts=registration_store,
        secrets=_local_auth_secrets(),
        binding=binding,
        registration=accounts_module.RegistrationPolicy.public(),
    )

    assert (session.mode, session.route_prefix, session.accounts) == (
        accounts_module.LocalAuthMode.SESSION,
        "/security",
        session_store,
    )
    assert (tokens.mode, tokens.token_audience, tokens.key_ring) == (
        accounts_module.LocalAuthMode.TOKENS,
        "local-client",
        key_ring,
    )
    assert hybrid.mode is accounts_module.LocalAuthMode.HYBRID
    assert hybrid.accounts is hybrid_store
    assert registration.registration.mode is accounts_module.RegistrationMode.PUBLIC
    for config in (session, tokens, hybrid):
        assert not hasattr(config, "__dict__")
        with pytest.raises(FrozenInstanceError):
            config.route_prefix = "/changed"  # type: ignore[misc]


def test_session_profile_passes_explicit_consistent_read_resolver_to_native_auth() -> None:
    store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES))

    class Resolver:
        async def resolve_user_auth_session(self, session_id: str, account_id: str, *, now: datetime) -> None:
            del session_id, account_id, now

    resolver = Resolver()
    profile = accounts_module.LocalAuth.session(
        accounts=store,
        secrets=_local_auth_secrets(),
        binding=accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        session_resolver=resolver,
    )

    assert profile.session_auth is not None
    assert profile.session_auth.resolver is resolver


@pytest.mark.parametrize(
    ("profile", "methods", "match"),
    [
        ("session", _BASE_LOCAL_CAPABILITIES, "SessionRegistry"),
        ("tokens", _BASE_LOCAL_CAPABILITIES, "RefreshTokenFamilyStore"),
        ("registration", _BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES, "RegistrationStore"),
    ],
)
def test_local_auth_profiles_report_only_missing_enabled_capabilities(
    profile: str, methods: set[str], match: str, local_key_ring: LocalKeyRing
) -> None:
    binding = accounts_module.SessionBindingConfig(pepper=b"p" * 32)
    store = _structural_capabilities(*methods)
    audience = "local-client"

    if profile == "session":
        operation = partial(
            accounts_module.LocalAuth.session, accounts=store, secrets=_local_auth_secrets(), binding=binding
        )
    elif profile == "tokens":
        operation = partial(
            accounts_module.LocalAuth.tokens,
            accounts=store,
            secrets=_local_auth_secrets(refresh=True),
            key_ring=local_key_ring,
            token_audience=audience,
        )
    else:
        operation = partial(
            accounts_module.LocalAuth.session,
            accounts=store,
            secrets=_local_auth_secrets(),
            binding=binding,
            registration=accounts_module.RegistrationPolicy.public(),
        )
    with pytest.raises(ImproperlyConfiguredException, match=match):
        operation()


def test_local_auth_rejects_transport_inconsistent_custom_session_runtime(local_key_ring: LocalKeyRing) -> None:
    binding = accounts_module.SessionBindingConfig(pepper=b"p" * 32)
    audience = "local-client"
    store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES | _REFRESH_CAPABILITIES))
    other_store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES | _REFRESH_CAPABILITIES))
    runtime = accounts_module.NativeSessionAuth(accounts=store, binding=binding)
    matching = accounts_module.LocalAuth.session(
        accounts=store, secrets=_local_auth_secrets(), binding=binding, session_auth=runtime
    )
    assert matching.session_auth is runtime

    with pytest.raises(ImproperlyConfiguredException, match="Token-only"):
        accounts_module.LocalAuthConfig(
            mode=accounts_module.LocalAuthMode.TOKENS,
            accounts=store,
            secrets=_local_auth_secrets(refresh=True),
            registration=accounts_module.RegistrationPolicy.disabled(),
            route_prefix="/auth",
            key_ring=local_key_ring,
            token_audience=audience,
            session_auth=runtime,
        )
    for mismatched in (
        accounts_module.NativeSessionAuth(accounts=other_store, binding=binding),
        accounts_module.NativeSessionAuth(
            accounts=store, binding=accounts_module.SessionBindingConfig(pepper=b"q" * 32)
        ),
    ):
        with pytest.raises(ImproperlyConfiguredException, match="must share"):
            accounts_module.LocalAuth.session(
                accounts=store, secrets=_local_auth_secrets(), binding=binding, session_auth=mismatched
            )


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "match"),
    [
        ("mode", "bogus", "LocalAuthMode"),
        ("registration", object(), "RegistrationPolicy"),
        ("route_prefix", object(), "absolute non-root path"),
        ("route_prefix", "/", "absolute non-root path"),
        ("route_prefix", "auth", "absolute non-root path"),
        ("route_prefix", "//auth", "absolute non-root path"),
        ("route_prefix", "/auth?next=/", "absolute non-root path"),
        ("route_prefix", "/auth#login", "absolute non-root path"),
        ("route_prefix", "/auth\\login", "absolute non-root path"),
        ("route_prefix", "/auth/{account_id}", "absolute non-root path"),
        ("route_prefix", "/auth/../login", "absolute non-root path"),
        ("route_prefix", "/auth/./login", "absolute non-root path"),
        ("route_prefix", "/auth /login", "absolute non-root path"),
        ("route_prefix", "/auth\n/login", "absolute non-root path"),
        ("binding", None, "explicit binding"),
        ("binding", object(), "explicit binding"),
        ("key_ring", None, "explicit key ring and audience"),
        ("key_ring", object(), "explicit key ring and audience"),
        ("token_audience", " ", "explicit key ring and audience"),
        ("token_audience", object(), "explicit key ring and audience"),
    ],
)
def test_local_auth_config_rejects_incomplete_transport_values(
    field_name: str, invalid_value: object, match: str, local_key_ring: LocalKeyRing
) -> None:
    binding = accounts_module.SessionBindingConfig(pepper=b"p" * 32)
    store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES | _REFRESH_CAPABILITIES))
    kwargs = {
        "mode": accounts_module.LocalAuthMode.HYBRID,
        "accounts": store,
        "secrets": _local_auth_secrets(refresh=True),
        "registration": accounts_module.RegistrationPolicy.disabled(),
        "route_prefix": "/auth",
        "binding": binding,
        "key_ring": local_key_ring,
        "token_audience": "local-client",
    }
    kwargs[field_name] = invalid_value

    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.LocalAuthConfig(**kwargs)  # type: ignore[arg-type]


def test_local_token_profile_builds_one_customizable_runtime_with_safe_defaults(local_key_ring: LocalKeyRing) -> None:
    store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _REFRESH_CAPABILITIES))
    config = accounts_module.LocalAuth.tokens(
        accounts=store,
        secrets=_local_auth_secrets(refresh=True),
        key_ring=local_key_ring,
        token_audience="local-api",  # noqa: S106 - public JWT audience
    )

    assert config.token_client_id == "local"  # noqa: S105 - public JWT client identifier
    assert config.access_token_lifetime == timedelta(minutes=10)
    assert isinstance(config.password_hasher, accounts_module.Argon2PasswordHasher)
    assert config.password_hasher.worker_limits is local_key_ring.worker_limits
    assert isinstance(config.password_login, accounts_module.PasswordLoginService)
    assert isinstance(config.access_token_issuer, accounts_module.LocalAccessTokenIssuer)
    assert isinstance(config.bearer_slot, BearerTokenSlot)
    assert config.bearer_slot.name == "local"
    assert isinstance(config.bearer_resolver, accounts_module.LocalBearerIdentityResolver)
    assert config.password_login.accounts is store
    assert config.bearer_resolver.accounts is store


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "match"),
    [
        ("token_client_id", " ", "client id"),
        ("token_client_id", object(), "client id"),
        ("access_token_lifetime", timedelta(seconds=29), "30 seconds"),
        ("access_token_lifetime", timedelta(hours=1, microseconds=1), "one hour"),
        ("access_token_lifetime", timedelta(seconds=30, microseconds=1), "whole seconds"),
        ("password_hasher", object(), "PasswordHasher"),
    ],
)
def test_local_token_profile_rejects_invalid_runtime_configuration(
    field_name: str, invalid_value: object, match: str, local_key_ring: LocalKeyRing
) -> None:
    store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _REFRESH_CAPABILITIES))
    kwargs = {
        "accounts": store,
        "secrets": _local_auth_secrets(refresh=True),
        "key_ring": local_key_ring,
        "token_audience": "local-api",
        field_name: invalid_value,
    }

    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.LocalAuth.tokens(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"purpose_tokens": object()},
        {
            "purpose_tokens": accounts_module.PurposeTokenCodec(b"p" * 32),
            "refresh_codec": accounts_module.RefreshTokenCodec(b"q" * 32),
        },
        {
            "purpose_tokens": accounts_module.PurposeTokenCodec(b"p" * 32),
            "refresh_codec": object(),
            "refresh_receipts": accounts_module.RefreshReceiptSealer(
                active_key=accounts_module.RefreshReceiptKey("key", b"r" * 32)
            ),
        },
        {
            "purpose_tokens": accounts_module.PurposeTokenCodec(b"p" * 32),
            "refresh_codec": accounts_module.RefreshTokenCodec(b"q" * 32),
            "refresh_receipts": object(),
        },
    ],
)
def test_local_auth_secrets_reject_incomplete_or_invalid_crypto(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        accounts_module.LocalAuthSecrets(**kwargs)  # type: ignore[arg-type]


def test_local_auth_secrets_offer_concise_explicit_transport_factories() -> None:
    session = accounts_module.LocalAuthSecrets.session(purpose_token_pepper=b"p" * 32)
    tokens = accounts_module.LocalAuthSecrets.tokens(
        purpose_token_pepper=b"p" * 32,
        refresh_token_pepper=b"q" * 32,
        active_receipt_key_id="active",
        active_receipt_key=b"r" * 32,
        retained_receipt_keys=(accounts_module.RefreshReceiptKey("retained", b"s" * 32),),
    )

    assert session.refresh_codec is None
    assert session.refresh_receipts is None
    assert isinstance(tokens.refresh_codec, accounts_module.RefreshTokenCodec)
    assert tokens.refresh_receipts is not None
    assert tuple(tokens.refresh_receipts._keys) == ("active", "retained")  # noqa: SLF001


@pytest.mark.parametrize(
    ("mode", "secrets", "register_routes", "match"),
    [
        (accounts_module.LocalAuthMode.SESSION, object(), True, "secrets"),
        (accounts_module.LocalAuthMode.SESSION, _local_auth_secrets(), 1, "boolean"),
        (accounts_module.LocalAuthMode.SESSION, _local_auth_secrets(refresh=True), True, "Session-only"),
        (accounts_module.LocalAuthMode.TOKENS, _local_auth_secrets(), True, "requires explicit refresh"),
    ],
)
def test_local_auth_config_rejects_invalid_route_and_secret_mode_combinations(
    mode: accounts_module.LocalAuthMode,
    secrets: object,
    register_routes: object,
    match: str,
    local_key_ring: LocalKeyRing,
) -> None:
    store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES | _REFRESH_CAPABILITIES))
    kwargs: dict[str, object] = {
        "mode": mode,
        "accounts": store,
        "secrets": secrets,
        "registration": accounts_module.RegistrationPolicy.disabled(),
        "route_prefix": "/auth",
        "register_routes": register_routes,
        "binding": accounts_module.SessionBindingConfig(pepper=b"b" * 32),
        "key_ring": local_key_ring,
        "token_audience": "local-client",
    }
    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.LocalAuthConfig(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"events": object()}, "events must implement SecurityEventSink"),
        ({"client_key": object()}, "client key extractor must be callable"),
        ({"rate_limiter": object()}, "rate limiter must implement RateLimiter"),
    ],
)
def test_local_auth_config_validates_limiting_and_audit_options(kwargs: dict[str, Any], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        _local_auth_rate_limit_config(**kwargs)


def test_local_auth_binds_the_bundled_limiter_store_once_and_leaves_custom_limiters_alone() -> None:
    config = _local_auth_rate_limit_config()
    registry = StoreRegistry()
    config.bind_rate_limit_store(registry)
    limiter = cast("Any", config.rate_limiter)
    bound = limiter.store

    assert bound is registry.get(accounts_module.RATE_LIMIT_STORE_NAME)
    config.bind_rate_limit_store(StoreRegistry({accounts_module.RATE_LIMIT_STORE_NAME: MemoryStore()}))
    assert limiter.store is bound

    custom = _local_auth_rate_limit_config(rate_limiter=accounts_module.UnlimitedRateLimiter())
    custom.bind_rate_limit_store(registry)
    assert isinstance(custom.rate_limiter, accounts_module.UnlimitedRateLimiter)


def test_local_auth_rate_limit_pepper_is_derived_and_domain_separated() -> None:
    secrets = accounts_module.LocalAuthSecrets.session(purpose_token_pepper=b"p" * 32)
    other = accounts_module.LocalAuthSecrets.session(purpose_token_pepper=b"q" * 32)

    assert len(secrets.rate_limit_pepper) == 32
    assert secrets.rate_limit_pepper != secrets.purpose_tokens.pepper
    assert secrets.rate_limit_pepper != other.rate_limit_pepper


async def test_local_auth_service_graph_composes_existing_services_without_handler_logic() -> None:
    account = accounts_module.LocalAccountState(
        account_id="account-1",
        normalized_identifier="user@example.com",
        display_name="User",
        active=True,
        verified=True,
        security_epoch=1,
    )
    proof = accounts_module.PasswordReauthenticationProof(
        account_id="account-1", security_epoch=1, authenticated_at=_JWT_NOW, expires_at=_JWT_NOW + timedelta(minutes=5)
    )
    authentication = SimpleNamespace(account_id="account-1", session_id="session-old")
    plan = SimpleNamespace(prior_session_id="session-old", command=object())
    changed = accounts_module.PasswordChangeOutcome(accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2)
    refresh_response = accounts_module.TokenPair(
        access_token="e30.e30.YQ",  # noqa: S106 - compact public test JWT
        refresh_token=accounts_module
        .RefreshTokenCodec(pepper=b"p" * 32, entropy=_RefreshEntropy())
        .issue()
        .refresh_token,
        expires_in=600,
    )
    session_auth = SimpleNamespace(
        establish=AsyncOutcome(
            VerificationUnavailable(),
            accounts_module.SessionAuthentication(
                session_id="c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M",
                binding_id="sb_aWlpaWlpaWlpaWlpaWlpaQ",
                account_id="account-1",
                security_epoch=1,
                authenticated_at=_JWT_NOW,
                expires_at=_JWT_NOW + timedelta(hours=1),
            ),
        ),
        current_authentication=lambda _request: authentication,
        prepare_password_rebind=lambda _request, _account: plan,
        activate_password_rebind=AsyncOutcome(bool(1)),
        logout=AsyncOutcome(bool(0)),
    )
    accounts = SimpleNamespace(get_by_id=AsyncOutcome(account, OSError(), None))
    services = accounts_module.LocalAuthService(
        accounts=cast("Any", accounts),
        password_login=cast("Any", SimpleNamespace(authenticate=AsyncOutcome(InvalidCredentials(), account, account))),
        password_reauthentication=cast(
            "Any", SimpleNamespace(verify=AsyncOutcome(InvalidCredentials(), proof, proof, proof, proof, proof))
        ),
        password_change=cast("Any", SimpleNamespace(change=AsyncOutcome(changed, changed, changed))),
        verification=cast("Any", object()),
        recovery=cast("Any", object()),
        session_auth=cast("Any", session_auth),
        refresh_tokens=cast("Any", SimpleNamespace(clock=lambda: _JWT_NOW, issue=AsyncOutcome(refresh_response))),
    )
    credentials = accounts_module.LocalCredentials(
        identifier="user@example.com",
        password="password",  # noqa: S106 - request DTO fixture
    )
    password_request = accounts_module.LocalPasswordChange(
        current_password="old",  # noqa: S106 - request DTO fixture
        password="new-password",  # noqa: S106 - request DTO fixture
    )
    request = cast("Any", SimpleNamespace())

    assert isinstance(await services.session_login(request, credentials), InvalidCredentials)
    assert isinstance(await services.session_login(request, credentials), VerificationUnavailable)
    assert isinstance(await services.session_login(request, credentials), accounts_module.LocalAccount)
    no_session = replace(services, session_auth=None)
    no_session.password_login.authenticate.outcomes.append(account)
    assert isinstance(await no_session.session_login(request, credentials), VerificationUnavailable)

    services.password_login.authenticate.outcomes.extend((InvalidCredentials(), account))
    assert isinstance(await services.token_login(request, credentials), InvalidCredentials)
    assert await services.token_login(request, credentials) == refresh_response
    no_refresh = replace(services, refresh_tokens=None)
    no_refresh.password_login.authenticate.outcomes.append(account)
    assert isinstance(await no_refresh.token_login(request, credentials), VerificationUnavailable)

    assert isinstance(
        await services.change_session_password(request, "account-1", password_request), InvalidCredentials
    )
    compromised = accounts_module.LocalPasswordChange(
        current_password="old",  # noqa: S106 - request DTO fixture
        password="new-password",  # noqa: S106 - request DTO fixture
        compromise=True,
    )
    assert await services.change_session_password(request, "account-1", compromised) == changed
    assert session_auth.logout.outcomes == []
    compromised_failure = replace(
        services, password_change=cast("Any", SimpleNamespace(change=AsyncOutcome(accounts_module.LifecycleRejected())))
    )
    assert isinstance(
        await compromised_failure.change_session_password(request, "account-1", compromised),
        accounts_module.LifecycleRejected,
    )
    assert await services.change_session_password(request, "account-1", password_request) == changed
    assert session_auth.activate_password_rebind.outcomes == []
    assert isinstance(
        await services.change_session_password(request, "account-1", password_request), VerificationUnavailable
    )
    assert isinstance(
        await services.change_session_password(request, "account-1", password_request), InvalidCredentials
    )
    assert isinstance(
        await replace(services, session_auth=None).change_session_password(request, "account-1", password_request),
        VerificationUnavailable,
    )

    services.password_reauthentication.verify.outcomes.extend((proof, proof, proof))
    no_authentication = SimpleNamespace(**vars(session_auth))
    no_authentication.current_authentication = lambda _request: None
    assert isinstance(
        await replace(services, session_auth=cast("Any", no_authentication)).change_session_password(
            request, "account-1", password_request
        ),
        InvalidCredentials,
    )

    services.accounts.get_by_id.outcomes.append(account)
    no_plan = SimpleNamespace(**vars(session_auth))
    no_plan.prepare_password_rebind = lambda _request, _account: VerificationUnavailable()
    assert isinstance(
        await replace(services, session_auth=cast("Any", no_plan)).change_session_password(
            request, "account-1", password_request
        ),
        VerificationUnavailable,
    )

    services.accounts.get_by_id.outcomes.append(account)
    unchanged_services = replace(
        services, password_change=cast("Any", SimpleNamespace(change=AsyncOutcome(accounts_module.LifecycleRejected())))
    )
    assert isinstance(
        await unchanged_services.change_session_password(request, "account-1", password_request),
        accounts_module.LifecycleRejected,
    )

    services.password_reauthentication.verify.outcomes.extend((InvalidCredentials(), proof))
    assert isinstance(await services.change_token_password("account-1", password_request), InvalidCredentials)
    assert await services.change_token_password("account-1", password_request) == changed
