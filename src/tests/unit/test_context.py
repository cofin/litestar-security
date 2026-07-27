"""Unit tests for public context, session, and package contracts."""

import sys
from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone
from functools import partial
from importlib import import_module
from importlib.metadata import requires
from subprocess import run
from types import SimpleNamespace

import pytest
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException, PermissionDeniedException

import litestar_security
import litestar_security._openapi as openapi_module
import litestar_security.accounts as accounts_module
import litestar_security.accounts.local as local_accounts_module
import litestar_security.authentication as authentication_module
from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    CredentialRestrictions,
    LitestarSessionHandle,
    NullSessionHandle,
    Principal,
    SecurityContext,
    SessionHandle,
    SessionPersistenceUnavailableError,
    SessionUnavailableError,
)
from litestar_security.guards import all_of as guards_all_of
from litestar_security.guards import any_of as guards_any_of
from litestar_security.guards import at_least as guards_at_least
from litestar_security.guards import (
    one_of,
    requires_authenticated,
    requires_capability,
    requires_role,
    requires_scope,
    requires_team_role,
    requires_tenant,
)
from litestar_security.providers.jwt import LocalKeyRing

_DUPLICATE_GUARD = requires_authenticated()
_ACCOUNT_NOW = datetime(2026, 7, 27, tzinfo=timezone.utc)
_SESSION_ID = "c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M"
_BINDING_ID = "sb_aWlpaWlpaWlpaWlpaWlpaQ"
_BASE_LOCAL_CAPABILITIES = {
    "compare_and_replace_password",
    "consume_and_reset",
    "consume_and_verify",
    "current_epoch",
    "find_for_login",
    "get_by_id",
    "get_password_state",
    "issue",
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
_REFRESH_CAPABILITIES = {"revoke_family", "revoke_for_account", "rotate"}
_PUBLIC_API = (
    "Authenticated",
    "AuthenticationEvidence",
    "AuthenticationMechanism",
    "AuthenticationOutcome",
    "AuthenticationPolicy",
    "AuthenticationRegistry",
    "AuthorizationPredicate",
    "AuthorizationSnapshot",
    "CredentialExtraction",
    "CredentialRestrictions",
    "CredentialSlot",
    "CurrentUser",
    "ExternalCSRF",
    "IdentityResolver",
    "InvalidCredentials",
    "LitestarSessionHandle",
    "MechanismRequirement",
    "NoCredentials",
    "NullSessionHandle",
    "PresentedCredential",
    "Principal",
    "PrincipalDependency",
    "RequestAuthenticator",
    "SecurityConfig",
    "SecurityContext",
    "SecurityContextDependency",
    "SecurityPlugin",
    "SessionHandle",
    "SessionPersistenceUnavailableError",
    "SessionUnavailableError",
    "VerificationUnavailable",
    "__project__",
    "__version__",
    "all_of",
    "any_of",
    "at_least",
    "guard_all_of",
    "guard_any_of",
    "guard_at_least",
    "guard_one_of",
    "mechanism",
    "optional",
    "public",
    "required",
    "requires_authenticated",
    "requires_capability",
    "requires_role",
    "requires_scope",
    "requires_team_role",
    "requires_tenant",
    "security",
)


class _Session:
    is_available = False
    can_persist = False

    def get(self, _key: str, default: object = None) -> object:
        return default

    def set(self, _key: str, _value: object) -> None:
        raise AssertionError

    def pop(self, _key: str, default: object = None) -> object:
        return default

    def clear(self) -> None:
        raise AssertionError


def _structural_capabilities(*method_names: str) -> object:
    def method(*_args: object, **_kwargs: object) -> None:
        return None

    return type("StructuralCapabilities", (), dict.fromkeys(method_names, method))()


def _guard_connection(
    *,
    authenticated: bool = True,
    authorization: AuthorizationSnapshot | None = None,
    path_params: dict[str, object] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        user=Principal(id="user-1") if authenticated else Principal.anonymous(),
        auth=SecurityContext(session=NullSessionHandle(), authorization=authorization or AuthorizationSnapshot()),
        path_params=path_params or {},
    )


def test_principal_supports_anonymous_user_and_service_states() -> None:
    user = object()

    anonymous = Principal[object].anonymous()
    application_user = Principal(id="user-1", display_name="User One", user=user)
    service = Principal(id="service-1", display_name="Worker")

    assert (anonymous.id, anonymous.is_authenticated, anonymous.has_user) == (None, False, False)
    assert (application_user.id, application_user.is_authenticated, application_user.has_user) == ("user-1", True, True)
    assert (service.id, service.is_authenticated, service.has_user) == ("service-1", True, False)


def test_principal_require_user_preserves_identity_and_fails_generically() -> None:
    user = object()

    assert Principal(id="user-1", user=user).require_user() is user
    for principal in (Principal.anonymous(), Principal(id="service-1")):
        with pytest.raises(NotAuthorizedException, match="Authentication required"):
            principal.require_user()


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"id": None, "user": object()}, "Anonymous principals cannot contain an application user"),
        ({"id": ""}, "Principal id must not be blank"),
        ({"id": "  "}, "Principal id must not be blank"),
        ({"id": "user-1", "display_name": " "}, "Display name must not be blank"),
    ],
)
def test_principal_rejects_invalid_states(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        Principal(**kwargs)


def test_principal_is_frozen_and_slotted() -> None:
    principal = Principal(id="user-1")

    with pytest.raises(FrozenInstanceError):
        principal.id = "changed"  # type: ignore[misc]
    assert not hasattr(principal, "__dict__")


def test_evidence_normalizes_utc_and_preserves_assurance_details() -> None:
    offset = timezone(timedelta(hours=2))
    evidence = AuthenticationEvidence(
        mechanism=" oidc ",
        slot=" authorization.bearer ",
        authenticated_at=datetime(2026, 7, 26, 12, tzinfo=offset),
        expires_at=datetime(2026, 7, 26, 13, tzinfo=offset),
        methods={" pwd ", "otp"},
        traits={" phishing-resistant "},
        acr="urn:example:aal2",
        amr=("pwd", "otp"),
    )

    assert evidence.mechanism == "oidc"
    assert evidence.slot == "authorization.bearer"
    assert evidence.authenticated_at == datetime(2026, 7, 26, 10, tzinfo=timezone.utc)
    assert evidence.expires_at == datetime(2026, 7, 26, 11, tzinfo=timezone.utc)
    assert evidence.methods == frozenset({"pwd", "otp"})
    assert evidence.traits == frozenset({"phishing-resistant"})
    assert evidence.acr == "urn:example:aal2"
    assert evidence.amr == ("pwd", "otp")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mechanism": "", "slot": "header", "authenticated_at": datetime.now(timezone.utc)},
        {"mechanism": "local", "slot": " ", "authenticated_at": datetime.now(timezone.utc)},
        {
            "mechanism": "local",
            "slot": "session",
            "authenticated_at": datetime(2026, 7, 26),  # noqa: DTZ001
        },
        {
            "mechanism": "local",
            "slot": "session",
            "authenticated_at": datetime.now(timezone.utc),
            "expires_at": datetime(2026, 7, 27),  # noqa: DTZ001
        },
        {"mechanism": "local", "slot": "session", "authenticated_at": datetime.now(timezone.utc), "methods": {" "}},
        {"mechanism": "local", "slot": "session", "authenticated_at": datetime.now(timezone.utc), "traits": {""}},
        {"mechanism": "local", "slot": "session", "authenticated_at": datetime.now(timezone.utc), "amr": (" ",)},
    ],
)
def test_evidence_rejects_blank_names_and_naive_timestamps(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match=r"must not be blank|must be timezone-aware"):
        AuthenticationEvidence(**kwargs)


def test_authorization_snapshot_defensively_freezes_input() -> None:
    scopes = {"read"}
    team_roles = {"team-1": {"member"}}
    attributes = {"region": "us"}
    snapshot = AuthorizationSnapshot(
        scopes=scopes,
        roles={"admin"},
        capabilities={"reports.export"},
        team_roles=team_roles,
        tenant_ids={"tenant-1"},
        attributes=attributes,
    )

    scopes.add("write")
    team_roles["team-1"].add("owner")
    team_roles["team-2"] = {"member"}
    attributes["region"] = "eu"

    assert snapshot.scopes == frozenset({"read"})
    assert snapshot.roles == frozenset({"admin"})
    assert snapshot.capabilities == frozenset({"reports.export"})
    assert snapshot.team_roles == {"team-1": frozenset({"member"})}
    assert snapshot.tenant_ids == frozenset({"tenant-1"})
    assert snapshot.attributes == {"region": "us"}
    with pytest.raises(TypeError):
        snapshot.team_roles["team-2"] = frozenset({"member"})  # type: ignore[index]
    with pytest.raises(TypeError):
        snapshot.attributes["region"] = "eu"  # type: ignore[index]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"scopes": {" "}},
        {"roles": {""}},
        {"capabilities": {" "}},
        {"team_roles": {"": {"member"}}},
        {"team_roles": {"team-1": {" "}}},
        {"tenant_ids": {" "}},
    ],
)
def test_authorization_snapshot_rejects_blank_values(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="must not be blank"):
        AuthorizationSnapshot(**kwargs)


def test_native_authorization_guard_allows_matching_scope_and_denies_without_leaking_grant() -> None:
    allowed = _guard_connection(authorization=AuthorizationSnapshot(scopes={"reports:read"}))
    denied = _guard_connection()
    guard = requires_scope("reports:read")

    guard(allowed, object())  # type: ignore[arg-type]
    with pytest.raises(PermissionDeniedException, match="Permission denied") as exc_info:
        guard(denied, object())  # type: ignore[arg-type]

    assert "reports:read" not in exc_info.value.detail


@pytest.mark.parametrize(
    ("case", "allowed"),
    [
        ("authenticated", True),
        ("scope", True),
        ("role", True),
        ("capability", True),
        ("team", True),
        ("team-role-mismatch", False),
        ("team-missing-param", False),
        ("team-forged-param", False),
        ("tenant", True),
        ("tenant-mismatch", False),
        ("tenant-missing-param", False),
    ],
)
def test_authorization_base_guard_truth_table(case: str, allowed: bool) -> None:  # noqa: FBT001
    authorization = AuthorizationSnapshot(
        scopes={"reports:read"},
        roles={"admin"},
        capabilities={"reports.export"},
        team_roles={"team-1": {"owner"}},
        tenant_ids={"tenant-1"},
    )
    path_params: dict[str, object] = {"team_id": "team-1", "tenant_id": "tenant-1"}
    if case == "team-role-mismatch":
        guard = requires_team_role(team_parameter="team_id", roles={"admin"})
    elif case == "team-missing-param":
        guard = requires_team_role(team_parameter="missing", roles={"owner"})
    elif case == "team-forged-param":
        guard = requires_team_role(team_parameter="team_id", roles={"owner"})
        path_params["team_id"] = "team-2"
    elif case == "tenant-mismatch":
        guard = requires_tenant(tenant_parameter="tenant_id")
        path_params["tenant_id"] = "tenant-2"
    elif case == "tenant-missing-param":
        guard = requires_tenant(tenant_parameter="missing")
    else:
        guard = {
            "authenticated": requires_authenticated(),
            "scope": requires_scope("reports:read"),
            "role": requires_role("admin"),
            "capability": requires_capability("reports.export"),
            "team": requires_team_role(team_parameter="team_id", roles={"owner", "admin"}),
            "tenant": requires_tenant(tenant_parameter="tenant_id"),
        }[case]
    connection = _guard_connection(authorization=authorization, path_params=path_params)

    if allowed:
        guard(connection, object())  # type: ignore[arg-type]
    else:
        with pytest.raises(PermissionDeniedException, match="Permission denied"):
            guard(connection, object())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "guard",
    [
        requires_authenticated(),
        requires_scope("reports:read"),
        requires_role("admin"),
        requires_capability("reports.export"),
        requires_team_role(team_parameter="team_id", roles={"owner"}),
        requires_tenant(tenant_parameter="tenant_id"),
        guards_any_of(requires_scope("reports:read"), requires_role("admin")),
    ],
)
def test_authorization_base_guards_map_anonymous_denial_to_generic_401(guard: object) -> None:
    with pytest.raises(NotAuthorizedException, match="Authentication required") as exc_info:
        guard(_guard_connection(authenticated=False), object())  # type: ignore[operator]

    assert exc_info.value.detail == "Authentication required"


@pytest.mark.parametrize(
    ("operator", "mask", "allowed"),
    [(guards_all_of, mask, mask == 0b111) for mask in range(8)]
    + [(guards_any_of, mask, mask != 0) for mask in range(8)]
    + [(one_of, mask, mask.bit_count() == 1) for mask in range(8)]
    + [(lambda *children: guards_at_least(2, *children), mask, mask.bit_count() >= 2) for mask in range(8)],
)
def test_authorization_combinator_truth_tables(
    operator: object,
    mask: int,
    allowed: bool,  # noqa: FBT001
) -> None:
    guards = (requires_scope("a"), requires_scope("b"), requires_scope("c"))
    scopes = {name for index, name in enumerate(("a", "b", "c")) if mask & (1 << index)}
    guard = operator(*guards)  # type: ignore[operator]
    connection = _guard_connection(authorization=AuthorizationSnapshot(scopes=scopes))

    if allowed:
        guard(connection, object())
    else:
        with pytest.raises(PermissionDeniedException, match="Permission denied"):
            guard(connection, object())


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (guards_all_of, "at least one"),
        (guards_any_of, "at least one"),
        (one_of, "at least one"),
        (partial(guards_at_least, 0, requires_authenticated()), "between 1 and 1"),
        (partial(guards_at_least, 2, requires_authenticated()), "between 1 and 1"),
        (partial(guards_all_of, _DUPLICATE_GUARD, _DUPLICATE_GUARD), "duplicate child"),
        (partial(requires_scope, " "), "must not be blank"),
        (partial(requires_team_role, team_parameter="team_id", roles=set()), "at least one role"),
    ],
)
def test_authorization_guard_construction_rejects_invalid_expressions(factory: object, match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        factory()  # type: ignore[operator]


def test_authorization_guards_are_frozen_hashable_and_expose_stable_private_denial() -> None:
    guard = guards_all_of(requires_scope("reports:read"), requires_role("admin"))
    connection = _guard_connection(authorization=AuthorizationSnapshot(scopes={"reports:read"}))

    decision = guard._decide(connection)  # noqa: SLF001

    assert (decision.granted, decision.code, decision.path) == (False, "missing_role", ("all_of", "1", "role"))
    assert hash(guard)
    with pytest.raises(FrozenInstanceError):
        guard.children = ()  # type: ignore[misc]


def test_authorization_guards_do_not_call_application_resolvers_or_adapters() -> None:
    calls = 0

    def storage_lookup() -> None:
        nonlocal calls
        calls += 1

    connection = _guard_connection(
        authorization=AuthorizationSnapshot(scopes={"reports:read"}, attributes={"storage_lookup": storage_lookup})
    )

    requires_scope("reports:read")(connection, object())  # type: ignore[arg-type]

    assert calls == 0


def test_credential_restrictions_normalize_sets_and_preserve_empty() -> None:
    restrictions = CredentialRestrictions(
        scopes={" read "}, roles=frozenset(), capabilities=None, team_ids={" team-1 "}, tenant_ids={"tenant-1"}
    )

    assert restrictions.scopes == frozenset({"read"})
    assert restrictions.roles == frozenset()
    assert restrictions.capabilities is None
    assert restrictions.team_ids == frozenset({"team-1"})
    assert restrictions.tenant_ids == frozenset({"tenant-1"})


@pytest.mark.parametrize(
    "kwargs", [{"scopes": {" "}}, {"roles": {""}}, {"capabilities": {" "}}, {"team_ids": {""}}, {"tenant_ids": {" "}}]
)
def test_credential_restrictions_reject_blank_values(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="must not be blank"):
        CredentialRestrictions(**kwargs)


def test_security_context_derives_earliest_expiry_without_principal() -> None:
    authenticated_at = datetime(2026, 7, 26, tzinfo=timezone.utc)
    context = SecurityContext(
        session=_Session(),
        evidence=(
            AuthenticationEvidence(
                mechanism="local",
                slot="session",
                authenticated_at=authenticated_at,
                expires_at=authenticated_at + timedelta(hours=2),
            ),
            AuthenticationEvidence(
                mechanism="oidc",
                slot="authorization.bearer",
                authenticated_at=authenticated_at,
                expires_at=authenticated_at + timedelta(hours=1),
            ),
            AuthenticationEvidence(mechanism="api-key", slot="x-api-key", authenticated_at=authenticated_at),
        ),
    )

    assert context.expires_at == authenticated_at + timedelta(hours=1)
    assert not hasattr(context, "principal")
    with pytest.raises(FrozenInstanceError):
        context.evidence = ()  # type: ignore[misc]


def test_native_http_session_supports_live_mapping_operations() -> None:
    scope = {"type": "http", "session": {"existing": "value"}}
    handle = LitestarSessionHandle(scope=scope)  # type: ignore[arg-type]

    assert isinstance(handle, SessionHandle)
    assert handle.is_available
    assert handle.can_persist
    assert handle.get("existing") == "value"
    assert handle.get("missing", "default") == "default"

    handle.set("new", 42)
    assert handle.pop("new") == 42
    assert handle.pop("missing", "default") == "default"

    scope["session"] = {"value": "replacement"}
    assert handle.get("value") == "replacement"
    handle.clear()
    assert scope["session"] == {}


def test_anonymous_context_retains_existing_session(anonymous_principal: Principal[object]) -> None:
    scope = {"type": "http", "session": {"cart": ["item-1"]}}
    context = SecurityContext(
        session=LitestarSessionHandle(scope=scope)  # type: ignore[arg-type]
    )

    assert not anonymous_principal.is_authenticated
    assert context.session.get("cart") == ["item-1"]
    assert scope["session"] == {"cart": ["item-1"]}


def test_null_session_reads_defaults_and_rejects_mutations() -> None:
    handle = NullSessionHandle()

    assert isinstance(handle, SessionHandle)
    assert not handle.is_available
    assert not handle.can_persist
    assert handle.get("missing") is None
    assert handle.get("missing", "default") == "default"
    assert handle.pop("missing", "default") == "default"
    for mutation in (lambda: handle.set("key", "value"), handle.clear):
        with pytest.raises(SessionUnavailableError, match="Session storage is unavailable"):
            mutation()


def test_native_handle_rejects_operations_when_session_disappears() -> None:
    scope = {"type": "http", "session": {}}
    handle = LitestarSessionHandle(scope=scope)  # type: ignore[arg-type]
    del scope["session"]

    assert not handle.is_available
    assert not handle.can_persist
    for operation in (
        lambda: handle.get("missing"),
        lambda: handle.set("key", "value"),
        lambda: handle.pop("missing"),
        handle.clear,
    ):
        with pytest.raises(SessionUnavailableError, match="Session storage is unavailable"):
            operation()


def test_websocket_native_session_is_read_only() -> None:
    scope = {"type": "websocket", "session": {"existing": "value"}}
    handle = LitestarSessionHandle(scope=scope)  # type: ignore[arg-type]

    assert handle.is_available
    assert not handle.can_persist
    assert handle.get("existing") == "value"
    for mutation in (lambda: handle.set("key", "value"), lambda: handle.pop("existing"), handle.clear):
        with pytest.raises(SessionPersistenceUnavailableError, match="cannot persist"):
            mutation()


def test_package_root_exports_only_foundational_contract() -> None:
    assert litestar_security.__all__ == _PUBLIC_API
    assert all(hasattr(litestar_security, name) for name in _PUBLIC_API)
    assert litestar_security.__project__ == "litestar-security"
    assert litestar_security.__version__ == "0.1.0"
    for private_name in (
        "OwnedSessionBackend",
        "SecurityMiddleware",
        "SecurityMiddlewareWrapper",
        "SecurityRuntimeConfig",
        "SecurityRuntimePlan",
        "_AuthenticationEvaluator",
    ):
        assert not hasattr(litestar_security, private_name)
    assert not {
        "OwnedSessionBackend",
        "SecurityMiddleware",
        "SecurityMiddlewareWrapper",
        "SecurityRuntimeConfig",
        "SecurityRuntimePlan",
    }.intersection(authentication_module.__all__)
    assert openapi_module.__all__ == ()


def test_provider_package_declares_crypto_dependency_without_duplicates() -> None:
    declared = tuple(requirement.lower().replace(" ", "") for requirement in requires("litestar-security") or ())

    assert any(requirement.startswith("pyjwt[crypto]") and ">=2.13" in requirement for requirement in declared)
    assert all(not requirement.startswith("httpx") for requirement in declared)
    assert all(not requirement.startswith("cryptography") for requirement in declared)
    for dependency in ("cryptography", "jwt"):
        assert import_module(dependency)

    providers = import_module("litestar_security.providers")
    assert providers.__all__ == (
        "AsyncJWKSFetcher",
        "BearerSlotSelector",
        "BearerTokenSlot",
        "CachedJWKSProvider",
        "CompositeBearerConfig",
        "DiscoveryPolicy",
        "JSONValue",
        "JWKSCacheEntry",
        "JWKSCachePolicy",
        "JWKSFetchRequest",
        "JWKSFetchResponse",
        "JWKSProvider",
        "JWTClaims",
        "JWTValidationConfig",
        "JWTVerifier",
        "LocalJWKSConfig",
        "LocalKeyRing",
        "NoOpSecurityMetrics",
        "OIDCDiscoveryClient",
        "OIDCDiscoveryError",
        "OIDCMetadata",
        "SecurityMetrics",
        "SigningKey",
        "SyncJWKSFetcher",
        "SyncJWTVerifier",
        "SyncTokenSigner",
        "TokenSigner",
        "VerificationKey",
        "VerificationKeySet",
        "WorkerLimits",
        "build_access_token_claims",
        "build_local_jwks_handler",
        "normalize_fetcher",
        "normalize_signer",
        "normalize_verifier",
    )
    jwks_module = import_module("litestar_security.providers.jwks")
    jwt_module = import_module("litestar_security.providers.jwt")
    oidc_module = import_module("litestar_security.providers.oidc")
    assert set(jwks_module.__all__).union(jwt_module.__all__, oidc_module.__all__) == set(providers.__all__)
    assert jwks_module.__all__ == (
        "AsyncJWKSFetcher",
        "CachedJWKSProvider",
        "JWKSCacheEntry",
        "JWKSCachePolicy",
        "JWKSFetchRequest",
        "JWKSFetchResponse",
        "JWKSProvider",
        "NoOpSecurityMetrics",
        "SecurityMetrics",
        "SyncJWKSFetcher",
        "WorkerLimits",
        "normalize_fetcher",
    )


def test_accounts_package_declares_argon2_without_backend_dependencies() -> None:
    declared = tuple(requirement.lower().replace(" ", "") for requirement in requires("litestar-security") or ())

    assert any(
        requirement.startswith("argon2-cffi") and ">=25.1" in requirement and "<26" in requirement
        for requirement in declared
    )
    assert all(
        not requirement.startswith(dependency)
        for dependency in ("advanced-alchemy", "redis", "sqlalchemy", "sqlspec")
        for requirement in declared
    )
    assert import_module("argon2")
    accounts = import_module("litestar_security.accounts")
    assert accounts.__all__ == (
        "AccountLookup",
        "Argon2PasswordHasher",
        "ConsumeResult",
        "ConsumeStatus",
        "CreateSessionCommand",
        "InvalidInvitation",
        "InvalidLifecycleRequest",
        "LifecycleAccepted",
        "LocalAccount",
        "LocalAccountCapabilities",
        "LocalAuth",
        "LocalAuthConfig",
        "LocalAuthMode",
        "LoginMethod",
        "LoginMethodStore",
        "NativeSessionAuth",
        "NativeSessionStore",
        "NoOpSecurityEventSink",
        "NotificationCommand",
        "PasswordChangeResult",
        "PasswordChangeService",
        "PasswordChangeStatus",
        "PasswordCredentialState",
        "PasswordCredentialStore",
        "PasswordHasher",
        "PasswordHashingUnavailableError",
        "PasswordPolicy",
        "PasswordPolicyResult",
        "PasswordPolicyViolation",
        "PasswordReauthenticationProof",
        "PasswordReauthenticationService",
        "PasswordResetResult",
        "PasswordResetStatus",
        "PasswordVerificationResult",
        "PasswordVerificationStatus",
        "PendingTokenIssue",
        "PurposeTokenCodec",
        "PurposeTokenDelivery",
        "PurposeTokenGenerationError",
        "PurposeTokenProof",
        "RecoveryTokenService",
        "RecoveryTokenStore",
        "RefreshRotationStatus",
        "RefreshTokenFamilyStore",
        "RegistrationCommand",
        "RegistrationMode",
        "RegistrationPolicy",
        "RegistrationResult",
        "RegistrationService",
        "RegistrationStatus",
        "RegistrationStore",
        "RevokeLoginMethodResult",
        "RevokeLoginMethodStatus",
        "RotateRefreshCommand",
        "RotateRefreshResult",
        "SecurityEpochStore",
        "SecurityEpochValidator",
        "SecurityEvent",
        "SecurityEventSink",
        "SessionAuthentication",
        "SessionBindingConfig",
        "SessionBindingProof",
        "SessionRecord",
        "SessionRegistry",
        "SessionSummary",
        "TokenIssue",
        "TokenPurpose",
        "VerificationTokenService",
        "VerificationTokenStore",
        "normalize_identifier",
    )


@pytest.mark.parametrize(
    ("protocol", "methods"),
    [
        (accounts_module.AccountLookup, {"find_for_login", "get_by_id"}),
        (accounts_module.LocalAccountCapabilities, _BASE_LOCAL_CAPABILITIES),
        (
            accounts_module.PasswordCredentialStore,
            {"get_password_state", "compare_and_replace_password", "replace_password_and_bump_epoch"},
        ),
        (accounts_module.LoginMethodStore, {"register_login_method", "revoke_login_method"}),
        (accounts_module.RegistrationStore, {"register"}),
        (accounts_module.VerificationTokenStore, {"issue", "consume_and_verify"}),
        (accounts_module.RecoveryTokenStore, {"issue", "consume_and_reset"}),
        (accounts_module.SecurityEpochStore, {"current_epoch"}),
        (accounts_module.SessionRegistry, _SESSION_CAPABILITIES),
        (accounts_module.RefreshTokenFamilyStore, _REFRESH_CAPABILITIES),
    ],
)
def test_account_capabilities_are_runtime_structural(protocol: type[object], methods: set[str]) -> None:
    implementation = _structural_capabilities(*methods)

    assert isinstance(implementation, protocol)
    assert protocol not in type(implementation).__mro__
    if methods:
        incomplete = _structural_capabilities(*tuple(methods)[1:])
        assert not isinstance(incomplete, protocol)


def test_local_account_commands_and_results_are_frozen_slotted_and_secret_safe() -> None:
    now = datetime(2026, 7, 26, 23, tzinfo=timezone.utc)
    account = accounts_module.LocalAccount(
        account_id="account-1",
        normalized_identifier="user@example.com",
        display_name="User",
        active=True,
        verified=True,
        security_epoch=1,
        user=object(),
    )
    event_correlation = {"request_id": "request-1"}
    event = accounts_module.SecurityEvent(
        event_id="event-1",
        occurred_at=now,
        operation="local.login",
        outcome="accepted",
        account_id=account.account_id,
        correlation=event_correlation,
    )
    binding_digest = b"b" * 32
    token_digest = b"d" * 32
    successor_digest = b"successor-secret-digest"
    receipt = b"sealed-secret-receipt"
    lookup_id = "verification_aWlpaWlpaWlpaWlpaWlpaQ"
    notification_value = "raw-notification-secret"
    refresh_lookup_id = "refresh-1"
    values = (
        account,
        accounts_module.LoginMethod(method_id="password-1", kind="password", created_at=now),
        event,
        accounts_module.TokenIssue(
            token_id=lookup_id,
            digest=token_digest,
            purpose=accounts_module.TokenPurpose.VERIFICATION,
            account_id=account.account_id,
            expires_at=now + timedelta(hours=1),
            maximum_attempts=5,
        ),
        accounts_module.NotificationCommand(
            template="verify",
            destination="destination-secret",
            token=notification_value,
            expires_at=now + timedelta(hours=1),
        ),
        accounts_module.RegistrationCommand(normalized_identifier="user@example.com"),
        accounts_module.PasswordCredentialState("encoded-secret-hash", 1),
        accounts_module.PasswordReauthenticationProof(
            account_id=account.account_id, security_epoch=1, authenticated_at=now, expires_at=now + timedelta(minutes=5)
        ),
        accounts_module.PasswordChangeResult(accounts_module.PasswordChangeStatus.CHANGED, security_epoch=2),
        accounts_module.RevokeLoginMethodResult(accounts_module.RevokeLoginMethodStatus.REVOKED),
        accounts_module.RegistrationResult(accounts_module.RegistrationStatus.CREATED, account),
        accounts_module.ConsumeResult(accounts_module.ConsumeStatus.CONSUMED, account.account_id, 1),
        accounts_module.PasswordResetResult(accounts_module.PasswordResetStatus.RESET, account.account_id, 2),
        accounts_module.RegistrationPolicy.disabled(),
        accounts_module.SessionBindingConfig(pepper=b"p" * 32),
        accounts_module.SessionAuthentication(
            session_id=_SESSION_ID,
            binding_id=_BINDING_ID,
            account_id=account.account_id,
            security_epoch=1,
            authenticated_at=now,
            expires_at=now + timedelta(hours=1),
        ),
        accounts_module.SessionBindingProof(binding_id=_BINDING_ID, digest=binding_digest),
        accounts_module.SessionRecord(
            session_id=_SESSION_ID,
            binding_id=_BINDING_ID,
            binding_digest=binding_digest,
            account_id=account.account_id,
            security_epoch=1,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(hours=1),
        ),
        accounts_module.CreateSessionCommand(
            session_id=_SESSION_ID,
            binding_id=_BINDING_ID,
            binding_digest=binding_digest,
            account_id=account.account_id,
            security_epoch=1,
            created_at=now,
            expires_at=now + timedelta(hours=1),
        ),
        accounts_module.SessionSummary(
            session_id=_SESSION_ID, current=True, created_at=now, last_seen_at=now, expires_at=now + timedelta(hours=1)
        ),
        accounts_module.RotateRefreshCommand(
            token_id=refresh_lookup_id,
            token_digest=token_digest,
            account_id=account.account_id,
            family_id="family-1",
            security_epoch=1,
            successor_id="refresh-2",
            successor_digest=successor_digest,
            successor_expires_at=now + timedelta(days=7),
            family_expires_at=now + timedelta(days=30),
            sealed_receipt=receipt,
            receipt_expires_at=now + timedelta(seconds=30),
        ),
        accounts_module.RotateRefreshResult(accounts_module.RefreshRotationStatus.ROTATED, receipt),
    )

    event_correlation["request_id"] = "changed"
    assert event.correlation == {"request_id": "request-1"}
    for value in values:
        assert not hasattr(value, "__dict__")
        with pytest.raises(FrozenInstanceError):
            setattr(value, fields(value)[0].name, None)
    rendered = " ".join(repr(value) for value in values)
    for secret in (
        "binding-secret-digest",
        "destination-secret",
        "raw-notification-secret",
        "encoded-secret-hash",
        "sealed-secret-receipt",
        "successor-secret-digest",
        "token-secret-digest",
    ):
        assert secret not in rendered


def test_atomic_results_reject_contradictory_status_payloads() -> None:
    account: accounts_module.LocalAccount[object] = accounts_module.LocalAccount(
        account_id="account-1",
        normalized_identifier="user@example.com",
        display_name=None,
        active=True,
        verified=True,
        security_epoch=1,
    )
    invalid_results = (
        partial(accounts_module.PasswordChangeResult, accounts_module.PasswordChangeStatus.CHANGED),
        partial(accounts_module.PasswordChangeResult, accounts_module.PasswordChangeStatus.CONFLICT, 2),
        partial(accounts_module.RegistrationResult, accounts_module.RegistrationStatus.CREATED),
        partial(accounts_module.RegistrationResult, accounts_module.RegistrationStatus.DUPLICATE, account),
        partial(accounts_module.ConsumeResult, accounts_module.ConsumeStatus.CONSUMED),
        partial(accounts_module.ConsumeResult, accounts_module.ConsumeStatus.INVALID, account.account_id, 1),
        partial(accounts_module.PasswordResetResult, accounts_module.PasswordResetStatus.RESET),
        partial(
            accounts_module.PasswordResetResult, accounts_module.PasswordResetStatus.INVALID, account.account_id, 1
        ),
        partial(accounts_module.RotateRefreshResult, accounts_module.RefreshRotationStatus.ROTATED),
        partial(
            accounts_module.RotateRefreshResult,
            accounts_module.RefreshRotationStatus.ROTATED,
            sealed_receipt=b"receipt",
            family_revoked=True,
        ),
        partial(accounts_module.RotateRefreshResult, accounts_module.RefreshRotationStatus.REPLAY_DETECTED),
        partial(
            accounts_module.RotateRefreshResult, accounts_module.RefreshRotationStatus.INVALID, family_revoked=True
        ),
    )

    for result in invalid_results:
        with pytest.raises(ValueError, match=r"require|must report"):
            result()

    assert accounts_module.PasswordChangeResult(accounts_module.PasswordChangeStatus.CONFLICT).security_epoch is None
    assert accounts_module.RegistrationResult(accounts_module.RegistrationStatus.DUPLICATE).account is None
    assert accounts_module.ConsumeResult(accounts_module.ConsumeStatus.INVALID).account_id is None
    assert accounts_module.PasswordResetResult(accounts_module.PasswordResetStatus.EXPIRED).account_id is None
    assert (
        accounts_module.RotateRefreshResult(
            accounts_module.RefreshRotationStatus.IDEMPOTENT_REPLAY, b"receipt"
        ).sealed_receipt
        == b"receipt"
    )
    assert accounts_module.RotateRefreshResult(
        accounts_module.RefreshRotationStatus.REPLAY_DETECTED, family_revoked=True
    ).family_revoked


@pytest.mark.parametrize("epoch", [-1, True, 9_223_372_036_854_775_808])
def test_account_password_session_and_refresh_contracts_share_one_strict_epoch_domain(epoch: object) -> None:
    now = _ACCOUNT_NOW
    factories = (
        lambda: accounts_module.LocalAccount(
            account_id="account-1",
            normalized_identifier="user@example.com",
            display_name=None,
            active=True,
            verified=True,
            security_epoch=epoch,
        ),
        lambda: accounts_module.PasswordCredentialState("encoded-hash", epoch),
        lambda: accounts_module.PasswordReauthenticationProof("account-1", epoch, now, now + timedelta(minutes=5)),
        lambda: accounts_module.PasswordChangeResult(accounts_module.PasswordChangeStatus.CHANGED, epoch),
        lambda: accounts_module.PasswordResetResult(accounts_module.PasswordResetStatus.RESET, "account-1", epoch),
        lambda: accounts_module.SessionAuthentication(
            _SESSION_ID, _BINDING_ID, "account-1", epoch, now, now + timedelta(hours=1)
        ),
        lambda: accounts_module.SessionRecord(
            _SESSION_ID, _BINDING_ID, b"d" * 32, "account-1", epoch, now, now, now + timedelta(hours=1)
        ),
        lambda: accounts_module.CreateSessionCommand(
            _SESSION_ID, _BINDING_ID, b"d" * 32, "account-1", epoch, now, now + timedelta(hours=1)
        ),
        lambda: accounts_module.RotateRefreshCommand(
            "refresh-1", b"digest", "account-1", "family-1", epoch, "refresh-2", b"successor", now, now, b"receipt", now
        ),
    )

    for factory in factories:
        with pytest.raises(ValueError, match="epoch"):
            factory()
    assert accounts_module.RotateRefreshResult(
        accounts_module.RefreshRotationStatus.REVOKED, family_revoked=True
    ).family_revoked
    assert not accounts_module.RotateRefreshResult(accounts_module.RefreshRotationStatus.EXPIRED).family_revoked


@pytest.mark.parametrize(
    ("authenticated_at", "expires_at", "match"),
    [
        (_ACCOUNT_NOW.replace(tzinfo=None), _ACCOUNT_NOW + timedelta(minutes=5), "timezone-aware"),
        (_ACCOUNT_NOW, _ACCOUNT_NOW.replace(tzinfo=None), "timezone-aware"),
        (object(), _ACCOUNT_NOW + timedelta(minutes=5), "timezone-aware"),
        (_ACCOUNT_NOW, _ACCOUNT_NOW + timedelta(minutes=5, microseconds=1), "valid lifetime"),
    ],
)
def test_password_reauthentication_proof_requires_aware_timestamps(
    authenticated_at: datetime, expires_at: datetime, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        accounts_module.PasswordReauthenticationProof("account-1", 1, authenticated_at, expires_at)


def test_local_auth_profiles_validate_only_structural_enabled_capabilities(local_key_ring: LocalKeyRing) -> None:
    csrf = litestar_security.ExternalCSRF("application", lambda _method, _path, _policy: True)
    binding = accounts_module.SessionBindingConfig(pepper=b"p" * 32)
    key_ring = local_key_ring
    audience = "local-client"
    session_store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES))
    token_store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _REFRESH_CAPABILITIES))
    hybrid_store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES | _REFRESH_CAPABILITIES))
    registration_store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES | {"register"}))

    session = accounts_module.LocalAuth.session(
        accounts=session_store, csrf=csrf, binding=binding, route_prefix="/security/"
    )
    tokens = accounts_module.LocalAuth.tokens(accounts=token_store, key_ring=key_ring, token_audience=f" {audience} ")
    hybrid = accounts_module.LocalAuth.hybrid(
        accounts=hybrid_store, csrf=csrf, binding=binding, key_ring=key_ring, token_audience=audience
    )
    registration = accounts_module.LocalAuth.session(
        accounts=registration_store,
        csrf=csrf,
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
    csrf = litestar_security.ExternalCSRF("application", lambda _method, _path, _policy: True)
    binding = accounts_module.SessionBindingConfig(pepper=b"p" * 32)
    store = _structural_capabilities(*methods)
    audience = "local-client"

    if profile == "session":
        operation = partial(accounts_module.LocalAuth.session, accounts=store, csrf=csrf, binding=binding)
    elif profile == "tokens":
        operation = partial(
            accounts_module.LocalAuth.tokens, accounts=store, key_ring=local_key_ring, token_audience=audience
        )
    else:
        operation = partial(
            accounts_module.LocalAuth.session,
            accounts=store,
            csrf=csrf,
            binding=binding,
            registration=accounts_module.RegistrationPolicy.public(),
        )
    with pytest.raises(ImproperlyConfiguredException, match=match):
        operation()


def test_local_auth_rejects_transport_inconsistent_custom_session_runtime(local_key_ring: LocalKeyRing) -> None:
    csrf = litestar_security.ExternalCSRF("application", lambda _method, _path, _policy: True)
    binding = accounts_module.SessionBindingConfig(pepper=b"p" * 32)
    audience = "local-client"
    store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES | _REFRESH_CAPABILITIES))
    other_store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES | _REFRESH_CAPABILITIES))
    runtime = accounts_module.NativeSessionAuth(accounts=store, binding=binding)
    matching = accounts_module.LocalAuth.session(accounts=store, csrf=csrf, binding=binding, session_auth=runtime)
    assert matching.session_auth is runtime

    with pytest.raises(ImproperlyConfiguredException, match="Token-only"):
        accounts_module.LocalAuthConfig(
            mode=accounts_module.LocalAuthMode.TOKENS,
            accounts=store,
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
            accounts_module.LocalAuth.session(accounts=store, csrf=csrf, binding=binding, session_auth=mismatched)


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
        ("csrf", None, "requires explicit CSRF"),
        ("csrf", object(), "requires explicit CSRF"),
        ("binding", None, "requires explicit CSRF"),
        ("binding", object(), "requires explicit CSRF"),
        ("key_ring", None, "explicit key ring and audience"),
        ("key_ring", object(), "explicit key ring and audience"),
        ("token_audience", " ", "explicit key ring and audience"),
        ("token_audience", object(), "explicit key ring and audience"),
    ],
)
def test_local_auth_config_rejects_incomplete_transport_values(
    field_name: str, invalid_value: object, match: str, local_key_ring: LocalKeyRing
) -> None:
    csrf = litestar_security.ExternalCSRF("application", lambda _method, _path, _policy: True)
    binding = accounts_module.SessionBindingConfig(pepper=b"p" * 32)
    store = _structural_capabilities(*(_BASE_LOCAL_CAPABILITIES | _SESSION_CAPABILITIES | _REFRESH_CAPABILITIES))
    kwargs = {
        "mode": accounts_module.LocalAuthMode.HYBRID,
        "accounts": store,
        "registration": accounts_module.RegistrationPolicy.disabled(),
        "route_prefix": "/auth",
        "csrf": csrf,
        "binding": binding,
        "key_ring": local_key_ring,
        "token_audience": "local-client",
    }
    kwargs[field_name] = invalid_value

    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.LocalAuthConfig(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"pepper": b"short"}, "at least 32 bytes"),
        ({"pepper": bytearray(b"p" * 32)}, "at least 32 bytes"),
        ({"pepper": b"p" * 32, "cookie_name": ""}, "cookie-safe"),
        ({"pepper": b"p" * 32, "cookie_name": " binding"}, "cookie-safe"),
        ({"pepper": b"p" * 32, "cookie_name": "bind;ing"}, "cookie-safe"),
        ({"pepper": b"p" * 32, "secure": 1}, "Secure setting"),
        ({"pepper": b"p" * 32, "same_site": "bogus"}, "SameSite"),
        ({"pepper": b"p" * 32, "allow_insecure": 1}, "opt-in must be boolean"),
        ({"pepper": b"p" * 32, "allow_insecure": True}, "requires an insecure cookie"),
        ({"pepper": b"p" * 32, "secure": False}, "development opt-in"),
        ({"pepper": b"p" * 32, "secure": False, "allow_insecure": True}, "__Host-"),
        (
            {
                "pepper": b"p" * 32,
                "cookie_name": "binding",
                "secure": False,
                "allow_insecure": True,
                "same_site": "none",
            },
            "SameSite=None",
        ),
        ({"pepper": b"p" * 32, "path": "/nested"}, "__Host-"),
        ({"pepper": b"p" * 32, "cookie_name": "binding", "path": "relative"}, "absolute printable"),
        ({"pepper": b"p" * 32, "cookie_name": "binding", "path": "/bad path"}, "absolute printable"),
        ({"pepper": b"p" * 32, "cookie_name": "binding", "domain": " "}, "domain"),
        ({"pepper": b"p" * 32, "cookie_name": "binding", "domain": "bad domain"}, "domain"),
        ({"pepper": b"p" * 32, "max_age": 0}, "positive integer"),
        ({"pepper": b"p" * 32, "max_age": True}, "positive integer"),
        ({"pepper": b"p" * 32, "touch_interval": timedelta(0)}, "touch interval"),
        ({"pepper": b"p" * 32, "touch_interval": object()}, "touch interval"),
        ({"pepper": b"p" * 32, "max_age": 1, "touch_interval": timedelta(seconds=2)}, "touch interval"),
        ({"pepper": b"p" * 32, "preserve_session_keys": ["cart"]}, "immutable tuple"),
        ({"pepper": b"p" * 32, "preserve_session_keys": ("cart", "cart")}, "unique"),
        ({"pepper": b"p" * 32, "preserve_session_keys": ("_litestar_security",)}, "unique"),
        ({"pepper": b"p" * 32, "preserve_session_keys": (" ",)}, "unique"),
    ],
)
def test_session_binding_config_rejects_unsafe_boundaries(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.SessionBindingConfig(**kwargs)  # type: ignore[arg-type]


def test_session_binding_config_supports_explicit_insecure_development() -> None:
    config = accounts_module.SessionBindingConfig(
        pepper=b"p" * 32,
        cookie_name="litestar-security-binding",
        secure=False,
        allow_insecure=True,
        preserve_session_keys=("cart",),
    )

    assert not config.secure
    assert config.allow_insecure
    assert config.preserve_session_keys == ("cart",)


@pytest.mark.parametrize(
    ("contract", "overrides", "match"),
    [
        ("authentication", {"authenticated_at": _ACCOUNT_NOW.replace(tzinfo=None)}, "timezone-aware"),
        ("authentication", {"session_id": object()}, "payload"),
        ("authentication", {"session_id": "invalid"}, "payload"),
        ("authentication", {"binding_id": "invalid"}, "payload"),
        ("authentication", {"account_id": " "}, "payload"),
        ("authentication", {"expires_at": _ACCOUNT_NOW}, "payload"),
        ("proof", {"binding_id": "invalid"}, "proof"),
        ("proof", {"digest": bytearray(b"d" * 32)}, "proof"),
        ("proof", {"digest": b"short"}, "proof"),
        ("record", {"created_at": _ACCOUNT_NOW.replace(tzinfo=None)}, "timezone-aware"),
        ("record", {"session_id": "invalid"}, "record is invalid"),
        ("record", {"binding_id": "invalid"}, "record is invalid"),
        ("record", {"binding_digest": bytearray(b"d" * 32)}, "record is invalid"),
        ("record", {"binding_digest": b"short"}, "record is invalid"),
        ("record", {"account_id": " "}, "record is invalid"),
        ("record", {"last_seen_at": _ACCOUNT_NOW + timedelta(hours=1)}, "record is invalid"),
        ("record", {"display_metadata": {" ": "browser"}}, "display metadata"),
        ("record", {"display_metadata": {str(index): "x" for index in range(33)}}, "display metadata"),
        ("record", {"display_metadata": {"device": "x" * 251}}, "display metadata"),
        ("record", {"display_metadata": {str(index): "x" * 200 for index in range(21)}}, "display metadata"),
        ("create", {"created_at": _ACCOUNT_NOW.replace(tzinfo=None)}, "timezone-aware"),
        ("create", {"session_id": "invalid"}, "creation command"),
        ("create", {"binding_id": "invalid"}, "creation command"),
        ("create", {"binding_digest": bytearray(b"d" * 32)}, "creation command"),
        ("create", {"binding_digest": b"short"}, "creation command"),
        ("create", {"account_id": " "}, "creation command"),
        ("create", {"expires_at": _ACCOUNT_NOW}, "creation command"),
        ("summary", {"created_at": _ACCOUNT_NOW.replace(tzinfo=None)}, "timezone-aware"),
        ("summary", {"session_id": "invalid"}, "summary is invalid"),
        ("summary", {"current": 1}, "summary is invalid"),
        ("summary", {"last_seen_at": _ACCOUNT_NOW + timedelta(hours=1)}, "summary is invalid"),
        ("summary", {"display_metadata": {"device": " "}}, "display metadata"),
    ],
)
def test_native_session_contracts_reject_malformed_state(
    contract: str, overrides: dict[str, object], match: str
) -> None:
    common: dict[str, object] = {
        "session_id": _SESSION_ID,
        "binding_id": _BINDING_ID,
        "binding_digest": b"d" * 32,
        "account_id": "account-1",
        "security_epoch": 1,
        "created_at": _ACCOUNT_NOW,
        "last_seen_at": _ACCOUNT_NOW,
        "authenticated_at": _ACCOUNT_NOW,
        "expires_at": _ACCOUNT_NOW + timedelta(hours=1),
        "current": True,
        "digest": b"d" * 32,
    }
    fields_by_contract = {
        "authentication": (
            "session_id",
            "binding_id",
            "account_id",
            "security_epoch",
            "authenticated_at",
            "expires_at",
        ),
        "proof": ("binding_id", "digest"),
        "record": (
            "session_id",
            "binding_id",
            "binding_digest",
            "account_id",
            "security_epoch",
            "created_at",
            "last_seen_at",
            "expires_at",
            "display_metadata",
        ),
        "create": (
            "session_id",
            "binding_id",
            "binding_digest",
            "account_id",
            "security_epoch",
            "created_at",
            "expires_at",
            "display_metadata",
        ),
        "summary": ("session_id", "current", "created_at", "last_seen_at", "expires_at", "display_metadata"),
    }
    factories = {
        "authentication": accounts_module.SessionAuthentication,
        "proof": accounts_module.SessionBindingProof,
        "record": accounts_module.SessionRecord,
        "create": accounts_module.CreateSessionCommand,
        "summary": accounts_module.SessionSummary,
    }
    common.update(overrides)
    values = {name: common[name] for name in fields_by_contract[contract] if name in common}

    with pytest.raises(ValueError, match=match):
        factories[contract](**values)  # type: ignore[operator]


def test_registration_policy_requires_an_explicit_mode() -> None:
    assert accounts_module.RegistrationPolicy.disabled() == accounts_module.RegistrationPolicy(
        accounts_module.RegistrationMode.DISABLED
    )
    assert accounts_module.RegistrationPolicy.public(require_verification=False) == accounts_module.RegistrationPolicy(
        accounts_module.RegistrationMode.PUBLIC, require_verification=False
    )
    assert accounts_module.RegistrationPolicy.invite_only() == accounts_module.RegistrationPolicy(
        accounts_module.RegistrationMode.INVITE_ONLY
    )


def _purpose_token_delivery(
    codec: accounts_module.PurposeTokenCodec, purpose: accounts_module.TokenPurpose, lifetime: timedelta
) -> accounts_module.PurposeTokenDelivery:
    return codec.issue(
        purpose, now=_ACCOUNT_NOW, lifetime=lifetime, template=f"local.{purpose.value}", destination="user@example.com"
    )


def test_purpose_token_codec_generates_strict_redacted_and_bindable_material() -> None:
    entropy_values = iter((b"i" * 16, b"s" * 32))
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32, entropy=lambda _length: next(entropy_values))

    issued = _purpose_token_delivery(codec, accounts_module.TokenPurpose.VERIFICATION, timedelta(hours=24))
    token = issued.notification.token
    proof = codec.proof(token, expected_purpose=accounts_module.TokenPurpose.VERIFICATION)

    assert token.startswith("verification_")
    assert len(token.split("_", 1)[1].split(".", 1)[0]) == 22
    assert len(token.rsplit(".", 1)[1]) == 43
    assert proof == accounts_module.PurposeTokenProof(
        token_id=issued.issue.token_id, digest=issued.issue.digest, purpose=accounts_module.TokenPurpose.VERIFICATION
    )
    assert issued.issue.expires_at == _ACCOUNT_NOW + timedelta(hours=24)
    assert issued.issue.maximum_attempts == 5
    bound, notification = issued.bind("account-1")
    assert (bound.account_id, bound.token_id, bound.digest) == ("account-1", issued.issue.token_id, issued.issue.digest)
    assert notification is issued.notification
    assert token not in repr(issued)
    assert issued.issue.digest.hex() not in repr(issued.issue)
    assert "p" * 32 not in repr(codec)


@pytest.mark.parametrize(
    "token",
    [
        None,
        object(),
        "",
        "verification_missing-secret",
        "verification_a.b.c",
        "verification_!!!!!!!!!!!!!!!!!!!!!!.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "verification_AAAAAAAAAAAAAAAAAAAAA=.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "verification_" + "\ud800" * 22 + "." + "A" * 43,
        "unknown_AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ],
)
def test_purpose_token_codec_rejects_malformed_runtime_values(token: object, monkeypatch: pytest.MonkeyPatch) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)
    calls = 0
    original = local_accounts_module.hmac_digest

    def tracked(key: bytes, message: bytes, digest: str) -> bytes:
        nonlocal calls
        calls += 1
        return original(key, message, digest)

    monkeypatch.setattr(local_accounts_module, "hmac_digest", tracked)

    assert codec.proof(token, expected_purpose=accounts_module.TokenPurpose.VERIFICATION) is None
    assert calls == 1


def test_purpose_token_codec_never_crosses_namespaces() -> None:
    entropy_values = iter((b"i" * 16, b"s" * 32))
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32, entropy=lambda _length: next(entropy_values))
    issued = _purpose_token_delivery(codec, accounts_module.TokenPurpose.RECOVERY, timedelta(minutes=30))
    token = issued.notification.token

    assert codec.proof(token, expected_purpose=accounts_module.TokenPurpose.VERIFICATION) is None
    assert codec.proof(token, expected_purpose=accounts_module.TokenPurpose.INVITATION) is None
    assert codec.proof(token, expected_purpose=accounts_module.TokenPurpose.RECOVERY) is not None


@pytest.mark.parametrize("kwargs", [{"pepper": b"short"}, {"pepper": "p" * 32}, {"pepper": b"p" * 32, "entropy": None}])
def test_purpose_token_codec_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Purpose token"):
        accounts_module.PurposeTokenCodec(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "entropy", [lambda _length: b"short", lambda _length: "not-bytes", lambda _length: (_ for _ in ()).throw(OSError)]
)
def test_purpose_token_codec_rejects_invalid_entropy(entropy: object) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32, entropy=entropy)  # type: ignore[arg-type]

    with pytest.raises(accounts_module.PurposeTokenGenerationError):
        _purpose_token_delivery(codec, accounts_module.TokenPurpose.VERIFICATION, timedelta(hours=24))


@pytest.mark.parametrize(
    ("purpose", "lifetime", "attempts"),
    [
        ("verification", timedelta(hours=1), 5),
        (accounts_module.TokenPurpose.VERIFICATION, timedelta(0), 5),
        (accounts_module.TokenPurpose.VERIFICATION, timedelta(hours=1), 0),
        (accounts_module.TokenPurpose.VERIFICATION, timedelta(hours=1), True),
    ],
)
def test_purpose_token_codec_rejects_invalid_issue_arguments(
    purpose: object, lifetime: timedelta, attempts: object
) -> None:
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32)

    with pytest.raises(ValueError, match="Purpose token"):
        codec.issue(  # type: ignore[arg-type]
            purpose,
            now=_ACCOUNT_NOW,
            lifetime=lifetime,
            template="local.verify",
            destination="user@example.com",
            maximum_attempts=attempts,
        )
    with pytest.raises(ValueError, match="Expected purpose"):
        codec.proof("invalid", expected_purpose="verification")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"token_id": "invalid"},
        {"token_id": object()},
        {"digest": b"short"},
        {"purpose": "verification"},
        {"maximum_attempts": 0},
        {"maximum_attempts": True},
        {"expires_at": datetime(2026, 7, 27)},  # noqa: DTZ001 - explicit rejection input
    ],
)
def test_pending_token_issue_rejects_invalid_storage_shapes(kwargs: dict[str, object]) -> None:
    values = {
        "token_id": "verification_aWlpaWlpaWlpaWlpaWlpaQ",
        "digest": b"d" * 32,
        "purpose": accounts_module.TokenPurpose.VERIFICATION,
        "expires_at": _ACCOUNT_NOW + timedelta(hours=1),
        "maximum_attempts": 5,
        **kwargs,
    }

    with pytest.raises(ValueError, match="purpose token"):
        accounts_module.PendingTokenIssue(**values)  # type: ignore[arg-type]


def test_bound_token_and_proof_reject_invalid_identifiers_or_digests() -> None:
    pending = accounts_module.PendingTokenIssue(
        token_id="verification_aWlpaWlpaWlpaWlpaWlpaQ",  # noqa: S106 - non-secret lookup ID
        digest=b"d" * 32,
        purpose=accounts_module.TokenPurpose.VERIFICATION,
        expires_at=_ACCOUNT_NOW + timedelta(hours=1),
        maximum_attempts=5,
    )

    with pytest.raises(ValueError, match="account binding"):
        pending.bind(" ")
    with pytest.raises(ValueError, match="proof"):
        accounts_module.PurposeTokenProof(
            token_id=pending.token_id, digest=b"short", purpose=accounts_module.TokenPurpose.VERIFICATION
        )

    recovery = accounts_module.PendingTokenIssue(
        token_id="recovery_aWlpaWlpaWlpaWlpaWlpaQ",  # noqa: S106 - non-secret lookup ID
        digest=b"d" * 32,
        purpose=accounts_module.TokenPurpose.RECOVERY,
        expires_at=_ACCOUNT_NOW + timedelta(hours=1),
        maximum_attempts=5,
    )
    with pytest.raises(ValueError, match="issuance epoch"):
        recovery.bind("account-1")
    assert recovery.bind("account-1", security_epoch=1).issued_security_epoch == 1
    with pytest.raises(ValueError, match="issuance epoch"):
        pending.bind("account-1", security_epoch=1)


def test_purpose_token_delivery_is_codec_created_digest_bound_and_redacted() -> None:
    entropy_values = iter((b"i" * 16, b"s" * 32))
    codec = accounts_module.PurposeTokenCodec(pepper=b"p" * 32, entropy=lambda _length: next(entropy_values))
    plan = codec.issue(
        accounts_module.TokenPurpose.VERIFICATION,
        now=_ACCOUNT_NOW,
        lifetime=timedelta(hours=24),
        template="local.verify",
        destination="user@example.com",
        return_url="https://app.example/verified",
    )
    proof = codec.proof(plan.notification.token, expected_purpose=accounts_module.TokenPurpose.VERIFICATION)

    assert plan.issue.purpose is accounts_module.TokenPurpose.VERIFICATION
    assert proof == accounts_module.PurposeTokenProof(
        plan.issue.token_id, plan.issue.digest, accounts_module.TokenPurpose.VERIFICATION
    )
    assert plan.notification.token not in repr(plan.notification)
    assert "user@example.com" not in repr(plan.notification)
    assert plan.notification.token not in repr(plan)


def test_purpose_token_delivery_cannot_be_publicly_constructed_with_mismatched_material() -> None:
    with pytest.raises(TypeError, match="PurposeTokenCodec"):
        accounts_module.PurposeTokenDelivery()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"template": "", "destination": "user", "token": "token"},
        {"template": "verify", "destination": "", "token": "token"},
        {"template": "verify", "destination": "user", "token": ""},
        {
            "template": "verify",
            "destination": "user",
            "token": "token",
            "expires_at": datetime(2026, 7, 27),  # noqa: DTZ001 - explicit rejection input
        },
        {
            "template": "verify",
            "destination": "user",
            "token": "token",
            "return_url": "https://user:secret@app.example/callback",
        },
        {
            "template": "verify",
            "destination": "user",
            "token": "token",
            "return_url": "https://app.example/callback#token",
        },
        {"template": "verify", "destination": "user", "token": "token", "return_url": object()},
    ],
)
def test_notification_command_rejects_incomplete_or_unsafe_values(kwargs: dict[str, object]) -> None:
    values = {"expires_at": _ACCOUNT_NOW + timedelta(hours=1), **kwargs}

    with pytest.raises(ValueError, match="Notification"):
        accounts_module.NotificationCommand(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("password", "identifier", "violations"),
    [
        ("a" * 14, None, {accounts_module.PasswordPolicyViolation.TOO_SHORT}),
        ("a" * 129, None, {accounts_module.PasswordPolicyViolation.TOO_LONG}),
        ("\ud800" * 15, None, {accounts_module.PasswordPolicyViolation.INVALID_TEXT}),
        (
            "é" * 513,
            None,
            {accounts_module.PasswordPolicyViolation.TOO_LONG, accounts_module.PasswordPolicyViolation.TOO_MANY_BYTES},
        ),
        (" USER@EXAMPLE.COM ", "user@example.com", {accounts_module.PasswordPolicyViolation.MATCHES_IDENTIFIER}),
        ("known compromised passphrase", None, {accounts_module.PasswordPolicyViolation.COMPROMISED}),
    ],
)
def test_password_policy_reports_only_secret_free_violations(
    password: str, identifier: str | None, violations: set["accounts_module.PasswordPolicyViolation"]
) -> None:
    policy = accounts_module.PasswordPolicy(compromised=lambda candidate: candidate == "known compromised passphrase")

    result = policy.check(password, normalized_identifier=identifier)

    assert result.violations == frozenset(violations)
    assert not result.accepted
    assert password not in repr(policy)
    assert password not in repr(result)


def test_password_policy_defaults_allow_unicode_spaces_and_long_passphrases() -> None:
    policy = accounts_module.PasswordPolicy()
    accepted = ("correct horse battery staple", "   spaced passphrase   ", "🦄 unicode passphrase", "é" * 128)

    assert (policy.minimum_length, policy.maximum_length, policy.maximum_bytes) == (15, 128, 1_024)
    assert all(policy.check(password).accepted for password in accepted)
    assert policy.check("sufficiently long candidate", normalized_identifier="another@example.com").accepted
    assert accounts_module.normalize_identifier("  Usér@EXAMPLE.COM  ") == "usér@example.com"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"minimum_length": 0},
        {"minimum_length": True},
        {"maximum_length": 14},
        {"maximum_bytes": 0},
        {"maximum_bytes": 1_025},
        {"normalizer": None},
        {"compromised": object()},
    ],
)
def test_password_policy_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Password policy"):
        accounts_module.PasswordPolicy(**kwargs)  # type: ignore[arg-type]


def test_password_policy_skips_compromised_hook_for_invalid_candidates_and_validates_its_result() -> None:
    candidates: list[str] = []

    def compromised(candidate: str) -> object:
        candidates.append(candidate)
        return object()

    policy = accounts_module.PasswordPolicy(compromised=compromised)  # type: ignore[arg-type]

    assert policy.check("short").violations == frozenset({accounts_module.PasswordPolicyViolation.TOO_SHORT})
    assert candidates == []
    with pytest.raises(ImproperlyConfiguredException, match="must return bool"):
        policy.check("sufficiently long candidate")
    assert candidates == ["sufficiently long candidate"]
    assert (
        accounts_module
        .PasswordPolicy(compromised=lambda _candidate: False)
        .check("sufficiently long candidate")
        .accepted
    )


def test_password_policy_handles_invalid_runtime_text_and_normalizer_failures() -> None:
    invalid_text = accounts_module.PasswordPolicy().check(object())  # type: ignore[arg-type]
    invalid_normalizer = accounts_module.PasswordPolicy(
        normalizer=lambda _value: (_ for _ in ()).throw(ValueError)
    ).check("sufficiently long candidate", normalized_identifier="user@example.com")

    assert invalid_text.violations == frozenset({accounts_module.PasswordPolicyViolation.INVALID_TEXT})
    assert invalid_normalizer.violations == frozenset({accounts_module.PasswordPolicyViolation.INVALID_TEXT})
    with pytest.raises(ValueError, match="requires text"):
        accounts_module.normalize_identifier(object())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("status", "replacement_hash"),
    [
        (accounts_module.PasswordVerificationStatus.VERIFIED, None),
        (accounts_module.PasswordVerificationStatus.VERIFIED, "replacement-secret"),
        (accounts_module.PasswordVerificationStatus.INVALID, None),
        (accounts_module.PasswordVerificationStatus.MALFORMED, None),
        (accounts_module.PasswordVerificationStatus.TOO_LONG, None),
    ],
)
def test_password_verification_results_are_discriminated_and_redacted(
    status: "accounts_module.PasswordVerificationStatus", replacement_hash: str | None
) -> None:
    result = accounts_module.PasswordVerificationResult(status=status, replacement_hash=replacement_hash)

    assert result.verified is (status is accounts_module.PasswordVerificationStatus.VERIFIED)
    assert "replacement-secret" not in repr(result)
    assert not hasattr(result, "__dict__")


def test_password_verification_result_rejects_replacement_for_failure() -> None:
    with pytest.raises(ValueError, match="replacement"):
        accounts_module.PasswordVerificationResult(
            status=accounts_module.PasswordVerificationStatus.INVALID, replacement_hash="replacement-secret"
        )


def test_security_config_is_typed_and_slotted() -> None:
    config = litestar_security.SecurityConfig()

    expected_fields = (
        "slots",
        "mechanisms",
        "default_policy",
        "openapi_policy",
        "max_openapi_combinations",
        "csrf_config",
        "external_csrf",
        "require_default",
        "session_backend",
        "local_auth",
        "local_jwks",
        "jwks_providers",
        "jwks_warmup_failure",
    )
    assert tuple(field.name for field in fields(config)) == expected_fields
    assert config.__slots__ == expected_fields
    assert not hasattr(config, "__dict__")


def test_security_config_rejects_invalid_jwks_warmup_failure_mode() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="JWKS warmup failure mode"):
        litestar_security.SecurityConfig(jwks_warmup_failure="invalid")  # type: ignore[arg-type]


def test_root_import_has_no_optional_integration_dependencies() -> None:
    script = """
import sys
import litestar_security

for module_name in sys.modules:
    if module_name.startswith("litestar_security.providers") or module_name.split(".", maxsplit=1)[0] in {
        "advanced_alchemy", "authlib", "cryptography", "jwt", "redis", "sqlalchemy", "sqlspec"
    }:
        print(module_name)
"""
    result = run([sys.executable, "-c", script], check=True, capture_output=True, text=True)  # noqa: S603

    assert not result.stdout
