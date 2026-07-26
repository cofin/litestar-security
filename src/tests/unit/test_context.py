"""Unit tests for public context, session, and package contracts."""

import sys
from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone
from functools import partial
from types import SimpleNamespace

import pytest
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException, PermissionDeniedException

import litestar_security
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

_DUPLICATE_GUARD = requires_authenticated()
_PUBLIC_API = (
    "Authenticated",
    "AuthenticationEvidence",
    "AuthenticationMechanism",
    "AuthenticationOutcome",
    "AuthenticationRegistry",
    "AuthorizationSnapshot",
    "CredentialExtraction",
    "CredentialRestrictions",
    "CredentialSlot",
    "CurrentUser",
    "IdentityResolver",
    "InvalidCredentials",
    "LitestarSessionHandle",
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


def _guard_connection(
    *,
    authenticated: bool = True,
    authorization: AuthorizationSnapshot | None = None,
    path_params: dict[str, object] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        user=Principal[object](id="user-1") if authenticated else Principal[object].anonymous(),
        auth=SecurityContext(session=NullSessionHandle(), authorization=authorization or AuthorizationSnapshot()),
        path_params=path_params or {},
    )


def test_principal_supports_anonymous_user_and_service_states() -> None:
    user = object()

    anonymous = Principal[object].anonymous()
    application_user = Principal(id="user-1", display_name="User One", user=user)
    service = Principal[object](id="service-1", display_name="Worker")

    assert (anonymous.id, anonymous.is_authenticated, anonymous.has_user) == (None, False, False)
    assert (application_user.id, application_user.is_authenticated, application_user.has_user) == ("user-1", True, True)
    assert (service.id, service.is_authenticated, service.has_user) == ("service-1", True, False)


def test_principal_require_user_preserves_identity_and_fails_generically() -> None:
    user = object()

    assert Principal(id="user-1", user=user).require_user() is user
    for principal in (Principal[object].anonymous(), Principal[object](id="service-1")):
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
    principal = Principal[object](id="user-1")

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


def test_security_config_is_typed_and_slotted() -> None:
    config = litestar_security.SecurityConfig()

    expected_fields = (
        "slots",
        "mechanisms",
        "default_policy",
        "openapi_policy",
        "require_default",
        "session_backend",
        "plan_lookup",
    )
    assert tuple(field.name for field in fields(config)) == expected_fields
    assert config.__slots__ == expected_fields
    assert not hasattr(config, "__dict__")


def test_root_import_has_no_optional_integration_dependencies() -> None:
    forbidden_roots = {"advanced_alchemy", "authlib", "cryptography", "jwt", "redis", "sqlalchemy", "sqlspec"}

    assert not {module_name for module_name in sys.modules if module_name.split(".", maxsplit=1)[0] in forbidden_roots}
    assert not any(module_name.startswith("litestar_security.providers") for module_name in sys.modules)
