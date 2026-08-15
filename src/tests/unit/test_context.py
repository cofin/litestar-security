"""Unit tests for public context, session, and package contracts."""

import sys
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from importlib import import_module
from importlib.metadata import requires
from json import loads
from subprocess import run
from typing import ClassVar, get_type_hints

import pytest
from litestar import Controller
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException

import litestar_security
import litestar_security._lazy as lazy_module
import litestar_security._openapi as openapi_module
import litestar_security._typing as typing_module
import litestar_security.authentication as authentication_module
import litestar_security.typing as public_typing
from litestar_security import CSRF_REQUIRED_OPT_KEY, PublicController, SecureController, exclude
from litestar_security.accounts._mfa import StepUpCredential
from litestar_security.authentication import public, required
from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    CredentialRestrictions,
    LitestarSessionHandle,
    NullSessionHandle,
    Principal,
    ResourcePermission,
    SecurityContext,
    SessionHandle,
    SessionPersistenceUnavailableError,
    SessionUnavailableError,
)
from litestar_security.testing import StaticAuthorizationSnapshotRefresher


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


def test_typing_public_surface_reexports_the_private_implementation() -> None:
    assert public_typing.__all__ == typing_module.__all__
    assert all(getattr(public_typing, name) is getattr(typing_module, name) for name in public_typing.__all__)


@pytest.mark.parametrize(("package", "install_package"), [("jwt", None), ("custom", "custom-dist"), ("plain", None)])
def test_missing_dependency_error_names_the_actionable_distribution(package: str, install_package: str | None) -> None:
    error = typing_module.MissingDependencyError(package, install_package)
    target = install_package or {"jwt": "PyJWT"}.get(package, package)

    assert str(error) == (
        f"Package {package!r} is not installed but is required for this feature. "
        f"Install it with 'pip install litestar-security[{target}]' or 'pip install {target}'."
    )


def test_optional_dependency_resolution_is_cached_and_resettable(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = object()
    find_calls: list[str] = []
    import_calls: list[str] = []

    def find(module_name: str) -> object | None:
        find_calls.append(module_name)
        if module_name == "invalid.parent.child":
            raise ImportError
        if module_name == "missing.__path__":
            raise ValueError
        return sentinel if module_name == "available" else None

    def load(module_name: str) -> object:
        import_calls.append(module_name)
        if module_name == "missing":
            raise ImportError
        return sentinel

    typing_module.reset_dependency_cache()
    monkeypatch.setattr(typing_module, "find_spec", find)
    monkeypatch.setattr(typing_module, "import_module", load)

    assert typing_module.module_available("available")
    assert typing_module.module_available("available")
    assert not typing_module.module_available("absent")
    assert not typing_module.module_available("invalid.parent.child")
    assert not typing_module.module_available("missing.__path__")
    assert find_calls == ["available", "absent", "invalid.parent.child", "missing.__path__"]

    assert typing_module.import_optional("available") is sentinel
    assert typing_module.import_optional("available") is sentinel
    assert typing_module.import_optional("missing") is None
    assert typing_module.import_optional("missing") is None
    assert import_calls == ["available", "missing"]

    typing_module.reset_dependency_cache("available")
    assert typing_module.module_available("available")
    assert typing_module.import_optional("available") is sentinel
    assert find_calls.count("available") == 2
    assert import_calls.count("available") == 2
    typing_module.reset_dependency_cache()


def test_optional_dependency_attributes_and_requirement(monkeypatch: pytest.MonkeyPatch) -> None:
    class Module:
        exported = object()

    module = Module()
    fallback = object()
    monkeypatch.setattr(
        typing_module, "import_optional", lambda module_name: None if module_name == "missing" else module
    )

    assert typing_module.import_optional_attr("available", "exported") is module.exported
    assert typing_module.import_optional_attr("available", "absent") is None
    assert typing_module.import_optional_attr("missing", "exported") is None
    assert typing_module.resolve_optional_attr("missing", "exported", fallback) is fallback
    assert typing_module.resolve_optional_attr("available", None, fallback) is module
    assert typing_module.resolve_optional_attr("available", "absent", fallback) is fallback
    assert typing_module.resolve_optional_attr("available", "exported", fallback) is module.exported
    assert typing_module.require_dependency("available") is module

    with pytest.raises(typing_module.MissingDependencyError, match="custom-dist"):
        typing_module.require_dependency("missing", "custom-dist")


def test_optional_dependency_flag_resolves_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    available = True
    calls: list[str] = []

    def module_available(module_name: str) -> bool:
        calls.append(module_name)
        return available

    monkeypatch.setattr(typing_module, "module_available", module_available)
    flag = typing_module.dependency_flag("feature")

    assert bool(flag)
    assert repr(flag) == "OptionalDependencyFlag(module='feature', status='available')"
    available = False
    assert not flag
    assert repr(flag) == "OptionalDependencyFlag(module='feature', status='missing')"
    assert calls == ["feature", "feature", "feature", "feature"]


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


async def test_static_authorization_snapshot_refresher_returns_its_immutable_snapshot() -> None:
    previous = AuthorizationSnapshot(attributes={"previous": "value"})
    snapshot = AuthorizationSnapshot(scopes={"reports:read"}, attributes={"source": "static"})

    refreshed = await StaticAuthorizationSnapshotRefresher(snapshot).refresh(
        principal=Principal(id="user-1"), previous=previous, route_name="reports.socket"
    )

    assert refreshed is snapshot
    assert previous.attributes == {"previous": "value"}
    with pytest.raises(TypeError):
        refreshed.attributes["mutated"] = True  # type: ignore[index]


def test_credential_restrictions_normalize_sets_and_preserve_empty() -> None:
    restrictions = CredentialRestrictions(
        scopes={" read "}, roles=frozenset(), capabilities=None, team_ids={" team-1 "}, tenant_ids={"tenant-1"}
    )

    assert restrictions.scopes == frozenset({"read"})
    assert restrictions.roles == frozenset()
    assert restrictions.capabilities is None
    assert restrictions.team_ids == frozenset({"team-1"})
    assert restrictions.tenant_ids == frozenset({"tenant-1"})


def test_resource_permission_is_immutable_and_normalized() -> None:
    permission = ResourcePermission(resource=" report-1 ", scopes={" read "})

    assert permission == ResourcePermission(resource="report-1", scopes=frozenset({"read"}))
    with pytest.raises(ValueError, match="must not be blank"):
        ResourcePermission(resource="", scopes=frozenset())
    with pytest.raises(ValueError, match="must not be blank"):
        ResourcePermission(resource="report-1", scopes={""})


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
    original_session = dict(scope["session"])  # type: ignore[arg-type]

    assert handle.is_available
    assert not handle.can_persist
    assert handle.get("existing") == "value"
    for mutation in (lambda: handle.set("key", "value"), lambda: handle.pop("existing"), handle.clear):
        with pytest.raises(SessionPersistenceUnavailableError, match="cannot persist"):
            mutation()
        assert scope["session"] == original_session


def test_package_root_exports_its_foundational_contract() -> None:
    assert litestar_security.__project__ == "litestar-security"
    assert CSRF_REQUIRED_OPT_KEY == "csrf_required"
    assert exclude() == authentication_module.exclude()
    assert "CSRF_REQUIRED_OPT_KEY" in authentication_module.__all__
    assert openapi_module.__all__ == ()


def test_typed_controllers_compile_auth_at_class_definition_time() -> None:
    """Typed controllers preserve native opt layering without constructing an app."""

    class Basic(SecureController):
        pass

    class WithExtraOpt(SecureController):
        opt: ClassVar = {"csrf_required": True}  # type: ignore[misc]

    class Grandchild(SecureController):
        auth: ClassVar = required("bearer")

    class Inherited(Grandchild):
        pass

    class Redeclared(Grandchild):
        auth: ClassVar = required("session")

    assert Basic.opt == {"auth": SecureController.auth}
    assert WithExtraOpt.opt == {"csrf_required": True, "auth": SecureController.auth}
    assert Inherited.opt == {"auth": required("bearer")}
    assert Redeclared.opt == {"auth": required("session")}
    assert PublicController.opt == {"auth": public()}


def test_typed_controllers_reject_own_explicit_opt_auth() -> None:
    """An own ``opt['auth']`` is ambiguous with the typed class attribute."""

    with pytest.raises(ImproperlyConfiguredException, match="declares both"):

        class WithExplicitOpt(SecureController):
            opt: ClassVar = {"auth": required("bearer")}  # type: ignore[misc]

    with pytest.raises(ImproperlyConfiguredException, match="declares both"):

        class WithBoth(SecureController):
            auth: ClassVar = required("session")
            opt: ClassVar = {"auth": required("bearer")}  # type: ignore[misc]


def test_plain_controller_auth_attribute_remains_inert() -> None:
    """The helper must not alter ordinary Litestar controller class behavior."""

    class Plain(Controller):
        auth: ClassVar = authentication_module.required("bearer")

    assert "opt" not in Plain.__dict__
    assert Plain.auth == authentication_module.required("bearer")


def test_provider_package_declares_crypto_dependency_without_duplicates() -> None:
    declared = tuple(requirement.lower().replace(" ", "") for requirement in requires("litestar-security") or ())

    assert any(requirement.startswith("pyjwt[crypto]") and ">=2.13" in requirement for requirement in declared)
    httpx_requirements = tuple(requirement for requirement in declared if requirement.startswith("httpx"))
    assert httpx_requirements == ("httpx>=0.28.1",)
    assert all(not requirement.startswith("cryptography") for requirement in declared)
    for dependency in ("cryptography", "jwt"):
        assert import_module(dependency)

    providers = import_module("litestar_security.providers")
    jwt_module = import_module("litestar_security.providers.jwt")
    capability_module = import_module("litestar_security.providers.jwt._capabilities")

    assert "VerifiedCapability" in jwt_module.__all__
    assert providers.VerifiedCapability is jwt_module.VerifiedCapability is capability_module.VerifiedCapability


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


def test_oauth_boundary_keeps_provider_tree_unloaded_until_requested() -> None:
    script = """
import sys

import litestar_security
import litestar_security.accounts

assert not any(module_name.startswith("litestar_security.providers.oauth") for module_name in sys.modules)
"""
    result = run([sys.executable, "-c", script], check=False, capture_output=True, text=True)  # noqa: S603

    assert result.returncode == 0, result.stderr


def test_lazy_extra_exports_preserve_eager_export_identity() -> None:
    script = """
from importlib import import_module

import litestar_security
import litestar_security.accounts as accounts

for name in litestar_security.__all__:
    resolved = getattr(litestar_security, name)
    eager = (
        getattr(import_module("litestar_security.providers"), name)
        if name in litestar_security._OAUTH_EXPORTS
        else litestar_security.__dict__[name]
    )
    assert resolved is eager, name

for name in accounts.__all__:
    resolved = getattr(accounts, name)
    target = accounts._OPTIONAL_EXPORTS.get(name)
    eager = (
        getattr(import_module(target[0]), name)
        if target is not None
        else getattr(import_module("litestar_security.accounts.controllers"), name)
        if name in accounts._CONTROLLER_EXPORTS
        else accounts.__dict__[name]
    )
    assert resolved is eager, name
"""
    result = run([sys.executable, "-c", script], check=False, capture_output=True, text=True)  # noqa: S603

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("module_name", "name", "target_module"),
    [
        ("litestar_security.accounts.controllers", "LOCAL_AUTH_TAGS", "litestar_security.accounts.controllers._local"),
        ("litestar_security.accounts.controllers", "build_mfa_routes", "litestar_security.accounts.controllers._mfa"),
        ("litestar_security.providers", "OAuthConfig", "litestar_security.providers.oauth"),
        ("litestar_security.providers", "OIDCMetadata", "litestar_security.providers.oidc"),
    ],
)
def test_lazy_export_packages_resolve_optional_attributes(module_name: str, name: str, target_module: str) -> None:
    module = import_module(module_name)

    assert getattr(module, name) is getattr(import_module(target_module), name)


@pytest.mark.parametrize("module_name", ["litestar_security.accounts.controllers", "litestar_security.providers"])
def test_lazy_export_packages_reject_unknown_attributes(module_name: str) -> None:
    module = import_module(module_name)

    with pytest.raises(AttributeError, match="has no attribute 'missing'"):
        module.__getattr__("missing")


@pytest.mark.parametrize(
    ("missing_dependency", "dependencies", "expected_exception"),
    [
        ("optional_dependency", frozenset({"optional_dependency"}), ImportError),
        ("unrelated_dependency", frozenset({"optional_dependency"}), ModuleNotFoundError),
    ],
)
def test_import_optional_attribute_only_translates_declared_missing_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    missing_dependency: str,
    dependencies: frozenset[str],
    expected_exception: type[Exception],
) -> None:
    def raise_missing_module(_module_name: str) -> None:
        raise ModuleNotFoundError(name=missing_dependency)

    monkeypatch.setattr(lazy_module, "import_module", raise_missing_module)

    with pytest.raises(expected_exception) as error:
        lazy_module.import_optional_attribute("feature.module", "export", extras="feature", dependencies=dependencies)

    if expected_exception is ImportError:
        expected_message = (
            "litestar-security feature requires the [feature] extra: pip install 'litestar-security[feature]'"
        )
        assert str(error.value) == expected_message


@pytest.mark.parametrize("blocked_dependency", ["pyotp", "webauthn", "argon2"])
def test_accounts_lazy_extra_exports_isolate_missing_dependencies(blocked_dependency: str) -> None:
    script = f"""
import sys
from importlib import import_module

sys.modules[{blocked_dependency!r}] = None
import litestar_security.accounts as accounts

assert accounts.RateLimiter
for name in accounts.__all__:
    target = accounts._OPTIONAL_EXPORTS.get(name)
    if target is None and name in accounts._CONTROLLER_EXPORTS:
        target = (
            ("litestar_security.accounts.controllers", "argon2,mfa", frozenset({{"argon2", "pyotp"}}))
            if name != "build_mfa_routes"
            else (
                "litestar_security.accounts.controllers",
                "argon2,mfa,passkeys",
                frozenset({{"argon2", "pyotp", "webauthn"}}),
            )
        )
    if target is None or {blocked_dependency!r} not in target[2]:
        getattr(accounts, name)
        continue
    try:
        getattr(accounts, name)
    except ImportError as error:
        expected = (
            f"litestar-security feature requires the [{{target[1]}}] extra: "
            f"pip install 'litestar-security[{{target[1]}}]'"
        )
        assert str(error) == expected, (name, str(error))
    else:
        raise AssertionError(f"expected an actionable optional-extra ImportError for {{name}}")

controllers = import_module("litestar_security.accounts.controllers")
for name in controllers.__all__:
    target = (
        ("argon2,mfa", frozenset({{"argon2", "pyotp"}}))
        if name in controllers._LOCAL_EXPORTS
        else ("argon2,mfa,passkeys", frozenset({{"argon2", "pyotp", "webauthn"}}))
    )
    if {blocked_dependency!r} not in target[1]:
        getattr(controllers, name)
        continue
    try:
        getattr(controllers, name)
    except ImportError as error:
        expected = (
            f"litestar-security feature requires the [{{target[0]}}] extra: "
            f"pip install 'litestar-security[{{target[0]}}]'"
        )
        assert str(error) == expected, (name, str(error))
    else:
        raise AssertionError(f"expected an actionable optional-extra ImportError for {{name}}")
"""

    result = run([sys.executable, "-c", script], check=False, capture_output=True, text=True)  # noqa: S603

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("blocked_dependency", ["pyotp", "webauthn", "cbor2", "argon2"])
def test_testing_module_isolates_missing_optional_dependencies(blocked_dependency: str) -> None:
    script = f"""
import sys
sys.modules[{blocked_dependency!r}] = None

import litestar_security.testing as testing
from litestar_security.testing import InMemoryLocalAccountStore, InMemorySecurityBackend

backend = InMemorySecurityBackend()
assert backend.accounts is not None
assert testing.assert_session_registry_conformance is not None
"""
    result = run([sys.executable, "-c", script], check=False, capture_output=True, text=True)  # noqa: S603
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("blocked_dependency", ["pyotp", "webauthn"])
def test_oauth_routes_isolate_missing_optional_dependencies(blocked_dependency: str) -> None:
    script = f"""
import sys
sys.modules[{blocked_dependency!r}] = None

import litestar_security.providers.oauth._routes as oauth_routes

assert oauth_routes.OAuthAuthorization is not None
"""
    result = run([sys.executable, "-c", script], check=False, capture_output=True, text=True)  # noqa: S603
    assert result.returncode == 0, result.stderr


def test_pyotp_absent_step_up_credential_mirror_matches_the_canonical_struct() -> None:
    script = """
import json
import sys
from typing import get_type_hints

sys.modules["pyotp"] = None

import litestar_security.providers.oauth._routes as oauth_routes

fields = [(name, str(kind)) for name, kind in get_type_hints(oauth_routes.StepUpCredential).items()]
print(json.dumps(fields))
"""
    result = run([sys.executable, "-c", script], check=False, capture_output=True, text=True)  # noqa: S603
    assert result.returncode == 0, result.stderr
    fallback_fields = [tuple(field) for field in loads(result.stdout)]
    canonical_fields = [(name, str(kind)) for name, kind in get_type_hints(StepUpCredential).items()]
    assert fallback_fields == canonical_fields, (
        "the pyotp-absent StepUpCredential mirror must match the canonical wire struct field-for-field"
    )
