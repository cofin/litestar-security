"""Unit tests for authorization guards and assurance requirements."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from functools import partial
from types import SimpleNamespace
from typing import Any, cast

import pytest
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException, PermissionDeniedException

import litestar_security
import litestar_security.guards as guards_module
from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    NullSessionHandle,
    Principal,
    SecurityContext,
)
from litestar_security.guards import (
    AssuranceRequirement,
    AssuranceTrait,
    requires_all_of,
    requires_any_of,
    requires_assurance,
    requires_at_least,
    requires_authenticated,
    requires_capability,
    requires_one_of,
    requires_role,
    requires_scope,
    requires_tenant,
    requires_tenant_role,
)

_DUPLICATE_GUARD = requires_authenticated()


def _guard_connection(
    *,
    authenticated: bool = True,
    authorization: AuthorizationSnapshot | None = None,
    evidence: tuple[AuthenticationEvidence, ...] = (),
    path_params: dict[str, object] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        user=Principal(id="user-1") if authenticated else Principal.anonymous(),
        auth=SecurityContext(
            session=NullSessionHandle(), evidence=evidence, authorization=authorization or AuthorizationSnapshot()
        ),
        path_params=path_params or {},
    )


def test_assurance_requires_distinct_method_and_trait_evidence_at_the_freshness_boundary() -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    connection = _guard_connection(
        evidence=(
            AuthenticationEvidence(
                mechanism="local",
                slot="session",
                authenticated_at=now - timedelta(minutes=5),
                methods=frozenset({"password"}),
            ),
            AuthenticationEvidence(
                mechanism="totp",
                slot="mfa",
                authenticated_at=now - timedelta(minutes=5),
                methods=frozenset({"totp"}),
                traits=frozenset({AssuranceTrait.USER_VERIFIED}),
            ),
        )
    )
    predicate = requires_assurance(
        methods={"password", "totp"},
        traits={AssuranceTrait.USER_VERIFIED},
        max_age=timedelta(minutes=5),
        clock=lambda: now,
    )

    assert predicate.decide(connection).granted  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("evidence", "purpose", "code"),
    [
        (
            AuthenticationEvidence(
                mechanism="oidc",
                slot="authorization.bearer",
                authenticated_at=datetime(2026, 7, 27, 11, 54, 59, tzinfo=timezone.utc),
                methods=frozenset({"password", "totp"}),
            ),
            None,
            "assurance_too_old",
        ),
        (
            AuthenticationEvidence(
                mechanism="oidc",
                slot="authorization.bearer",
                authenticated_at=datetime(2026, 7, 27, 12, tzinfo=timezone.utc),
                acr="urn:example:aal2",
                amr=("pwd", "otp"),
            ),
            None,
            "missing_assurance",
        ),
        (
            AuthenticationEvidence(
                mechanism="step-up",
                slot="session",
                authenticated_at=datetime(2026, 7, 27, 12, tzinfo=timezone.utc),
                methods=frozenset({"password"}),
                traits=frozenset({"purpose:password-change"}),
            ),
            "provider-unlink",
            "assurance_purpose_mismatch",
        ),
    ],
)
def test_assurance_rejects_stale_raw_provider_or_wrong_purpose_evidence(
    evidence: AuthenticationEvidence, purpose: str | None, code: str
) -> None:
    connection = _guard_connection(evidence=(evidence,))
    predicate = requires_assurance(
        methods={"password"},
        max_age=timedelta(minutes=5),
        purpose=purpose,
        clock=lambda: datetime(2026, 7, 27, 12, tzinfo=timezone.utc),
    )

    assert predicate.decide(connection).code == code  # type: ignore[arg-type]


def test_assurance_rejects_expired_evidence_without_max_age() -> None:
    """Expired evidence cannot satisfy a bare assurance requirement."""
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    predicate = requires_assurance(methods={"totp"}, clock=lambda: now)
    expired = AuthenticationEvidence(
        mechanism="totp",
        slot="mfa",
        authenticated_at=now - timedelta(minutes=6),
        expires_at=now - timedelta(minutes=1),
        methods=frozenset({"totp"}),
    )
    live = AuthenticationEvidence(
        mechanism="totp",
        slot="mfa",
        authenticated_at=now - timedelta(minutes=4),
        expires_at=now + timedelta(minutes=1),
        methods=frozenset({"totp"}),
    )

    assert predicate.decide(_guard_connection(evidence=(expired,))).code == "missing_assurance"  # type: ignore[arg-type]
    assert predicate.decide(_guard_connection(evidence=(live,))).granted  # type: ignore[arg-type]


def test_assurance_contract_validates_utc_clock_and_requirement_values() -> None:
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    with pytest.raises(ImproperlyConfiguredException, match="clock must return a timezone-aware"):
        requires_assurance(clock=lambda: datetime(2026, 7, 27, 12)).decide(  # noqa: DTZ001
            _guard_connection()  # type: ignore[arg-type]
        )
    with pytest.raises(ImproperlyConfiguredException, match="max_age must be positive"):
        AssuranceRequirement(max_age=timedelta())
    with pytest.raises(ImproperlyConfiguredException, match="purpose must not be blank"):
        AssuranceRequirement(purpose=" ")
    for kwargs in ({"methods": cast("Any", {1})}, {"traits": cast("Any", {"unsupported"})}):
        with pytest.raises(ImproperlyConfiguredException, match="methods and traits"):
            AssuranceRequirement(**kwargs)

    predicate = requires_assurance(max_age=timedelta(minutes=5), clock=lambda: now)
    assert requires_assurance(clock=lambda: now).decide(_guard_connection()).granted  # type: ignore[arg-type]
    assert predicate.decide(_guard_connection(authenticated=False)).code == "authentication_required"  # type: ignore[arg-type]
    assert predicate.decide(  # type: ignore[arg-type]
        _guard_connection(
            evidence=(
                AuthenticationEvidence(
                    mechanism="local", slot="session", authenticated_at=now, expires_at=now + timedelta(minutes=1)
                ),
            )
        )
    ).granted
    for evidence in (
        AuthenticationEvidence(mechanism="local", slot="session", authenticated_at=now + timedelta(seconds=1)),
        AuthenticationEvidence(mechanism="local", slot="session", authenticated_at=now, expires_at=now),
    ):
        assert predicate.decide(_guard_connection(evidence=(evidence,))).code == "assurance_too_old"  # type: ignore[arg-type]


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
        ("tenant_role", True),
        ("tenant-role-mismatch", False),
        ("tenant-role-missing-param", False),
        ("tenant-role-forged-param", False),
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
        tenant_roles={"tenant-1": {"owner"}},
        tenant_ids={"tenant-1"},
    )
    path_params: dict[str, object] = {"tenant_id": "tenant-1"}
    if case == "tenant-role-mismatch":
        guard = requires_tenant_role(tenant_parameter="tenant_id", roles={"admin"})
    elif case == "tenant-role-missing-param":
        guard = requires_tenant_role(tenant_parameter="missing", roles={"owner"})
    elif case == "tenant-role-forged-param":
        guard = requires_tenant_role(tenant_parameter="tenant_id", roles={"owner"})
        path_params["tenant_id"] = "tenant-2"
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
            "tenant_role": requires_tenant_role(tenant_parameter="tenant_id", roles={"owner", "admin internal"}),
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
        requires_tenant_role(tenant_parameter="tenant_id", roles={"owner"}),
        requires_tenant(tenant_parameter="tenant_id"),
        requires_any_of(requires_scope("reports:read"), requires_role("admin")),
    ],
)
def test_authorization_base_guards_map_anonymous_denial_to_generic_401(guard: object) -> None:
    with pytest.raises(NotAuthorizedException, match="Authentication required") as exc_info:
        guard(_guard_connection(authenticated=False), object())  # type: ignore[operator]

    assert exc_info.value.detail == "Authentication required"


@pytest.mark.parametrize(
    ("operator", "mask", "allowed"),
    [(requires_all_of, mask, mask == 0b111) for mask in range(8)]
    + [(requires_any_of, mask, mask != 0) for mask in range(8)]
    + [(requires_one_of, mask, mask.bit_count() == 1) for mask in range(8)]
    + [(lambda *children: requires_at_least(2, *children), mask, mask.bit_count() >= 2) for mask in range(8)],
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
        (requires_all_of, "at least one"),
        (requires_any_of, "at least one"),
        (requires_one_of, "at least one"),
        (partial(requires_at_least, 0, requires_authenticated()), "between 1 and 1"),
        (partial(requires_at_least, 2, requires_authenticated()), "between 1 and 1"),
        (partial(requires_all_of, _DUPLICATE_GUARD, _DUPLICATE_GUARD), "duplicate child"),
        (partial(requires_scope, " "), "must not be blank"),
        (partial(requires_tenant_role, tenant_parameter="tenant_id", roles=set()), "at least one role"),
    ],
)
def test_authorization_guard_construction_rejects_invalid_expressions(factory: object, match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        factory()  # type: ignore[operator]


def test_authorization_guards_are_frozen_hashable_and_expose_stable_denial() -> None:
    guard = requires_all_of(requires_scope("reports:read"), requires_role("admin"))
    connection = _guard_connection(authorization=AuthorizationSnapshot(scopes={"reports:read"}))

    decision = guard.decide(connection)

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


def test_requires_guard_exports_and_clean_break() -> None:
    """Verify requires_* guards are exported and the previous spellings are removed."""
    assert litestar_security.requires_all_of is requires_all_of
    assert litestar_security.requires_any_of is requires_any_of
    assert litestar_security.requires_at_least is requires_at_least
    assert litestar_security.requires_one_of is requires_one_of
    assert litestar_security.requires_authenticated is requires_authenticated
    assert litestar_security.requires_assurance is requires_assurance
    assert litestar_security.requires_scope is requires_scope
    assert litestar_security.requires_role is requires_role
    assert litestar_security.requires_capability is requires_capability
    assert litestar_security.requires_tenant is requires_tenant
    assert litestar_security.requires_tenant_role is requires_tenant_role

    for name in ("requires_all_of", "requires_any_of", "requires_at_least", "requires_one_of"):
        assert getattr(guards_module, name).__name__ == name

    for name in ("all_of", "any_of", "at_least", "one_of"):
        assert not hasattr(guards_module, name)
        assert name not in guards_module.__all__

    for name in (
        "guard_all_of",
        "guard_any_of",
        "guard_at_least",
        "guard_one_of",
        "require_authenticated",
        "require_assurance",
        "require_scope",
        "require_role",
        "require_capability",
        "require_team_role",
        "requires_team_role",
        "require_tenant",
        "require_all_of",
        "require_any_of",
        "require_at_least",
        "require_one_of",
    ):
        assert not hasattr(litestar_security, name)
        assert name not in litestar_security.__all__
        assert not hasattr(guards_module, name)
        assert name not in guards_module.__all__
