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
    require_all_of,
    require_any_of,
    require_assurance,
    require_at_least,
    require_authenticated,
    require_capability,
    require_one_of,
    require_role,
    require_scope,
    require_team_role,
    require_tenant,
)

_DUPLICATE_GUARD = require_authenticated()


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
    predicate = require_assurance(
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
    predicate = require_assurance(
        methods={"password"},
        max_age=timedelta(minutes=5),
        purpose=purpose,
        clock=lambda: datetime(2026, 7, 27, 12, tzinfo=timezone.utc),
    )

    assert predicate.decide(connection).code == code  # type: ignore[arg-type]


def test_assurance_rejects_expired_evidence_without_max_age() -> None:
    """Expired evidence cannot satisfy a bare assurance requirement."""
    now = datetime(2026, 7, 27, 12, tzinfo=timezone.utc)
    predicate = require_assurance(methods={"totp"}, clock=lambda: now)
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
        require_assurance(clock=lambda: datetime(2026, 7, 27, 12)).decide(  # noqa: DTZ001
            _guard_connection()  # type: ignore[arg-type]
        )
    with pytest.raises(ImproperlyConfiguredException, match="max_age must be positive"):
        AssuranceRequirement(max_age=timedelta())
    with pytest.raises(ImproperlyConfiguredException, match="purpose must not be blank"):
        AssuranceRequirement(purpose=" ")
    for kwargs in ({"methods": cast("Any", {1})}, {"traits": cast("Any", {"unsupported"})}):
        with pytest.raises(ImproperlyConfiguredException, match="methods and traits"):
            AssuranceRequirement(**kwargs)

    predicate = require_assurance(max_age=timedelta(minutes=5), clock=lambda: now)
    assert require_assurance(clock=lambda: now).decide(_guard_connection()).granted  # type: ignore[arg-type]
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
    guard = require_scope("reports:read")

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
        guard = require_team_role(team_parameter="team_id", roles={"admin"})
    elif case == "team-missing-param":
        guard = require_team_role(team_parameter="missing", roles={"owner"})
    elif case == "team-forged-param":
        guard = require_team_role(team_parameter="team_id", roles={"owner"})
        path_params["team_id"] = "team-2"
    elif case == "tenant-mismatch":
        guard = require_tenant(tenant_parameter="tenant_id")
        path_params["tenant_id"] = "tenant-2"
    elif case == "tenant-missing-param":
        guard = require_tenant(tenant_parameter="missing")
    else:
        guard = {
            "authenticated": require_authenticated(),
            "scope": require_scope("reports:read"),
            "role": require_role("admin"),
            "capability": require_capability("reports.export"),
            "team": require_team_role(team_parameter="team_id", roles={"owner", "admin"}),
            "tenant": require_tenant(tenant_parameter="tenant_id"),
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
        require_authenticated(),
        require_scope("reports:read"),
        require_role("admin"),
        require_capability("reports.export"),
        require_team_role(team_parameter="team_id", roles={"owner"}),
        require_tenant(tenant_parameter="tenant_id"),
        require_any_of(require_scope("reports:read"), require_role("admin")),
    ],
)
def test_authorization_base_guards_map_anonymous_denial_to_generic_401(guard: object) -> None:
    with pytest.raises(NotAuthorizedException, match="Authentication required") as exc_info:
        guard(_guard_connection(authenticated=False), object())  # type: ignore[operator]

    assert exc_info.value.detail == "Authentication required"


@pytest.mark.parametrize(
    ("operator", "mask", "allowed"),
    [(require_all_of, mask, mask == 0b111) for mask in range(8)]
    + [(require_any_of, mask, mask != 0) for mask in range(8)]
    + [(require_one_of, mask, mask.bit_count() == 1) for mask in range(8)]
    + [(lambda *children: require_at_least(2, *children), mask, mask.bit_count() >= 2) for mask in range(8)],
)
def test_authorization_combinator_truth_tables(
    operator: object,
    mask: int,
    allowed: bool,  # noqa: FBT001
) -> None:
    guards = (require_scope("a"), require_scope("b"), require_scope("c"))
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
        (require_all_of, "at least one"),
        (require_any_of, "at least one"),
        (require_one_of, "at least one"),
        (partial(require_at_least, 0, require_authenticated()), "between 1 and 1"),
        (partial(require_at_least, 2, require_authenticated()), "between 1 and 1"),
        (partial(require_all_of, _DUPLICATE_GUARD, _DUPLICATE_GUARD), "duplicate child"),
        (partial(require_scope, " "), "must not be blank"),
        (partial(require_team_role, team_parameter="team_id", roles=set()), "at least one role"),
    ],
)
def test_authorization_guard_construction_rejects_invalid_expressions(factory: object, match: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match=match):
        factory()  # type: ignore[operator]


def test_authorization_guards_are_frozen_hashable_and_expose_stable_denial() -> None:
    guard = require_all_of(require_scope("reports:read"), require_role("admin"))
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

    require_scope("reports:read")(connection, object())  # type: ignore[arg-type]

    assert calls == 0


def test_require_guard_exports_and_clean_break() -> None:
    """Verify require_* combinators and predicates are exported from top-level and guard_*/requires_* are removed."""
    assert litestar_security.require_all_of is require_all_of
    assert litestar_security.require_any_of is require_any_of
    assert litestar_security.require_at_least is require_at_least
    assert litestar_security.require_one_of is require_one_of
    assert litestar_security.require_authenticated is require_authenticated
    assert litestar_security.require_assurance is require_assurance
    assert litestar_security.require_scope is require_scope
    assert litestar_security.require_role is require_role
    assert litestar_security.require_capability is require_capability
    assert litestar_security.require_team_role is require_team_role
    assert litestar_security.require_tenant is require_tenant

    for name in ("require_all_of", "require_any_of", "require_at_least", "require_one_of"):
        assert getattr(guards_module, name).__name__ == name

    for name in ("all_of", "any_of", "at_least", "one_of"):
        assert not hasattr(guards_module, name)
        assert name not in guards_module.__all__

    for name in (
        "guard_all_of",
        "guard_any_of",
        "guard_at_least",
        "guard_one_of",
        "requires_authenticated",
        "requires_assurance",
        "requires_scope",
        "requires_role",
        "requires_capability",
        "requires_team_role",
        "requires_tenant",
    ):
        assert not hasattr(litestar_security, name)
        assert name not in litestar_security.__all__
        assert not hasattr(guards_module, name)
        assert name not in guards_module.__all__
