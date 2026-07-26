from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest
from litestar.exceptions import NotAuthorizedException

from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    CredentialRestrictions,
    Principal,
    SecurityContext,
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
