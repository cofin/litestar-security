from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

import pytest
from litestar.exceptions import NotAuthorizedException, ServiceUnavailableException

from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationRegistry,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    VerificationUnavailable,
)
from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    CredentialRestrictions,
    NullSessionHandle,
    Principal,
)

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection

    from litestar_security.authentication import _AuthenticationEvaluator

_CONNECTION = cast("ASGIConnection", object())
_NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)


class _Slot:
    def __init__(self, name: str, extraction: object, events: list[str]) -> None:
        self.name = name
        self.extraction = extraction
        self.events = events
        self.calls = 0

    def extract(self, _connection: object) -> object:
        self.calls += 1
        self.events.append(f"extract:{self.name}")
        return self.extraction


class _Authenticator:
    participates_by_default = True

    def __init__(self, name: str, slot: str, outcome: object, events: list[str]) -> None:
        self.name = name
        self.slot = slot
        self.outcome = outcome
        self.events = events
        self.calls = 0

    async def authenticate(self, _credential: str, _connection: object) -> object:
        self.calls += 1
        self.events.append(f"authenticate:{self.name}")
        return self.outcome


class _Resolver:
    def __init__(self, principal: Principal[object], name: str, events: list[str]) -> None:
        self.principal = principal
        self.name = name
        self.events = events
        self.calls = 0

    async def resolve(self, _claims: str) -> Principal[object]:
        self.calls += 1
        self.events.append(f"resolve:{self.name}")
        return self.principal


def _success(
    mechanism: str,
    slot: str,
    *,
    grants: AuthorizationSnapshot | None = None,
    restrictions: CredentialRestrictions | None = None,
) -> Authenticated[str]:
    return Authenticated(
        claims=mechanism,
        evidence=AuthenticationEvidence(mechanism=mechanism, slot=slot, authenticated_at=_NOW),
        grants=grants or AuthorizationSnapshot(),
        restrictions=restrictions or CredentialRestrictions(),
    )


def _evaluator(
    definitions: list[tuple[str, object, object, Principal[object]]],
    events: list[str],
) -> tuple[
    _AuthenticationEvaluator[object],
    list[_Slot],
    list[_Authenticator],
    list[_Resolver],
]:
    slots: list[_Slot] = []
    authenticators: list[_Authenticator] = []
    resolvers: list[_Resolver] = []
    mechanisms: list[AuthenticationMechanism[str, str, object]] = []
    for name, extraction, outcome, principal in definitions:
        slot = _Slot(f"slot-{name}", extraction, events)
        authenticator = _Authenticator(name, slot.name, outcome, events)
        resolver = _Resolver(principal, name, events)
        slots.append(slot)
        authenticators.append(authenticator)
        resolvers.append(resolver)
        mechanisms.append(
            AuthenticationMechanism(
                authenticator=authenticator,  # type: ignore[arg-type]
                resolver=resolver,
            )
        )
    registry = AuthenticationRegistry(slots=slots, mechanisms=mechanisms)  # type: ignore[arg-type]
    return registry.evaluator(), slots, authenticators, resolvers


@pytest.mark.anyio
async def test_no_credentials_required_rejects_and_optional_remains_anonymous() -> None:
    events: list[str] = []
    evaluator, slots, authenticators, resolvers = _evaluator(
        [("local", NoCredentials(), NoCredentials(), Principal(id="unused"))], events
    )

    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=True)
    principal, context = await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=False)

    assert not principal.is_authenticated
    assert context.evidence == ()
    assert [slot.calls for slot in slots] == [2]
    assert [authenticator.calls for authenticator in authenticators] == [0]
    assert [resolver.calls for resolver in resolvers] == [0]


@pytest.mark.anyio
async def test_one_valid_credential_resolves_once() -> None:
    events: list[str] = []
    principal = Principal[object](id="user-1")
    evaluator, slots, authenticators, resolvers = _evaluator(
        [("local", PresentedCredential("token"), _success("local", "slot-local"), principal)], events
    )

    resolved, context = await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=True)

    assert resolved is principal
    assert context.evidence[0].mechanism == "local"
    assert [slot.calls for slot in slots] == [1]
    assert [authenticator.calls for authenticator in authenticators] == [1]
    assert [resolver.calls for resolver in resolvers] == [1]
    assert events == ["extract:slot-local", "authenticate:local", "resolve:local"]


@pytest.mark.anyio
async def test_malformed_extraction_is_terminal() -> None:
    events: list[str] = []
    evaluator, slots, authenticators, resolvers = _evaluator(
        [("local", InvalidCredentials(), NoCredentials(), Principal(id="unused"))], events
    )

    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=False)

    assert [slot.calls for slot in slots] == [1]
    assert [authenticator.calls for authenticator in authenticators] == [0]
    assert [resolver.calls for resolver in resolvers] == [0]


@pytest.mark.anyio
async def test_presented_slot_without_authenticator_is_terminal() -> None:
    events: list[str] = []
    slot = _Slot("unowned", PresentedCredential("token"), events)
    registry = AuthenticationRegistry[object](slots=[slot], mechanisms=())  # type: ignore[list-item]
    evaluator = registry.evaluator()

    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=False)

    assert slot.calls == 1


@pytest.mark.anyio
@pytest.mark.parametrize("order", ["forward", "reverse"])
async def test_valid_plus_invalid_is_terminal_in_either_order(order: str) -> None:
    events: list[str] = []
    definitions = [
        ("valid", PresentedCredential("valid"), _success("valid", "slot-valid"), Principal(id="user-1")),
        ("invalid", PresentedCredential("invalid"), InvalidCredentials(), Principal(id="unused")),
    ]
    if order == "reverse":
        definitions.reverse()
    evaluator, slots, authenticators, resolvers = _evaluator(definitions, events)

    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=False)

    assert [slot.calls for slot in slots] == [1, 1]
    assert [authenticator.calls for authenticator in authenticators] == [1, 1]
    assert [resolver.calls for resolver in resolvers] == [0, 0]


@pytest.mark.anyio
@pytest.mark.parametrize("order", ["forward", "reverse"])
async def test_valid_plus_unavailable_returns_503_in_either_order(order: str) -> None:
    events: list[str] = []
    definitions = [
        ("valid", PresentedCredential("valid"), _success("valid", "slot-valid"), Principal(id="user-1")),
        (
            "unavailable",
            PresentedCredential("unavailable"),
            VerificationUnavailable(retry_after=30),
            Principal(id="unused"),
        ),
    ]
    if order == "reverse":
        definitions.reverse()
    evaluator, slots, authenticators, resolvers = _evaluator(definitions, events)

    with pytest.raises(ServiceUnavailableException, match="Authentication service unavailable"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=False)

    assert [slot.calls for slot in slots] == [1, 1]
    assert [authenticator.calls for authenticator in authenticators] == [1, 1]
    assert [resolver.calls for resolver in resolvers] == [0, 0]


@pytest.mark.anyio
async def test_different_subjects_reject_after_single_resolution_each() -> None:
    events: list[str] = []
    evaluator, _, _, resolvers = _evaluator(
        [
            ("a", PresentedCredential("a"), _success("a", "slot-a"), Principal(id="user-1")),
            ("b", PresentedCredential("b"), _success("b", "slot-b"), Principal(id="user-2")),
        ],
        events,
    )

    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=True)

    assert [resolver.calls for resolver in resolvers] == [1, 1]


@pytest.mark.anyio
async def test_authenticated_outcome_cannot_resolve_to_anonymous() -> None:
    events: list[str] = []
    evaluator, _, _, resolvers = _evaluator(
        [
            (
                "local",
                PresentedCredential("token"),
                _success("local", "slot-local"),
                Principal[object].anonymous(),
            )
        ],
        events,
    )

    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=True)

    assert [resolver.calls for resolver in resolvers] == [1]


@pytest.mark.anyio
async def test_explicit_participant_set_controls_required_satisfaction() -> None:
    events: list[str] = []
    evaluator, _, _, _ = _evaluator(
        [
            (
                "local",
                PresentedCredential("token"),
                _success("local", "slot-local"),
                Principal(id="user-1"),
            )
        ],
        events,
    )

    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        await evaluator.evaluate(
            _CONNECTION,
            NullSessionHandle(),
            required=True,
            participant_names={"other"},
        )
    principal, _ = await evaluator.evaluate(
        _CONNECTION,
        NullSessionHandle(),
        required=True,
        participant_names={"local"},
    )

    assert principal.id == "user-1"


@pytest.mark.anyio
async def test_same_subject_merges_evidence_and_grants_in_order() -> None:
    events: list[str] = []
    evaluator, _, _, _ = _evaluator(
        [
            (
                "a",
                PresentedCredential("a"),
                _success(
                    "a",
                    "slot-a",
                    grants=AuthorizationSnapshot(
                        scopes={"read"},
                        roles={"member"},
                        capabilities={"reports.view"},
                        team_roles={"team-1": {"member"}},
                        tenant_ids={"tenant-1"},
                        attributes={"source-a": True},
                    ),
                ),
                Principal(id="user-1", display_name="First"),
            ),
            (
                "b",
                PresentedCredential("b"),
                _success(
                    "b",
                    "slot-b",
                    grants=AuthorizationSnapshot(
                        scopes={"write"},
                        roles={"admin"},
                        capabilities={"reports.export"},
                        team_roles={"team-1": {"owner"}, "team-2": {"member"}},
                        tenant_ids={"tenant-2"},
                        attributes={"source-b": True},
                    ),
                ),
                Principal(id="user-1", display_name="Second"),
            ),
        ],
        events,
    )

    principal, context = await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=True)

    assert principal.display_name == "First"
    assert tuple(evidence.mechanism for evidence in context.evidence) == ("a", "b")
    assert context.authorization.scopes == frozenset({"read", "write"})
    assert context.authorization.roles == frozenset({"member", "admin"})
    assert context.authorization.capabilities == frozenset({"reports.view", "reports.export"})
    assert context.authorization.team_roles == {
        "team-1": frozenset({"member", "owner"}),
        "team-2": frozenset({"member"}),
    }
    assert context.authorization.tenant_ids == frozenset({"tenant-1", "tenant-2"})
    assert context.authorization.attributes == {"source-a": True, "source-b": True}


def _authorization_for_dimension(dimension: str) -> AuthorizationSnapshot:
    if dimension == "team_ids":
        return AuthorizationSnapshot(team_roles={"a": {"member"}, "b": {"member"}, "c": {"member"}})
    return AuthorizationSnapshot(**{dimension: {"a", "b", "c"}})


@pytest.mark.anyio
@pytest.mark.parametrize("dimension", ["scopes", "roles", "capabilities", "team_ids", "tenant_ids"])
@pytest.mark.parametrize(
    ("bounds", "expected"),
    [
        ((None, None), {"a", "b", "c"}),
        ((None, frozenset()), set()),
        ((frozenset({"a", "b"}), frozenset({"b", "c"})), {"b"}),
        ((frozenset({"a"}), frozenset({"c"})), set()),
    ],
)
async def test_restriction_intersection_truth_table(
    dimension: str,
    bounds: tuple[frozenset[str] | None, frozenset[str] | None],
    expected: set[str],
) -> None:
    events: list[str] = []
    restrictions_a = CredentialRestrictions(**{dimension: bounds[0]})
    restrictions_b = CredentialRestrictions(**{dimension: bounds[1]})
    evaluator, _, _, _ = _evaluator(
        [
            (
                "a",
                PresentedCredential("a"),
                _success(
                    "a",
                    "slot-a",
                    grants=_authorization_for_dimension(dimension),
                    restrictions=restrictions_a,
                ),
                Principal(id="user-1"),
            ),
            (
                "b",
                PresentedCredential("b"),
                _success("b", "slot-b", restrictions=restrictions_b),
                Principal(id="user-1"),
            ),
        ],
        events,
    )

    _, context = await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=True)

    if dimension == "team_ids":
        actual = set(context.authorization.team_roles)
    else:
        actual = set(getattr(context.authorization, dimension))
    assert actual == expected


@pytest.mark.anyio
async def test_presented_credential_cannot_normalize_back_to_missing() -> None:
    events: list[str] = []
    evaluator, _, authenticators, resolvers = _evaluator(
        [("local", PresentedCredential("token"), NoCredentials(), Principal(id="unused"))], events
    )

    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=False)

    assert [authenticator.calls for authenticator in authenticators] == [1]
    assert [resolver.calls for resolver in resolvers] == [0]
