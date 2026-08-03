"""Unit tests for strict authentication evaluation and authorization merging."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

import pytest
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException, ServiceUnavailableException

from litestar_security._openapi import PolicyCompiler
from litestar_security.authentication import (
    Authenticated,
    AuthenticationMechanism,
    AuthenticationPolicy,
    AuthenticationRegistry,
    InvalidCredentials,
    NoCredentials,
    PresentedCredential,
    SecurityMiddlewareWrapper,
    SecurityRuntimeConfig,
    VerificationUnavailable,
    all_of,
    any_of,
    at_least,
    mechanism,
    optional,
    public,
    queue_security_response_header,
    required,
)
from litestar_security.context import (
    AuthenticationEvidence,
    AuthorizationSnapshot,
    CredentialRestrictions,
    NullSessionHandle,
    Principal,
    ResourcePermission,
    resolve_authorization,
)

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.types import Message, Receive, Scope, Send

    from litestar_security.authentication import _AuthenticationEvaluator

_CONNECTION = cast("ASGIConnection", object())
_NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)


def _scope(scope_type: str = "http") -> Scope:
    return cast(
        "Scope",
        {
            "type": scope_type,
            "asgi": {"spec_version": "2.0", "version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "root_path": "",
            "headers": [],
            "client": ("test", 50000),
            "server": ("testserver", 80),
        },
    )


async def _receive() -> Message:
    return {"type": "http.request", "body": b"", "more_body": False}


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
    def __init__(
        self, name: str, slot: str, outcome: object, events: list[str], *, participates_by_default: bool = True
    ) -> None:
        self.name = name
        self.slot = slot
        self.outcome = outcome
        self.events = events
        self.calls = 0
        self.participates_by_default = participates_by_default

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


class _AuthorizationResolver:
    def __init__(self, outcome: object, events: list[str]) -> None:
        self.outcome = outcome
        self.events = events
        self.calls = 0

    async def resolve(self, principal: Principal[object]) -> object:
        self.calls += 1
        self.events.append(f"authorize:{principal.id}")
        return self.outcome


@pytest.mark.anyio
@pytest.mark.parametrize("status", [200, 401], ids=["normal", "exception"])
async def test_security_wrapper_appends_queued_headers_to_every_http_response(status: int) -> None:
    sent: list[Message] = []
    existing = (b"x-existing", b"value")
    first_cookie = (b"set-cookie", b"binding=first; Path=/; HttpOnly")
    second_cookie = (b"set-cookie", b"binding=second; Path=/; HttpOnly")

    async def app(scope: Scope, _receive: Receive, send: Send) -> None:
        queue_security_response_header(scope, first_cookie)
        queue_security_response_header(scope, second_cookie)
        await send({"type": "http.response.start", "status": status, "headers": [existing]})
        await send({"type": "http.response.body", "body": b""})

    async def capture(message: Message) -> None:
        sent.append(message)

    wrapper = SecurityMiddlewareWrapper(app=app, config=SecurityRuntimeConfig(registry=AuthenticationRegistry()))
    await wrapper(_scope(), _receive, capture)

    assert sent[0]["headers"] == [existing, first_cookie, second_cookie]
    assert sent[1] == {"type": "http.response.body", "body": b""}


@pytest.mark.anyio
async def test_security_response_headers_are_not_queued_or_injected_for_websocket() -> None:
    sent: list[Message] = []
    existing = (b"x-existing", b"value")

    async def app(scope: Scope, _receive: Receive, send: Send) -> None:
        queue_security_response_header(scope, (b"set-cookie", b"binding=secret"))
        await send({"type": "websocket.accept", "subprotocol": None, "headers": [existing]})

    async def capture(message: Message) -> None:
        sent.append(message)

    wrapper = SecurityMiddlewareWrapper(app=app, config=SecurityRuntimeConfig(registry=AuthenticationRegistry()))
    scope = _scope("websocket")
    await wrapper(scope, _receive, capture)

    assert sent == [{"type": "websocket.accept", "subprotocol": None, "headers": [existing]}]


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
    *,
    authorization_resolver: object | None = None,
) -> tuple[_AuthenticationEvaluator[object], list[_Slot], list[_Authenticator], list[_Resolver]]:
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
    registry = AuthenticationRegistry(  # type: ignore[arg-type]
        slots=slots, mechanisms=mechanisms, authorization_resolver=authorization_resolver
    )
    return registry.evaluator(), slots, authenticators, resolvers


def _policy_evaluator(
    presented: set[str], *, different_subject: str | None = None
) -> tuple[_AuthenticationEvaluator[object], PolicyCompiler[object], list[_Slot]]:
    events: list[str] = []
    slots: list[_Slot] = []
    mechanisms: list[AuthenticationMechanism[str, str, object]] = []
    for name in ("a", "b", "c"):
        slot = _Slot(f"slot-{name}", PresentedCredential(name) if name in presented else NoCredentials(), events)
        authenticator = _Authenticator(
            name, slot.name, _success(name, slot.name), events, participates_by_default=name != "c"
        )
        principal_id = "user-2" if name == different_subject else "user-1"
        slots.append(slot)
        mechanisms.append(
            AuthenticationMechanism(
                authenticator=authenticator,  # type: ignore[arg-type]
                resolver=_Resolver(Principal(id=principal_id), name, events),
            )
        )
    registry = AuthenticationRegistry(slots=slots, mechanisms=mechanisms)  # type: ignore[arg-type]
    return registry.evaluator(), PolicyCompiler(registry), slots


@pytest.mark.anyio
@pytest.mark.parametrize(
    "case",
    [
        (required(), {"a"}, True, True),
        (required(), {"c"}, False, False),
        (any_of("a", "c"), {"c"}, True, True),
        (any_of("a", "b"), {"c"}, False, False),
        (all_of("a", "b"), {"a"}, False, False),
        (all_of("a", "b"), {"a", "b"}, True, True),
        (at_least(2, "a", "b", "c"), {"a", "c"}, True, True),
        (at_least(2, "a", "b", "c"), {"a"}, False, False),
        (optional(required("a")), set(), True, False),
        (optional(required("a")), {"c"}, False, False),
    ],
)
async def test_compiled_policy_runtime_truth_table(case: tuple[AuthenticationPolicy, set[str], bool, bool]) -> None:
    policy, presented, accepted, authenticated = case
    evaluator, compiler, slots = _policy_evaluator(presented)
    plan = compiler.compile(policy)

    if accepted:
        principal, _ = await evaluator.evaluate(_CONNECTION, NullSessionHandle(), plan=plan)
        assert principal.is_authenticated is authenticated
    else:
        with pytest.raises(NotAuthorizedException, match="Authentication required"):
            await evaluator.evaluate(_CONNECTION, NullSessionHandle(), plan=plan)
    assert [slot.calls for slot in slots] == [1, 1, 1]


def test_policy_compiler_is_deterministic_cached_and_preserves_forced_csrf() -> None:
    _, compiler, slots = _policy_evaluator(set())
    policy = at_least(2, "c", "a", "b")

    first = compiler.compile(policy)
    second = compiler.compile(at_least(2, "b", "c", "a"))
    third = compiler.compile(policy)
    public_plan = compiler.compile(public(), csrf_required=True)

    assert first is second is third
    assert first.alternatives == (
        (mechanism("a"), mechanism("b")),
        (mechanism("a"), mechanism("c")),
        (mechanism("b"), mechanism("c")),
    )
    assert not public_plan.authenticate
    assert public_plan.csrf_required is True
    assert [slot.calls for slot in slots] == [0, 0, 0]


@pytest.mark.anyio
async def test_public_compiled_plan_skips_all_credential_work() -> None:
    evaluator, compiler, slots = _policy_evaluator({"a", "b", "c"})

    principal, context = await evaluator.evaluate(_CONNECTION, NullSessionHandle(), plan=compiler.compile(public()))

    assert not principal.is_authenticated
    assert context.evidence == ()
    assert [slot.calls for slot in slots] == [0, 0, 0]


@pytest.mark.anyio
async def test_nonqualifying_credentials_still_merge_or_reject_different_subjects() -> None:
    evaluator, compiler, _ = _policy_evaluator({"a", "c"})

    principal, context = await evaluator.evaluate(
        _CONNECTION, NullSessionHandle(), plan=compiler.compile(required("a"))
    )

    assert principal.id == "user-1"
    assert tuple(evidence.mechanism for evidence in context.evidence) == ("a", "c")

    evaluator, compiler, _ = _policy_evaluator({"a", "c"}, different_subject="c")
    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), plan=compiler.compile(required("a")))


@pytest.mark.parametrize(
    ("policy", "match"),
    [(required("missing"), "undefined authentication mechanism"), (required(), "default-participating")],
)
def test_policy_compiler_rejects_unresolvable_required_policy(policy: AuthenticationPolicy, match: str) -> None:
    registry: AuthenticationRegistry[object] = AuthenticationRegistry()

    with pytest.raises(ImproperlyConfiguredException, match=match):
        PolicyCompiler(registry).compile(policy)


def test_policy_compiler_rejects_foreign_policy_subclasses() -> None:
    class _ForeignPolicy(AuthenticationPolicy):
        pass

    with pytest.raises(ImproperlyConfiguredException, match="policy helper"):
        PolicyCompiler(AuthenticationRegistry()).compile(_ForeignPolicy())


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
    principal = Principal(id="user-1")
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
    registry: AuthenticationRegistry[object] = AuthenticationRegistry(
        slots=[slot],
        mechanisms=(),  # type: ignore[list-item]
    )
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
        [("local", PresentedCredential("token"), _success("local", "slot-local"), Principal[object].anonymous())],
        events,
    )

    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=True)

    assert [resolver.calls for resolver in resolvers] == [1]


@pytest.mark.anyio
async def test_explicit_participant_set_controls_required_satisfaction() -> None:
    events: list[str] = []
    evaluator, _, _, _ = _evaluator(
        [("local", PresentedCredential("token"), _success("local", "slot-local"), Principal(id="user-1"))], events
    )

    with pytest.raises(NotAuthorizedException, match="Authentication required"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=True, participant_names={"other"})
    principal, _ = await evaluator.evaluate(
        _CONNECTION, NullSessionHandle(), required=True, participant_names={"local"}
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
                        resources={ResourcePermission(resource="report-1", scopes={"read"})},
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
                        resources={ResourcePermission(resource="report-2", scopes={"write"})},
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
    assert context.authorization.resources == frozenset({
        ResourcePermission(resource="report-1", scopes={"read"}),
        ResourcePermission(resource="report-2", scopes={"write"}),
    })
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
        ((frozenset({"a", "b", "c"}), frozenset({"a", "b", "c"})), {"a", "b", "c"}),
        ((frozenset({"a", "b"}), None), {"a", "b"}),
        ((frozenset({"a", "b", "c", "d"}), None), {"a", "b", "c"}),
        ((frozenset({"a", "b"}), frozenset({"b", "c"})), {"b"}),
        ((frozenset({"a"}), frozenset({"c"})), set()),
    ],
)
async def test_restriction_intersection_truth_table(
    dimension: str, bounds: tuple[frozenset[str] | None, frozenset[str] | None], expected: set[str]
) -> None:
    events: list[str] = []
    restrictions_a = CredentialRestrictions(**{dimension: bounds[0]})
    restrictions_b = CredentialRestrictions(**{dimension: bounds[1]})
    evaluator, _, _, _ = _evaluator(
        [
            (
                "a",
                PresentedCredential("a"),
                _success("a", "slot-a", grants=_authorization_for_dimension(dimension), restrictions=restrictions_a),
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


@pytest.mark.parametrize(
    ("bounds", "expected"),
    [
        (None, {"report-1": {"read", "write"}, "report-2": {"view"}}),
        (frozenset(), {}),
        (
            frozenset({
                ResourcePermission(resource="report-1", scopes={"read"}),
                ResourcePermission(resource="report-3", scopes={"admin"}),
            }),
            {"report-1": {"read"}},
        ),
        (frozenset({ResourcePermission(resource="missing", scopes={"read"})}), {}),
    ],
)
def test_resource_restriction_truth_table(
    bounds: frozenset[ResourcePermission] | None, expected: dict[str, set[str]]
) -> None:
    snapshot = AuthorizationSnapshot(
        resources={
            ResourcePermission(resource="report-1", scopes={"read", "write"}),
            ResourcePermission(resource="report-2", scopes={"view"}),
        }
    )

    effective = resolve_authorization(snapshot, (CredentialRestrictions(resources=bounds),))

    assert {permission.resource: set(permission.scopes) for permission in effective.resources} == expected


@pytest.mark.anyio
async def test_application_authorization_is_resolved_once_then_narrowed_by_all_credentials() -> None:
    events: list[str] = []
    application = AuthorizationSnapshot(
        scopes={"read", "write"},
        team_roles={"team-1": {"member"}, "team-2": {"owner"}},
        tenant_ids={"tenant-1"},
        resources={ResourcePermission(resource="report-1", scopes={"read", "write"})},
    )
    authorization_resolver = _AuthorizationResolver(application, events)
    evaluator, _, _, _ = _evaluator(
        [
            (
                "api-key",
                PresentedCredential("key"),
                _success(
                    "api-key",
                    "slot-api-key",
                    grants=AuthorizationSnapshot(scopes={"manufactured"}, team_roles={"missing": {"owner"}}),
                    restrictions=CredentialRestrictions(
                        scopes={"read"},
                        team_ids={"team-1", "missing"},
                        resources=frozenset({ResourcePermission(resource="report-1", scopes={"read"})}),
                    ),
                ),
                Principal(id="user-1"),
            ),
            (
                "rpt",
                PresentedCredential("token"),
                _success(
                    "rpt",
                    "slot-rpt",
                    restrictions=CredentialRestrictions(
                        tenant_ids={"tenant-1", "missing"},
                        resources=frozenset({
                            ResourcePermission(resource="report-1", scopes={"write"}),
                            ResourcePermission(resource="missing", scopes={"admin"}),
                        }),
                    ),
                ),
                Principal(id="user-1"),
            ),
        ],
        events,
        authorization_resolver=authorization_resolver,
    )

    _, context = await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=True)

    assert authorization_resolver.calls == 1
    assert context.authorization.scopes == frozenset({"read"})
    assert context.authorization.team_roles == {"team-1": frozenset({"member"})}
    assert context.authorization.tenant_ids == frozenset({"tenant-1"})
    assert context.authorization.resources == frozenset({ResourcePermission(resource="report-1", scopes=frozenset())})
    assert "manufactured" not in context.authorization.scopes
    assert events[-1] == "authorize:user-1"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("resolution", "error"),
    [(InvalidCredentials(), NotAuthorizedException), (VerificationUnavailable(), ServiceUnavailableException)],
)
async def test_authorization_resolution_preserves_structured_failure(
    resolution: object, error: type[Exception]
) -> None:
    events: list[str] = []
    evaluator, _, _, _ = _evaluator(
        [("a", PresentedCredential("a"), _success("a", "slot-a"), Principal(id="user-1"))],
        events,
        authorization_resolver=_AuthorizationResolver(resolution, events),
    )

    with pytest.raises(error):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=True)


def test_registry_rejects_malformed_authorization_resolver() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Authorization resolver"):
        AuthenticationRegistry(authorization_resolver=object())  # type: ignore[arg-type]


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


@pytest.mark.anyio
async def test_identity_resolution_unavailable_wins_over_invalid_after_all_resolvers_run() -> None:
    events: list[str] = []
    evaluator, _, _, resolvers = _evaluator(
        [
            ("a", PresentedCredential("a"), _success("a", "slot-a"), Principal(id="unused-a")),
            ("b", PresentedCredential("b"), _success("b", "slot-b"), Principal(id="unused-b")),
        ],
        events,
    )
    resolvers[0].principal = cast("Principal[object]", InvalidCredentials())
    resolvers[1].principal = cast("Principal[object]", VerificationUnavailable())

    with pytest.raises(ServiceUnavailableException, match="service unavailable"):
        await evaluator.evaluate(_CONNECTION, NullSessionHandle(), required=True)

    assert [resolver.calls for resolver in resolvers] == [1, 1]
