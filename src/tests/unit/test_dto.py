"""Unit tests for the DTO types that spell generated bodies in one convention."""

from collections.abc import Iterator
from typing import Any, cast, get_args, get_type_hints

import msgspec
import pytest
from litestar import Litestar, Response, get, post
from litestar.exceptions import ImproperlyConfiguredException
from litestar.openapi.config import OpenAPIConfig
from litestar.params import FromQuery
from litestar.typing import FieldDefinition
from litestar.testing import TestClient

from litestar_security._dto import MAX_NESTED_DEPTH, WireBackend, union_wire_dto, wire_dto, wire_struct
from litestar_security.accounts import (
    LocalAccount,
    LocalCredentials,
    LocalMFAChallenge,
    LocalSession,
    LocalSessionList,
    RouteStatus,
    TokenPair,
)
from litestar_security.providers.oauth import OAuthRouteStatus
from litestar_security.schema import WirePolicy, WireStruct

from tests.fixtures.collaborators import build_token_pair

SNAKE = WirePolicy()
CAMEL = WirePolicy(rename="camel")
LENIENT = WirePolicy(rename="camel", forbid_unknown_fields=False)


def _document(app: Litestar) -> dict[str, Any]:
    return cast("dict[str, Any]", msgspec.json.decode(msgspec.json.encode(app.openapi_schema.to_schema())))


def _schemas(app: Litestar) -> dict[str, Any]:
    return cast("dict[str, Any]", _document(app)["components"]["schemas"])


def _app(*handlers: Any) -> Litestar:
    return Litestar(list(handlers), openapi_config=OpenAPIConfig(title="wire", version="1", create_examples=False))


def _session(identifier: str = "session-1") -> LocalSession:
    moment = msgspec.convert("2026-01-01T00:00:00Z", type=Any, strict=False)
    return msgspec.convert(
        {
            "session_id": identifier,
            "current": True,
            "created_at": moment,
            "last_seen_at": moment,
            "expires_at": moment,
            "display_metadata": {"device": "laptop"},
        },
        type=LocalSession,
    )


def test_wire_dto_returns_one_class_per_schema_and_policy() -> None:
    assert wire_dto(LocalAccount, SNAKE) is wire_dto(LocalAccount, WirePolicy())
    assert wire_dto(LocalAccount, CAMEL) is not wire_dto(LocalAccount, SNAKE)
    assert wire_dto(LocalSession, SNAKE) is not wire_dto(LocalAccount, SNAKE)


def test_narrowed_wire_dto_classes_do_not_share_a_backend_registry() -> None:
    snake = wire_dto(LocalAccount, SNAKE)
    camel = wire_dto(LocalAccount, CAMEL)

    assert snake._dto_backends is not camel._dto_backends  # noqa: SLF001 - the registry is the point of the test


def test_component_keys_name_the_model_including_the_nested_one() -> None:
    @post("/login", dto=wire_dto(LocalCredentials, SNAKE), return_dto=wire_dto(LocalAccount, SNAKE))
    async def login(data: LocalCredentials) -> LocalAccount:
        return LocalAccount(account_id=data.identifier)

    @get("/me", return_dto=wire_dto(LocalAccount, SNAKE))
    async def me() -> LocalAccount:
        return LocalAccount(account_id="a")

    @get("/sessions", return_dto=wire_dto(LocalSessionList, SNAKE))
    async def sessions() -> LocalSessionList:
        return LocalSessionList(sessions=(_session(),))

    schemas = _schemas(_app(login, me, sessions))

    assert set(schemas) == {"LocalAccount", "LocalCredentials", "LocalSession", "LocalSessionList"}
    assert schemas["LocalSessionList"]["properties"]["sessions"]["items"]["$ref"].endswith("/LocalSession")


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        (SNAKE, {"session_id", "current", "created_at", "last_seen_at", "expires_at", "display_metadata"}),
        (CAMEL, {"sessionId", "current", "createdAt", "lastSeenAt", "expiresAt", "displayMetadata"}),
        (
            WirePolicy(rename=str.upper),
            {"SESSION_ID", "CURRENT", "CREATED_AT", "LAST_SEEN_AT", "EXPIRES_AT", "DISPLAY_METADATA"},
        ),
    ],
)
def test_a_nested_schema_is_renamed_at_every_level(policy: WirePolicy, expected: set[str]) -> None:
    @get("/sessions", return_dto=wire_dto(LocalSessionList, policy))
    async def sessions() -> LocalSessionList:
        return LocalSessionList(sessions=(_session(),))

    app = _app(sessions)
    schemas = _schemas(app)
    listed = next(iter(schemas["LocalSessionList"]["properties"]))

    assert set(schemas["LocalSession"]["properties"]) == expected
    with TestClient(app=app) as client:
        assert set(client.get("/sessions").json()[listed][0]) == expected


def _nesting_depth(schema: type[Any], seen: frozenset[type[Any]] = frozenset()) -> int:
    """Return how many struct layers sit below one generated schema."""
    if schema in seen:
        return 0
    nested = [
        _nesting_depth(found, seen | {schema}) + 1
        for hint in get_type_hints(schema).values()
        for found in _wire_structs(hint)
    ]
    return max(nested, default=0)


def _wire_structs(annotation: Any) -> "Iterator[type[Any]]":
    if isinstance(annotation, type) and issubclass(annotation, WireStruct):
        yield annotation
        return
    for argument in get_args(annotation):
        yield from _wire_structs(argument)


def _generated_schemas() -> "Iterator[type[Any]]":
    pending = [WireStruct]
    while pending:
        schema = pending.pop()
        pending.extend(schema.__subclasses__())
        if schema is not WireStruct:
            yield schema


def test_the_configured_nesting_depth_covers_every_generated_schema() -> None:
    deepest = max((_nesting_depth(schema), schema.__name__) for schema in _generated_schemas())

    assert deepest[0] >= 1, "no generated schema nests, so this guard is watching nothing"
    assert MAX_NESTED_DEPTH >= deepest[0]


def test_a_schema_deeper_than_the_limit_loses_its_leaf_with_no_error_raised() -> None:
    class Leaf(WireStruct, frozen=True):
        leaf_name: str

    class Mid(WireStruct, frozen=True):
        leaf: Leaf

    class Top(WireStruct, frozen=True):
        mid: Mid

    truncating = WirePolicy(rename="camel")

    @get("/deep", return_dto=wire_dto(Top, truncating))
    async def deep() -> Top:
        return Top(mid=Mid(leaf=Leaf(leaf_name="l")))

    app = _app(deep)
    with TestClient(app=app) as client:
        body = client.get("/deep").json()

    kept = MAX_NESTED_DEPTH >= _nesting_depth(Top)
    assert kept, "raise MAX_NESTED_DEPTH or this schema silently loses its leaf"
    assert body == {"mid": {"leaf": {"leafName": "l"}}}


@pytest.mark.parametrize(
    ("policy", "identifier", "accepted", "rejected"),
    [(SNAKE, "account_id", "display_name", "displayName"), (CAMEL, "accountId", "displayName", "display_name")],
)
def test_a_request_body_decodes_in_the_configured_casing_and_rejects_the_other(
    policy: WirePolicy, identifier: str, accepted: str, rejected: str
) -> None:
    @post("/accounts", dto=wire_dto(LocalAccount, policy), return_dto=wire_dto(LocalAccount, policy))
    async def create(data: LocalAccount) -> LocalAccount:
        return data

    with TestClient(app=_app(create)) as client:
        assert client.post("/accounts", json={identifier: "a", accepted: "Ada"}).status_code == 201
        assert client.post("/accounts", json={identifier: "a", rejected: "Ada"}).status_code == 400


def test_an_unknown_member_is_accepted_only_when_the_policy_allows_it() -> None:
    @post("/strict", dto=wire_dto(LocalAccount, CAMEL), return_dto=wire_dto(LocalAccount, CAMEL))
    async def strict(data: LocalAccount) -> LocalAccount:
        return data

    @post("/lenient", dto=wire_dto(LocalAccount, LENIENT), return_dto=wire_dto(LocalAccount, LENIENT))
    async def lenient(data: LocalAccount) -> LocalAccount:
        return data

    with TestClient(app=_app(strict, lenient)) as client:
        body = {"accountId": "a", "unknown": "member"}
        assert client.post("/strict", json=body).status_code == 400
        assert client.post("/lenient", json=body).status_code == 201


def test_wire_struct_is_the_struct_the_handler_transfers_through() -> None:
    documented = wire_struct(LocalAccount, CAMEL)

    @get("/me", return_dto=wire_dto(LocalAccount, CAMEL))
    async def me() -> LocalAccount:
        return LocalAccount(account_id="a")

    app = _app(me)

    assert wire_struct(LocalAccount, CAMEL) is documented
    assert WireBackend.transfer_model_for(LocalAccount, wire_dto(LocalAccount, CAMEL).config) is documented
    assert set(_schemas(app)["LocalAccount"]["properties"]) == {"accountId", "displayName"}


def test_a_union_return_renames_each_arm_and_publishes_both() -> None:
    arms = LocalAccount | LocalMFAChallenge

    @get("/login", return_dto=union_wire_dto(arms, CAMEL))
    async def login(mfa: FromQuery[bool] = False) -> "Response[LocalAccount | LocalMFAChallenge]":
        challenge = LocalMFAChallenge(
            challenge="c", account_id="a", expires_at=_session().created_at, methods=("totp",)
        )
        return Response(challenge if mfa else LocalAccount(account_id="a"))

    app = _app(login)
    schemas = _schemas(app)

    assert set(schemas["LocalAccount"]["properties"]) == {"accountId", "displayName"}
    assert "accountId" in schemas["LocalMFAChallenge"]["properties"]
    with TestClient(app=app) as client:
        assert set(client.get("/login").json()) == {"accountId", "displayName"}
        assert "accountId" in client.get("/login", params={"mfa": True}).json()


def test_a_union_arm_whose_members_belong_to_a_specification_is_left_alone() -> None:
    @get("/token", return_dto=union_wire_dto(TokenPair | LocalMFAChallenge, CAMEL))
    async def token() -> Response[TokenPair | LocalMFAChallenge]:
        return Response(build_token_pair())

    app = _app(token)

    with TestClient(app=app) as client:
        assert set(client.get("/token").json()) == {"access_token", "refresh_token", "expires_in", "token_type"}


def test_a_union_arm_carried_inside_a_response_is_still_renamed() -> None:
    arms = Response[OAuthRouteStatus] | OAuthRouteStatus

    @get("/logout", return_dto=union_wire_dto(arms, CAMEL))
    async def logout(redirected: FromQuery[bool] = False) -> "Response[OAuthRouteStatus] | OAuthRouteStatus":
        status = OAuthRouteStatus(detail="Logged out.", revoked_sessions=2)
        return Response(status, status_code=200) if redirected else status

    with TestClient(app=_app(logout)) as client:
        assert client.get("/logout").json() == {"detail": "Logged out.", "revokedSessions": 2}
        assert client.get("/logout", params={"redirected": True}).json() == {
            "detail": "Logged out.",
            "revokedSessions": 2,
        }


def test_a_union_cannot_narrow_a_request_body() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="cannot be narrowed to a union"):

        @post("/login", dto=union_wire_dto(LocalAccount | LocalCredentials, SNAKE))
        async def login(data: LocalAccount | LocalCredentials) -> RouteStatus:
            return RouteStatus(detail="ok")

        _app(login).openapi_schema  # noqa: B018 - building the document resolves the DTO


def test_a_schema_that_omits_defaults_still_omits_them_after_renaming() -> None:
    @get("/status", return_dto=wire_dto(OAuthRouteStatus, CAMEL))
    async def status() -> OAuthRouteStatus:
        return OAuthRouteStatus(detail="Linked.", provider_account_id="p1")

    with TestClient(app=_app(status)) as client:
        assert client.get("/status").json() == {"detail": "Linked.", "providerAccountId": "p1"}


def test_one_schema_cannot_publish_two_wire_shapes_under_one_policy() -> None:
    from typing import Annotated

    from litestar.dto import DTOConfig

    from litestar_security._dto import MAX_NESTED_DEPTH as depth
    from litestar_security._dto import WireDTO

    def narrowed(exclude: set[str]) -> Any:
        config = DTOConfig(exclude=exclude, max_nested_depth=depth)
        return WireDTO[Annotated[LocalSession, config]]

    def backend(dto: Any) -> WireBackend:
        return WireBackend(
            dto_factory=dto,
            field_definition=FieldDefinition.from_annotation(LocalSession),
            model_type=LocalSession,
            handler_id=f"shape::{sorted(dto.config.exclude)}",
            is_data_field=False,
            wrapper_attribute_name=None,
        )

    backend(narrowed(set()))

    with pytest.raises(ImproperlyConfiguredException, match="two different wire shapes"):
        backend(narrowed({"current"}))
