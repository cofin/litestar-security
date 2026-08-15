"""What a client reading the published document should expect from an error.

A client generated from this library's own OpenAPI document decodes each
response against the schema the document declares for that status. These tests
hold the two halves of that contract apart:

* A **raised** status is produced by an exception, so Litestar serializes it as
  ``ExceptionResponseContent`` - ``status_code``, ``detail``, and ``extra`` when
  the exception carries one. The route's ``ResponseSpec`` has to describe that
  body, whatever the handler's own return type is.
* A **returned** status is produced by a handler returning a value, so the
  declared schema *is* the handler's return type and is accurate by
  construction.

The distinction that decides which half a status belongs to is
raised-versus-returned, not error-versus-success: the 403 second-factor
challenge and the 409 conflict are returned, and the 400/401/429/503 denials are
raised.
"""

from collections.abc import Mapping
from typing import Any, NamedTuple, cast

import msgspec
import pytest
from litestar import Litestar, Request, Response, get
from litestar.exceptions import HTTPException, LitestarWarning, TooManyRequestsException
from litestar.plugins.problem_details import ProblemDetailsConfig, ProblemDetailsPlugin
from litestar.status_codes import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_409_CONFLICT,
    HTTP_429_TOO_MANY_REQUESTS,
    HTTP_503_SERVICE_UNAVAILABLE,
)
from litestar.testing import AsyncTestClient, TestClient

from litestar_security import RaisedErrorSchema
from litestar_security.providers.oauth import (
    AccountLinkError,
    InvalidOAuthCallback,
    OAuthAccountError,
    OAuthProviderError,
    OAuthTransactionUnavailable,
)
from tests.integration.test_oauth_routes import raising_oauth_app
from tests.integration.test_openapi_document import build_documented_app, canonical


class _Denial(NamedTuple):
    """One request that provokes a raised denial, and the spec that should describe it."""

    method: str
    path: str
    template: str
    body: Mapping[str, Any] | None
    status: int


_RAISED_DENIALS = (
    pytest.param(_Denial("GET", "/auth/sessions", "/auth/sessions", None, HTTP_401_UNAUTHORIZED), id="sessions-401"),
    pytest.param(
        _Denial(
            "POST",
            "/auth/token",
            "/auth/token",
            {"identifier": "absent@example.com", "password": "wrong-password"},
            HTTP_401_UNAUTHORIZED,
        ),
        id="token-401",
    ),
    pytest.param(
        _Denial("POST", "/auth/token/refresh", "/auth/token/refresh", {}, HTTP_400_BAD_REQUEST), id="refresh-400-extra"
    ),
    pytest.param(_Denial("GET", "/auth/passkeys", "/auth/passkeys", None, HTTP_401_UNAUTHORIZED), id="passkeys-401"),
    pytest.param(
        _Denial("POST", "/auth/step-up/password", "/auth/step-up/{purpose}", {}, HTTP_401_UNAUTHORIZED),
        id="step-up-401",
    ),
    pytest.param(
        _Denial("POST", "/auth/mfa/totp/enroll", "/auth/mfa/totp/enroll", {}, HTTP_401_UNAUTHORIZED), id="mfa-401"
    ),
    pytest.param(
        _Denial("GET", "/auth/oauth/example/callback", "/auth/oauth/{provider}/callback", None, HTTP_400_BAD_REQUEST),
        id="oauth-callback-400",
    ),
    pytest.param(
        _Denial(
            "POST",
            "/auth/oauth/example/link",
            "/auth/oauth/{provider}/link",
            {"step_up_grant": "grant"},
            HTTP_401_UNAUTHORIZED,
        ),
        id="oauth-link-401",
    ),
    pytest.param(
        _Denial(
            "POST",
            "/auth/oidc/example/backchannel-logout",
            "/auth/oidc/{provider}/backchannel-logout",
            None,
            HTTP_400_BAD_REQUEST,
        ),
        id="oidc-backchannel-400-extra",
    ),
)

_RETURNED_BODIES = {
    ("/auth/login", "post", "200"): "LocalAccount",
    ("/auth/login", "post", "403"): "LocalMFAChallenge",
    ("/auth/token", "post", "200"): "TokenPair",
    ("/auth/token", "post", "403"): "LocalMFAChallenge",
    ("/auth/mfa/totp/{method_id}/remove", "post", "200"): "OperationMessage",
    ("/auth/mfa/totp/{method_id}/remove", "post", "409"): "OperationMessage",
    ("/auth/passkeys/{credential_id}/remove", "post", "409"): "OperationMessage",
    ("/auth/password/recovery", "post", "202"): "LifecycleAccepted",
    ("/auth/sessions", "get", "200"): "LocalSessionList",
    ("/auth/oauth/{provider}/revoke", "post", "200"): "OAuthOperationSummary",
}


@pytest.fixture
def documented_app(jwt_key_material: Mapping[str, tuple[bytes, bytes]]) -> Litestar:
    """Return one request-local application because its stores and limiters record every attempt."""
    return build_documented_app(jwt_key_material["EdDSA"][0])


@pytest.fixture
def documented_schema(documented_app: Litestar) -> Mapping[str, Any]:
    """Return the OpenAPI document the application under test publishes."""
    assert documented_app.openapi_schema is not None
    return cast("dict[str, Any]", documented_app.openapi_schema.to_schema())


def _declared_body(
    document: Mapping[str, Any], path: str, method: str, status: str
) -> tuple[str, Mapping[str, Any]] | None:
    """Return the media type and resolved schema the document declares for one status."""
    responses = document["paths"][path][method]["responses"]
    content = responses.get(status, {}).get("content", {})
    for media_type, entry in content.items():
        schema = cast("dict[str, Any]", entry["schema"])
        reference = schema.get("$ref")
        if reference is not None:
            schema = document["components"]["schemas"][reference.rsplit("/", 1)[-1]]
        return cast("str", media_type), schema
    return None


def _assert_denial_is_described(app: Litestar, denial: _Denial) -> None:
    """Assert the document's schema for one raised status describes the body that status sends."""
    assert app.openapi_schema is not None
    document = cast("dict[str, Any]", app.openapi_schema.to_schema())
    with TestClient(app=app) as client:
        request: dict[str, Any] = {"follow_redirects": False}
        if denial.body is not None:
            request["json"] = denial.body
        response = client.request(denial.method, denial.path, **request)

    assert response.status_code == denial.status
    payload = response.json()
    declared = _declared_body(document, denial.template, denial.method.lower(), str(denial.status))
    assert declared is not None, f"{denial.method} {denial.template} documents no body for {denial.status}"
    media_type, schema = declared

    assert media_type == response.headers["content-type"].split(";")[0]
    undeclared = sorted(set(payload) - set(schema.get("properties", {})))
    assert not undeclared, f"{denial.path} sends undeclared members {undeclared} against {schema.get('title')}"
    missing = sorted(set(schema.get("required", ())) - set(payload))
    assert not missing, f"{denial.path} omits required members {missing} of {schema.get('title')}"


@pytest.mark.parametrize("denial", _RAISED_DENIALS)
def test_a_documented_denial_declares_every_member_the_wire_sends(documented_app: Litestar, denial: _Denial) -> None:
    """A member the wire always sends but the document never declares is a member no client can read."""
    _assert_denial_is_described(documented_app, denial)


@pytest.mark.parametrize("denial", _RAISED_DENIALS)
def test_a_converting_problem_details_configuration_is_described_too(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], denial: _Denial
) -> None:
    """Converting every HTTP exception rewrites the body, so it has to rewrite the document with it."""
    app = build_documented_app(
        jwt_key_material["EdDSA"][0],
        plugins=[ProblemDetailsPlugin(ProblemDetailsConfig(enable_for_all_http_exceptions=True))],
    )

    _assert_denial_is_described(app, denial)


def test_a_problem_details_plugin_that_converts_nothing_changes_nothing(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], documented_schema: Mapping[str, Any]
) -> None:
    """The default configuration converts nothing, so detecting mere presence would publish a lie."""
    app = build_documented_app(jwt_key_material["EdDSA"][0], plugins=[ProblemDetailsPlugin()])
    assert app.openapi_schema is not None

    assert canonical(cast("dict[str, Any]", app.openapi_schema.to_schema())) == canonical(documented_schema)


def test_detection_reads_the_plugin_class_not_its_name(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], documented_schema: Mapping[str, Any]
) -> None:
    """Matching on a name string would follow any impostor and miss a Litestar reorganization."""

    class ProblemDetailsPlugin:  # the impostor shares the name and nothing else
        config = ProblemDetailsConfig(enable_for_all_http_exceptions=True)

    app = build_documented_app(jwt_key_material["EdDSA"][0], plugins=[ProblemDetailsPlugin()])
    assert app.openapi_schema is not None

    assert canonical(cast("dict[str, Any]", app.openapi_schema.to_schema())) == canonical(documented_schema)


class _OAuthFailure(NamedTuple):
    """One OAuth domain failure, the status it answers with, and its sanitized message."""

    exception: Exception
    status: int
    detail: str


_OAUTH_FAILURES = (
    pytest.param(
        _OAuthFailure(InvalidOAuthCallback(), HTTP_401_UNAUTHORIZED, "OAuth callback is invalid"), id="invalid-callback"
    ),
    pytest.param(
        _OAuthFailure(
            OAuthProviderError(retry_after=30), HTTP_503_SERVICE_UNAVAILABLE, "OAuth provider is unavailable"
        ),
        id="provider-unavailable",
    ),
    pytest.param(
        _OAuthFailure(
            OAuthTransactionUnavailable(), HTTP_503_SERVICE_UNAVAILABLE, "OAuth transaction service is unavailable"
        ),
        id="transaction-unavailable",
    ),
    pytest.param(
        _OAuthFailure(AccountLinkError(), HTTP_409_CONFLICT, "OAuth account operation denied"), id="link-conflict"
    ),
    pytest.param(
        _OAuthFailure(OAuthAccountError(), HTTP_400_BAD_REQUEST, "OAuth account operation denied"), id="account-denied"
    ),
    pytest.param(
        _OAuthFailure(TooManyRequestsException(detail="Too many requests."), HTTP_429_TOO_MANY_REQUESTS, "Too many"),
        id="rate-limited-control",
    ),
)


def _application_error_format(request: Request[Any, Any, Any], exc: HTTPException) -> Response[Any]:
    """Stand in for an application that publishes an error format of its own."""
    del request
    return Response(
        content={"error": {"origin": "application", "status": exc.status_code, "message": exc.detail}},
        status_code=exc.status_code,
    )


async def _oauth_failure_response(failure: _OAuthFailure) -> Any:
    app = raising_oauth_app(failure.exception, exception_handlers={HTTPException: _application_error_format})
    async with AsyncTestClient(app=app) as client:
        return await client.get("/auth/oauth/example/callback", params={"code": "code", "state": "state"})


@pytest.mark.parametrize("failure", _OAUTH_FAILURES)
async def test_an_application_error_format_reaches_an_oauth_failure(failure: _OAuthFailure) -> None:
    """Answering a failure inside the route tree would silently override the application's own format."""
    response = await _oauth_failure_response(failure)

    assert response.status_code == failure.status
    assert response.json()["error"]["origin"] == "application"


@pytest.mark.parametrize("failure", _OAUTH_FAILURES)
async def test_an_oauth_failure_still_reveals_nothing_about_its_cause(failure: _OAuthFailure) -> None:
    """Routing a failure through the application must not widen what the caller learns."""
    response = await _oauth_failure_response(failure)
    body = response.text

    assert response.status_code == failure.status
    assert failure.detail in body
    assert type(failure.exception).__name__ not in body
    assert "Traceback" not in body


class _EnvelopeResponse(Response[Any]):
    """Stand in for the response class a presentation plugin installs."""


class _ApplicationError(msgspec.Struct):
    """Describe the body the example application's exception handler emits."""

    error: dict[str, object]


@get("/application/owned", response_class=_EnvelopeResponse, sync_to_thread=False)
def _application_owned_route() -> str:
    return "owned"


def _response_class_warnings(recorded: pytest.WarningsRecorder) -> list[str]:
    return [str(warning.message) for warning in recorded if "response class" in str(warning.message)]


def test_a_customized_response_class_warns_once_however_many_routes_it_reaches(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    """Every generated route resolves the same application-level class, so one warning says it all."""
    with pytest.warns(LitestarWarning) as recorded:
        build_documented_app(jwt_key_material["EdDSA"][0], response_class=_EnvelopeResponse)

    warnings = _response_class_warnings(recorded)
    assert len(warnings) == 1
    assert "_EnvelopeResponse" in warnings[0]


def test_a_complete_application_error_declaration_suppresses_the_response_class_warning(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], recwarn: pytest.WarningsRecorder
) -> None:
    """A complete declaration gives the application an accurate alternative to the warning."""
    build_documented_app(
        jwt_key_material["EdDSA"][0],
        response_class=_EnvelopeResponse,
        raised_error_schema=RaisedErrorSchema(_ApplicationError, "application/vnd.example.error+json"),
    )

    assert _response_class_warnings(recwarn) == []


@pytest.mark.parametrize("denial", _RAISED_DENIALS)
def test_an_application_declaration_restates_every_raised_denial(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], denial: _Denial
) -> None:
    """Every raised status shares the application-declared schema and media type."""
    app = build_documented_app(
        jwt_key_material["EdDSA"][0],
        raised_error_schema=RaisedErrorSchema(_ApplicationError, "application/vnd.example.error+json"),
    )
    assert app.openapi_schema is not None
    document = cast("dict[str, Any]", app.openapi_schema.to_schema())

    declared = _declared_body(document, denial.template, denial.method.lower(), str(denial.status))
    assert declared == ("application/vnd.example.error+json", document["components"]["schemas"]["_ApplicationError"])


def test_an_application_declaration_takes_precedence_over_problem_details_detection(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    """An explicit application contract is more precise than plugin inference."""
    app = build_documented_app(
        jwt_key_material["EdDSA"][0],
        raised_error_schema=RaisedErrorSchema(_ApplicationError, "application/vnd.example.error+json"),
        plugins=[ProblemDetailsPlugin(ProblemDetailsConfig(enable_for_all_http_exceptions=True))],
    )
    assert app.openapi_schema is not None
    document = cast("dict[str, Any]", app.openapi_schema.to_schema())

    declared = _declared_body(document, "/auth/sessions", "get", "401")
    assert declared == ("application/vnd.example.error+json", document["components"]["schemas"]["_ApplicationError"])


def test_the_default_configuration_says_nothing_about_response_classes(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], recwarn: pytest.WarningsRecorder
) -> None:
    """A warning nobody can act on is noise, and the framework default describes the document exactly."""
    build_documented_app(jwt_key_material["EdDSA"][0])

    assert _response_class_warnings(recwarn) == []


def test_a_route_the_application_owns_is_its_own_business(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]], recwarn: pytest.WarningsRecorder
) -> None:
    """This library documents the routes it generates and makes no claim about the rest."""
    build_documented_app(jwt_key_material["EdDSA"][0], route_handlers=[_application_owned_route])

    assert _response_class_warnings(recwarn) == []


def test_one_application_converting_leaves_the_next_one_alone(
    jwt_key_material: Mapping[str, tuple[bytes, bytes]],
) -> None:
    """The denial specifications are module-level and shared, so restating them per application must not stick."""
    build_documented_app(
        jwt_key_material["EdDSA"][0],
        plugins=[ProblemDetailsPlugin(ProblemDetailsConfig(enable_for_all_http_exceptions=True))],
    )
    later = build_documented_app(jwt_key_material["EdDSA"][0])
    assert later.openapi_schema is not None
    document = cast("dict[str, Any]", later.openapi_schema.to_schema())

    declared = _declared_body(document, "/auth/sessions", "get", "401")
    assert declared is not None
    assert declared == ("application/json", document["components"]["schemas"]["RouteError"])


def test_a_returned_body_keeps_its_own_typed_schema(documented_schema: Mapping[str, Any]) -> None:
    """Correcting the raised statuses must not touch a status a handler returns."""
    declared = {
        key: _declared_body(documented_schema, *key)[1].get("title")  # type: ignore[index]
        for key in _RETURNED_BODIES
    }

    assert declared == _RETURNED_BODIES
