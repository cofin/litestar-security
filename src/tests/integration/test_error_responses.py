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

import pytest
from litestar import Litestar
from litestar.status_codes import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED
from litestar.testing import TestClient

from tests.integration.test_openapi_document import build_documented_app


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
            HTTP_400_BAD_REQUEST,
        ),
        id="token-400",
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
    ("/auth/mfa/totp/{method_id}/remove", "post", "200"): "RouteStatus",
    ("/auth/mfa/totp/{method_id}/remove", "post", "409"): "RouteStatus",
    ("/auth/passkeys/{credential_id}/remove", "post", "409"): "RouteStatus",
    ("/auth/password/recovery", "post", "202"): "LifecycleAccepted",
    ("/auth/sessions", "get", "200"): "LocalSessionList",
    ("/auth/oauth/{provider}/revoke", "post", "200"): "OAuthRouteStatus",
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


@pytest.mark.parametrize("denial", _RAISED_DENIALS)
def test_a_documented_denial_declares_every_member_the_wire_sends(
    documented_app: Litestar, documented_schema: Mapping[str, Any], denial: _Denial
) -> None:
    """A member the wire always sends but the document never declares is a member no client can read."""
    with TestClient(app=documented_app) as client:
        request: dict[str, Any] = {"follow_redirects": False}
        if denial.body is not None:
            request["json"] = denial.body
        response = client.request(denial.method, denial.path, **request)

    assert response.status_code == denial.status
    payload = response.json()
    declared = _declared_body(documented_schema, denial.template, denial.method.lower(), str(denial.status))
    assert declared is not None, f"{denial.method} {denial.template} documents no body for {denial.status}"
    media_type, schema = declared

    assert media_type == response.headers["content-type"].split(";")[0]
    undeclared = sorted(set(payload) - set(schema.get("properties", {})))
    assert not undeclared, f"{denial.path} sends undeclared members {undeclared} against {schema.get('title')}"
    missing = sorted(set(schema.get("required", ())) - set(payload))
    assert not missing, f"{denial.path} omits required members {missing} of {schema.get('title')}"


def test_a_returned_body_keeps_its_own_typed_schema(documented_schema: Mapping[str, Any]) -> None:
    """Correcting the raised statuses must not touch a status a handler returns."""
    declared = {
        key: _declared_body(documented_schema, *key)[1].get("title")  # type: ignore[index]
        for key in _RETURNED_BODIES
    }

    assert declared == _RETURNED_BODIES
