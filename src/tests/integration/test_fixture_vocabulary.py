"""Smoke tests for the integration half of the shared fixture vocabulary.

A fixture defined in ``src/tests/integration/conftest.py`` is invisible from
``src/tests/unit/``, so the three collaborators wired there are proved here
rather than in the unit sibling.
"""

import ast
import pathlib

import pytest

from litestar_security.testing import FakeOAuthHTTPTransport, FakeOAuthProvider, InMemoryWebSocketRevocationSource

TYPED_FIXTURES = {
    "oauth_provider": FakeOAuthProvider,
    "oauth_transport": FakeOAuthHTTPTransport,
    "revocation_source": InMemoryWebSocketRevocationSource,
}


@pytest.mark.parametrize(("name", "expected"), sorted(TYPED_FIXTURES.items(), key=lambda item: item[0]))
def test_every_integration_fixture_resolves_with_its_documented_type(
    name: str, expected: type, request: pytest.FixtureRequest
) -> None:
    assert isinstance(request.getfixturevalue(name), expected)


def test_the_oauth_provider_records_its_calls(oauth_provider: FakeOAuthProvider) -> None:
    assert oauth_provider.calls == []


def test_function_scope_gives_each_test_its_own_provider(oauth_provider: FakeOAuthProvider) -> None:
    # A provider carrying calls from an earlier test would mean the fixture is
    # shared, which is what its function scope exists to prevent.
    assert oauth_provider.calls == []


def test_this_file_does_not_reintroduce_the_anyio_marker() -> None:
    # Covered from the unit sibling too; kept here so this file stands alone.
    module = ast.parse(pathlib.Path(__file__).read_text())
    decorators = [
        decorator
        for node in ast.walk(module)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for decorator in node.decorator_list
    ]
    targets = [d.func if isinstance(d, ast.Call) else d for d in decorators]
    assert not [t for t in targets if isinstance(t, ast.Attribute) and t.attr == "anyio"]
