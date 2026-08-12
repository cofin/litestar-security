"""Smoke tests proving the shared fixture vocabulary is wired and usable.

Not a coverage contributor. This file exists so a chapter consuming the
vocabulary finds a working toolkit instead of debugging the toolkit: if a
fixture stops resolving, a factory stops building, or function scope stops
isolating, it fails here rather than halfway through a rewrite.

The integration collaborators are proved in the sibling file under
``src/tests/integration/`` -- a fixture defined in the integration conftest is
not visible from here.
"""

import ast
import pathlib
from datetime import timedelta

import msgspec
import pytest

from litestar_security.accounts import AESGCMSecretProtector, StoreRateLimiter, TokenPair
from litestar_security.testing import FakeClock, InMemoryOIDCSessionLogoutStore, InMemorySecurityBackend
from tests.fixtures import collaborators, corpora, factories
from tests.helpers import assert_validation_contract

# Fixture name -> the backend attribute the T5 mapping table says it returns.
BACKEND_DERIVED_FIXTURES = {
    "account_store": "accounts",
    "session_registry": "accounts",
    "refresh_family_store": "accounts",
    "api_key_store": "api_keys",
    "mfa_store": "mfa",
    "mfa_login_challenge_store": "mfa_login",
    "passkey_store": "passkeys",
    "webauthn_challenge_store": "challenges",
    "step_up_store": "step_up",
    "oauth_account_store": "oauth_accounts",
    "oauth_transaction_store": "oauth_transactions",
    "connect_token_store": "websocket_connect_tokens",
}

# Fixture name -> the type its docstring documents.
TYPED_FIXTURES = {
    "clock": FakeClock,
    "security_backend": InMemorySecurityBackend,
    "oidc_logout_store": InMemoryOIDCSessionLogoutStore,
    "rate_limiter": StoreRateLimiter,
    "secret_protector": AESGCMSecretProtector,
}

FACTORY_CLASSES = tuple(
    getattr(factories, name)
    for name in sorted(dir(factories))
    if name.endswith("Factory") and getattr(getattr(factories, name), "__module__", "") == factories.__name__
)

CORPUS_NAMES = (
    "ADVERSARIAL_TEXT",
    "IDENTIFIERS",
    "ARBITRARY_RUNTIME_VALUES",
    "JWT_LIKE_TOKENS",
    "JWT_DEPTH_BOMBS",
    "CSP_SOURCES",
    "PKCE_VERIFIERS",
    "HANDSHAKE_BYTES",
)

_HERE = pathlib.Path(__file__)
VOCABULARY_TEST_FILES = (_HERE, _HERE.parents[1] / "integration" / _HERE.name)


def anyio_marked_functions(path: pathlib.Path) -> list[str]:
    """Return the names of functions decorated with the anyio marker.

    Args:
        path: The test module to inspect.

    Returns:
        Every decorated function name, empty when the marker is absent.
    """
    module = ast.parse(path.read_text())
    marked = []
    for node in ast.walk(module):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute) and target.attr == "anyio":
                marked.append(node.name)
    return marked


# Populated by the two isolation tests below, which keep their stores alive so
# an identity comparison cannot be fooled by a recycled id.
_STORES_SEEN: list[object] = []


@pytest.mark.parametrize(("name", "expected"), sorted(TYPED_FIXTURES.items(), key=lambda item: item[0]))
def test_every_typed_fixture_resolves_with_its_documented_type(
    name: str, expected: type, request: pytest.FixtureRequest
) -> None:
    assert isinstance(request.getfixturevalue(name), expected)


@pytest.mark.parametrize(("name", "attribute"), sorted(BACKEND_DERIVED_FIXTURES.items(), key=lambda item: item[0]))
def test_every_derived_fixture_is_the_backend_store_it_claims(
    name: str, attribute: str, security_backend: InMemorySecurityBackend, request: pytest.FixtureRequest
) -> None:
    assert request.getfixturevalue(name) is getattr(security_backend, attribute)


def test_session_and_refresh_state_live_in_the_account_store(
    account_store: object, session_registry: object, refresh_family_store: object
) -> None:
    assert account_store is session_registry
    assert account_store is refresh_family_store


def test_clock_advances_and_the_backend_sees_it(clock: FakeClock, security_backend: InMemorySecurityBackend) -> None:
    assert security_backend.clock() == collaborators.FIXED_NOW
    clock.advance(timedelta(hours=1))
    assert security_backend.clock() == collaborators.FIXED_NOW + timedelta(hours=1)


def test_function_scope_isolates_first(clock: FakeClock, account_store: object) -> None:
    _STORES_SEEN.append(account_store)
    assert clock() == collaborators.FIXED_NOW
    clock.advance(timedelta(days=1))
    assert clock() == collaborators.FIXED_NOW + timedelta(days=1)


def test_function_scope_isolates_second(clock: FakeClock, account_store: object) -> None:
    # Whichever of the pair ran first advanced its own clock by a day. Reading
    # FIXED_NOW here is the proof that the advance did not leak, and a store
    # that is not identical to the other test's is the proof it was rebuilt.
    assert clock() == collaborators.FIXED_NOW
    assert all(account_store is not seen for seen in _STORES_SEEN)
    _STORES_SEEN.append(account_store)


@pytest.mark.parametrize("factory", FACTORY_CLASSES, ids=lambda factory: factory.__name__)
def test_every_wire_factory_builds(factory: type) -> None:
    built = factory.build()
    assert isinstance(built, msgspec.Struct)
    assert isinstance(built, factory.__model__)


def test_thirty_three_factories_cover_the_wire_layer_without_token_pair() -> None:
    assert len(FACTORY_CLASSES) == 33
    assert TokenPair not in {factory.__model__ for factory in FACTORY_CLASSES}


def test_token_pair_comes_from_its_hand_written_builder() -> None:
    pair = collaborators.build_token_pair()
    assert isinstance(pair, TokenPair)
    assert pair.refresh_token.startswith("rt_")


def test_an_asserted_field_is_passed_in_never_generated() -> None:
    # The generated values are arbitrary and their order changes under -n auto,
    # so anything a test asserts on is supplied explicitly to build().
    account = factories.LocalAccountFactory.build(account_id="acct-1")
    assert account.account_id == "acct-1"


def test_validation_contract_fails_when_an_override_constructs() -> None:
    with pytest.raises(pytest.fail.Exception):
        assert_validation_contract(dict, base={"name": "ok"}, overrides=[{"name": "also ok"}], match="never reached")


@pytest.mark.parametrize("name", CORPUS_NAMES)
def test_every_corpus_is_a_non_empty_tuple(name: str) -> None:
    corpus = getattr(corpora, name)
    assert isinstance(corpus, tuple)
    assert corpus


async def test_async_tests_need_no_marker(security_backend: InMemorySecurityBackend) -> None:
    # anyio_mode = "auto" runs this without a decorator. Awaiting a real backend
    # call is what makes that observable: if auto mode were dropped, the
    # coroutine would never be awaited and this assertion would stop running.
    assert await security_backend.accounts.find_for_login("nobody@example.com") is None


@pytest.mark.parametrize("path", VOCABULARY_TEST_FILES, ids=lambda path: path.parent.name)
def test_neither_file_reintroduces_the_anyio_marker(path: pathlib.Path) -> None:
    # Read as a syntax tree rather than as text: a source-text search would
    # match the marker name written in this very assertion.
    assert anyio_marked_functions(path) == []
