"""One contract for the public value surface: frozen, slotted, and classified.

Reading the class rather than an instance is what makes this total. A check that
assigns to a field has to build the type first, which caps it at the handful that
construct without arguments; ``__dataclass_params__`` and ``cls.__dict__`` cover
every public type regardless. The partition is asserted to be exact, so a new
public dataclass that is neither frozen nor listed in ``MUTABLE_SERVICES`` fails
here until someone classifies it.

``MUTABLE_SERVICES`` names the public dataclasses that hold mutable state by
design (services, stores, coordinators, a runner, a buffer, the root config, and
a test-kit barrier) by qualified path so a rename is a visible failure rather
than a silent reclassification; everything else public must be frozen.

``PRIVATE_RUNTIME_NAMES`` enumerates runtime middlewares, plans, and evaluators
that must remain unexported across the flat re-export layout so callers never
depend on internal execution shapes.

``FROZEN_SAMPLE`` captures frozen dataclasses and ``msgspec.Struct`` values
(including ``LifecycleAccepted``) that construct from bare or simple calls so
runtime mutation and slot enforcement verify both ``FrozenInstanceError`` and
``AttributeError`` paths alongside the class-level sweep.
"""

import dataclasses
import importlib
from dataclasses import FrozenInstanceError

import msgspec
import pytest

import litestar_security
from litestar_security import Principal, any_of, authentication
from litestar_security.accounts import LifecycleAccepted, PasswordPolicy
from litestar_security.headers import SecurityHeadersConfig
from litestar_security.schema import WirePolicy
from litestar_security.websocket import WebSocketSecurityConfig
from litestar_security.workers import BlockingIntegration

MODULES: tuple[str, ...] = (
    "litestar_security",
    "litestar_security.accounts",
    "litestar_security.accounts.controllers",
    "litestar_security.authentication",
    "litestar_security.config",
    "litestar_security.context",
    "litestar_security.guards",
    "litestar_security.headers",
    "litestar_security.providers",
    "litestar_security.providers.api_key",
    "litestar_security.providers.iap",
    "litestar_security.providers.jwks",
    "litestar_security.providers.jwt",
    "litestar_security.providers.oauth",
    "litestar_security.providers.oidc",
    "litestar_security.schema",
    "litestar_security.testing",
    "litestar_security.websocket",
    "litestar_security.workers",
)

MUTABLE_SERVICES: frozenset[str] = frozenset({
    "litestar_security.InMemoryWebSocketConnectTokenStore",
    "litestar_security.SecurityConfig",
    "litestar_security.accounts.MFAService",
    "litestar_security.accounts.NativeSessionAuth",
    "litestar_security.accounts.PasskeyService",
    "litestar_security.accounts.StepUpService",
    "litestar_security.accounts.StoreRateLimiter",
    "litestar_security.providers.APIKeyService",
    "litestar_security.providers.BufferedAPIKeyUsage",
    "litestar_security.providers.HttpxJWKSFetcher",
    "litestar_security.providers.JWKSCacheCoordinator",
    "litestar_security.testing.BackendBarrier",
    "litestar_security.workers.BlockingCallRunner",
})

PRIVATE_RUNTIME_NAMES: tuple[str, ...] = (
    "OwnedSessionBackend",
    "SecurityMiddleware",
    "SecurityMiddlewareWrapper",
    "SecurityRuntimeConfig",
    "SecurityRuntimePlan",
    "_AuthenticationEvaluator",
)

REMOVED_PUBLIC_NAMES: frozenset[str] = frozenset({
    "APIKeyRecord",
    "AssertionRecordStatus",
    "ConsumeOutcome",
    "ConsumeStatus",
    "InvalidWebAuthnResponseError",
    "JWKSCacheEntry",
    "JWKSFetchRequest",
    "JWKSFetchResponse",
    "LocalAccountRecord",
    "OAuthHTTPRequest",
    "OAuthLoginResolution",
    "OAuthRevocationRetryStore",
    "OAuthRouteService",
    "OAuthRouteStatus",
    "PasskeyRecord",
    "RequestAuthenticator",
    "require_all_of",
    "require_any_of",
    "require_assurance",
    "require_at_least",
    "require_authenticated",
    "require_capability",
    "require_one_of",
    "require_role",
    "require_scope",
    "require_team_role",
    "require_tenant",
    "RouteStatus",
    "SessionRecord",
    "StepUpRecord",
    "TokenVault",
    "WebSocketConnectTokenRecord",
})
FORBIDDEN_CLASS_SUFFIXES: tuple[str, ...] = ("Record", "Request", "Response", "Result")


def _public_classes() -> tuple[tuple[str, type], ...]:
    """Collect every class the public modules export.

    Returns:
        One ``(qualified name, class)`` pair per distinct class, ordered by name.
        The flat re-export layout means one class reaches several modules under
        different paths, so entries are deduplicated by identity and the first
        qualified name wins.
    """
    collected: dict[int, tuple[str, type]] = {}
    for module_name in MODULES:
        module = importlib.import_module(module_name)
        for name in module.__all__:
            value = getattr(module, name)
            if isinstance(value, type):
                collected.setdefault(id(value), (f"{module_name}.{name}", value))
    return tuple(sorted(collected.values(), key=lambda entry: entry[0]))


PUBLIC_CLASSES = _public_classes()
PUBLIC_DATACLASSES = tuple((name, cls) for name, cls in PUBLIC_CLASSES if dataclasses.is_dataclass(cls))
FROZEN_EXPECTED = tuple(
    (name, cls)
    for name, cls in PUBLIC_CLASSES
    if (dataclasses.is_dataclass(cls) and name not in MUTABLE_SERVICES) or issubclass(cls, msgspec.Struct)
)

FROZEN_SAMPLE: tuple[tuple[str, object, str], ...] = (
    ("AssuranceRequirement", any_of("a"), "requirements"),
    ("BlockingIntegration", BlockingIntegration(object()), "implementation"),
    ("PasswordPolicy", PasswordPolicy(), "minimum_length"),
    ("Principal", Principal(id="account-1"), "id"),
    ("SecurityHeadersConfig", SecurityHeadersConfig(), "static"),
    ("WebSocketSecurityConfig", WebSocketSecurityConfig(), "allowed_origins"),
    ("WirePolicy", WirePolicy(), "rename"),
    ("LifecycleAccepted", LifecycleAccepted(), "detail"),
)


@pytest.mark.parametrize(("name", "cls"), FROZEN_EXPECTED, ids=[name for name, _ in FROZEN_EXPECTED])
def test_public_value_types_are_frozen(name: str, cls: type) -> None:
    if issubclass(cls, msgspec.Struct):
        assert cls.__struct_config__.frozen, f"{name} is a public Struct and must be frozen"
    else:
        assert cls.__dataclass_params__.frozen, f"{name} is a public value type and must be frozen"


@pytest.mark.parametrize(("name", "cls"), PUBLIC_DATACLASSES, ids=[name for name, _ in PUBLIC_DATACLASSES])
def test_public_dataclasses_declare_their_own_slots(name: str, cls: type) -> None:
    """Require every public dataclass to declare ``__slots__`` directly.

    ``slotscheck`` validates that slotted classes have no unslotted bases rather
    than requiring ``__slots__`` to exist, making this explicit declaration check
    complementary.
    """
    assert "__slots__" in cls.__dict__, f"{name} must declare its own __slots__"


def test_mutable_service_list_is_exact() -> None:
    unfrozen = {name for name, cls in PUBLIC_DATACLASSES if not cls.__dataclass_params__.frozen}

    assert unfrozen == MUTABLE_SERVICES


@pytest.mark.parametrize(
    ("instance", "field"),
    [(instance, field) for _, instance, field in FROZEN_SAMPLE],
    ids=[name for name, _, _ in FROZEN_SAMPLE],
)
def test_frozen_instances_reject_assignment(instance: object, field: str) -> None:
    """Verify sampled frozen dataclasses and structs reject mutation and ``__dict__``.

    Frozen dataclasses raise ``FrozenInstanceError`` while frozen ``msgspec.Struct``
    instances such as ``LifecycleAccepted`` raise ``AttributeError``, and omitting
    ``__dict__`` at runtime proves every base class is slotted too.
    """
    with pytest.raises((FrozenInstanceError, AttributeError)):
        setattr(instance, field, object())
    assert not hasattr(instance, "__dict__")
    with pytest.raises((AttributeError, TypeError)):
        instance.attribute_that_was_never_declared = True  # type: ignore[attr-defined]


@pytest.mark.parametrize("module_name", MODULES)
def test_public_exports_resolve_and_hide_private_names(module_name: str) -> None:
    """Verify ``__all__`` resolves cleanly and exports only public names or dunders.

    Package dunders such as ``__project__`` and ``__version__`` are legitimately
    exported, whereas single-leading-underscore names must remain private.
    """
    module = importlib.import_module(module_name)

    assert isinstance(module.__all__, tuple)
    for name in module.__all__:
        assert hasattr(module, name), f"{module_name}.__all__ names {name}, which does not resolve"
        assert not (name.startswith("_") and not name.startswith("__")), f"{module_name} exports private {name}"


@pytest.mark.parametrize("module_name", MODULES)
def test_public_exports_are_sorted(module_name: str) -> None:
    module = importlib.import_module(module_name)

    expected = tuple(sorted(module.__all__, key=lambda name: (not name.isupper(), name[0].islower(), name)))
    assert module.__all__ == expected, f"{module_name}.__all__ must be sorted"


@pytest.mark.parametrize("module_name", MODULES)
def test_public_exports_contain_no_removed_or_generic_record_names(module_name: str) -> None:
    module = importlib.import_module(module_name)

    for name in module.__all__:
        assert name not in REMOVED_PUBLIC_NAMES, f"{module_name} still exports removed name {name}"
        value = getattr(module, name)
        if isinstance(value, type):
            assert not name.endswith(FORBIDDEN_CLASS_SUFFIXES), f"{module_name} exports generic class name {name}"


def test_private_runtime_names_are_not_exported() -> None:
    for name in PRIVATE_RUNTIME_NAMES:
        assert not hasattr(litestar_security, name), f"litestar_security leaks {name}"
        assert name not in authentication.__all__, f"litestar_security.authentication exports {name}"
