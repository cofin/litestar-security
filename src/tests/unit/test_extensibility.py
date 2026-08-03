"""Cross-feature extension-boundary tests."""

import ast
import inspect
import sys
from dataclasses import FrozenInstanceError
from importlib.metadata import metadata
from pathlib import Path
from subprocess import run
from threading import Event as ThreadEvent
from threading import Lock
from typing import Protocol

import pytest
from anyio import CancelScope, CapacityLimiter, Event, create_task_group, from_thread
from anyio.lowlevel import checkpoint

import litestar_security.config as config_module
import litestar_security.workers as workers_module
from litestar_security.accounts import (
    LoginMethodStore,
    MFAStore,
    PasskeyStore,
    PasswordCredentialStore,
    RefreshTokenFamilyStore,
    RegistrationStore,
    WebAuthnChallengeStore,
)
from litestar_security.providers.api_key import APIKeyStore
from litestar_security.providers.oauth import OAuthAccountStore, OAuthTransactionStore
from litestar_security.websocket import WebSocketTicketStore

_PACKAGE_ROOT = Path(__file__).parents[2] / "litestar_security"
_FORBIDDEN_RUNTIME_ROOTS = frozenset({
    "advanced_alchemy",
    "aioboto3",
    "aiomysql",
    "aiosqlite",
    "asyncpg",
    "boto3",
    "google.cloud",
    "litestar_mcp",
    "motor",
    "pymongo",
    "redis",
    "sqlalchemy",
    "sqlspec",
})
_ATOMIC_METHODS = {
    RegistrationStore: ("register",),
    PasswordCredentialStore: ("compare_and_replace_password", "replace_password_and_bump_epoch"),
    LoginMethodStore: ("revoke_login_method",),
    RefreshTokenFamilyStore: ("rotate",),
    MFAStore: ("advance_totp_counter", "consume_recovery_code"),
    WebAuthnChallengeStore: ("consume",),
    PasskeyStore: ("record_assertion",),
    OAuthTransactionStore: ("consume",),
    OAuthAccountStore: ("unlink_identity",),
    APIKeyStore: ("rotate",),
    WebSocketTicketStore: ("consume",),
}


def _imported_module(node: ast.Import | ast.ImportFrom) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        return tuple(alias.name for alias in node.names)
    if node.level and node.module == "testing":
        return ("litestar_security.testing",)
    return () if node.module is None else (node.module,)


def test_runtime_source_has_no_reverse_integration_dependencies() -> None:
    violations: list[str] = []
    for source_path in sorted(_PACKAGE_ROOT.rglob("*.py")):
        if source_path.name == "testing.py":
            continue
        tree = ast.parse(source_path.read_text(), filename=str(source_path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            violations.extend(
                f"{source_path.relative_to(_PACKAGE_ROOT)} imports {imported}"
                for imported in _imported_module(node)
                if imported == "litestar_security.testing"
                or any(imported == root or imported.startswith(f"{root}.") for root in _FORBIDDEN_RUNTIME_ROOTS)
            )

    assert violations == []


def test_runtime_distribution_has_no_adapter_dependencies() -> None:
    requirements = tuple(metadata("litestar-security").get_all("Requires-Dist") or ())

    assert not any(
        requirement.lower().replace("-", "_").startswith(tuple(_FORBIDDEN_RUNTIME_ROOTS))
        for requirement in requirements
    )


def test_atomic_protocols_are_feature_owned_and_async() -> None:
    for protocol, methods in _ATOMIC_METHODS.items():
        assert issubclass(protocol, Protocol)
        assert protocol.__module__ != "litestar_security.testing"
        for method in methods:
            assert inspect.iscoroutinefunction(protocol.__dict__[method])


def test_capability_protocols_do_not_expose_generic_persistence_methods() -> None:
    for protocol in _ATOMIC_METHODS:
        assert not {"add", "update", "delete", "query", "transaction", "connection"}.intersection(protocol.__dict__)


def test_blocking_integration_marker_is_public_configuration() -> None:
    marker = config_module.BlockingIntegration(object())

    assert hasattr(config_module, "BlockingIntegration")
    assert marker.__slots__ == ("implementation",)
    with pytest.raises(FrozenInstanceError):
        marker.implementation = object()  # type: ignore[misc]


def test_package_root_does_not_eagerly_import_testing_surface() -> None:
    script = (
        "import sys; import litestar_security; "
        "assert 'litestar_security.testing' not in sys.modules; "
        "assert not hasattr(litestar_security, 'InMemorySecurityBackend')"
    )

    result = run(  # noqa: S603 - fixed interpreter-only import isolation
        [sys.executable, "-I", "-c", script], check=False, capture_output=True, text=True
    )

    assert result.returncode == 0, result.stderr


def test_normalized_runtime_has_no_per_call_awaitability_branch() -> None:
    violations = [
        str(source_path.relative_to(_PACKAGE_ROOT))
        for source_path in sorted(_PACKAGE_ROOT.rglob("*.py"))
        if "inspect.isawaitable" in source_path.read_text()
    ]

    assert violations == []


@pytest.mark.anyio
async def test_blocking_call_runner_enforces_its_capacity_limit() -> None:
    runner = workers_module.BlockingCallRunner(limiter=CapacityLimiter(1))
    first_started = Event()
    release = ThreadEvent()
    state_lock = Lock()
    active = 0
    maximum_active = 0
    completed: list[int] = []

    def operation(value: int) -> int:
        nonlocal active, maximum_active
        with state_lock:
            active += 1
            maximum_active = max(maximum_active, active)
        if value == 1:
            from_thread.run_sync(first_started.set)
        release.wait()
        with state_lock:
            active -= 1
        return value

    async def run(value: int) -> None:
        completed.append(await runner.run(operation, value))

    async with create_task_group() as task_group:
        task_group.start_soon(run, 1)
        await first_started.wait()
        task_group.start_soon(run, 2)
        await checkpoint()
        release.set()

    assert maximum_active == 1
    assert sorted(completed) == [1, 2]


@pytest.mark.anyio
async def test_blocking_call_runner_finishes_in_flight_mutation_before_cancellation() -> None:
    runner = workers_module.BlockingCallRunner(limiter=CapacityLimiter(1))
    started = Event()
    caller_finished = Event()
    release = ThreadEvent()
    scopes: list[CancelScope] = []
    mutations: list[str] = []

    def mutation() -> None:
        from_thread.run_sync(started.set)
        release.wait()
        mutations.append("committed")

    async def call() -> None:
        try:
            with CancelScope() as scope:
                scopes.append(scope)
                await runner.run(mutation)
        finally:
            caller_finished.set()

    async with create_task_group() as task_group:
        task_group.start_soon(call)
        await started.wait()
        scopes[0].cancel()
        await checkpoint()
        assert not caller_finished.is_set()
        release.set()

    assert mutations == ["committed"]
    assert caller_finished.is_set()
