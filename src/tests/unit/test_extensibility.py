"""Cross-feature extension-boundary tests."""

import ast
import inspect
from importlib.metadata import metadata
from pathlib import Path
from typing import Protocol

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
