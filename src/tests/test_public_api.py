import sys
from dataclasses import fields

import litestar_security

_PUBLIC_API = (
    "Authenticated",
    "AuthenticationEvidence",
    "AuthenticationMechanism",
    "AuthenticationOutcome",
    "AuthenticationRegistry",
    "AuthorizationSnapshot",
    "CredentialExtraction",
    "CredentialRestrictions",
    "CredentialSlot",
    "CurrentUser",
    "IdentityResolver",
    "InvalidCredentials",
    "LitestarSessionHandle",
    "NoCredentials",
    "NullSessionHandle",
    "PresentedCredential",
    "Principal",
    "PrincipalDependency",
    "RequestAuthenticator",
    "SecurityConfig",
    "SecurityContext",
    "SecurityContextDependency",
    "SecurityPlugin",
    "SessionHandle",
    "SessionPersistenceUnavailableError",
    "SessionUnavailableError",
    "VerificationUnavailable",
    "__project__",
    "__version__",
)


def test_package_root_exports_foundational_contract() -> None:
    assert litestar_security.__all__ == _PUBLIC_API
    assert all(hasattr(litestar_security, name) for name in _PUBLIC_API)
    assert litestar_security.__project__ == "litestar-security"
    assert litestar_security.__version__ == "0.1.0"


def test_compiled_runtime_helpers_are_not_root_exports() -> None:
    assert not hasattr(litestar_security, "OwnedSessionBackend")
    assert not hasattr(litestar_security, "SecurityMiddleware")
    assert not hasattr(litestar_security, "SecurityMiddlewareWrapper")
    assert not hasattr(litestar_security, "SecurityRuntimeConfig")
    assert not hasattr(litestar_security, "SecurityRuntimePlan")
    assert not hasattr(litestar_security, "_AuthenticationEvaluator")


def test_security_config_is_typed_and_slotted() -> None:
    config = litestar_security.SecurityConfig()

    assert tuple(field.name for field in fields(config)) == (
        "slots",
        "mechanisms",
        "require_default",
        "session_backend",
        "plan_lookup",
    )
    assert config.__slots__ == ("slots", "mechanisms", "require_default", "session_backend", "plan_lookup")
    assert not hasattr(config, "__dict__")


def test_root_import_has_no_provider_database_cache_or_crypto_dependencies() -> None:
    forbidden_roots = ("advanced_alchemy", "authlib", "cryptography", "jwt", "redis", "sqlalchemy", "sqlspec")

    assert not {module_name for module_name in sys.modules if module_name.split(".", maxsplit=1)[0] in forbidden_roots}
    assert not any(module_name.startswith("litestar_security.providers") for module_name in sys.modules)
