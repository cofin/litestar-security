"""Unit tests for security and wire configuration."""

from dataclasses import FrozenInstanceError, fields
from importlib import import_module
from typing import Any, cast

import msgspec
import pytest
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security
from litestar_security.schema import WirePolicy


def test_security_config_declares_its_fields_in_order() -> None:
    config = litestar_security.SecurityConfig()

    expected_fields = (
        "slots",
        "mechanisms",
        "max_openapi_combinations",
        "external_csrf",
        "exclude",
        "require_default",
        "local_auth",
        "local_jwks",
        "oauth",
        "protected_resource",
        "mfa",
        "passkeys",
        "api_key",
        "iap",
        "service_token",
        "headers",
        "websocket",
        "authorization_resolver",
        "jwks_providers",
        "jwks_warmup_failure",
        "wire_rename",
        "wire_forbid_unknown_fields",
    )
    assert tuple(field.name for field in fields(config)) == expected_fields


def test_security_config_wire_casing_defaults_to_snake_case_and_strict() -> None:
    config = litestar_security.SecurityConfig()

    assert config.wire_rename is None
    assert config.wire_forbid_unknown_fields is True
    assert config.wire_policy() == WirePolicy()


@pytest.mark.parametrize("rename", ["lower", "upper", "camel", "pascal", "kebab", str.upper])
def test_security_config_accepts_every_supported_wire_rename_strategy(rename: object) -> None:
    config = litestar_security.SecurityConfig(wire_rename=cast("Any", rename))

    assert config.wire_policy() == WirePolicy(rename=cast("Any", rename))


@pytest.mark.parametrize("rename", ["snake", "", object(), 5, True])
def test_security_config_rejects_an_unsupported_wire_rename_strategy(rename: object) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Wire rename strategy"):
        litestar_security.SecurityConfig(wire_rename=cast("Any", rename))


@pytest.mark.parametrize("forbid", [object(), 1, None])
def test_security_config_rejects_a_non_boolean_wire_strictness(forbid: object) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Wire unknown-field policy"):
        litestar_security.SecurityConfig(wire_forbid_unknown_fields=cast("Any", forbid))


def test_wire_policy_is_frozen_slotted_and_hashable() -> None:
    policy = WirePolicy(rename="camel", forbid_unknown_fields=False)

    assert {policy: "cached"}[WirePolicy(rename="camel", forbid_unknown_fields=False)] == "cached"
    assert not hasattr(policy, "__dict__")
    with pytest.raises(FrozenInstanceError):
        cast("Any", policy).rename = "kebab"


def test_security_config_rejects_invalid_jwks_warmup_failure_mode() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="JWKS warmup failure mode"):
        litestar_security.SecurityConfig(jwks_warmup_failure="invalid")  # type: ignore[arg-type]


def test_security_config_rejects_invalid_headers_config() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Browser security headers"):
        litestar_security.SecurityConfig(headers=object())  # type: ignore[arg-type]


@pytest.mark.parametrize("exclude", [object(), 5, [object()], ["/ok", 5], (name for name in ())])
def test_security_config_rejects_invalid_exclude_patterns(exclude: object) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Route exclusion patterns"):
        litestar_security.SecurityConfig(exclude=cast("Any", exclude))


@pytest.mark.parametrize(
    ("exclude", "expected"),
    [(None, None), ("^/static", "^/static"), (["^/static", "^/assets"], ("^/static", "^/assets"))],
)
def test_security_config_freezes_exclude_patterns(exclude: object, expected: object) -> None:
    assert litestar_security.SecurityConfig(exclude=cast("Any", exclude)).exclude == expected


def test_every_wire_schema_in_the_tree_shares_one_casing_and_strictness_policy() -> None:
    import_module("litestar_security.accounts")
    import_module("litestar_security.providers.oauth")

    def descendants(base: type) -> set[type]:
        found: set[type] = set()
        for subclass in base.__subclasses__():
            found.add(subclass)
            found |= descendants(subclass)
        return found

    schemas = descendants(litestar_security.WireStruct)
    # A schema that must tolerate members it does not model states so on itself and
    # is listed here with the reason.
    tolerant = {
        "RouteError": "Litestar renders this body, and an application exception handler may add members.",
        "ProblemDetail": "RFC 9457 permits extension members, and Litestar renders this body.",
    }

    assert len(schemas) >= 30
    for schema in schemas:
        assert schema.__struct_config__.frozen, schema.__name__
        assert schema.__struct_encode_fields__ == schema.__struct_fields__, schema.__name__
        strict = schema.__struct_config__.forbid_unknown_fields
        assert strict is (schema.__name__ not in tolerant), schema.__name__


def test_wire_struct_is_frozen_strict_and_never_renamed() -> None:
    class _Probe(litestar_security.WireStruct, frozen=True):
        account_identifier: str
        step_up_grant: str

    probe = _Probe(account_identifier="user@example.com", step_up_grant="grant")

    assert _Probe.__struct_config__.frozen
    assert _Probe.__struct_config__.forbid_unknown_fields
    assert _Probe.__struct_encode_fields__ == _Probe.__struct_fields__
    assert msgspec.json.encode(probe) == b'{"account_identifier":"user@example.com","step_up_grant":"grant"}'
    with pytest.raises(AttributeError):
        probe.account_identifier = "other@example.com"  # type: ignore[misc]


def test_wire_struct_subclasses_reject_unknown_and_camel_case_members() -> None:
    class _Probe(litestar_security.WireStruct, frozen=True):
        account_identifier: str

    with pytest.raises(msgspec.ValidationError, match="unknown field"):
        msgspec.json.decode(b'{"account_identifier":"user@example.com","extra":1}', type=_Probe)
    with pytest.raises(msgspec.ValidationError, match="accountIdentifier"):
        msgspec.json.decode(b'{"accountIdentifier":"user@example.com"}', type=_Probe)


def test_wire_struct_subclasses_may_relax_strictness_without_losing_casing_or_immutability() -> None:
    class _Tolerant(litestar_security.WireStruct, frozen=True, forbid_unknown_fields=False):
        account_identifier: str
        return_to: str = "/"

    decoded = msgspec.json.decode(
        b'{"account_identifier":"user@example.com","return_to":"/dashboard","unrecognized":1}', type=_Tolerant
    )

    assert decoded.return_to == "/dashboard"
    assert _Tolerant.__struct_config__.frozen
    assert not _Tolerant.__struct_config__.forbid_unknown_fields
    assert _Tolerant.__struct_encode_fields__ == _Tolerant.__struct_fields__
