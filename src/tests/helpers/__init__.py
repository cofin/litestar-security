"""Shared assertions for the whole test tree.

Imported as ``tests.helpers`` from both ``src/tests/unit/`` and
``src/tests/integration/``. This module imports nothing from
``tests.fixtures``: the dependency runs one way only, so a helper can never
require a fixture to be wired before it can be used.

``assert_validation_contract`` is the lever. 97 ``rejects_invalid*`` test
functions across 16 files build a valid keyword mapping, apply one override at a
time, and assert the constructor rejects each with one message family.
``ImproperlyConfiguredException`` and ``ValueError`` together account for more
than half of the suite's ``pytest.raises`` calls, so both are reachable through
the ``error`` parameter rather than through two helpers.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

import msgspec
import pytest

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence


def assert_validation_contract(
    factory: Callable[..., object],
    *,
    base: Mapping[str, object],
    overrides: Sequence[Mapping[str, object]],
    match: str,
    error: type[Exception] = ValueError,
) -> None:
    """Assert every override is rejected with one message family.

    Args:
        factory: Constructor under test.
        base: Keyword arguments that construct a valid instance.
        overrides: Each mapping is applied over ``base`` and must be rejected.
        match: Regex the raised message must match.
        error: Expected exception type.

    Raises:
        Failed: If an override constructs successfully instead of being
            rejected. This is ``pytest.fail.Exception``.
        AssertionError: If an override is rejected but its message does not
            match ``match``, so the family is wider than the test claims.
    """
    for override in overrides:
        with pytest.raises(error, match=match):
            factory(**{**base, **override})


def assert_no_secret_in(payload: object, *secrets: object) -> None:
    """Assert no secret appears anywhere in a rendered payload.

    Each secret is compared as text. A secret carrier exposing
    ``get_secret_value()`` is unwrapped first, so the wrapper and the value it
    guards are both checked against the same rendering.

    Args:
        payload: The value to render and search. Any object is accepted.
        secrets: The secrets that must not appear.

    Raises:
        AssertionError: If any secret appears in the rendered payload.
    """
    rendered = payload if isinstance(payload, str) else repr(payload)
    for secret in secrets:
        for value in _secret_values(secret):
            assert value not in rendered, f"secret leaked into payload: {value[:4]}..."


def assert_no_store(response: object) -> None:
    """Assert a response forbids caching.

    Args:
        response: A response exposing a ``headers`` mapping.

    Raises:
        AssertionError: If ``Cache-Control`` is absent or does not forbid storage.
    """
    headers = getattr(response, "headers", {})
    cache_control = headers.get("cache-control", headers.get("Cache-Control", ""))
    assert cache_control, "response carries no Cache-Control header"
    assert "no-store" in cache_control, f"Cache-Control does not forbid storage: {cache_control!r}"


def assert_denial(response: object, *, status: int, code: str | None = None) -> None:
    """Assert a response is the expected denial.

    Args:
        response: A response exposing ``status_code`` and, when ``code`` is
            given, a ``json()`` payload carrying a ``code`` member.
        status: The expected status code.
        code: The expected machine-readable denial code, when one is asserted.

    Raises:
        AssertionError: If the status or the denial code differs.
    """
    actual = getattr(response, "status_code", None)
    assert actual == status, f"expected status {status}, got {actual}"
    if code is None:
        return
    payload = response.json()
    assert isinstance(payload, Mapping), f"denial payload is not a mapping: {payload!r}"
    assert payload.get("code") == code, f"expected denial code {code!r}, got {payload.get('code')!r}"


def assert_wire_shape(struct: msgspec.Struct, expected_fields: Iterable[str]) -> None:
    """Assert a wire struct serializes to exactly the expected member names.

    Serialized member names are the OpenAPI component schema keys and therefore
    the generated client's field names, so a change here is a consumer-visible
    change.

    Args:
        struct: The wire struct to serialize.
        expected_fields: The member names the serialized form must carry, in
            any order.

    Raises:
        AssertionError: If the serialized member names differ.
    """
    serialized = msgspec.to_builtins(struct)
    assert isinstance(serialized, dict), f"wire struct did not serialize to a mapping: {serialized!r}"
    assert set(serialized) == set(expected_fields), (
        f"wire members {sorted(serialized)} do not match expected {sorted(expected_fields)}"
    )


def _secret_values(secret: object) -> tuple[str, ...]:
    reveal = getattr(secret, "get_secret_value", None)
    if callable(reveal):
        return (str(reveal()),)
    return (str(secret),)
