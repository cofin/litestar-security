import pytest

from litestar_security.context import (
    LitestarSessionHandle,
    NullSessionHandle,
    Principal,
    SecurityContext,
    SessionHandle,
    SessionPersistenceUnavailableError,
    SessionUnavailableError,
)


def test_native_http_session_supports_mapping_operations() -> None:
    scope = {"type": "http", "session": {"existing": "value"}}
    handle = LitestarSessionHandle(scope=scope)  # type: ignore[arg-type]

    assert isinstance(handle, SessionHandle)
    assert handle.is_available
    assert handle.can_persist
    assert handle.get("existing") == "value"
    assert handle.get("missing", "default") == "default"

    handle.set("new", 42)
    assert handle.pop("new") == 42
    assert handle.pop("missing", "default") == "default"

    handle.clear()
    assert scope["session"] == {}


def test_native_handle_reads_replaced_scope_session() -> None:
    scope = {"type": "http", "session": {"value": "old"}}
    handle = LitestarSessionHandle(scope=scope)  # type: ignore[arg-type]

    scope["session"] = {"value": "new"}

    assert handle.get("value") == "new"


def test_anonymous_context_retains_existing_session() -> None:
    scope = {"type": "http", "session": {"cart": ["item-1"]}}
    handle = LitestarSessionHandle(scope=scope)  # type: ignore[arg-type]

    context = SecurityContext(session=handle)
    principal = Principal[object].anonymous()

    assert not principal.is_authenticated
    assert context.session.get("cart") == ["item-1"]
    assert scope["session"] == {"cart": ["item-1"]}


def test_null_session_reads_defaults_and_rejects_mutations() -> None:
    handle = NullSessionHandle()

    assert isinstance(handle, SessionHandle)
    assert not handle.is_available
    assert not handle.can_persist
    assert handle.get("missing") is None
    assert handle.get("missing", "default") == "default"
    assert handle.pop("missing", "default") == "default"
    with pytest.raises(SessionUnavailableError, match="Session storage is unavailable"):
        handle.set("key", "value")
    with pytest.raises(SessionUnavailableError, match="Session storage is unavailable"):
        handle.clear()


def test_native_handle_rejects_access_when_session_disappears() -> None:
    scope = {"type": "http", "session": {}}
    handle = LitestarSessionHandle(scope=scope)  # type: ignore[arg-type]
    del scope["session"]

    assert not handle.is_available
    assert not handle.can_persist
    with pytest.raises(SessionUnavailableError, match="Session storage is unavailable"):
        handle.get("missing")
    with pytest.raises(SessionUnavailableError, match="Session storage is unavailable"):
        handle.set("key", "value")
    with pytest.raises(SessionUnavailableError, match="Session storage is unavailable"):
        handle.pop("missing")
    with pytest.raises(SessionUnavailableError, match="Session storage is unavailable"):
        handle.clear()


def test_websocket_native_session_is_read_only() -> None:
    scope = {"type": "websocket", "session": {"existing": "value"}}
    handle = LitestarSessionHandle(scope=scope)  # type: ignore[arg-type]

    assert handle.is_available
    assert not handle.can_persist
    assert handle.get("existing") == "value"
    with pytest.raises(SessionPersistenceUnavailableError, match="cannot persist"):
        handle.set("key", "value")
    with pytest.raises(SessionPersistenceUnavailableError, match="cannot persist"):
        handle.pop("existing")
    with pytest.raises(SessionPersistenceUnavailableError, match="cannot persist"):
        handle.clear()
