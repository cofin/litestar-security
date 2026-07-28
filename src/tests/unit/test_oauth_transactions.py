"""OAuth transaction and browser-binding contracts."""

from __future__ import annotations

import asyncio
from base64 import urlsafe_b64decode
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, cast

import pytest
from litestar.exceptions import ImproperlyConfiguredException

from litestar_security.providers.oauth import (
    InvalidOAuthCallback,
    MemoryOAuthTransactionStore,
    OAuthOperation,
    OAuthRedirectPolicy,
    OAuthTransaction,
    OAuthTransactionService,
    OAuthTransactionUnavailable,
    ProtectedOAuthSecret,
    SecretStr,
    oauth_binding_cookie,
    pkce_s256,
)

if TYPE_CHECKING:
    from collections.abc import Callable


_NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)
_PEPPER = b"p" * 32
_CALLBACK = "https://app.example/auth/google/callback"


@dataclass(slots=True)
class _Protector:
    fail: bool = False
    active_key_version: str = "test-key"

    async def protect(self, secret: bytes, *, associated_data: bytes) -> ProtectedOAuthSecret:
        del associated_data
        if self.fail:
            message = "secret protect detail"
            raise RuntimeError(message)
        return ProtectedOAuthSecret(
            ciphertext=bytes(value ^ 0xA5 for value in secret), key_version=self.active_key_version
        )

    async def unprotect(self, protected: ProtectedOAuthSecret, *, associated_data: bytes) -> bytes:
        del associated_data
        if self.fail:
            message = "secret unprotect detail"
            raise RuntimeError(message)
        return bytes(value ^ 0xA5 for value in protected.ciphertext)


def _service(
    *, protector: _Protector | None = None, entropy: Callable[[int], bytes] | None = None
) -> OAuthTransactionService:
    protector = protector or _Protector()
    store = MemoryOAuthTransactionStore(protector=protector)
    return OAuthTransactionService(
        store=store,
        pepper=_PEPPER,
        redirects=OAuthRedirectPolicy(
            callback_uris={"google": frozenset({_CALLBACK})},
            return_to=frozenset({"/", "/settings/security", "https://app.example/account"}),
        ),
        entropy=entropy,
    )


def _decode_secret(value: SecretStr) -> bytes:
    encoded = value.get_secret_value()
    return urlsafe_b64decode(f"{encoded}{'=' * (-len(encoded) % 4)}")


def _transaction() -> OAuthTransaction:
    return OAuthTransaction(
        state_digest=b"s" * 32,
        binding_digest=b"b" * 32,
        operation=OAuthOperation.LOGIN,
        provider="google",
        expected_issuer="https://accounts.google.com",
        redirect_uri=_CALLBACK,
        return_to="/",
        requested_scopes=frozenset({"openid"}),
        pkce_verifier=SecretStr("v" * 43),
        nonce=SecretStr("n" * 43),
        account_id="account-1",
        session_binding="session-1",
        expires_at=_NOW + timedelta(minutes=10),
    )


@pytest.mark.anyio
async def test_start_generates_independent_256_bit_material_and_s256_pkce() -> None:
    calls: list[int] = []

    def entropy(length: int) -> bytes:
        calls.append(length)
        return bytes([len(calls)]) * length

    start = await _service(entropy=entropy).start(
        operation=OAuthOperation.LOGIN,
        provider="google",
        redirect_uri=_CALLBACK,
        return_to="/",
        requested_scopes=frozenset({"openid", "email"}),
        expected_issuer="https://accounts.google.com",
        now=_NOW,
        include_nonce=True,
    )

    assert calls == [32, 32, 32, 32]
    assert start.nonce is not None
    assert {_decode_secret(start.state), _decode_secret(start.browser_binding), _decode_secret(start.nonce)} == {
        b"\x01" * 32,
        b"\x02" * 32,
        b"\x04" * 32,
    }
    assert len(start.transaction.pkce_verifier.get_secret_value()) == 43
    assert start.pkce_challenge == pkce_s256(start.transaction.pkce_verifier)
    assert "AQEBAQ" not in repr(start)
    assert "AwMDAw" not in repr(start.transaction)


@pytest.mark.anyio
async def test_start_reuses_valid_browser_binding_for_concurrent_tabs() -> None:
    service = _service()
    binding = SecretStr("b" * 43)
    arguments = {
        "operation": OAuthOperation.LOGIN,
        "provider": "google",
        "redirect_uri": _CALLBACK,
        "return_to": "/",
        "requested_scopes": frozenset({"openid"}),
        "expected_issuer": "https://accounts.google.com",
        "now": _NOW,
        "include_nonce": True,
        "browser_binding": binding,
    }

    first = await service.start(**arguments)  # type: ignore[arg-type]
    second = await service.start(**arguments)  # type: ignore[arg-type]

    assert first.browser_binding is binding
    assert second.browser_binding is binding
    assert first.state != second.state


def test_pkce_s256_matches_rfc_7636_vector() -> None:
    verifier = SecretStr("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

    assert pkce_s256(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@pytest.mark.parametrize("value", ["", cast("Any", None)])
def test_secret_string_rejects_empty_values(value: Any) -> None:
    with pytest.raises(ValueError, match="Secret string"):
        SecretStr(value)


def test_secret_string_string_forms_are_redacted() -> None:
    value = SecretStr("do-not-print")

    assert str(value) == "**********"
    assert repr(value) == "SecretStr('**********')"


@pytest.mark.parametrize(
    ("ciphertext", "key_version"),
    [(b"", "key"), (cast("Any", "bytes"), "key"), (b"value", ""), (b"value", cast("Any", None))],
)
def test_protected_secret_rejects_incomplete_envelopes(ciphertext: Any, key_version: Any) -> None:
    with pytest.raises(ValueError, match="Protected OAuth secret"):
        ProtectedOAuthSecret(ciphertext=ciphertext, key_version=key_version)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("state_digest", b""),
        ("binding_digest", b""),
        ("operation", cast("Any", "login")),
        ("provider", ""),
        ("requested_scopes", cast("Any", {"openid"})),
        ("requested_scopes", frozenset({""})),
        ("pkce_verifier", cast("Any", "verifier")),
        ("nonce", cast("Any", "nonce")),
        ("expected_issuer", ""),
        ("account_id", ""),
        ("session_binding", ""),
        ("expires_at", _NOW.replace(tzinfo=None)),
    ],
)
def test_transaction_rejects_malformed_storage_state(field_name: str, value: Any) -> None:
    with pytest.raises(ValueError, match="OAuth transaction is invalid"):
        replace(_transaction(), **{field_name: value})


def test_transaction_allows_optional_bindings_to_be_absent() -> None:
    transaction = replace(
        _transaction(),
        expected_issuer=None,
        nonce=None,
        account_id=None,
        session_binding=None,
        requested_scopes=frozenset(),
    )

    assert transaction.nonce is None


@pytest.mark.anyio
async def test_concurrent_consume_is_atomic_and_replay_safe() -> None:
    service = _service()
    start = await service.start(
        operation=OAuthOperation.LOGIN,
        provider="google",
        redirect_uri=_CALLBACK,
        return_to="/",
        requested_scopes=frozenset({"openid"}),
        now=_NOW,
        include_nonce=False,
    )

    async def consume() -> OAuthTransaction | None:
        try:
            return await service.consume(
                state=start.state,
                browser_binding=start.browser_binding,
                provider="google",
                operation=OAuthOperation.LOGIN,
                session_binding=None,
                now=_NOW,
            )
        except InvalidOAuthCallback:
            return None

    first, second = await asyncio.gather(consume(), consume())

    assert sum(transaction is not None for transaction in (first, second)) == 1
    with pytest.raises(InvalidOAuthCallback, match="OAuth callback is invalid"):
        await service.consume(
            state=start.state,
            browser_binding=start.browser_binding,
            provider="google",
            operation=OAuthOperation.LOGIN,
            session_binding=None,
            now=_NOW,
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("change", "value"),
    [("state", SecretStr("A" * 43)), ("browser_binding", SecretStr("B" * 43)), ("provider", "github")],
)
async def test_lookup_mismatch_is_one_generic_failure_and_does_not_consume(change: str, value: SecretStr | str) -> None:
    service = _service()
    start = await service.start(
        operation=OAuthOperation.LOGIN,
        provider="google",
        redirect_uri=_CALLBACK,
        return_to="/",
        requested_scopes=frozenset(),
        now=_NOW,
        include_nonce=False,
    )
    state = value if change == "state" else start.state
    browser_binding = value if change == "browser_binding" else start.browser_binding
    provider = value if change == "provider" else "google"
    assert isinstance(state, (SecretStr, str))
    assert isinstance(browser_binding, (SecretStr, str))
    assert isinstance(provider, str)

    with pytest.raises(InvalidOAuthCallback, match="OAuth callback is invalid"):
        await service.consume(
            state=state,
            browser_binding=browser_binding,
            provider=provider,
            operation=OAuthOperation.LOGIN,
            session_binding=None,
            now=_NOW,
        )

    transaction = await service.consume(
        state=start.state,
        browser_binding=start.browser_binding,
        provider="google",
        operation=OAuthOperation.LOGIN,
        session_binding=None,
        now=_NOW,
    )
    assert transaction.provider == "google"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("stored_session", "callback_session", "operation"),
    [
        ("session-1", "session-2", OAuthOperation.LOGIN),
        ("session-1", None, OAuthOperation.LOGIN),
        (None, "session-1", OAuthOperation.LOGIN),
        ("session-1", "session-1", OAuthOperation.LINK),
    ],
)
async def test_session_and_operation_mismatch_are_consumed_generic_failures(
    stored_session: str | None, callback_session: str | None, operation: OAuthOperation
) -> None:
    service = _service()
    start = await service.start(
        operation=OAuthOperation.LOGIN,
        provider="google",
        redirect_uri=_CALLBACK,
        return_to="/",
        requested_scopes=frozenset(),
        session_binding=stored_session,
        now=_NOW,
        include_nonce=False,
    )

    with pytest.raises(InvalidOAuthCallback, match="OAuth callback is invalid"):
        await service.consume(
            state=start.state,
            browser_binding=start.browser_binding,
            provider="google",
            operation=operation,
            session_binding=callback_session,
            now=_NOW,
        )
    with pytest.raises(InvalidOAuthCallback, match="OAuth callback is invalid"):
        await service.consume(
            state=start.state,
            browser_binding=start.browser_binding,
            provider="google",
            operation=OAuthOperation.LOGIN,
            session_binding=stored_session,
            now=_NOW,
        )


@pytest.mark.anyio
async def test_expired_transaction_and_absent_nonce_are_generic() -> None:
    service = _service()
    start = await service.start(
        operation=OAuthOperation.LOGIN,
        provider="google",
        redirect_uri=_CALLBACK,
        return_to="/",
        requested_scopes=frozenset(),
        now=_NOW,
        include_nonce=False,
    )

    assert start.nonce is None
    with pytest.raises(InvalidOAuthCallback, match="OAuth callback is invalid"):
        await service.consume(
            state=start.state,
            browser_binding=start.browser_binding,
            provider="google",
            operation=OAuthOperation.LOGIN,
            session_binding=None,
            now=_NOW + timedelta(minutes=10),
        )


@pytest.mark.anyio
async def test_multi_tab_transactions_do_not_overwrite_each_other() -> None:
    service = _service()
    first = await service.start(
        operation=OAuthOperation.LOGIN,
        provider="google",
        redirect_uri=_CALLBACK,
        return_to="/",
        requested_scopes=frozenset(),
        now=_NOW,
        include_nonce=False,
    )
    second = await service.start(
        operation=OAuthOperation.LOGIN,
        provider="google",
        redirect_uri=_CALLBACK,
        return_to="/settings/security",
        requested_scopes=frozenset(),
        now=_NOW,
        include_nonce=False,
    )

    first_transaction = await service.consume(
        state=first.state,
        browser_binding=first.browser_binding,
        provider="google",
        operation=OAuthOperation.LOGIN,
        session_binding=None,
        now=_NOW,
    )
    second_transaction = await service.consume(
        state=second.state,
        browser_binding=second.browser_binding,
        provider="google",
        operation=OAuthOperation.LOGIN,
        session_binding=None,
        now=_NOW,
    )

    assert (first_transaction.return_to, second_transaction.return_to) == ("/", "/settings/security")


@pytest.mark.anyio
async def test_reference_store_rejects_duplicate_lookup() -> None:
    store = MemoryOAuthTransactionStore(protector=_Protector())
    transaction = _transaction()
    await store.create(transaction)

    with pytest.raises(ValueError, match="already exists"):
        await store.create(transaction)


def test_reference_store_requires_protector_contract() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="protector"):
        MemoryOAuthTransactionStore(protector=cast("Any", object()))


def test_oauth_cookie_uses_dedicated_host_only_policy() -> None:
    cookie = oauth_binding_cookie(SecretStr("cookie-secret"))

    assert cookie.key == "__Host-litestar-security-oauth"
    assert cookie.value == "cookie-secret"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "lax"
    assert cookie.path == "/"
    assert cookie.domain is None
    assert cookie.max_age == 600


@pytest.mark.parametrize(
    ("callbacks", "return_to", "provider", "redirect_uri", "requested_return_to"),
    [
        ({"google": frozenset({_CALLBACK})}, frozenset({"/"}), "google", f"{_CALLBACK}/", "/"),
        ({"google": frozenset({_CALLBACK})}, frozenset({"/"}), "google", _CALLBACK, "//evil.example"),
        ({"google": frozenset({_CALLBACK})}, frozenset({"/"}), "google", _CALLBACK, "https://evil.example"),
        ({"google": frozenset({_CALLBACK})}, frozenset({"/"}), "github", _CALLBACK, "/"),
        ({"google": frozenset({"https://*.example/callback"})}, frozenset({"/"}), "google", _CALLBACK, "/"),
        ({"google": frozenset({"http://app.example/callback"})}, frozenset({"/"}), "google", _CALLBACK, "/"),
    ],
)
def test_redirect_policy_rejects_non_exact_or_unsafe_values(
    callbacks: dict[str, frozenset[str]],
    return_to: frozenset[str],
    provider: str,
    redirect_uri: str,
    requested_return_to: str,
) -> None:
    if "*" in next(iter(callbacks["google"])) or next(iter(callbacks["google"])).startswith("http:"):
        with pytest.raises(ImproperlyConfiguredException):
            OAuthRedirectPolicy(callback_uris=callbacks, return_to=return_to)
        return

    policy = OAuthRedirectPolicy(callback_uris=callbacks, return_to=return_to)
    with pytest.raises(InvalidOAuthCallback, match="OAuth callback is invalid"):
        policy.validate(provider=provider, redirect_uri=redirect_uri, return_to=requested_return_to)


def test_redirect_policy_allows_exact_same_origin_absolute_return() -> None:
    policy = OAuthRedirectPolicy(
        callback_uris={"google": frozenset({_CALLBACK})}, return_to=frozenset({"https://app.example/account"})
    )

    policy.validate(provider="google", redirect_uri=_CALLBACK, return_to="https://app.example/account")


@pytest.mark.parametrize(
    "callback_uris",
    [
        cast("Any", None),
        cast("dict[str, frozenset[str]]", {}),
        {"": frozenset({_CALLBACK})},
        {" google": frozenset({_CALLBACK})},
        {"google": cast("Any", {_CALLBACK})},
        {"google": frozenset[str]()},
    ],
)
def test_redirect_policy_rejects_invalid_provider_mapping(callback_uris: Any) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        OAuthRedirectPolicy(callback_uris=callback_uris)


@pytest.mark.parametrize("return_to", [cast("Any", {"/"}), frozenset[str]()])
def test_redirect_policy_requires_non_empty_immutable_return_allowlist(return_to: Any) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        OAuthRedirectPolicy(callback_uris={"google": frozenset({_CALLBACK})}, return_to=return_to)


@pytest.mark.parametrize(
    "uri",
    [
        "",
        " https://app.example/callback",
        "https://app.example/*",
        "https://app.example\\callback",
        "/relative",
        "https://user@app.example/callback",
        "https://user:pass@app.example/callback",
        "https://app.example/callback#fragment",
        "ftp://app.example/callback",
        "http://app.example/callback",
        "https://app.example:invalid/callback",
    ],
)
def test_redirect_policy_rejects_malformed_callback_configuration(uri: str) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        OAuthRedirectPolicy(callback_uris={"google": frozenset({uri})})


@pytest.mark.parametrize(
    "return_to",
    [
        "",
        " /account",
        "/*",
        "/account\\settings",
        "/account#fragment",
        "https://user@app.example/account",
        "account",
        "//app.example/account",
        "https://evil.example/account",
    ],
)
def test_redirect_policy_rejects_malformed_return_configuration(return_to: str) -> None:
    with pytest.raises(ImproperlyConfiguredException):
        OAuthRedirectPolicy(callback_uris={"google": frozenset({_CALLBACK})}, return_to=frozenset({return_to}))


@pytest.mark.parametrize(
    "callback",
    [
        "http://localhost:8000/auth/callback",
        "http://127.0.0.1/auth/callback",
        "http://[::1]/auth/callback",
        "https://app.example:8443/auth/callback",
    ],
)
def test_redirect_policy_allows_explicit_local_development_and_exact_ports(callback: str) -> None:
    policy = OAuthRedirectPolicy(callback_uris={"dev": frozenset({callback})}, allow_insecure_localhost=True)

    policy.validate(provider="dev", redirect_uri=callback, return_to="/")


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"store": cast("Any", object())}, "store"),
        ({"pepper": b"short"}, "pepper"),
        ({"pepper": cast("Any", "p" * 32)}, "pepper"),
        ({"redirects": cast("Any", object())}, "redirect policy"),
        ({"lifetime": timedelta()}, "lifetime"),
        ({"lifetime": timedelta(minutes=11)}, "lifetime"),
        ({"entropy": cast("Any", 1)}, "entropy"),
    ],
)
def test_service_rejects_invalid_configuration(overrides: dict[str, Any], match: str) -> None:
    arguments: dict[str, Any] = {
        "store": MemoryOAuthTransactionStore(protector=_Protector()),
        "pepper": _PEPPER,
        "redirects": OAuthRedirectPolicy(callback_uris={"google": frozenset({_CALLBACK})}),
    }
    arguments.update(overrides)

    with pytest.raises(ImproperlyConfiguredException, match=match):
        OAuthTransactionService(**arguments)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "overrides",
    [
        {"operation": cast("Any", "login")},
        {"requested_scopes": cast("Any", {"openid"})},
        {"requested_scopes": frozenset({""})},
        {"now": _NOW.replace(tzinfo=None)},
    ],
)
async def test_start_rejects_invalid_transaction_input(overrides: dict[str, Any]) -> None:
    arguments: dict[str, Any] = {
        "operation": OAuthOperation.LOGIN,
        "provider": "google",
        "redirect_uri": _CALLBACK,
        "return_to": "/",
        "requested_scopes": frozenset(),
        "now": _NOW,
        "include_nonce": False,
    }
    arguments.update(overrides)

    with pytest.raises(InvalidOAuthCallback):
        await _service().start(**arguments)


@pytest.mark.anyio
@pytest.mark.parametrize("result", [b"short", cast("Any", "x" * 32)])
async def test_start_sanitizes_invalid_entropy(result: Any) -> None:
    def entropy(length: int) -> bytes:
        del length
        return cast("bytes", result)

    with pytest.raises(OAuthTransactionUnavailable):
        await _service(entropy=entropy).start(
            operation=OAuthOperation.LOGIN,
            provider="google",
            redirect_uri=_CALLBACK,
            return_to="/",
            requested_scopes=frozenset(),
            now=_NOW,
            include_nonce=False,
        )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "overrides",
    [
        {"state": "short"},
        {"state": "!" * 43},
        {"browser_binding": "short"},
        {"provider": ""},
        {"operation": cast("Any", "login")},
        {"now": _NOW.replace(tzinfo=None)},
    ],
)
async def test_consume_rejects_malformed_callback_input(overrides: dict[str, Any]) -> None:
    arguments: dict[str, Any] = {
        "state": "s" * 43,
        "browser_binding": "b" * 43,
        "provider": "google",
        "operation": OAuthOperation.LOGIN,
        "session_binding": None,
        "now": _NOW,
    }
    arguments.update(overrides)

    with pytest.raises(InvalidOAuthCallback):
        await _service().consume(**arguments)


@pytest.mark.anyio
async def test_consume_sanitizes_unprotect_failure() -> None:
    protector = _Protector()
    service = _service(protector=protector)
    start = await service.start(
        operation=OAuthOperation.LOGIN,
        provider="google",
        redirect_uri=_CALLBACK,
        return_to="/",
        requested_scopes=frozenset(),
        now=_NOW,
        include_nonce=False,
    )
    protector.fail = True

    with pytest.raises(OAuthTransactionUnavailable, match="unavailable"):
        await service.consume(
            state=start.state,
            browser_binding=start.browser_binding,
            provider="google",
            operation=OAuthOperation.LOGIN,
            session_binding=None,
            now=_NOW,
        )


@pytest.mark.parametrize("verifier", [cast("Any", None), "x" * 42, "x" * 129, "!" * 43])
def test_pkce_rejects_non_canonical_verifiers(verifier: Any) -> None:
    with pytest.raises(ValueError, match="PKCE verifier"):
        pkce_s256(verifier)


@pytest.mark.parametrize(
    ("binding", "max_age"),
    [(cast("Any", None), 600), ("", 600), ("binding", cast("Any", 1.5)), ("binding", 0), ("binding", 601)],
)
def test_cookie_rejects_invalid_values_and_lifetimes(binding: Any, max_age: Any) -> None:
    with pytest.raises(ValueError, match="cookie"):
        oauth_binding_cookie(binding, max_age=max_age)


@pytest.mark.anyio
async def test_protector_failure_is_secret_free_unavailable_error() -> None:
    protector = _Protector(fail=True)
    service = _service(protector=protector)

    with pytest.raises(OAuthTransactionUnavailable, match="OAuth transaction service is unavailable") as exc_info:
        await service.start(
            operation=OAuthOperation.LOGIN,
            provider="google",
            redirect_uri=_CALLBACK,
            return_to="/",
            requested_scopes=frozenset(),
            now=_NOW,
            include_nonce=False,
        )

    assert "protect detail" not in repr(exc_info.value)


@pytest.mark.anyio
async def test_start_rejects_invalid_reused_browser_binding() -> None:
    with pytest.raises(OAuthTransactionUnavailable, match="unavailable"):
        await _service().start(
            operation=OAuthOperation.LOGIN,
            provider="google",
            redirect_uri=_CALLBACK,
            return_to="/",
            requested_scopes=frozenset(),
            browser_binding=SecretStr("invalid"),
            now=_NOW,
            include_nonce=False,
        )
