"""Source-oriented accounts unit tests."""

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import pytest
from litestar.exceptions import ImproperlyConfiguredException

import litestar_security.accounts as accounts_module
import litestar_security.accounts._access_tokens as access_tokens_module
from litestar_security.authentication import Authenticated, InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence, AuthorizationSnapshot, Principal
from litestar_security.providers.jwt import JWTClaims, JWTValidationConfig, LocalKeyRing, build_access_token_claims
from litestar_security.providers.jwt import _claims as jwt_claims
from tests.fixtures.accounts import (
    InvalidAssuranceVerifier,
    PasswordLogin,
    RefreshTokens,
    _AccessSigner,
    _local_access_account,
    _LocalAccessStore,
    _PasswordHasher,
    _RefreshEntropy,
)

_JWT_NOW = datetime(2026, 7, 26, 12, tzinfo=timezone.utc)
_NAIVE_JWT_NOW = datetime(2026, 7, 26)  # noqa: DTZ001 - explicit rejection fixture
_JWT_ISSUER = "https://issuer.example"
_JWT_AUDIENCE = "litestar-security"
_OIDC_ISSUER = "https://issuer.example/tenant"
_OIDC_DISCOVERY_URL = f"{_OIDC_ISSUER}/.well-known/openid-configuration"
_OIDC_PUBLIC_IP = "93.184.216.34"
_JWKS_URI = f"{_JWT_ISSUER}/.well-known/jwks.json"
_MFA_VECTOR_NOW = datetime.fromtimestamp(59, tz=timezone.utc)
_MFA_ENCODED_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
_MFA_POLICY = accounts_module.TOTPPolicy()


@pytest.mark.parametrize("scope", ["admin read", "admin\tread", '"quoted', "back\\slash", "é"])
def test_access_token_claims_reject_non_oauth_scope_tokens(scope: str) -> None:
    with pytest.raises(ValueError, match="scope"):
        build_access_token_claims(
            issuer=_JWT_ISSUER,
            audience=_JWT_AUDIENCE,
            subject="account-1",
            client_id="local",
            security_epoch=1,
            now=_JWT_NOW,
            lifetime=timedelta(minutes=10),
            scopes=frozenset({scope}),
        )


async def test_local_access_issue_cross_verifies_exact_minimal_claims_without_generic_scope_grants(
    local_key_ring: LocalKeyRing,
) -> None:
    account = _local_access_account()
    issuer = accounts_module.LocalAccessTokenIssuer(
        signer=local_key_ring.build_signer(),
        issuer=local_key_ring.issuer,
        audience=_JWT_AUDIENCE,
        client_id="local-web",
        clock=lambda: _JWT_NOW,
        token_ids=lambda: "access-token-1",
    )

    issued = await issuer.issue(account, scopes=frozenset({"write", "read"}))

    assert isinstance(issued, accounts_module.LocalAccessToken)
    assert (issued.token_type, issued.expires_in) == ("Bearer", 600)
    assert "access_token" not in repr(issued)
    verifier = local_key_ring.build_verifier(
        JWTValidationConfig(
            issuer=local_key_ring.issuer,
            audiences=frozenset({_JWT_AUDIENCE}),
            algorithms=frozenset(key.algorithm for key in local_key_ring.all_verification_keys),
            required_claims=frozenset({"se"}),
            maximum_lifetime=timedelta(minutes=10),
        ),
        mechanism_name="bearer",
        slot_name="local",
    )
    outcome = await verifier.verify(issued.access_token, now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)
    assert outcome.grants == AuthorizationSnapshot()
    assert outcome.claims.raw == {
        "iss": local_key_ring.issuer,
        "sub": "account-1",
        "aud": _JWT_AUDIENCE,
        "exp": int((_JWT_NOW + timedelta(minutes=10)).timestamp()),
        "iat": int(_JWT_NOW.timestamp()),
        "client_id": "local-web",
        "jti": "access-token-1",
        "se": 3,
        "scope": "read write",
    }
    serialized_claims = json.dumps(dict(outcome.claims.raw))
    for forbidden in ("person@example.com", "Local Person", "application object", "password", "roles", "team"):
        assert forbidden not in serialized_claims


async def test_local_access_token_preserves_passkey_assurance(local_key_ring: LocalKeyRing) -> None:
    validation = JWTValidationConfig(
        issuer=local_key_ring.issuer,
        audiences=frozenset({_JWT_AUDIENCE}),
        algorithms=frozenset(key.algorithm for key in local_key_ring.all_verification_keys),
        required_claims=frozenset({"se"}),
        maximum_lifetime=timedelta(minutes=10),
    )
    issuer = accounts_module.LocalAccessTokenIssuer(
        signer=local_key_ring.build_signer(),
        issuer=local_key_ring.issuer,
        audience=_JWT_AUDIENCE,
        clock=lambda: _JWT_NOW,
        token_ids=lambda: "passkey-access-token",
    )
    evidence = AuthenticationEvidence(
        mechanism="passkey",
        slot="mfa",
        authenticated_at=_JWT_NOW,
        methods=frozenset({"passkey"}),
        traits=frozenset({"phishing-resistant", "user-verified"}),
        amr=("passkey",),
    )
    issued = await issuer.issue(_local_access_account(), evidence=evidence)
    assert isinstance(issued, accounts_module.LocalAccessToken)
    verifier = access_tokens_module.LocalAccessVerifier(
        config=validation,
        verifier=local_key_ring.build_verifier(validation, mechanism_name="bearer", slot_name="local"),
    )

    outcome = await verifier.verify(issued.access_token, now=_JWT_NOW)

    assert isinstance(outcome, Authenticated)
    assert outcome.evidence.methods == frozenset({"passkey"})
    assert outcome.evidence.traits == frozenset({"phishing-resistant", "user-verified"})
    assert outcome.evidence.amr == ("passkey",)

    invalid = access_tokens_module.LocalAccessVerifier(
        config=validation, verifier=cast("Any", InvalidAssuranceVerifier(outcome))
    )
    assert isinstance(await invalid.verify("token", now=_JWT_NOW), InvalidCredentials)
    assert access_tokens_module._claim_set("passkey") is None  # noqa: SLF001 - defensive parser branch

    malformed = dict(outcome.claims.raw)
    malformed["amr"] = []
    with pytest.raises(ValueError, match="Invalid local access-token claims"):
        jwt_claims.validate_local_access_claims(malformed, issuer=local_key_ring.issuer, now=_JWT_NOW)
    malformed = dict(outcome.claims.raw)
    malformed["auth_time"] = int(_JWT_NOW.timestamp()) + 1
    with pytest.raises(ValueError, match="Invalid local access-token claims"):
        jwt_claims.validate_local_access_claims(malformed, issuer=local_key_ring.issuer, now=_JWT_NOW)
    with pytest.raises(ValueError, match="authentication time"):
        build_access_token_claims(
            issuer=local_key_ring.issuer,
            audience=_JWT_AUDIENCE,
            subject="account-1",
            client_id="local",
            security_epoch=1,
            now=_JWT_NOW,
            lifetime=timedelta(minutes=10),
            authenticated_at=_JWT_NOW + timedelta(seconds=1),
        )
    invalid_time: object = True
    assert access_tokens_module._claim_authentication_time(invalid_time, fallback=_JWT_NOW) is None  # noqa: SLF001
    assert (
        access_tokens_module._claim_authentication_time(10**30, fallback=_JWT_NOW)  # noqa: SLF001
        is None
    )


async def test_legacy_local_access_assurance_falls_back_to_issued_at(local_key_ring: LocalKeyRing) -> None:
    """Legacy access tokens without auth_time retain their frozen issuance time."""
    validation = JWTValidationConfig(
        issuer=local_key_ring.issuer,
        audiences=frozenset({_JWT_AUDIENCE}),
        algorithms=frozenset(key.algorithm for key in local_key_ring.all_verification_keys),
        required_claims=frozenset({"se"}),
        maximum_lifetime=timedelta(minutes=10),
    )
    issued_at = _JWT_NOW
    verified_at = issued_at + timedelta(minutes=5)
    claims = build_access_token_claims(
        issuer=local_key_ring.issuer,
        audience=_JWT_AUDIENCE,
        subject="account-1",
        client_id="local",
        security_epoch=3,
        now=issued_at,
        lifetime=timedelta(minutes=10),
        methods=frozenset({"password"}),
    )
    token = await local_key_ring.build_signer().sign(claims, now=issued_at)
    verifier = access_tokens_module.LocalAccessVerifier(
        config=validation,
        verifier=local_key_ring.build_verifier(validation, mechanism_name="bearer", slot_name="local"),
    )

    outcome = await verifier.verify(token, now=verified_at)

    assert isinstance(outcome, Authenticated)
    assert outcome.evidence.authenticated_at == issued_at


async def test_token_login_preserves_password_assurance_at_refresh_issuance() -> None:
    """Password token login carries its original assurance into the refresh family."""
    account = _local_access_account()
    issued_at = _JWT_NOW + timedelta(minutes=1)
    response = accounts_module.TokenPair(
        access_token="e30.e30.YQ",  # noqa: S106 - compact public test JWT
        refresh_token=(
            accounts_module.RefreshTokenCodec(pepper=b"p" * 32, entropy=_RefreshEntropy()).issue().refresh_token
        ),
        expires_in=600,
    )

    refresh_tokens = RefreshTokens(issued_at=issued_at, account=account, response=response)
    service = accounts_module.LocalAuthService(
        accounts=cast("Any", object()),
        password_login=cast("Any", PasswordLogin(account)),
        password_reauthentication=cast("Any", object()),
        password_change=cast("Any", object()),
        verification=cast("Any", object()),
        recovery=cast("Any", object()),
        refresh_tokens=cast("Any", refresh_tokens),
    )

    credentials = accounts_module.LocalCredentials(identifier="person@example.com", password="password")  # noqa: S106
    assert await service.token_login(cast("Any", object()), credentials) == response
    assert refresh_tokens.evidence == AuthenticationEvidence(
        mechanism="bearer", slot="local", authenticated_at=issued_at, methods=frozenset({"password"}), amr=("pwd",)
    )


async def test_token_login_fails_closed_when_refresh_issuance_clock_is_unavailable() -> None:
    """A failed refresh issuance clock never mints a token with invented assurance time."""
    account = _local_access_account()

    service = accounts_module.LocalAuthService(
        accounts=cast("Any", object()),
        password_login=cast("Any", PasswordLogin(account)),
        password_reauthentication=cast("Any", object()),
        password_change=cast("Any", object()),
        verification=cast("Any", object()),
        recovery=cast("Any", object()),
        refresh_tokens=cast("Any", RefreshTokens(clock_failure=True)),
    )

    credentials = accounts_module.LocalCredentials(identifier="person@example.com", password="password")  # noqa: S106
    assert isinstance(await service.token_login(cast("Any", object()), credentials), VerificationUnavailable)


@pytest.mark.parametrize(
    ("account", "fail_lookup", "fail_epoch", "epoch", "expected_type"),
    [
        (_local_access_account(), False, False, 3, Principal),
        (None, False, False, 3, InvalidCredentials),
        (_local_access_account(active=False), False, False, 3, InvalidCredentials),
        (_local_access_account(verified=False), False, False, 3, InvalidCredentials),
        (_local_access_account(), True, False, 3, VerificationUnavailable),
        (_local_access_account(), False, True, 3, VerificationUnavailable),
        (_local_access_account(), False, False, 2, InvalidCredentials),
    ],
)
async def test_local_bearer_identity_resolution_checks_account_and_exact_epoch(
    account: accounts_module.LocalAccountState[object] | None,
    fail_lookup: bool,  # noqa: FBT001
    fail_epoch: bool,  # noqa: FBT001
    epoch: int,
    expected_type: type[object],
) -> None:
    store = _LocalAccessStore(account, fail_lookup=fail_lookup, fail_epoch=fail_epoch)
    resolver = accounts_module.LocalBearerIdentityResolver(accounts=store)
    claims = JWTClaims(
        issuer=_JWT_ISSUER,
        subject="account-1",
        audiences=frozenset({_JWT_AUDIENCE}),
        expires_at=_JWT_NOW + timedelta(minutes=10),
        issued_at=_JWT_NOW,
        not_before=None,
        token_id="access-token-1",  # noqa: S106 - public JWT identifier
        client_id="local",
        scopes=frozenset(),
        raw={"se": epoch},
    )

    outcome = await resolver.resolve(claims)

    assert isinstance(outcome, expected_type)
    if isinstance(outcome, Principal):
        assert (outcome.id, outcome.display_name, outcome.user) == (
            "account-1",
            "Local Person",
            {"safe": "application object"},
        )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"accounts": object()}, "AccountLookup"),
        ({"hasher": object()}, "PasswordHasher"),
        ({"normalizer": None}, "normalizer"),
    ],
)
def test_password_login_rejects_invalid_configuration(kwargs: dict[str, object], match: str) -> None:
    values = {"accounts": _LocalAccessStore(_local_access_account()), "hasher": _PasswordHasher(), **kwargs}

    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.PasswordLoginService(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("identifier", "unavailable", "expected_type"),
    [(" ", False, InvalidCredentials), ("person@example.com", True, VerificationUnavailable)],
)
async def test_password_login_dummy_work_handles_empty_identifiers_and_worker_failure(
    identifier: str,
    unavailable: bool,  # noqa: FBT001
    expected_type: type[object],
) -> None:
    hasher = _PasswordHasher(unavailable=unavailable)
    service = accounts_module.PasswordLoginService(accounts=_LocalAccessStore(None), hasher=hasher)

    outcome = await service.authenticate(identifier, "presented secret", now=_JWT_NOW)

    assert isinstance(outcome, expected_type)
    assert hasher.calls == [(None, "presented secret")]


@pytest.mark.parametrize(
    ("token", "expires_in"),
    [
        (cast("Any", object()), 600),
        ("not-compact", 600),
        ("a..c", 600),
        ("a.b.c", 600),
        ("e30.%.YQ", 600),
        ("é.b.c", 600),
        ("e30.e30.YQ", True),
        ("e30.e30.YQ", 29),
        ("e30.e30.YQ", 3_601),
    ],
)
def test_local_access_token_rejects_invalid_response_values(token: object, expires_in: int) -> None:
    with pytest.raises(ValueError, match="bounded expiry"):
        accounts_module.LocalAccessToken(access_token=token, expires_in=expires_in)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"signer": object()}, "TokenSigner"),
        ({"issuer": " "}, "issuer"),
        ({"audience": "bad audience"}, "audience"),
        ({"client_id": "e\u0301"}, "client id"),
        ({"lifetime": object()}, "timedelta"),
        ({"clock": None}, "clock"),
        ({"token_ids": None}, "token id"),
    ],
)
def test_local_access_token_issuer_rejects_invalid_configuration(kwargs: dict[str, object], match: str) -> None:
    values = {
        "signer": _AccessSigner(),
        "issuer": _JWT_ISSUER,
        "audience": _JWT_AUDIENCE,
        "client_id": "local",
        **kwargs,
    }

    with pytest.raises(ImproperlyConfiguredException, match=match):
        accounts_module.LocalAccessTokenIssuer(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("account", "signer", "clock", "token_ids", "scopes", "expected_type"),
    [
        (
            _local_access_account(active=False),
            _AccessSigner(),
            lambda: _JWT_NOW,
            lambda: "token",
            frozenset(),
            InvalidCredentials,
        ),
        (
            _local_access_account(),
            _AccessSigner(),
            lambda: 1 / 0,
            lambda: "token",
            frozenset(),
            VerificationUnavailable,
        ),
        (
            _local_access_account(),
            _AccessSigner(),
            lambda: _JWT_NOW,
            lambda: 1 / 0,
            frozenset(),
            VerificationUnavailable,
        ),
        (
            _local_access_account(),
            _AccessSigner(),
            lambda: _JWT_NOW,
            lambda: "token",
            frozenset({"bad scope"}),
            InvalidCredentials,
        ),
        (
            _local_access_account(),
            _AccessSigner(fail=True),
            lambda: _JWT_NOW,
            lambda: "token",
            frozenset(),
            VerificationUnavailable,
        ),
        (
            _local_access_account(),
            _AccessSigner("malformed"),
            lambda: _JWT_NOW,
            lambda: "token",
            frozenset(),
            VerificationUnavailable,
        ),
    ],
)
async def test_local_access_token_issuer_maps_invalid_and_unavailable_composition(  # noqa: PLR0913 - one composition matrix per parametrized case
    *,
    account: accounts_module.LocalAccountState[object],
    signer: _AccessSigner,
    clock: Callable[[], datetime],
    token_ids: Callable[[], str],
    scopes: frozenset[str],
    expected_type: type[object],
) -> None:
    service = accounts_module.LocalAccessTokenIssuer(
        signer=signer, issuer=_JWT_ISSUER, audience=_JWT_AUDIENCE, clock=clock, token_ids=token_ids
    )

    outcome = await service.issue(account, scopes=scopes)

    assert isinstance(outcome, expected_type)


def test_local_bearer_resolver_rejects_missing_capabilities() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="AccountLookup and SecurityEpochStore"):
        accounts_module.LocalBearerIdentityResolver(accounts=object())  # type: ignore[arg-type]


@pytest.mark.parametrize("epoch", [None, True, -1, 1.0, "1"])
async def test_local_bearer_resolver_rejects_malformed_epoch_without_lookup(epoch: object) -> None:
    store = _LocalAccessStore(_local_access_account())
    resolver = accounts_module.LocalBearerIdentityResolver(accounts=store)
    claims = JWTClaims(
        issuer=_JWT_ISSUER,
        subject="account-1",
        audiences=frozenset({_JWT_AUDIENCE}),
        expires_at=_JWT_NOW + timedelta(minutes=10),
        issued_at=_JWT_NOW,
        not_before=None,
        token_id="public-token-id",  # noqa: S106
        client_id="local",
        scopes=frozenset(),
        raw={"se": cast("Any", epoch)},
    )

    outcome = await resolver.resolve(claims)

    assert isinstance(outcome, InvalidCredentials)
    assert store.id_lookups == []
