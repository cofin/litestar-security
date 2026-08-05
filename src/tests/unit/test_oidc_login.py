from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import httpx
import pytest
from litestar.exceptions import ImproperlyConfiguredException, NotAuthorizedException

from litestar_security.authentication import Authenticated, InvalidCredentials, VerificationUnavailable
from litestar_security.context import AuthenticationEvidence
from litestar_security.providers.jwt import JSONValue, JWTClaims, JWTValidationConfig
from litestar_security.providers.oauth import (
    OAuthClientAuth,
    OAuthEndpointConfig,
    OAuthOperation,
    OAuthProviderClient,
    OAuthProviderError,
    OAuthTransaction,
    OAuthTransactionStart,
    ProviderTokenSet,
    SecretStr,
)
from litestar_security.providers.oidc import (
    OIDCJWTLogoutTokenConsumer,
    OIDCMetadata,
    OIDCProvider,
    google_oidc_provider,
    keycloak_oidc_provider,
    oidc_provider,
)

NOW = datetime(2026, 7, 28, tzinfo=timezone.utc)
ISSUER = "https://issuer.example.com"
CLIENT_ID = "client-id"
ID_TOKEN = SecretStr("header.payload.signature")


@dataclass
class StubVerifier:
    config: JWTValidationConfig
    outcome: object
    seen_token: str | None = None

    async def verify(self, token: str, *, now: datetime) -> object:
        del now
        self.seen_token = token
        return self.outcome


def claims(**overrides: JSONValue) -> JWTClaims:
    raw: dict[str, JSONValue] = {
        "iss": ISSUER,
        "sub": "subject-1",
        "aud": CLIENT_ID,
        "exp": int((NOW + timedelta(minutes=10)).timestamp()),
        "iat": int(NOW.timestamp()),
        "nonce": "transaction-nonce",
        "name": "Ada Lovelace",
        "email": "ada@example.com",
        "email_verified": True,
        "acr": "urn:mfa",
        "amr": ["pwd", "otp"],
    }
    raw.update(overrides)
    audience_value = raw["aud"]
    audiences = (
        frozenset(cast("list[str]", audience_value))
        if isinstance(audience_value, list)
        else frozenset({cast("str", audience_value)})
    )
    return JWTClaims(
        issuer=cast("str", raw["iss"]),
        subject=cast("str", raw["sub"]),
        audiences=audiences,
        expires_at=NOW + timedelta(minutes=10),
        issued_at=NOW,
        not_before=None,
        token_id=None,
        client_id=None,
        scopes=frozenset(),
        raw=raw,
    )


def transaction(**overrides: object) -> OAuthTransaction:
    values: dict[str, object] = {
        "state_digest": b"s" * 32,
        "binding_digest": b"b" * 32,
        "operation": OAuthOperation.LOGIN,
        "provider": "oidc",
        "expected_issuer": ISSUER,
        "redirect_uri": "https://app.example.com/auth/oidc/callback",
        "return_to": "/",
        "requested_scopes": frozenset({"openid", "email", "profile"}),
        "pkce_verifier": SecretStr("v" * 43),
        "nonce": SecretStr("transaction-nonce"),
        "expires_at": NOW + timedelta(minutes=10),
    }
    values.update(overrides)
    return OAuthTransaction(**values)  # type: ignore[arg-type]


async def test_oidc_logout_token_consumer_verifies_events_and_rejects_replay() -> None:
    base_claims = claims(events={"http://schemas.openid.net/event/backchannel-logout": {}}, sid="sid-1")
    raw = dict(base_claims.raw)
    raw.pop("nonce")
    logout_claims = replace(base_claims, raw=raw, token_id="jti-1")  # noqa: S106 - public JWT identifier
    verifier = StubVerifier(
        config=JWTValidationConfig(
            issuer=ISSUER,
            audiences=frozenset({CLIENT_ID}),
            algorithms=frozenset({"RS256"}),
            access_token_profile=False,
            subject_required=False,
            token_types=frozenset({"logout+jwt"}),
        ),
        outcome=Authenticated(
            claims=logout_claims,
            evidence=AuthenticationEvidence(mechanism="oidc-logout", slot="logout", authenticated_at=NOW),
        ),
    )
    consumer = OIDCJWTLogoutTokenConsumer(verifiers={"oidc": cast("Any", verifier)})

    identity = await consumer.consume("oidc", "signed-token", now=NOW)

    assert identity.session_id == "sid-1"
    assert identity.expires_at == logout_claims.expires_at
    sid_only_raw = dict(logout_claims.raw)
    sid_only_raw.pop("sub")
    verifier.outcome = Authenticated(
        claims=replace(
            logout_claims,
            subject=None,
            raw=sid_only_raw,
            token_id="jti-2",  # noqa: S106 - public JWT identifier
        ),
        evidence=AuthenticationEvidence(mechanism="oidc-logout", slot="logout", authenticated_at=NOW),
    )
    assert (await consumer.consume("oidc", "sid-only-token", now=NOW)).subject is None


async def test_oidc_logout_token_consumer_rejects_invalid_event() -> None:
    base_invalid = claims(events={})
    invalid_raw = dict(base_invalid.raw)
    invalid_raw.pop("nonce")
    invalid = replace(base_invalid, raw=invalid_raw, token_id="jti")  # noqa: S106 - public JWT identifier
    verifier = StubVerifier(
        config=JWTValidationConfig(
            issuer=ISSUER,
            audiences=frozenset({CLIENT_ID}),
            algorithms=frozenset({"RS256"}),
            access_token_profile=False,
            subject_required=False,
            token_types=frozenset({"logout+jwt"}),
        ),
        outcome=Authenticated(
            claims=invalid,
            evidence=AuthenticationEvidence(mechanism="oidc-logout", slot="logout", authenticated_at=NOW),
        ),
    )
    consumer = OIDCJWTLogoutTokenConsumer(verifiers={"oidc": cast("Any", verifier)})
    with pytest.raises(NotAuthorizedException, match="logout token is invalid"):
        await consumer.consume("oidc", "signed-token", now=NOW)


def test_oidc_logout_consumer_rejects_invalid_configuration() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="consumer configuration"):
        OIDCJWTLogoutTokenConsumer(verifiers={})
    with pytest.raises(ImproperlyConfiguredException, match="consumer configuration"):
        OIDCJWTLogoutTokenConsumer(verifiers={"oidc": cast("Any", object())})
    verifier = StubVerifier(
        config=JWTValidationConfig(
            issuer=ISSUER, audiences=frozenset({CLIENT_ID}), algorithms=frozenset({"RS256"}), access_token_profile=False
        ),
        outcome=InvalidCredentials(),
    )
    with pytest.raises(ImproperlyConfiguredException, match="consumer configuration"):
        OIDCJWTLogoutTokenConsumer(verifiers={"oidc": cast("Any", verifier)})


async def test_oidc_logout_consumer_rejects_missing_provider_and_failed_verification() -> None:
    verifier = StubVerifier(
        config=JWTValidationConfig(
            issuer=ISSUER,
            audiences=frozenset({CLIENT_ID}),
            algorithms=frozenset({"RS256"}),
            access_token_profile=False,
            subject_required=False,
            token_types=frozenset({"logout+jwt"}),
        ),
        outcome=InvalidCredentials(),
    )
    consumer = OIDCJWTLogoutTokenConsumer(verifiers={"oidc": cast("Any", verifier)})

    with pytest.raises(NotAuthorizedException, match="logout token is invalid"):
        await consumer.consume("missing", "signed-token", now=NOW)
    with pytest.raises(NotAuthorizedException, match="logout token is invalid"):
        await consumer.consume("oidc", "signed-token", now=NOW)


@pytest.mark.parametrize(
    ("raw_overrides", "token_id"),
    [
        ({"events": {"http://schemas.openid.net/event/backchannel-logout": {}}}, None),
        ({"events": "invalid", "nonce": None}, "jti"),
        ({"events": {"extra": {}}, "nonce": None}, "jti"),
        ({"events": {"http://schemas.openid.net/event/backchannel-logout": "invalid"}, "nonce": None}, "jti"),
        ({"events": {"http://schemas.openid.net/event/backchannel-logout": {"value": True}}, "nonce": None}, "jti"),
        ({"events": {"http://schemas.openid.net/event/backchannel-logout": {}}, "nonce": None, "sid": ""}, "jti"),
        ({"events": {"http://schemas.openid.net/event/backchannel-logout": {}}, "nonce": None, "sub": None}, "jti"),
    ],
)
async def test_oidc_logout_consumer_rejects_invalid_claim_matrix(
    raw_overrides: dict[str, JSONValue], token_id: str | None
) -> None:
    value = claims(**raw_overrides)
    raw = dict(value.raw)
    if raw.get("nonce") is None:
        raw.pop("nonce", None)
    invalid = replace(value, raw=raw, token_id=token_id)
    verifier = StubVerifier(
        config=JWTValidationConfig(
            issuer=ISSUER,
            audiences=frozenset({CLIENT_ID}),
            algorithms=frozenset({"RS256"}),
            access_token_profile=False,
            subject_required=False,
            token_types=frozenset({"logout+jwt"}),
        ),
        outcome=Authenticated(
            claims=invalid,
            evidence=AuthenticationEvidence(mechanism="oidc-logout", slot="logout", authenticated_at=NOW),
        ),
    )
    consumer = OIDCJWTLogoutTokenConsumer(verifiers={"oidc": cast("Any", verifier)})

    with pytest.raises(NotAuthorizedException, match="logout token is invalid"):
        await consumer.consume("oidc", "signed-token", now=NOW)


def tokens(*, id_token: SecretStr | None = ID_TOKEN) -> ProviderTokenSet:
    return ProviderTokenSet(
        access_token=SecretStr("access-token"),
        token_type="Bearer",  # noqa: S106 - standardized OAuth token type, not a credential
        scopes=frozenset({"openid", "email", "profile"}),
        expires_at=NOW + timedelta(hours=1),
        id_token=id_token,
    )


def metadata(*, issuer: str = ISSUER) -> OIDCMetadata:
    return OIDCMetadata(
        issuer=issuer,
        jwks_uri=f"{issuer}/jwks",
        authorization_endpoint=f"{issuer}/authorize",
        token_endpoint=f"{issuer}/token",
        end_session_endpoint=f"{issuer}/logout",
        algorithms=frozenset({"RS256"}),
    )


def verifier(outcome: object) -> StubVerifier:
    return StubVerifier(
        config=JWTValidationConfig(
            issuer=ISSUER,
            audiences=frozenset({CLIENT_ID}),
            algorithms=frozenset({"RS256"}),
            access_token_profile=False,
            token_types=frozenset({"jwt"}),
        ),
        outcome=outcome,
    )


def provider(outcome: object) -> OIDCProvider:
    return oidc_provider(
        name="oidc",
        client_id=CLIENT_ID,
        client_secret=SecretStr("client-secret"),
        metadata=metadata(),
        verifier=verifier(outcome),  # type: ignore[arg-type]
        scopes=frozenset({"openid", "email", "profile"}),
    )


def authenticated(claim_set: JWTClaims) -> Authenticated[JWTClaims]:
    return Authenticated(
        claims=claim_set,
        evidence=AuthenticationEvidence(
            mechanism="oidc-id-token", slot="oidc.id-token", authenticated_at=NOW, expires_at=claim_set.expires_at
        ),
    )


async def test_oidc_maps_verified_identity_and_raw_assurance() -> None:
    verified = claims()
    oidc = provider(
        Authenticated(
            claims=verified,
            evidence=AuthenticationEvidence(
                mechanism="oidc-id-token", slot="oidc.id-token", authenticated_at=NOW, expires_at=verified.expires_at
            ),
        )
    )

    identity = await oidc.resolve_identity(tokens(), transaction=transaction(), now=NOW)

    assert identity.provider == "oidc"
    assert identity.issuer == ISSUER
    assert identity.subject == "subject-1"
    assert identity.display_name == "Ada Lovelace"
    assert identity.email == "ada@example.com"
    assert identity.email_verified is True
    assert identity.acr == "urn:mfa"
    assert identity.amr == ("pwd", "otp")
    assert identity.raw_claims["acr"] == "urn:mfa"
    assert identity.raw_claims["amr"] == ("pwd", "otp")


@pytest.mark.parametrize(
    ("claim_overrides", "transaction_overrides"),
    [
        ({"nonce": "wrong"}, {}),
        ({"nonce": None}, {}),
        ({"azp": "other-client"}, {}),
        ({"aud": [CLIENT_ID, "other"]}, {}),
        ({"email": 1}, {}),
        ({"email_verified": "true"}, {}),
        ({"acr": 1}, {}),
        ({"amr": ["pwd", 1]}, {}),
        ({"amr": ["pwd", "pwd"]}, {}),
        ({}, {"expected_issuer": "https://other.example.com"}),
        ({}, {"nonce": None}),
    ],
)
async def test_oidc_rejects_invalid_claim_and_transaction_bindings(
    claim_overrides: dict[str, JSONValue], transaction_overrides: dict[str, object]
) -> None:
    verified = claims(**claim_overrides)
    oidc = provider(
        Authenticated(
            claims=verified,
            evidence=AuthenticationEvidence(
                mechanism="oidc-id-token", slot="oidc.id-token", authenticated_at=NOW, expires_at=verified.expires_at
            ),
        )
    )

    with pytest.raises(OAuthProviderError, match="OAuth provider request failed"):
        await oidc.resolve_identity(tokens(), transaction=transaction(**transaction_overrides), now=NOW)


async def test_oidc_accepts_multi_audience_with_matching_azp() -> None:
    verified = claims(aud=[CLIENT_ID, "other"], azp=CLIENT_ID)
    oidc = provider(
        Authenticated(
            claims=verified,
            evidence=AuthenticationEvidence(
                mechanism="oidc-id-token", slot="oidc.id-token", authenticated_at=NOW, expires_at=verified.expires_at
            ),
        )
    )

    identity = await oidc.resolve_identity(tokens(), transaction=transaction(), now=NOW)

    assert identity.subject == "subject-1"


@pytest.mark.parametrize("outcome", [InvalidCredentials(), VerificationUnavailable()])
async def test_oidc_collapses_verifier_failures(outcome: object) -> None:
    oidc = provider(outcome)

    with pytest.raises(OAuthProviderError, match="OAuth provider request failed"):
        await oidc.resolve_identity(tokens(), transaction=transaction(), now=NOW)


async def test_oidc_requires_id_token() -> None:
    oidc = provider(InvalidCredentials())

    with pytest.raises(OAuthProviderError):
        await oidc.resolve_identity(tokens(id_token=None), transaction=transaction(), now=NOW)


def test_oidc_constructor_rejects_discovery_or_verifier_mismatch() -> None:
    mismatched = verifier(InvalidCredentials())
    mismatched.config = JWTValidationConfig(
        issuer="https://other.example.com",
        audiences=frozenset({CLIENT_ID}),
        algorithms=frozenset({"RS256"}),
        access_token_profile=False,
        token_types=frozenset({"jwt"}),
    )

    with pytest.raises(Exception, match="OIDC provider"):
        oidc_provider(
            name="oidc",
            client_id=CLIENT_ID,
            client_secret=SecretStr("secret"),
            metadata=metadata(),
            verifier=mismatched,  # type: ignore[arg-type]
            scopes=frozenset({"openid"}),
        )


@pytest.mark.parametrize("token_types", [None, frozenset({"logout+jwt"}), frozenset({"jwt", "logout+jwt"})])
def test_oidc_constructor_rejects_non_id_token_types(token_types: frozenset[str] | None) -> None:
    config_arguments: dict[str, object] = {
        "issuer": ISSUER,
        "audiences": frozenset({CLIENT_ID}),
        "algorithms": frozenset({"RS256"}),
        "access_token_profile": False,
    }
    if token_types is not None:
        config_arguments["token_types"] = token_types
    rejected = StubVerifier(  # type: ignore[arg-type]
        config=JWTValidationConfig(**config_arguments), outcome=InvalidCredentials()
    )

    with pytest.raises(ImproperlyConfiguredException, match="OIDC provider trust configuration is inconsistent"):
        oidc_provider(
            name="oidc",
            client_id=CLIENT_ID,
            client_secret=SecretStr("secret"),
            metadata=metadata(),
            verifier=rejected,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("token_types", [None, frozenset({"jwt"}), frozenset({"jwt", "logout+jwt"})])
def test_oidc_logout_consumer_rejects_non_logout_token_types(token_types: frozenset[str] | None) -> None:
    config_arguments: dict[str, object] = {
        "issuer": ISSUER,
        "audiences": frozenset({CLIENT_ID}),
        "algorithms": frozenset({"RS256"}),
        "access_token_profile": False,
        "subject_required": False,
    }
    if token_types is not None:
        config_arguments["token_types"] = token_types
    rejected = StubVerifier(  # type: ignore[arg-type]
        config=JWTValidationConfig(**config_arguments), outcome=InvalidCredentials()
    )

    with pytest.raises(ImproperlyConfiguredException, match="OIDC logout token consumer configuration is invalid"):
        OIDCJWTLogoutTokenConsumer(verifiers={"oidc": rejected})  # type: ignore[arg-type]


def test_google_constructor_uses_pinned_profile() -> None:
    google_verifier = verifier(InvalidCredentials())
    google_verifier.config = JWTValidationConfig(
        issuer="https://accounts.google.com",
        audiences=frozenset({CLIENT_ID}),
        algorithms=frozenset({"RS256"}),
        access_token_profile=False,
        token_types=frozenset({"jwt"}),
    )
    google = google_oidc_provider(
        client_id=CLIENT_ID,
        client_secret=SecretStr("secret"),
        metadata=metadata(issuer="https://accounts.google.com"),
        verifier=google_verifier,  # type: ignore[arg-type]
    )

    assert google.name == "google"
    assert google.end_session_endpoint == "https://accounts.google.com/logout"
    assert google.oauth.config.extra_authorization_parameters["access_type"] == "offline"


def test_keycloak_constructor_requires_exact_realm_issuer() -> None:
    issuer = "https://id.example.com/realms/acme"
    keycloak_verifier = verifier(InvalidCredentials())
    keycloak_verifier.config = JWTValidationConfig(
        issuer=issuer,
        audiences=frozenset({CLIENT_ID}),
        algorithms=frozenset({"RS256"}),
        access_token_profile=False,
        token_types=frozenset({"jwt"}),
    )

    keycloak = keycloak_oidc_provider(
        base_url="https://id.example.com",
        realm="acme",
        client_id=CLIENT_ID,
        client_secret=SecretStr("secret"),
        metadata=metadata(issuer=issuer),
        verifier=keycloak_verifier,  # type: ignore[arg-type]
    )

    assert keycloak.name == "keycloak"
    assert keycloak.issuer == issuer


async def test_oidc_provider_delegates_lifecycle_and_close() -> None:
    async def resolver(_host: str, _port: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/revoke":
            return httpx.Response(200)
        return httpx.Response(
            200,
            json={
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "id_token": "header.payload.signature",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid",
            },
        )

    base = OAuthProviderClient(
        OAuthEndpointConfig(
            name="oidc",
            client_id=CLIENT_ID,
            client_secret=SecretStr("secret"),
            client_auth=OAuthClientAuth.CLIENT_SECRET_BASIC,
            authorization_endpoint=f"{ISSUER}/authorize",
            token_endpoint=f"{ISSUER}/token",
            revocation_endpoint=f"{ISSUER}/revoke",
            allowed_scopes=frozenset({"openid"}),
            required_scopes=frozenset({"openid"}),
        ),
        transport=httpx.MockTransport(handler),
        resolver=resolver,
    )
    oidc = OIDCProvider(oauth=base, metadata=metadata(), verifier=verifier(InvalidCredentials()))  # type: ignore[arg-type]
    tx = transaction(requested_scopes=frozenset({"openid"}))
    start = OAuthTransactionStart(
        state=SecretStr("state"),
        browser_binding=SecretStr("binding"),
        pkce_challenge="challenge",
        nonce=SecretStr("transaction-nonce"),
        transaction=tx,
    )

    assert oidc.issuer == ISSUER
    assert oidc.end_session_endpoint == f"{ISSUER}/logout"
    assert oidc.build_authorization_url(start).startswith(f"{ISSUER}/authorize?")
    assert (await oidc.exchange_code(code=SecretStr("code"), transaction=tx, now=NOW)).access_token.get_secret_value()
    assert (await oidc.refresh(SecretStr("refresh"), now=NOW)).refresh_token is not None
    await oidc.revoke(
        SecretStr("access"),
        token_type_hint="access_token",  # noqa: S106 - standardized OAuth token kind, not a credential
    )
    await oidc.aclose()
    assert base.closed


def test_oidc_constructor_rejects_invalid_verifier_contract() -> None:
    base = OAuthProviderClient(
        OAuthEndpointConfig(
            name="oidc",
            client_id=CLIENT_ID,
            client_secret=SecretStr("secret"),
            client_auth=OAuthClientAuth.CLIENT_SECRET_BASIC,
            authorization_endpoint=f"{ISSUER}/authorize",
            token_endpoint=f"{ISSUER}/token",
            revocation_endpoint=None,
            allowed_scopes=frozenset({"openid"}),
            required_scopes=frozenset({"openid"}),
        )
    )

    with pytest.raises(ImproperlyConfiguredException, match="OIDC provider requires a JWT verifier"):
        OIDCProvider(oauth=base, metadata=metadata(), verifier=cast("Any", object()))


@pytest.mark.parametrize(
    "invalid_metadata",
    [
        OIDCMetadata(
            issuer=ISSUER,
            jwks_uri=f"{ISSUER}/jwks",
            authorization_endpoint=None,
            token_endpoint=f"{ISSUER}/token",
            end_session_endpoint=None,
            algorithms=frozenset({"RS256"}),
        ),
        OIDCMetadata(
            issuer=ISSUER,
            jwks_uri=f"{ISSUER}/jwks",
            authorization_endpoint=f"{ISSUER}/authorize",
            token_endpoint=None,
            end_session_endpoint=None,
            algorithms=frozenset({"RS256"}),
        ),
    ],
)
def test_oidc_constructor_requires_discovered_code_endpoints(invalid_metadata: OIDCMetadata) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="OIDC provider requires authorization and token endpoints"):
        oidc_provider(
            name="oidc",
            client_id=CLIENT_ID,
            client_secret=SecretStr("secret"),
            metadata=invalid_metadata,
            verifier=verifier(InvalidCredentials()),  # type: ignore[arg-type]
        )


def test_oidc_constructor_requires_openid_scope() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="OIDC provider requires the openid scope"):
        oidc_provider(
            name="oidc",
            client_id=CLIENT_ID,
            client_secret=SecretStr("secret"),
            metadata=metadata(),
            verifier=verifier(InvalidCredentials()),  # type: ignore[arg-type]
            scopes=frozenset({"email"}),
        )


def test_google_constructor_rejects_other_issuer() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Google OIDC issuer is invalid"):
        google_oidc_provider(
            client_id=CLIENT_ID,
            client_secret=SecretStr("secret"),
            metadata=metadata(),
            verifier=verifier(InvalidCredentials()),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("base_url", "realm"), [("https://id.example.com/", "acme"), ("https://id.example.com", "a/b")]
)
def test_keycloak_constructor_rejects_non_exact_realm(base_url: str, realm: str) -> None:
    with pytest.raises(ImproperlyConfiguredException, match="Keycloak OIDC realm issuer is invalid"):
        keycloak_oidc_provider(
            base_url=base_url,
            realm=realm,
            client_id=CLIENT_ID,
            client_secret=SecretStr("secret"),
            metadata=metadata(),
            verifier=verifier(InvalidCredentials()),  # type: ignore[arg-type]
        )


async def test_oidc_optional_claim_fallbacks_and_time_validation() -> None:
    preferred = claims(name=None, preferred_username="ada", email=None, email_verified=False, acr=None, amr=None)
    oidc = provider(authenticated(preferred))

    identity = await oidc.resolve_identity(tokens(), transaction=transaction(), now=NOW)

    assert identity.display_name == "ada"
    assert identity.email is None
    assert identity.acr is None
    assert identity.amr == ()

    with pytest.raises(OAuthProviderError):
        await oidc.resolve_identity(
            tokens(),
            transaction=transaction(),
            now=datetime(2026, 7, 28),  # noqa: DTZ001 - deliberately exercise naive timestamp rejection
        )


async def test_oidc_rejects_claim_issuer_even_after_custom_verifier_success() -> None:
    oidc = provider(authenticated(claims(iss="https://other.example.com")))

    with pytest.raises(OAuthProviderError):
        await oidc.resolve_identity(tokens(), transaction=transaction(), now=NOW)


async def test_oidc_rejects_verified_email_without_email() -> None:
    oidc = provider(authenticated(claims(email=None, email_verified=True)))

    with pytest.raises(OAuthProviderError):
        await oidc.resolve_identity(tokens(), transaction=transaction(), now=NOW)
