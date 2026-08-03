JWT signing, discovery, and JWKS
================================

This guide covers the provider primitives available in the initial JWT and
JWKS runtime. Applications still own key storage, KMS clients, identity
resolution, and network transports. Litestar Security does not generate keys or
read key material from paths or environment variables.

Local keys
----------

Use Ed25519 with ``EdDSA`` for new local trust domains unless an interoperating
system requires ``ES256`` or ``RS256``. Pass key bytes from the application's
secret-management boundary explicitly:

.. code-block:: python

   from collections.abc import Sequence
   from dataclasses import dataclass
   from datetime import datetime, timedelta, timezone

   from litestar import Litestar
   from litestar.di import Provide
   from litestar.types import ControllerRouterHandler

   from litestar_security import Principal, SecurityConfig, SecurityPlugin
   from litestar_security.config import SecurityMetrics, WorkerLimits
   from litestar_security.providers import (
       BearerSlotSelector,
       BearerTokenSlot,
       CompositeBearerConfig,
       JWTClaims,
       JWTValidationConfig,
       LocalJWKSConfig,
       LocalKeyRing,
       SigningKey,
       build_access_token_claims,
   )


   @dataclass(frozen=True, slots=True)
   class User:
       id: str


   class UserResolver:
       async def resolve(self, claims: JWTClaims) -> Principal[User]:
           user = User(id=claims.subject)
           return Principal(id=user.id, user=user)


   def create_app(
       private_key_pem: bytes,
       metrics: SecurityMetrics,
       route_handlers: Sequence[ControllerRouterHandler] = (),
   ) -> tuple[Litestar, LocalKeyRing]:
       workers = WorkerLimits(network_tokens=8, crypto_tokens=32, timeout=10.0)
       ring = LocalKeyRing(
           issuer="https://auth.example.com",
           active_signing_key=SigningKey(
               key_id="2026-07",
               algorithm="EdDSA",
               private_key=private_key_pem,
           ),
           worker_limits=workers,
           metrics=metrics,
       )
       validation = JWTValidationConfig(
           issuer=ring.issuer,
           audiences=frozenset({"https://api.example.com"}),
           algorithms=frozenset({"EdDSA"}),
       )
       verifier = ring.build_verifier(validation)
       slot, mechanism = CompositeBearerConfig(
           mechanism_name="bearer",
           slots=(
               BearerTokenSlot(
                   name="local",
                   selector=BearerSlotSelector(
                       issuers=frozenset({ring.issuer}),
                       audiences=validation.audiences,
                   ),
                   verifier=verifier,
               ),
           ),
       ).build(UserResolver())
       plugin = SecurityPlugin(
           SecurityConfig[User](
               slots=(slot,),
               mechanisms=(mechanism,),
               local_jwks=LocalJWKSConfig(ring.verification_key_set),
           )
       )
       return Litestar(
           route_handlers=route_handlers,
           plugins=[plugin],
           dependencies={"ring": Provide(lambda: ring)},
       ), ring


   async def issue_token(ring: LocalKeyRing, user_id: str) -> str:
       now = datetime.now(timezone.utc)
       claims = build_access_token_claims(
           issuer=ring.issuer,
           audience="https://api.example.com",
           subject=user_id,
           client_id="first-party-web",
           security_epoch=0,
           now=now,
           lifetime=timedelta(minutes=15),
           scopes={"reports:read"},
       )
       return await ring.build_signer().sign(claims, now=now)

``SigningKey`` validates the private key and derives its public JWK during
configuration. ``LocalJWKSConfig`` publishes only asymmetric public material at
``/auth/.well-known/jwks.json`` with a stable ETag and native Litestar OpenAPI
metadata.

Rotation is an explicit configuration replacement. Make the new key active and
retain old public keys as ``VerificationKey`` instances for at least the
maximum lifetime of tokens issued with them. ``HS256`` is limited to a single
trust domain and cannot be published as JWKS.

Capability tokens
-----------------

Capabilities are bounded, signed grants for one application-defined purpose.
For example, an authenticated route can mint a short-lived download URL, while
the download route remains ``public()`` and verifies the URL's token itself.
Register the local key ring as the application's ``ring`` dependency:

.. code-block:: python

   from datetime import datetime, timedelta, timezone

   from litestar import get
   from litestar.di import NamedDependency
   from litestar.exceptions import NotAuthorizedException, ServiceUnavailableException

   from litestar_security import (
       InvalidCredentials,
       Principal,
       VerificationUnavailable,
       public,
       required,
   )
   from litestar_security.providers import LocalKeyRing, VerifiedCapability


   @get("/files/{file_id:str}/download-url", auth=required())
   async def create_download_url(
       file_id: str,
       principal: NamedDependency[Principal[object]],
       ring: NamedDependency[LocalKeyRing],
   ) -> dict[str, str]:
       token = await ring.mint_capability(
           purpose="download",
           subject=principal.id,
           audience="files",
           lifetime=timedelta(minutes=15),
           claims={"file_id": file_id},
       )
       return {"url": f"/files/{file_id}/download?token={token}"}


   @get("/files/{file_id:str}/download", auth=public())
   async def download_file(
       file_id: str,
       token: str,
       ring: NamedDependency[LocalKeyRing],
   ) -> dict[str, str]:
       result = await ring.verify_capability(
           token,
           purpose="download",
           audience="files",
           now=datetime.now(timezone.utc),
       )
       if isinstance(result, VerificationUnavailable):
           raise ServiceUnavailableException(detail="Download verification is unavailable")
       if isinstance(result, InvalidCredentials):
           raise NotAuthorizedException(detail="Invalid download capability")
       if not isinstance(result, VerifiedCapability) or result.claims.get("file_id") != file_id:
           raise NotAuthorizedException(detail="Invalid download capability")
       return {"file_id": file_id, "subject": result.subject}


   app, _ = create_app(
       private_key_pem,
       metrics,
       route_handlers=[create_download_url, download_file],
   )

The return value stands in for the application's file read after authorization.
``VerifiedCapability`` contains only verified application claims and metadata;
it never retains the compact token. Capabilities are stateless, so applications
that need single-use links must atomically consume or reject the returned
``token_id`` in their own durable store.

Custom KMS and HSM operations
-----------------------------

Custom objects use structural protocols. An async signer defines
``async sign(claims, *, now)``; a sync signer defines the same method without
``async``. A verifier also exposes a ``JWTValidationConfig`` as ``config`` and
returns an ``AuthenticationOutcome`` from ``verify(token, *, now)``.

Normalize custom objects once while assembling the application:

.. code-block:: python

   from litestar_security.config import SecurityMetrics, WorkerLimits
   from litestar_security.providers import (
       JWTVerifier,
       SyncJWTVerifier,
       SyncTokenSigner,
       TokenSigner,
       normalize_signer,
       normalize_verifier,
   )


   def normalize_kms(
       async_signer: TokenSigner,
       sync_signer: SyncTokenSigner,
       async_verifier: JWTVerifier[object],
       sync_verifier: SyncJWTVerifier[object],
       workers: WorkerLimits,
       metrics: SecurityMetrics,
   ) -> tuple[TokenSigner, TokenSigner, JWTVerifier[object], JWTVerifier[object]]:
       return (
           normalize_signer(async_signer, worker_limits=workers, metrics=metrics),
           normalize_signer(sync_signer, worker_limits=workers, metrics=metrics),
           normalize_verifier(async_verifier, worker_limits=workers, metrics=metrics),
           normalize_verifier(sync_verifier, worker_limits=workers, metrics=metrics),
       )

Native async implementations remain on the event loop. Sync implementations run
through the shared crypto limiter with a timeout covering queue wait and
execution. Signer failures raise a sanitized ``RuntimeError``; verifier
capacity or operation failures return ``VerificationUnavailable``.

A KMS signer should also expose its current and retained public keys through a
``VerificationKeySet``. That key set can build a local verifier and a
``LocalJWKSConfig`` without exposing the KMS private key.

Strict OIDC discovery
---------------------

Discovery starts only from an exact issuer configured by the operator:

.. code-block:: python

   from litestar_security.providers import DiscoveryPolicy, OIDCDiscoveryClient


   async def discover_provider() -> tuple[str, str, frozenset[str]]:
       issuer = "https://id.example.com/realms/production"
       policy = DiscoveryPolicy(
           allowed_issuers=frozenset({issuer}),
           allowed_ports=frozenset({443}),
           require_https=True,
           allow_private_hosts=False,
           connect_timeout=2.0,
           read_timeout=3.0,
           maximum_document_bytes=65_536,
       )
       async with OIDCDiscoveryClient(
           policy=policy,
           algorithms=frozenset({"EdDSA", "RS256"}),
       ) as discovery:
           metadata = await discovery.discover(issuer)
       return metadata.issuer, metadata.jwks_uri, metadata.algorithms

The client disables redirects and proxy-environment trust, validates public
network addresses, requires exact metadata issuer equality, and permits a JWKS
URI on the issuer origin only. Add an exact origin to
``allowed_jwks_origins`` only when the provider deliberately hosts JWKS
elsewhere. ``allow_private_hosts=True`` is appropriate only inside a controlled
network, such as an isolated Keycloak development environment.

JWKS cache lifecycle
--------------------

``CachedJWKSProvider`` is transport-neutral. Supply a bounded async or sync
fetcher that returns ``JWKSFetchResponse`` and configure each trusted
``(issuer, jwks_uri)`` pair explicitly:

.. code-block:: python

   from litestar import Litestar

   from litestar_security import SecurityConfig, SecurityPlugin
   from litestar_security.config import SecurityMetrics, WorkerLimits
   from litestar_security.providers import (
       AsyncJWKSFetcher,
       CachedJWKSProvider,
       JWKSCacheEntry,
       JWKSCachePolicy,
   )


   def create_remote_app(
       fetcher: AsyncJWKSFetcher,
       workers: WorkerLimits,
       metrics: SecurityMetrics,
   ) -> Litestar:
       provider = CachedJWKSProvider(
           entries=(
               JWKSCacheEntry(
                   issuer="https://id.example.com/realms/production",
                   jwks_uri="https://id.example.com/realms/production/protocol/openid-connect/certs",
                   algorithms=frozenset({"EdDSA", "RS256"}),
               ),
           ),
           fetcher=fetcher,
           policy=JWKSCachePolicy(warm_on_startup=True),
           worker_limits=workers,
           metrics=metrics,
           fetcher_owned=True,
       )
       return Litestar(
           plugins=[
               SecurityPlugin(
                   SecurityConfig(
                       jwks_providers=(provider,),
                       jwks_warmup_failure="fail_startup",
                   )
               )
           ]
       )

The default warmup failure mode fails application startup. Set
``jwks_warmup_failure="lazy"`` only when the application may start while key
verification remains unavailable. Litestar's lifespan closes every configured
provider. The provider closes its fetcher only when ``fetcher_owned=True``;
otherwise the application that supplied the fetcher remains responsible for
closing it.

Fresh snapshots are immutable and selected without network I/O or lock
acquisition. Expiry and unknown key IDs use per-entry single-flight refreshes;
conditional ETags support ``304`` revalidation. Rotation replaces the complete
snapshot atomically, removed keys disappear immediately, and unknown-key
negative entries are generation-scoped and bounded.

Sync fetchers implement ``fetch(request)`` and are normalized once by the
provider through ``workers.network_limiter``. Async fetchers are used directly.
Cancellation of one waiter does not cancel a shared refresh.

Stale keys fail closed by default
---------------------------------

``JWKSCachePolicy.stale_if_error`` defaults to zero. This is the recommended
setting because an expired key is unavailable when refresh fails.

An application with a documented availability requirement may opt into a short,
locally bounded grace period:

.. code-block:: python

   from datetime import timedelta

   from litestar_security.providers import JWKSCachePolicy

   cache_policy = JWKSCachePolicy(
       stale_if_error=timedelta(seconds=30),
   )

Only a matching key already present in the expired snapshot can be used before
the bounded stale deadline. Unknown keys never use stale fallback. Remote
``stale-if-error`` cache directives cannot enable or extend this policy, and
every stale use emits ``security.jwks.stale_use``.

Shared workers and metrics
--------------------------

Create one ``WorkerLimits`` instance and pass it to local rings, KMS
normalizers, and remote JWKS providers that should share a capacity budget:

.. code-block:: python

   from litestar_security.config import WorkerLimits

   security_workers = WorkerLimits(
       network_tokens=8,
       crypto_tokens=32,
       timeout=10.0,
   )

Network and crypto operations use separate capacity limiters. The timeout for a
sync operation includes both limiter queueing and execution. No executor is
created per request or provider.

``SecurityMetrics`` is a synchronous, vendor-neutral protocol. Implement
``increment(name, *, attributes)`` and
``observe(name, value, *, attributes)`` with non-blocking methods, or omit the
argument to use ``NoOpSecurityMetrics``. Metric sink failures are suppressed so
observability cannot change authentication results.

The runtime emits ``security.jwks.*`` counters and durations for cache hits,
misses, refreshes, rotation, invalid documents, negative entries, parsing,
fetching, and single-flight waits. ``security.jwt.*`` covers signing and
verification durations; ``security.worker.*`` covers saturation, queue wait,
and execution. Metric inputs never include token contents, claims, keys,
untrusted key IDs, raw issuers, or exception messages.
