# Litestar Security examples

These applications are deterministic development examples. They generate
ephemeral signing material and use insecure loopback-only cookies; replace all
stores, keys, secrets, delivery hooks, and rate-limiting policy in production.

Choose one explicit transport and run it with the Litestar CLI:

```console
LITESTAR_SECURITY_EXAMPLE=local-session uv run litestar --app examples.app:create_app run
LITESTAR_SECURITY_EXAMPLE=local-token uv run litestar --app examples.app:create_app run
LITESTAR_SECURITY_EXAMPLE=local-hybrid uv run litestar --app examples.app:create_app run
LITESTAR_SECURITY_EXAMPLE=no-session uv run litestar --app examples.app:create_app run
LITESTAR_SECURITY_EXAMPLE=google-iap uv run litestar --app examples.app:create_app run
LITESTAR_SECURITY_EXAMPLE=google-oauth uv run litestar --app examples.app:create_app run
LITESTAR_SECURITY_EXAMPLE=github-oauth uv run litestar --app examples.app:create_app run
LITESTAR_SECURITY_EXAMPLE=keycloak uv run litestar --app examples.app:create_app run
LITESTAR_SECURITY_EXAMPLE=api-team-service uv run litestar --app examples.app:create_app run
```

`local-session` and `local-hybrid` explicitly install native session and CSRF
configuration. `local-token` never installs a session. `no-session` demonstrates
that public and protected request paths still receive a typed
`SecurityContext` whose session handle is `NullSessionHandle`.

Provider modes use deterministic, secret-free stub transports by default.
`google-iap` admits only a signed IAP assertion for the exact configured
audience; unsigned identity headers are never credentials. The OAuth modes
exercise native login, callback, link, unlink, scope-upgrade, revoke, and logout
routes with state/PKCE binding. The disposable Keycloak realm lives at
`src/tests/fixtures/keycloak/realm.json`. `api-team-service` composes an opaque
HMAC-digested API key with an external userless workload JWT; application guards
remain responsible for team and tenant authorization.

The stub modes are not deployment configuration. Production IAP must be behind
the intended Google load-balancer boundary, OAuth clients must load real
credentials from a secret manager, and every discovery/JWKS issuer, audience,
redirect URI, and egress destination must be pinned explicitly.
