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
```

`local-session` and `local-hybrid` explicitly install native session and CSRF
configuration. `local-token` never installs a session. `no-session` demonstrates
that public and protected request paths still receive a typed
`SecurityContext` whose session handle is `NullSessionHandle`.
