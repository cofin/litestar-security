# Litestar Security

Litestar Security is a pre-alpha plugin library for adding security integrations
to [Litestar](https://litestar.dev/) applications.

The initial `0.1.0` release is a packaging and integration scaffold. It exposes
a typed configuration object, a Litestar plugin, and a CLI namespace.
Authentication and authorization behavior is not implemented yet.

## Installation

The project is not published to PyPI. For local development, clone the
repository and install its locked dependencies:

```console
make install
```

## Plugin scaffold

The public API is intentionally small:

```python
from litestar import Litestar
from litestar_security import SecurityConfig, SecurityPlugin

security_config = SecurityConfig()
security_plugin = SecurityPlugin(config=security_config)

app = Litestar(plugins=[security_plugin])
```

`SecurityConfig` currently has no settings, and `SecurityPlugin` leaves the
application configuration unchanged. Provider, middleware, guard, state,
dependency, route, authentication, and authorization contracts will be added
with their corresponding features.

## CLI

Installing the project adds a `security` group to the Litestar CLI:

```console
litestar security --help
litestar security --version
```

Feature-specific commands will arrive with their implementations.

## Development

Run the complete local validation suite with:

```console
make check-all
```

See [CONTRIBUTING.rst](CONTRIBUTING.rst) for setup, testing, documentation, and
contribution guidance.

## License

Litestar Security is distributed under the MIT license.
