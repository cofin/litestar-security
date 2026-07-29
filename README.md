# Litestar Security

Authentication and authorization for [Litestar](https://litestar.dev/)
applications.

Litestar Security connects authentication providers to Litestar's middleware,
dependency injection, guards, OpenAPI schema, and WebSocket lifecycle. Use
local sessions or tokens, OAuth and OIDC, Google IAP, API keys, or workload
JWTs without tying your application to a database library.

## Quickstart

Install the package:

```console
pip install litestar-security
```

Create `app.py`:

```python
from litestar import Litestar, get
from litestar.di import NamedDependency

from litestar_security import (
    SecurityConfig,
    SecurityContext,
    SecurityPlugin,
    public,
)


@get("/", auth=public(), sync_to_thread=False)
def index(security_context: NamedDependency[SecurityContext]) -> dict[str, bool]:
    return {"authenticated": bool(security_context.evidence)}


app = Litestar(route_handlers=[index], plugins=[SecurityPlugin(SecurityConfig())])
```

Run the application:

```console
litestar --app app:app run
```

Public routes must be explicit. Once an authentication provider and
authorization resolver are configured, routes are protected by default and
guards can enforce application permissions:

```python
from litestar import get

from litestar_security import required, requires_team_role


@get(
    "/teams/{team_id:str}",
    auth=required(),
    guards=[requires_team_role(team_parameter="team_id", roles={"owner"})],
)
async def team_settings(team_id: str) -> dict[str, str]:
    return {"team_id": team_id}
```

## Next steps

- [Read the documentation](https://cofin.github.io/litestar-security/)
- [Choose an authentication provider](https://cofin.github.io/litestar-security/providers.html)
- [Configure local accounts](https://cofin.github.io/litestar-security/getting-started.html)
- [Run the API, team, and local-auth examples](examples/README.md)
- [Browse the API reference](https://cofin.github.io/litestar-security/reference.html)

Litestar Security supports Python 3.10 through 3.14 and is licensed under MIT.
