from litestar import Litestar, Router, get
from litestar.testing import TestClient

from litestar_security import SecurityPlugin
from litestar_security.authentication import required

from tests.integration.test_route_exclusion import _api_team_config


def test_inner_exclude_under_outer_auth() -> None:
    @get("/plain", sync_to_thread=False)
    def plain() -> str:
        return "plain"

    inner = Router(path="/in", route_handlers=[plain], opt={"exclude_from_auth": True})
    outer = Router(path="/out", route_handlers=[inner], opt={"auth": required("api-key")})
    app = Litestar(route_handlers=[outer], openapi_config=None, plugins=[SecurityPlugin(_api_team_config())])
    with TestClient(app) as client:
        r = client.get("/out/in/plain")
        assert r.status_code == 200, r.status_code
