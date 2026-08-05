"""Runtime metadata shared by authentication compilation and WebSocket connect tokens."""

RUNTIME_PLAN_OPT_KEY = "litestar_security_plan"

GENERATED_ROUTE_OPT_KEY = "litestar_security_generated_route"
"""Marks a route this plugin generated, so checks about generated routes skip the application's own."""
