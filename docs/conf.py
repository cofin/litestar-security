"""Sphinx configuration for Litestar Security.

Section auto-labels stay capped at ``autosectionlabel_maxdepth = 2`` (page titles
and top-level sections) so repeated changelog subsection headings such as ``Added``
never collide under ``sphinx-build -W``, and ``linkcheck_ignore`` skips immutable
IETF Datatracker ``:rfc:`` targets because Datatracker's edge filter rejects
automated GitHub Actions runner requests with HTTP ``404``.
"""

from importlib import metadata
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sphinx.application import Sphinx

project = "Litestar Security"
author = "Cody Fincher"
copyright = "2026, Cody Fincher"
version = metadata.version("litestar-security")
release = version

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.githubpages",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx_copybutton",
    "sphinx_design",
]

autoclass_content = "class"
autodoc_default_options = {"members": True, "show-inheritance": True, "special-members": "__init__"}
autodoc_member_order = "bysource"
autodoc_preserve_defaults = True
autodoc_typehints_format = "short"
autosectionlabel_prefix_document = True
autosectionlabel_maxdepth = 2
copybutton_prompt_text = "$ "
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_use_ivar = True
python_display_short_literal_types = True
python_maximum_signature_line_length = 68
python_use_unqualified_type_names = True
viewcode_follow_imported_members = False

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
linkcheck_ignore = [
    r"^https://datatracker\.ietf\.org/doc/html/rfc\d+\.html(?:#.*)?$",
    r"^https://discord\.gg/",
    r"^https://img\.shields\.io/",
]

pygments_style = "default"
html_theme = "shibuya"
html_title = "Litestar Security"
html_short_title = "Security"
html_static_path = ["_static"]
html_css_files = ["custom.css", "syntax-highlighting.css"]
html_favicon = "_static/favicon.svg"
html_show_sourcelink = True
html_copy_source = True

html_context = {"source_type": "github", "source_user": "cofin", "source_repo": "litestar-security", "version": release}

html_theme_options = {
    "accent_color": "amber",
    "dark_logo": "_static/logo.svg",
    "discord_url": "https://discord.gg/litestar",
    "github_url": "https://github.com/cofin/litestar-security",
    "globaltoc_expand_depth": 1,
    "light_logo": "_static/logo.svg",
    "navigation_with_keys": True,
    "og_image_url": (
        "https://raw.githubusercontent.com/litestar-org/branding/main/"
        "assets/projects/litestar-security/banners/banner-inline-dark.png"
    ),
    "nav_links": [
        {
            "title": "Learn",
            "children": [
                {
                    "title": "Introduction",
                    "url": "introduction",
                    "summary": "Core architecture and application-ownership boundaries.",
                },
                {
                    "title": "Getting Started",
                    "url": "getting-started",
                    "summary": "Install Litestar Security and configure your first route policy.",
                },
                {
                    "title": "Authentication & Guards",
                    "url": "authentication",
                    "summary": "Compile route policies and enforce roles, scopes, tenants, and assurance.",
                },
                {
                    "title": "Local Accounts",
                    "url": "accounts",
                    "summary": "Sessions, rotating refresh families, MFA, passkeys, and step-up grants.",
                },
                {
                    "title": "Runnable Examples",
                    "url": "examples",
                    "summary": "Try session, token, hybrid, OAuth, IAP, and team apps locally.",
                },
            ],
        },
        {
            "title": "Providers",
            "children": [
                {
                    "title": "Provider Overview",
                    "url": "providers",
                    "summary": "Choose between local accounts, OAuth/OIDC, IAP, API keys, and workload JWTs.",
                },
                {
                    "title": "JWT Signing & JWKS",
                    "url": "jwt-and-jwks",
                    "summary": "Local key rings, OIDC discovery, and bounded remote JWKS caches.",
                },
                {
                    "title": "OAuth 2.1 Resource Server",
                    "url": "resource-server",
                    "summary": "Serve RFC 9728 protected-resource metadata and Bearer hints.",
                },
                {
                    "title": "WebSocket Security",
                    "url": "websockets",
                    "summary": "Single-use connect tokens, origin checks, and live revocation supervision.",
                },
            ],
        },
        {
            "title": "Operations",
            "children": [
                {
                    "title": "Generated Routes",
                    "url": "generated-routes",
                    "summary": "Inspect OpenAPI tags, wire schemas, and /auth route contracts.",
                },
                {
                    "title": "Composing Plugins",
                    "url": "composition",
                    "summary": "Coordinate route exclusions, asset routers, and sibling plugins.",
                },
                {
                    "title": "Rate Limiting",
                    "url": "rate-limiting",
                    "summary": "Atomic multi-bucket admission and trusted forwarded-IP extraction.",
                },
                {
                    "title": "Hardening & Headers",
                    "url": "hardening",
                    "summary": "CSRF boundaries, static response headers, CSP nonces, and worker budgets.",
                },
                {
                    "title": "Custom Stores & Testing",
                    "url": "customization",
                    "summary": "Implement persistence protocols and run backend conformance checks.",
                },
            ],
        },
        {"title": "API Reference", "url": "reference"},
        {
            "title": "Project",
            "children": [
                {
                    "title": "Changelog",
                    "url": "changelog",
                    "summary": "Review released features, breaking changes, and fixes.",
                },
                {
                    "title": "Contributing",
                    "url": "contributing",
                    "summary": "Follow the local development and verification workflow.",
                },
                {
                    "title": "Litestar Organization",
                    "url": "https://litestar.dev/about/organization",
                    "summary": "Learn about the Litestar ecosystem and maintainers.",
                },
            ],
        },
    ],
}

__all__ = ("setup",)


def setup(app: "Sphinx") -> dict[str, bool]:
    """Initialize Shibuya's Sphinx extension."""
    app.setup_extension("shibuya")
    return {"parallel_read_safe": True, "parallel_write_safe": True}
