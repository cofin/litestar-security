"""Sphinx configuration for Litestar Security."""

from importlib import metadata
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sphinx.application import Sphinx

project = "litestar-security"
author = "Cody Fincher"
copyright = "2026, Cody Fincher"
version = metadata.version("litestar-security")
release = version

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx_copybutton",
    "sphinx_design",
]

autoclass_content = "class"
autodoc_default_options = {"members": True, "show-inheritance": True, "special-members": "__init__"}
autodoc_member_order = "bysource"
autodoc_typehints_format = "short"
autosectionlabel_prefix_document = True
napoleon_google_docstring = True

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
html_theme = "shibuya"
html_title = "Litestar Security"
html_short_title = "Security"
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_favicon = "_static/security-star.svg"
html_theme_options = {
    "accent_color": "amber",
    "dark_logo": "_static/security-shield.svg",
    "globaltoc_expand_depth": 1,
    "light_logo": "_static/security-shield.svg",
    "navigation_with_keys": True,
    "nav_links": [
        {
            "title": "Documentation",
            "children": [
                {"title": "Introduction", "url": "introduction", "summary": "Understand the stable 1.0 model."},
                {
                    "title": "Getting started",
                    "url": "getting-started",
                    "summary": "Choose an explicit authentication transport.",
                },
                {
                    "title": "Hardening",
                    "url": "hardening",
                    "summary": "Operate browser, provider, worker, and key boundaries.",
                },
                {"title": "API reference", "url": "reference", "summary": "Browse the typed public surface."},
            ],
        },
        {
            "title": "Project",
            "children": [
                {"title": "Contributing", "url": "contributing", "summary": "Follow the development workflow."},
                {"title": "Changelog", "url": "changelog", "summary": "Review unreleased and released changes."},
            ],
        },
    ],
}

__all__ = ("setup",)


def setup(app: "Sphinx") -> dict[str, bool]:
    """Initialize Shibuya's Sphinx extension."""
    app.setup_extension("shibuya")
    return {"parallel_read_safe": True, "parallel_write_safe": True}
