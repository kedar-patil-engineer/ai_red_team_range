# core/integrations/base.py
"""
Shared helpers for optional external engine adapters.
"""
from __future__ import annotations

import importlib.util


class IntegrationNotAvailable(RuntimeError):
    """Raised when an optional engine is requested but not installed."""


_SETUP_HINT = (
    "Install it in a separate Python 3.10 to 3.12 environment:\n"
    "    py -3.11 -m venv .venv-integrations\n"
    "    .venv-integrations\\Scripts\\activate\n"
    "    pip install -r requirements-integrations.txt\n"
    "See docs/INTEGRATIONS.md for details."
)


def is_module_available(module_name: str) -> bool:
    """True if the named module can be imported without importing it."""
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ValueError):
        return False


def require_module(module_name: str, engine_label: str):
    """Import and return a module, or raise IntegrationNotAvailable with guidance."""
    if not is_module_available(module_name):
        raise IntegrationNotAvailable(
            f"{engine_label} is not installed in this environment.\n{_SETUP_HINT}"
        )
    import importlib

    return importlib.import_module(module_name)


def integration_status() -> dict[str, bool]:
    """Report which optional engines are available right now."""
    return {
        "garak": is_module_available("garak"),
        "pyrit": is_module_available("pyrit"),
    }
