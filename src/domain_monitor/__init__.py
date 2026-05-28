"""Domain Monitor — track suspicious look-alike domains and detect when they go live.

Public API:
    from domain_monitor import create_app, run_server
"""
from .app import create_app, run_server

__version__ = "0.1.0"
__all__ = ["create_app", "run_server", "__version__"]
