"""meshdispatch web layer: read-only JSON dashboard with live SSE push."""

from __future__ import annotations

from .server import (
    PUBLIC_PATHS,
    Request,
    create_app,
    create_server,
    main,
)
from .sse import ChangeTracker

__all__ = [
    "PUBLIC_PATHS",
    "ChangeTracker",
    "Request",
    "create_app",
    "create_server",
    "main",
]
