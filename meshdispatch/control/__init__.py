"""Control plane (phase 4): manual task dispatch to registered agents."""

from __future__ import annotations

from .dispatch import A2ATransport, Transport, UnknownAgent, dispatch

__all__ = ["A2ATransport", "Transport", "UnknownAgent", "dispatch"]
