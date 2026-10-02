"""Support ``python -m meshdispatch`` as an alias for the console script.

Keeping this module (and the entry point in ``pyproject.toml``) pointing at the
same ``main`` callable guarantees both invocation styles behave identically.
"""

from __future__ import annotations

from meshdispatch.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
