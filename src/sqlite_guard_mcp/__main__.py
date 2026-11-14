"""Allow running `python3 -m sqlite_guard_mcp` directly."""

from .server import main

if __name__ == "__main__":
    raise SystemExit(main())
