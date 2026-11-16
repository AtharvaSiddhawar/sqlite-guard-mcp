"""Run SQLite Guard MCP with ``python -m sqlite_guard_mcp``.

Security-hardened, zero-dependency SQLite MCP server entry point.
"""

from sqlite_guard_mcp.server import main

if __name__ == "__main__":
    raise SystemExit(main())
