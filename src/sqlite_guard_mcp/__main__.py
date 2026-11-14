"""MCP server entry point."""

import os
import sys

from mcp.server.fastmcp import FastMCP

from .server import SQLiteGuard


def main() -> None:
    """Start the stdio MCP server."""
    database_path = os.environ.get("SQLITE_GUARD_DB")
    if not database_path:
        print(
            "Set SQLITE_GUARD_DB to the SQLite database file to inspect.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    try:
        guard = SQLiteGuard(database_path)
    except (OSError, ValueError) as exc:
        print(f"Cannot open configured database: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    mcp = FastMCP("sqlite-guard")

    @mcp.tool()
    def list_tables() -> str:
        """List tables and views in the configured SQLite database."""
        return guard.list_tables()

    @mcp.tool()
    def describe_table(table_name: str) -> str:
        """Show column names, declared types, and primary-key details."""
        return guard.describe_table(table_name)

    @mcp.tool()
    def query_database(sql: str) -> str:
        """Run one read-only SELECT or WITH query; results are capped at 200 rows."""
        return guard.query(sql)

    mcp.run()


if __name__ == "__main__":
    main()
