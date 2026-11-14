"""
sqlite-guard-mcp: Deterministic, zero-setup, sandboxed Model Context Protocol (MCP)
server for local SQLite databases.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import quote

__version__ = "0.1.0"

SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = (
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2024-11-05",
)
DEFAULT_PROTOCOL_VERSION = "2026-07-28"

_LEADING_COMMENTS_RE = re.compile(
    r"^\s*(?:(?:--[^\r\n]*[\r\n]+)|(?:/\*[\s\S]*?\*/\s*))+",
    re.MULTILINE,
)
_READ_QUERY_RE = re.compile(r"^\s*(SELECT|WITH|EXPLAIN|PRAGMA)\b", re.IGNORECASE)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_BLOCKED_FUNCTIONS: frozenset[str] = frozenset(
    {
        "load_extension",
        "readfile",
        "writefile",
        "fts3_tokenizer",
        "edit",
        "randomblob",
        "zeroblob",
    }
)

_TABLE_INSPECTION_PRAGMAS: frozenset[str] = frozenset(
    {
        "table_info",
        "table_xinfo",
        "index_list",
        "index_info",
        "index_xinfo",
        "foreign_key_list",
    }
)

_NOARG_READ_PRAGMAS: frozenset[str] = frozenset(
    {
        "database_list",
        "compile_options",
        "encoding",
        "data_version",
    }
)

_ALLOWED_PRAGMAS: frozenset[str] = _TABLE_INSPECTION_PRAGMAS | _NOARG_READ_PRAGMAS

_SENSITIVE_COLUMN_PATTERNS: tuple[str, ...] = (
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "ssn",
    "credential",
    "auth_key",
)


def _strip_leading_comments(sql: str) -> str:
    """Remove leading `--` and `/* ... */` comments before checking statement verb."""
    return _LEADING_COMMENTS_RE.sub("", sql or "").strip()


def _is_sensitive_column(column_name: str | None) -> bool:
    """Return True if `column_name` matches a sensitive credential or secret pattern."""
    if not column_name:
        return False
    lowered = column_name.lower()
    return any(pattern in lowered for pattern in _SENSITIVE_COLUMN_PATTERNS)


def _authorize(
    action: int,
    arg1: str | None,
    arg2: str | None,
    db_name: str | None,
    trigger_or_view: str | None,
) -> int:
    """
    Deterministic SQLite C-API compile-time authorizer callback.

    - Permits `SQLITE_SELECT` and `SQLITE_RECURSIVE`
    - Masks sensitive columns as `NULL` via `SQLITE_IGNORE` on `SQLITE_READ`
    - Permits read-only schema and index PRAGMAs (`table_info`, `index_list`, `index_info`)
    - Blocks `_BLOCKED_FUNCTIONS` (`load_extension`, `readfile`, `writefile`, `fts3_tokenizer`)
    - Denies all writes (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ATTACH`, `ALTER`)
    """
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK

    if action == sqlite3.SQLITE_READ:
        if _is_sensitive_column(arg2):
            return sqlite3.SQLITE_IGNORE
        return sqlite3.SQLITE_OK

    if action == sqlite3.SQLITE_PRAGMA:
        pragma_name = (arg1 or "").lower()
        if pragma_name in _TABLE_INSPECTION_PRAGMAS:
            return sqlite3.SQLITE_OK
        if pragma_name in _NOARG_READ_PRAGMAS and arg2 is None:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    if action == getattr(sqlite3, "SQLITE_FUNCTION", 31):
        fn_name = (arg2 or "").lower()
        if fn_name in _BLOCKED_FUNCTIONS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    if action == getattr(sqlite3, "SQLITE_RECURSIVE", 33):
        return sqlite3.SQLITE_OK

    return sqlite3.SQLITE_DENY


def _json_result(payload: dict[str, Any], *, is_error: bool | None = None) -> dict[str, Any]:
    """Wrap a structured dictionary payload into an MCP tool result block."""
    if is_error is None:
        is_error = "error" in payload
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, indent=2, default=str),
            }
        ],
        "isError": is_error,
    }


def _open_guarded_connection(
    db_path: Path,
    timeout_seconds: float = 2.0,
    max_vm_steps: int = 250_000,
) -> sqlite3.Connection:
    """Open a read-only, C-API hardened SQLite connection with authorizer and progress limits."""
    resolved = db_path.expanduser().resolve()
    if not resolved.exists() or not resolved.is_file():
        raise FileNotFoundError(f"SQLite database not found: {resolved}")

    encoded_path = quote(str(resolved), safe="/:\\")
    uri = f"file:{encoded_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=timeout_seconds, isolation_level=None)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA query_only = ON;")
    conn.execute("PRAGMA trusted_schema = OFF;")

    if hasattr(conn, "setlimit"):
        for limit_attr, limit_val in (
            ("SQLITE_LIMIT_SQL_LENGTH", 100_000),
            ("SQLITE_LIMIT_EXPR_DEPTH", 100),
            ("SQLITE_LIMIT_COMPOUND_SELECT", 10),
            ("SQLITE_LIMIT_ATTACHED", 0),
        ):
            limit_id = getattr(sqlite3, limit_attr, None)
            if limit_id is not None:
                try:
                    conn.setlimit(limit_id, limit_val)
                except sqlite3.Error:
                    pass

    start_time = time.monotonic()
    batches = 0
    batch_size = 1_000

    def _progress_handler() -> int:
        nonlocal batches
        batches += 1
        if batches * batch_size > max_vm_steps:
            return 1
        if (time.monotonic() - start_time) > timeout_seconds:
            return 1
        return 0

    conn.set_progress_handler(_progress_handler, batch_size)
    conn.set_authorizer(_authorize)
    return conn


def execute_guarded_query(
    db_path: str | Path,
    sql: str,
    params: dict[str, Any] | list[Any] | tuple[Any, ...] | None = None,
    *,
    max_rows: int = 250,
    timeout_seconds: float = 2.0,
    max_vm_steps: int = 250_000,
) -> dict[str, Any]:
    """Execute a read-only SQL query inside the deterministic SQLite sandbox."""
    cleaned_sql = (sql or "").strip()
    uncommented_sql = _strip_leading_comments(cleaned_sql)
    if not uncommented_sql:
        return _json_result({"error": "SQL query must not be empty."})

    if not _READ_QUERY_RE.match(uncommented_sql):
        return _json_result(
            {"error": "Only read-only SELECT, WITH, EXPLAIN, or PRAGMA statements are allowed."}
        )

    try:
        conn = _open_guarded_connection(
            Path(db_path),
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
        )
    except FileNotFoundError:
        return _json_result({"error": "Database file not found."})
    except (sqlite3.Error, sqlite3.Warning):
        return _json_result({"error": "Failed to open read-only database connection."})

    start = time.perf_counter()
    try:
        cursor = conn.execute(cleaned_sql, params or ())
        fetched = cursor.fetchmany(max_rows + 1)
        truncated = len(fetched) > max_rows
        bounded = fetched[:max_rows]
        columns = [col[0] for col in (cursor.description or [])]
        rows = [dict(row) for row in bounded]
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 3)
        return _json_result(
            {
                "columns": columns,
                "rows": rows,
                "row_count": len(rows),
                "truncated": truncated,
                "elapsed_ms": elapsed_ms,
            },
            is_error=False,
        )
    except (sqlite3.Error, sqlite3.Warning):
        return _json_result({"error": "Query execution failed or timed out."})
    finally:
        conn.close()


execute_query = execute_guarded_query


def list_tables(db_path: str | Path) -> dict[str, Any]:
    """List all user tables and views in the SQLite database."""
    return execute_guarded_query(
        db_path,
        """
        SELECT name, type
        FROM sqlite_master
        WHERE type IN ('table', 'view')
          AND name NOT LIKE 'sqlite_%'
        ORDER BY name ASC;
        """,
    )


def describe_table(db_path: str | Path, table_name: str) -> dict[str, Any]:
    """Return column metadata (`table_info`) and index metadata (`index_list`) for a table."""
    cleaned = (table_name or "").strip()
    if not _IDENTIFIER_RE.match(cleaned):
        return _json_result({"error": "Invalid table name."})

    try:
        conn = _open_guarded_connection(Path(db_path))
    except (FileNotFoundError, sqlite3.Error, sqlite3.Warning):
        return _json_result({"error": "Failed to open read-only database connection."})

    try:
        cols_cur = conn.execute(f'PRAGMA table_info("{cleaned}");')
        columns = []
        for row in cols_cur.fetchall():
            col_dict = dict(row)
            col_dict["masked_by_guard"] = _is_sensitive_column(str(col_dict.get("name", "")))
            columns.append(col_dict)

        if not columns:
            return _json_result({"error": f"Table '{cleaned}' not found."})

        idx_cur = conn.execute(f'PRAGMA index_list("{cleaned}");')
        indexes = []
        for idx_row in idx_cur.fetchall():
            idx_dict = dict(idx_row)
            idx_name = str(idx_dict.get("name", ""))
            if _IDENTIFIER_RE.match(idx_name):
                info_cur = conn.execute(f'PRAGMA index_info("{idx_name}");')
                idx_dict["columns"] = [dict(r) for r in info_cur.fetchall()]
            indexes.append(idx_dict)

        fk_cur = conn.execute(f'PRAGMA foreign_key_list("{cleaned}");')
        foreign_keys = [dict(r) for r in fk_cur.fetchall()]

        return _json_result(
            {
                "table": cleaned,
                "columns": columns,
                "indexes": indexes,
                "foreign_keys": foreign_keys,
            },
            is_error=False,
        )
    except (sqlite3.Error, sqlite3.Warning):
        return _json_result({"error": "Schema inspection failed or timed out."})
    finally:
        conn.close()


def explain_query(
    db_path: str | Path,
    sql: str,
    params: dict[str, Any] | list[Any] | tuple[Any, ...] | None = None,
) -> dict[str, Any]:
    """Run `EXPLAIN QUERY PLAN` on a read-only SQL query to inspect index usage."""
    cleaned_sql = _strip_leading_comments(sql or "")
    if not cleaned_sql:
        return _json_result({"error": "SQL query must not be empty."})
    if not re.match(r"^\s*(SELECT|WITH|EXPLAIN)\b", cleaned_sql, re.IGNORECASE):
        return _json_result({"error": "Only SELECT or WITH queries can be explained."})

    explain_sql = (
        cleaned_sql
        if re.match(r"^\s*EXPLAIN\b", cleaned_sql, re.IGNORECASE)
        else f"EXPLAIN QUERY PLAN {cleaned_sql}"
    )
    return execute_guarded_query(db_path, explain_sql, params=params)


class SQLiteGuardServer:
    """MCP JSON-RPC 2.0 stdio server wrapping deterministic SQLite C-API guards."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        max_rows: int = 250,
        timeout_seconds: float = 2.0,
        max_vm_steps: int = 250_000,
    ) -> None:
        self.db_path = Path(db_path).expanduser().resolve()
        self.max_rows = max_rows
        self.timeout_seconds = timeout_seconds
        self.max_vm_steps = max_vm_steps

    def get_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "read_query",
                "description": (
                    "Execute a read-only SQLite query (`SELECT`, `WITH`, `EXPLAIN QUERY PLAN`, "
                    "or allowed `PRAGMA` such as `PRAGMA index_list`)."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "description": "Read-only SQL statement."},
                        "params": {
                            "type": ["object", "array"],
                            "description": "Optional bound query parameters.",
                        },
                    },
                    "required": ["sql"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_tables",
                "description": "List all user tables and views in the SQLite database.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            },
            {
                "name": "describe_table",
                "description": (
                    "Inspect columns (`PRAGMA table_info`), indexes (`PRAGMA index_list`), "
                    "foreign keys, and sensitive column masking status for a table."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string", "description": "Table name to inspect."}
                    },
                    "required": ["table_name"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "explain_query",
                "description": "Run `EXPLAIN QUERY PLAN` on a SELECT/WITH query.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "description": "SELECT or WITH query."}
                    },
                    "required": ["sql"],
                    "additionalProperties": False,
                },
            },
        ]

    def handle_request(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        if msg_id is None:
            return None

        if method == "initialize":
            requested_version = str(params.get("protocolVersion", DEFAULT_PROTOCOL_VERSION))
            negotiated = (
                requested_version
                if requested_version in SUPPORTED_PROTOCOL_VERSIONS
                else DEFAULT_PROTOCOL_VERSION
            )
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": negotiated,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "sqlite-guard-mcp", "version": __version__},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": self.get_tools()}}

        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments") or {}

            if tool_name == "read_query":
                result = execute_guarded_query(
                    self.db_path,
                    str(args.get("sql", "")),
                    args.get("params"),
                    max_rows=self.max_rows,
                    timeout_seconds=self.timeout_seconds,
                    max_vm_steps=self.max_vm_steps,
                )
            elif tool_name == "list_tables":
                result = list_tables(self.db_path)
            elif tool_name == "describe_table":
                result = describe_table(self.db_path, str(args.get("table_name", "")))
            elif tool_name == "explain_query":
                result = explain_query(
                    self.db_path,
                    str(args.get("sql", "")),
                    args.get("params"),
                )
            else:
                result = _json_result({"error": f"Unknown tool: {tool_name}"})

            return {"jsonrpc": "2.0", "id": msg_id, "result": result}

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def serve_stdio(self, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
        for raw_line in stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                err = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Invalid JSON payload."},
                }
                stdout.write(json.dumps(err) + "\n")
                stdout.flush()
                continue

            resp = self.handle_request(msg)
            if resp is not None:
                stdout.write(json.dumps(resp) + "\n")
                stdout.flush()


SQLiteGuardMCPServer = SQLiteGuardServer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sqlite-guard-mcp",
        description="Deterministic, zero-setup, sandboxed SQLite MCP server for local AI agents.",
    )
    parser.add_argument(
        "db_positional",
        nargs="?",
        help="Path to the SQLite database file.",
    )
    parser.add_argument("--db", dest="db_flag", help="Path to the SQLite database file.")
    parser.add_argument(
        "--max-rows",
        type=int,
        default=250,
        help="Maximum rows returned per query.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Maximum query execution timeout in seconds (default: 2.0).",
    )
    parser.add_argument(
        "--max-vm-steps",
        type=int,
        default=250_000,
        help="Maximum SQLite VM steps before aborting (default: 250000).",
    )
    args = parser.parse_args(argv)

    db_target = args.db_flag or args.db_positional or os.environ.get("SQLITE_GUARD_DB")
    if not db_target:
        parser.error("A SQLite database path is required (pass `--db /path/to/db.sqlite`).")

    server = SQLiteGuardServer(
        db_target,
        max_rows=args.max_rows,
        timeout_seconds=args.timeout,
        max_vm_steps=args.max_vm_steps,
    )
    server.serve_stdio()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
