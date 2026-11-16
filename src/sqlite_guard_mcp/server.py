
"""Read-only SQLite MCP server with bounded execution and credential masking."""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from . import __version__

MAX_SQL_LENGTH = 100_000
MAX_ROWS_HARD_LIMIT = 1_000
MAX_COLUMNS = 100
MAX_CELL_TEXT = 4_096
MAX_BLOB_BYTES = 4_096
MAX_RESULT_BYTES = 1_000_000

DEFAULT_MAX_ROWS = 250
DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_MAX_VM_STEPS = 250_000

_LEADING_COMMENTS = re.compile(
    r"\A(?:\s+|--[^\r\n]*(?:\r?\n|\Z)|/\*[\s\S]*?\*/)*",
    re.MULTILINE,
)
_FIRST_WORD = re.compile(r"\A([A-Za-z]+)\b")
_EXPLAIN_QUERY_PLAN = re.compile(
    r"\AEXPLAIN\s+QUERY\s+PLAN\b",
    re.IGNORECASE,
)

_BLOCKED_FUNCTIONS = frozenset(
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

_TABLE_PRAGMAS = frozenset(
    {
        "table_info",
        "table_xinfo",
        "index_list",
        "index_info",
        "index_xinfo",
        "foreign_key_list",
    }
)

_NO_ARGUMENT_PRAGMAS = frozenset(
    {
        "database_list",
        "compile_options",
        "encoding",
        "data_version",
    }
)

_SAFE_TOKEN_METRICS = frozenset(
    {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "input_tokens",
        "output_tokens",
        "cached_tokens",
    }
)

_SENSITIVE_PARTS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "credential",
        "authorization",
        "cookie",
        "private_key",
        "client_secret",
        "access_key",
        "api_key",
        "apikey",
        "ssn",
        "social_security",
        "credit_card",
        "card_number",
        "cvv",
        "cvc",
        "tax_id",
        "national_id",
        "bank_account",
        "routing_number",
    }
)


def _strip_leading_comments(sql: str) -> str:
    """Remove whitespace and SQL comments before checking the first keyword."""
    return _LEADING_COMMENTS.sub("", sql, count=1).lstrip()


def _is_sensitive_column(name: str | None) -> bool:
    """Detect common credential and sensitive-data column names."""
    if not name:
        return False

    normalized = re.sub(
        r"(?<=[a-z0-9])(?=[A-Z])",
        "_",
        name.strip(),
    )

    normalized = re.sub(
        r"[^a-zA-Z0-9]+",
        "_",
        normalized,
    ).strip("_").casefold()

    if normalized in _SAFE_TOKEN_METRICS:
        return False

    parts = set(normalized.split("_"))

    if "token" in parts:
        return True

    if parts.intersection(_SENSITIVE_PARTS):
        return True

    return any(
        sensitive in normalized
        for sensitive in (
            "password",
            "passwd",
            "passphrase",
            "client_secret",
            "authorization",
            "private_key",
            "credential",
            "social_security",
        )
    )


def _authorize(
    action: int,
    arg1: str | None,
    arg2: str | None,
    _database_name: str | None,
    _source: str | None,
) -> int:
    """Permit safe reads, mask sensitive columns, and deny other actions."""
    if action in {
        sqlite3.SQLITE_SELECT,
        getattr(sqlite3, "SQLITE_RECURSIVE", 33),
    }:
        return sqlite3.SQLITE_OK

    if action == sqlite3.SQLITE_READ:
        if _is_sensitive_column(arg2):
            return sqlite3.SQLITE_IGNORE
        return sqlite3.SQLITE_OK

    if action == sqlite3.SQLITE_FUNCTION:
        function_name = (arg2 or "").casefold()
        if function_name in _BLOCKED_FUNCTIONS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    if action == sqlite3.SQLITE_PRAGMA:
        pragma = (arg1 or "").casefold()

        if pragma in _TABLE_PRAGMAS:
            return sqlite3.SQLITE_OK

        if pragma in _NO_ARGUMENT_PRAGMAS and arg2 is None:
            return sqlite3.SQLITE_OK

        return sqlite3.SQLITE_DENY

    return sqlite3.SQLITE_DENY


def _validate_query(
    sql: str,
    *,
    explain: bool = False,
    allow_explain_plan: bool = False,
) -> str:
    """Validate the permitted SQL statement shape."""
    if not isinstance(sql, str) or not sql.strip():
        raise ValueError("SQL query must be a non-empty string.")

    if len(sql) > MAX_SQL_LENGTH:
        raise ValueError(
            f"SQL query exceeds the {MAX_SQL_LENGTH}-character limit."
        )

    cleaned = _strip_leading_comments(sql)

    if not cleaned:
        raise ValueError("SQL query must be a non-empty string.")

    if explain:
        if not re.match(r"\A(?:SELECT|WITH)\b", cleaned, re.IGNORECASE):
            raise ValueError("Only SELECT or WITH queries can be explained.")
        return f"EXPLAIN QUERY PLAN {cleaned}"

    match = _FIRST_WORD.match(cleaned)

    if not match:
        raise ValueError("Only read-only SELECT and WITH queries are allowed.")

    first = match.group(1).upper()

    if first in {"SELECT", "WITH"}:
        return sql.strip()

    if first == "EXPLAIN" and allow_explain_plan:
        explain_match = _EXPLAIN_QUERY_PLAN.match(cleaned)

        if explain_match is None:
            raise ValueError("Only EXPLAIN QUERY PLAN is permitted.")

        explained = cleaned[explain_match.end():].lstrip()
        explained_match = _FIRST_WORD.match(explained)

        if (
            not explained_match
            or explained_match.group(1).upper() not in {"SELECT", "WITH"}
        ):
            raise ValueError(
                "EXPLAIN QUERY PLAN must contain a SELECT or WITH query."
            )

        return sql.strip()

    raise ValueError("Only read-only SELECT and WITH queries are allowed.")


def _validate_params(
    params: Any,
) -> dict[str, Any] | list[Any] | tuple[Any, ...]:
    """Validate SQLite scalar query parameters."""
    if params is None:
        return ()

    if not isinstance(params, (dict, list, tuple)):
        raise ValueError(
            "Query parameters must be an object, array, or null."
        )

    if isinstance(params, dict):
        if not all(isinstance(key, str) for key in params):
            raise ValueError("Named query parameter keys must be strings.")
        values = params.values()
    else:
        values = params

    for value in values:
        if value is None or isinstance(value, (str, int, float, bytes)):
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError(
                    "Floating-point query parameters must be finite."
                )

            if isinstance(value, str) and len(value) > MAX_CELL_TEXT:
                raise ValueError(
                    "A query parameter exceeds the maximum text length."
                )

            if isinstance(value, bytes) and len(value) > MAX_BLOB_BYTES:
                raise ValueError(
                    "A BLOB query parameter exceeds the maximum byte length."
                )

            continue

        if isinstance(value, bool):
            continue

        raise ValueError(
            "Query parameters must contain only SQLite scalar values."
        )

    return params


def _open_connection(
    db_path: str | Path,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
) -> sqlite3.Connection:
    """Open an existing database in read-only mode with execution limits."""
    path = Path(db_path).expanduser().resolve(strict=True)

    if not path.is_file():
        raise FileNotFoundError(
            "Database path is not a regular file."
        )

    encoded_path = quote(path.as_posix(), safe="/:\\")

    connection = sqlite3.connect(
        f"file:{encoded_path}?mode=ro",
        uri=True,
        timeout=timeout_seconds,
        isolation_level=None,
    )

    connection.row_factory = sqlite3.Row

    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")

        if hasattr(connection, "setlimit"):
            limits = (
                ("SQLITE_LIMIT_LENGTH", 1_000_000),
                ("SQLITE_LIMIT_SQL_LENGTH", MAX_SQL_LENGTH),
                ("SQLITE_LIMIT_EXPR_DEPTH", 100),
                ("SQLITE_LIMIT_COMPOUND_SELECT", 10),
                ("SQLITE_LIMIT_ATTACHED", 0),
            )

            for name, value in limits:
                limit_id = getattr(sqlite3, name, None)

                if limit_id is not None:
                    connection.setlimit(limit_id, value)

        started = time.monotonic()
        vm_interval = 1_000
        vm_calls = 0

        def progress() -> int:
            nonlocal vm_calls
            vm_calls += 1

            time_exceeded = (
                time.monotonic() - started > timeout_seconds
            )
            steps_exceeded = vm_calls * vm_interval >= max_vm_steps

            return int(time_exceeded or steps_exceeded)

        connection.set_progress_handler(progress, vm_interval)
        connection.set_authorizer(_authorize)

        return connection

    except Exception:
        connection.close()
        raise


def _json_safe(value: Any) -> Any:
    """Convert SQLite values into bounded JSON-compatible values."""
    if value is None or isinstance(value, (str, int, bool)):
        if isinstance(value, str) and len(value) > MAX_CELL_TEXT:
            return value[:MAX_CELL_TEXT] + "…[truncated]"
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    if isinstance(value, bytes):
        sample = value[:MAX_BLOB_BYTES]

        return {
            "type": "blob",
            "byte_length": len(value),
            "base64": base64.b64encode(sample).decode("ascii"),
            "truncated": len(value) > MAX_BLOB_BYTES,
        }

    return str(value)[:MAX_CELL_TEXT]


def _error(message: str, code: str) -> dict[str, Any]:
    """Build a consistent, non-sensitive error response."""
    return {
        "ok": False,
        "error": message,
        "code": code,
    }


def _serialized_size(payload: dict[str, Any]) -> int:
    """Return the UTF-8 serialized JSON size of a response."""
    return len(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _bounded_result(
    columns: list[str],
    rows: list[dict[str, Any]],
    truncated: bool,
    elapsed_ms: float,
) -> dict[str, Any]:
    """Build a response within the configured column and byte limits."""
    original_columns = columns[:MAX_COLUMNS]
    limited_columns = [name[:256] for name in original_columns]
    column_names = dict(
        zip(original_columns, limited_columns, strict=False)
    )

    columns_truncated = len(columns) > MAX_COLUMNS

    safe_rows = [
        {
            column_names[key]: _json_safe(value)
            for key, value in row.items()
            if key in column_names
        }
        for row in rows
    ]

    payload: dict[str, Any] = {
        "ok": True,
        "columns": limited_columns,
        "rows": safe_rows,
        "row_count": len(safe_rows),
        "truncated": truncated,
        "columns_truncated": columns_truncated,
        "elapsed_ms": elapsed_ms,
    }

    while safe_rows and _serialized_size(payload) > MAX_RESULT_BYTES:
        safe_rows.pop()
        payload["row_count"] = len(safe_rows)
        payload["truncated"] = True

    if _serialized_size(payload) > MAX_RESULT_BYTES:
        payload["rows"] = []
        payload["row_count"] = 0
        payload["truncated"] = True
        payload["columns_truncated"] = True
        payload["warning"] = (
            "The result exceeded the maximum response size and was omitted."
        )

    return payload


def execute_guarded_query(
    db_path: str | Path,
    sql: str,
    params: dict[str, Any] | list[Any] | tuple[Any, ...] | None = None,
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
    _allow_explain_plan: bool = False,
) -> dict[str, Any]:
    """Execute one parameterized, read-only SQL statement."""
    if not 1 <= max_rows <= MAX_ROWS_HARD_LIMIT:
        return _error(
            f"max_rows must be between 1 and {MAX_ROWS_HARD_LIMIT}.",
            "invalid_limit",
        )

    if not 0.05 <= timeout_seconds <= 60:
        return _error(
            "timeout_seconds must be between 0.05 and 60.",
            "invalid_limit",
        )

    if not 1_000 <= max_vm_steps <= 100_000_000:
        return _error(
            "max_vm_steps is outside the permitted range.",
            "invalid_limit",
        )

    try:
        statement = _validate_query(
            sql,
            allow_explain_plan=_allow_explain_plan,
        )
        bindings = _validate_params(params)

    except ValueError as exc:
        return _error(str(exc), "invalid_input")

    try:
        connection = _open_connection(
            db_path,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
        )

    except FileNotFoundError:
        return _error(
            "Database file was not found or is not a regular file.",
            "database_not_found",
        )

    except (sqlite3.Error, OSError, RuntimeError):
        return _error(
            "Could not open the database in read-only mode.",
            "database_open_failed",
        )

    started = time.perf_counter()

    try:
        cursor = connection.execute(statement, bindings)
        fetched = cursor.fetchmany(max_rows + 1)

        was_truncated = len(fetched) > max_rows
        selected = fetched[:max_rows]

        columns = [
            item[0]
            for item in (cursor.description or [])
        ]

        rows = [
            dict(row)
            for row in selected
        ]

        elapsed = round(
            (time.perf_counter() - started) * 1000,
            3,
        )

        return _bounded_result(
            columns,
            rows,
            was_truncated,
            elapsed,
        )

    except sqlite3.OperationalError as exc:
        reason = str(exc).casefold()

        if "not authorized" in reason or "prohibited" in reason:
            return _error(
                "The SQLite authorizer blocked this operation.",
                "blocked_operation",
            )

        if "interrupted" in reason:
            return _error(
                "The query exceeded its execution budget.",
                "query_budget_exceeded",
            )

        return _error(
            "SQLite could not execute this query.",
            "query_failed",
        )

    except sqlite3.Error:
        return _error(
            "SQLite could not execute this query.",
            "query_failed",
        )

    finally:
        connection.close()


def list_tables(
    db_path: str | Path,
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
) -> dict[str, Any]:
    """List user-created tables and views."""
    return execute_guarded_query(
        db_path,
        (
            "SELECT name, type FROM sqlite_schema "
            "WHERE type IN ('table', 'view') "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ),
        max_rows=max_rows,
        timeout_seconds=timeout_seconds,
        max_vm_steps=max_vm_steps,
    )


def _quote_identifier(identifier: str) -> str:
    """Safely quote a SQLite identifier."""
    if (
        not isinstance(identifier, str)
        or not identifier
        or len(identifier) > 256
        or "\x00" in identifier
    ):
        raise ValueError(
            "Table name must contain 1–256 non-NUL characters."
        )

    return '"' + identifier.replace('"', '""') + '"'


def describe_table(
    db_path: str | Path,
    table_name: str,
) -> dict[str, Any]:
    """Return table columns, indexes, foreign keys, and masking metadata."""
    try:
        quoted_table = _quote_identifier(table_name)

    except ValueError as exc:
        return _error(str(exc), "invalid_table_name")

    try:
        connection = _open_connection(db_path)

    except FileNotFoundError:
        return _error(
            "Database file was not found or is not a regular file.",
            "database_not_found",
        )

    except (sqlite3.Error, OSError, RuntimeError):
        return _error(
            "Could not open the database in read-only mode.",
            "database_open_failed",
        )

    try:
        columns = [
            dict(row)
            for row in connection.execute(
                f"PRAGMA table_xinfo({quoted_table})"
            )
        ][:MAX_COLUMNS]

        if not columns:
            return _error(
                "The requested table or view does not exist.",
                "table_not_found",
            )

        for column in columns:
            column["masked_by_guard"] = _is_sensitive_column(
                str(column.get("name", ""))
            )

        indexes = []

        index_rows = list(
            connection.execute(
                f"PRAGMA index_list({quoted_table})"
            )
        )[:MAX_COLUMNS]

        for index in index_rows:
            item = dict(index)
            quoted_index = _quote_identifier(str(item["name"]))

            item["columns"] = [
                dict(row)
                for row in connection.execute(
                    f"PRAGMA index_xinfo({quoted_index})"
                )
            ]

            indexes.append(item)

        foreign_keys = [
            dict(row)
            for row in list(
                connection.execute(
                    f"PRAGMA foreign_key_list({quoted_table})"
                )
            )[:MAX_COLUMNS]
        ]

        return {
            "ok": True,
            "table": table_name,
            "columns": columns,
            "indexes": indexes,
            "foreign_keys": foreign_keys,
        }

    except sqlite3.Error:
        return _error(
            "SQLite could not inspect this table's schema.",
            "schema_inspection_failed",
        )

    finally:
        connection.close()


def explain_query(
    db_path: str | Path,
    sql: str,
    params: dict[str, Any] | list[Any] | tuple[Any, ...] | None = None,
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
) -> dict[str, Any]:
    """Return SQLite's query plan for a SELECT or WITH query."""
    try:
        statement = _validate_query(sql, explain=True)

    except ValueError as exc:
        return _error(str(exc), "invalid_input")

    return execute_guarded_query(
        db_path,
        statement,
        params,
        max_rows=max_rows,
        timeout_seconds=timeout_seconds,
        max_vm_steps=max_vm_steps,
        _allow_explain_plan=True,
    )



def create_server(
    db_path: str | Path,
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
) -> Any:
    """Create the official MCP SDK server with four SQLite Guard tools."""
    from mcp.server.mcpserver import MCPServer

    database = Path(db_path).expanduser()

    server = MCPServer(
        "sqlite-guard-mcp",
        version=__version__,
        instructions=(
            "Inspect the configured SQLite database using read-only tools. "
            "Sensitive credential columns are masked as NULL. "
            "Never claim masked values were retrieved. "
            "Use parameterized SQL for user-provided values."
        ),
    )

    @server.tool()
    def read_query(
        sql: str,
        params: dict[str, Any] | list[Any] | None = None,
    ) -> str:
        """Run a read-only SELECT or WITH query."""
        result = execute_guarded_query(
            database,
            sql,
            params,
            max_rows=max_rows,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
        )
        return json.dumps(result, ensure_ascii=False)

    @server.tool()
    def list_database_tables() -> str:
        """List user-created tables and views."""
        result = list_tables(
            database,
            max_rows=max_rows,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
        )
        return json.dumps(result, ensure_ascii=False)

    @server.tool()
    def describe_database_table(table_name: str) -> str:
        """Inspect a table's columns, indexes, and foreign keys."""
        result = describe_table(database, table_name)
        return json.dumps(result, ensure_ascii=False)

    @server.tool()
    def explain_read_query(
        sql: str,
        params: dict[str, Any] | list[Any] | None = None,
    ) -> str:
        """Explain the query plan for a read-only SELECT or WITH query."""
        result = explain_query(
            database,
            sql,
            params,
            max_rows=max_rows,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
        )
        return json.dumps(result, ensure_ascii=False)

    return server


def main(argv: list[str] | None = None) -> int:
    """Run the SQLite Guard MCP server over standard input/output."""
    parser = argparse.ArgumentParser(
        description="Read-only, security-hardened SQLite MCP server."
    )
    parser.add_argument(
        "--db",
        default=os.environ.get("SQLITE_GUARD_DB"),
        help="Path to an existing SQLite database.",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=DEFAULT_MAX_ROWS,
        help="Maximum rows returned per query.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Maximum query execution time in seconds.",
    )
    parser.add_argument(
        "--max-vm-steps",
        type=int,
        default=DEFAULT_MAX_VM_STEPS,
        help="Maximum SQLite virtual-machine steps.",
    )

    args = parser.parse_args(argv)

    if not args.db:
        parser.error(
            "Provide --db or set the SQLITE_GUARD_DB environment variable."
        )

    if not 1 <= args.max_rows <= MAX_ROWS_HARD_LIMIT:
        parser.error(
            f"--max-rows must be between 1 and {MAX_ROWS_HARD_LIMIT}."
        )

    if not 0.05 <= args.timeout <= 60:
        parser.error("--timeout must be between 0.05 and 60 seconds.")

    if not 1_000 <= args.max_vm_steps <= 100_000_000:
        parser.error("--max-vm-steps is outside the permitted range.")

    try:
        database = Path(args.db).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        parser.error("The configured database path does not exist.")

    if not database.is_file():
        parser.error("The configured database path is not a regular file.")

    server = create_server(
        database,
        max_rows=args.max_rows,
        timeout_seconds=args.timeout,
        max_vm_steps=args.max_vm_steps,
    )
    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
    
