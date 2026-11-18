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
from typing import Annotated, Any

from pydantic import Field

from . import __version__

MAX_SQL_LENGTH = 100_000
MAX_ROWS_HARD_LIMIT = 1_000
MAX_COLUMNS = 100
MAX_CELL_TEXT = 4_096
MAX_BLOB_BYTES = 4_096
MAX_RESULT_BYTES = 1_000_000

SQLITE_INT64_MIN = -9_223_372_036_854_775_808
SQLITE_INT64_MAX = 9_223_372_036_854_775_807
MAX_SCHEMA_TABLES = 500
MAX_INDEXES = 100
MAX_INDEX_COLUMNS = 50
MAX_FOREIGN_KEYS = 100

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
        "fsdir",
        "fileio_read",
        "fileio_write",
        "zipfile",
        "zipfile_cds",
        "eval",
        "sqlite_eval",
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
        "compile_options",
        "encoding",
        "data_version",
        "quick_check",
        "integrity_check",
    }
)

_SCHEMA_TABLES = frozenset(
    {
        "sqlite_schema",
        "sqlite_master",
        "sqlite_temp_schema",
        "sqlite_temp_master",
    }
)

_SAFE_TOKEN_METRICS = frozenset(
    {
        "prompt_tokens",
        "prompt_token",
        "completion_tokens",
        "completion_token",
        "total_tokens",
        "total_token",
        "input_tokens",
        "input_token",
        "output_tokens",
        "output_token",
        "cached_tokens",
        "cached_token",
        "reasoning_tokens",
        "reasoning_token",
    }
)

_SENSITIVE_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "credential",
        "credentials",
        "authorization",
        "cookie",
        "cookies",
        "apikey",
        "ssn",
        "cvv",
        "cvc",
        "pin",
        "salt",
    }
)

_SENSITIVE_PHRASES = frozenset(
    {
        "api_key",
        "access_key",
        "auth_key",
        "private_key",
        "secret_key",
        "signing_key",
        "encryption_key",
        "session_key",
        "client_secret",
        "social_security",
        "credit_card",
        "card_number",
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

    normalized = (
        re.sub(
            r"[^a-zA-Z0-9]+",
            "_",
            normalized,
        )
        .strip("_")
        .casefold()
    )

    if normalized in _SAFE_TOKEN_METRICS:
        return False

    parts = set(normalized.split("_"))

    if "token" in parts:
        return True

    if parts.intersection(_SENSITIVE_WORDS):
        return True

    padded = f"_{normalized}_"
    return any(f"_{phrase}_" in padded for phrase in _SENSITIVE_PHRASES)


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
        table_name = (arg1 or "").casefold()
        column_name = (arg2 or "").casefold()

        if table_name == "pragma_database_list":
            return sqlite3.SQLITE_DENY

        if table_name in _SCHEMA_TABLES and column_name == "sql":
            return sqlite3.SQLITE_IGNORE

        if (
            table_name in {"pragma_table_info", "pragma_table_xinfo"}
            and column_name == "dflt_value"
        ):
            return sqlite3.SQLITE_IGNORE

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

        if pragma == "database_list":
            return sqlite3.SQLITE_DENY

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
        raise ValueError(f"SQL query exceeds the {MAX_SQL_LENGTH}-character limit.")

    cleaned = _strip_leading_comments(sql)

    if not cleaned:
        raise ValueError("SQL query must be a non-empty string.")

    if explain:
        if not re.match(r"\A(?:SELECT|WITH|VALUES)\b", cleaned, re.IGNORECASE):
            raise ValueError("Only SELECT, WITH, or VALUES queries can be explained.")
        return f"EXPLAIN QUERY PLAN {cleaned}"

    match = _FIRST_WORD.match(cleaned)

    if not match:
        raise ValueError("Only read-only SELECT and WITH queries are allowed.")

    first = match.group(1).upper()

    if first in {"SELECT", "WITH", "VALUES"}:
        return sql.strip()

    if first == "EXPLAIN" and allow_explain_plan:
        explain_match = _EXPLAIN_QUERY_PLAN.match(cleaned)

        if explain_match is None:
            raise ValueError("Only EXPLAIN QUERY PLAN is permitted.")

        explained = cleaned[explain_match.end() :].lstrip()
        explained_match = _FIRST_WORD.match(explained)

        if not explained_match or explained_match.group(1).upper() not in {
            "SELECT",
            "WITH",
            "VALUES",
        }:
            raise ValueError("EXPLAIN QUERY PLAN must contain a SELECT or WITH query.")

        return sql.strip()

    raise ValueError("Only read-only SELECT and WITH queries are allowed.")


def _validate_params(
    params: Any,
) -> dict[str, Any] | list[Any] | tuple[Any, ...]:
    """Validate SQLite scalar query parameters."""
    if params is None:
        return ()

    if not isinstance(params, (dict, list, tuple)):
        raise ValueError("Query parameters must be an object, array, or null.")

    if isinstance(params, dict):
        if not all(isinstance(key, str) for key in params):
            raise ValueError("Named query parameter keys must be strings.")
        values = params.values()
    else:
        values = params

    for value in values:
        if value is None:
            continue

        if isinstance(value, bool):
            continue

        if isinstance(value, int):
            if not (SQLITE_INT64_MIN <= value <= SQLITE_INT64_MAX):
                raise ValueError(
                    f"Integer query parameter {value} is outside SQLite's signed 64-bit "
                    f"integer range ({SQLITE_INT64_MIN} to {SQLITE_INT64_MAX})."
                )
            continue

        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("Floating-point query parameters must be finite.")
            continue

        if isinstance(value, str):
            if len(value) > MAX_CELL_TEXT:
                raise ValueError("A query parameter exceeds the maximum text length.")
            continue

        if isinstance(value, bytes):
            if len(value) > MAX_BLOB_BYTES:
                raise ValueError("A BLOB query parameter exceeds the maximum byte length.")
            continue

        raise ValueError("Query parameters must contain only SQLite scalar values.")

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
        raise FileNotFoundError("Database path is not a regular file.")

    connection = sqlite3.connect(
        f"{path.as_uri()}?mode=ro",
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

            time_exceeded = time.monotonic() - started > timeout_seconds
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


_PATH_PATTERN = re.compile(
    r"(?:[A-Za-z]:\\[^\s:;,()]+|/(?:home|usr|var|tmp|etc|opt|private|Users|mnt|c|d|e)/[^\s:;,()]+|file://[^\s:;,()]+)",
)


def _sanitize_error_message(message: str) -> str:
    """Strip local filesystem paths and file URIs from error messages."""
    return _PATH_PATTERN.sub("<path>", message)


def _error(message: str, code: str) -> dict[str, Any]:
    """Build a consistent, non-sensitive error response."""
    return {
        "ok": False,
        "error": _sanitize_error_message(message),
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
    column_names = dict(zip(original_columns, limited_columns, strict=False))

    columns_truncated = len(columns) > MAX_COLUMNS

    safe_rows = [
        {column_names[key]: _json_safe(value) for key, value in row.items() if key in column_names}
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
        payload["warning"] = "The result exceeded the maximum response size and was omitted."

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
    cursor = None

    try:
        cursor = connection.execute(statement, bindings)
        fetched = cursor.fetchmany(max_rows + 1)

        was_truncated = len(fetched) > max_rows
        selected = fetched[:max_rows]

        columns = [item[0] for item in (cursor.description or [])]

        rows = [dict(row) for row in selected]

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

    except sqlite3.ProgrammingError as exc:
        reason = str(exc).casefold()
        if "one statement" in reason:
            return _error(
                "Only a single SQL statement can be executed at a time.",
                "invalid_input",
            )
        return _error(
            f"SQLite parameter error: {exc}",
            "invalid_input",
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
            f"SQLite could not execute this query: {exc}",
            "query_failed",
        )

    except sqlite3.DatabaseError as exc:
        reason = str(exc).casefold()

        if "not authorized" in reason or "prohibited" in reason:
            return _error(
                "The SQLite authorizer blocked this operation.",
                "blocked_operation",
            )

        return _error(
            f"SQLite could not execute this query: {exc}",
            "query_failed",
        )

    except sqlite3.Error as exc:
        return _error(
            f"SQLite could not execute this query: {exc}",
            "query_failed",
        )

    except OverflowError as exc:
        return _error(
            f"Integer parameter overflow: {exc}",
            "invalid_input",
        )

    finally:
        if cursor is not None:
            cursor.close()
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
        raise ValueError("Table name must contain 1–256 non-NUL characters.")

    return '"' + identifier.replace('"', '""') + '"'


def _analyze_indexes_for_table(
    columns: list[dict[str, Any]],
    indexes: list[dict[str, Any]],
    foreign_keys: list[dict[str, Any]],
) -> dict[str, Any]:
    """Provide deterministic index intelligence and optimization recommendations."""
    recommendations: list[str] = []
    unindexed_fks: list[str] = []

    indexed_leading_columns = set()
    index_column_signatures: list[tuple[str, tuple[str, ...]]] = []

    for idx in indexes:
        idx_cols = [str(c.get("name", "")) for c in idx.get("columns", []) if c.get("name")]
        if idx_cols:
            indexed_leading_columns.add(idx_cols[0])
            index_column_signatures.append((str(idx.get("name", "")), tuple(idx_cols)))

    for fk in foreign_keys:
        from_col = fk.get("from")
        if from_col and from_col not in indexed_leading_columns:
            is_pk = any(col.get("name") == from_col and col.get("pk") for col in columns)
            if not is_pk:
                unindexed_fks.append(str(from_col))
                recommendations.append(
                    f"Foreign key column '{from_col}' lacks a supporting index with leading "
                    f"column '{from_col}'. Adding an index on '{from_col}' can improve JOIN "
                    "performance and referential integrity checks."
                )

    for i in range(len(index_column_signatures)):
        for j in range(i + 1, len(index_column_signatures)):
            name1, cols1 = index_column_signatures[i]
            name2, cols2 = index_column_signatures[j]
            if cols1 == cols2:
                recommendations.append(
                    f"Duplicate indexes detected: '{name1}' and '{name2}' index the same columns."
                )
            else:
                shorter, longer = (cols1, cols2) if len(cols1) <= len(cols2) else (cols2, cols1)
                short_name, long_name = (
                    (name1, name2) if len(cols1) <= len(cols2) else (name2, name1)
                )
                if len(shorter) < len(longer) and longer[: len(shorter)] == shorter:
                    short_str = ", ".join(shorter)
                    long_str = ", ".join(longer)
                    recommendations.append(
                        f"Index '{short_name}' ({short_str}) is a prefix of composite index "
                        f"'{long_name}' ({long_str})."
                    )

    return {
        "recommendations": recommendations,
        "unindexed_foreign_keys": unindexed_fks,
    }


def describe_table(
    db_path: str | Path,
    table_name: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
) -> dict[str, Any]:
    """Return table columns, indexes, foreign keys, and masking metadata."""
    if not isinstance(table_name, str) or not table_name.strip():
        return _error("table_name must be a non-empty string.", "invalid_table_name")

    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 0
    ):
        return _error("timeout_seconds must be a non-negative number.", "invalid_input")
    if timeout_seconds > 300:
        return _error("timeout_seconds exceeds maximum allowed limit (300).", "invalid_input")

    if isinstance(max_vm_steps, bool) or not isinstance(max_vm_steps, int) or max_vm_steps <= 0:
        return _error("max_vm_steps must be a positive integer.", "invalid_input")

    try:
        quoted_table = _quote_identifier(table_name)
    except ValueError as exc:
        return _error(str(exc), "invalid_table_name")

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

    try:

        def _fetch_rows(query: str) -> list[sqlite3.Row]:
            cur = connection.execute(query)
            try:
                return cur.fetchall()
            finally:
                cur.close()

        raw_columns_all = _fetch_rows(f"PRAGMA table_xinfo({quoted_table})")
        if not raw_columns_all:
            return _error(
                "The requested table or view does not exist.",
                "table_not_found",
            )

        columns_truncated = len(raw_columns_all) > MAX_COLUMNS
        raw_columns = raw_columns_all[:MAX_COLUMNS]
        columns = [dict(row) for row in raw_columns]

        for column in columns:
            col_name = str(column.get("name", ""))
            is_sensitive = _is_sensitive_column(col_name)
            column["masked_by_guard"] = is_sensitive
            if is_sensitive:
                column["default_redacted"] = column.get("dflt_value") is not None
                column["dflt_value"] = None
            else:
                column["default_redacted"] = False

        indexes = []
        raw_indexes_all = _fetch_rows(f"PRAGMA index_list({quoted_table})")
        indexes_truncated = len(raw_indexes_all) > MAX_INDEXES
        raw_indexes = raw_indexes_all[:MAX_INDEXES]
        index_columns_truncated = False

        for index in raw_indexes:
            item = dict(index)
            quoted_index = _quote_identifier(str(item["name"]))
            raw_idx_cols_all = _fetch_rows(f"PRAGMA index_xinfo({quoted_index})")
            if len(raw_idx_cols_all) > MAX_INDEX_COLUMNS:
                index_columns_truncated = True
            item["columns"] = [dict(row) for row in raw_idx_cols_all[:MAX_INDEX_COLUMNS]]
            indexes.append(item)

        raw_fks_all = _fetch_rows(f"PRAGMA foreign_key_list({quoted_table})")
        foreign_keys_truncated = len(raw_fks_all) > MAX_FOREIGN_KEYS
        raw_fks = raw_fks_all[:MAX_FOREIGN_KEYS]
        foreign_keys = [dict(row) for row in raw_fks]

        relationships = [
            {
                "from_column": fk.get("from"),
                "target_table": fk.get("table"),
                "target_column": fk.get("to"),
                "on_update": fk.get("on_update"),
                "on_delete": fk.get("on_delete"),
            }
            for fk in foreign_keys
            if fk.get("from") and fk.get("table")
        ]

        index_intelligence = _analyze_indexes_for_table(columns, indexes, foreign_keys)
        warnings: list[str] = []

        payload: dict[str, Any] = {
            "ok": True,
            "table": table_name,
            "columns": columns,
            "indexes": indexes,
            "foreign_keys": foreign_keys,
            "relationships": relationships,
            "index_intelligence": index_intelligence,
            "truncated": (
                columns_truncated
                or indexes_truncated
                or index_columns_truncated
                or foreign_keys_truncated
            ),
            "columns_truncated": columns_truncated,
            "indexes_truncated": indexes_truncated,
            "index_columns_truncated": index_columns_truncated,
            "foreign_keys_truncated": foreign_keys_truncated,
            "response_truncated": False,
            "warnings": warnings,
        }

        if _serialized_size(payload) > MAX_RESULT_BYTES:
            payload["response_truncated"] = True
            payload["truncated"] = True
            warnings.append("Schema metadata response exceeded byte budget and was truncated.")
            for idx in payload["indexes"]:
                idx["columns"] = idx["columns"][:2]
            if _serialized_size(payload) > MAX_RESULT_BYTES:
                payload["relationships"] = []
                payload["indexes"] = payload["indexes"][:10]

        return payload

    except sqlite3.Error:
        return _error(
            "SQLite could not inspect this table's schema.",
            "schema_inspection_failed",
        )
    finally:
        connection.close()


def _analyze_query_plan(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Provide structured, evidence-based diagnostics for an EXPLAIN QUERY PLAN."""
    uses_index = False
    scans_table = False
    covering_index_detected = False
    indexes_used: list[str] = []
    scanned_tables: list[str] = []
    temp_btree = False
    recommendations: list[str] = []

    for row in rows:
        detail = str(row.get("detail", "")).strip()
        detail_upper = detail.upper()

        if "USE TEMP B-TREE" in detail_upper:
            temp_btree = True

        if detail_upper.startswith("SEARCH "):
            uses_index = True
            rest = detail[7:].strip()
            if rest.upper().startswith("TABLE "):
                rest = rest[6:].strip()
            parts = re.split(r"\s+USING\s+", rest, maxsplit=1, flags=re.IGNORECASE)
            if len(parts) == 2:
                using_part = parts[1].strip()
                if using_part.upper().startswith("COVERING INDEX "):
                    covering_index_detected = True
                    idx_name = using_part[15:].split("(", 1)[0].strip().strip('"[]`')
                    if idx_name:
                        indexes_used.append(idx_name)
                elif using_part.upper().startswith("INDEX "):
                    idx_name = using_part[6:].split("(", 1)[0].strip().strip('"[]`')
                    if idx_name:
                        indexes_used.append(idx_name)
        elif "USING INTEGER PRIMARY KEY" in detail_upper:
            uses_index = True

        if detail_upper.startswith("SCAN "):
            scans_table = True
            rest = detail[5:].strip()
            if rest.upper().startswith("TABLE "):
                rest = rest[6:].strip()
            tbl = (
                re.split(r"\s+AS\s+|\s+USING\s+", rest, flags=re.IGNORECASE)[0]
                .strip()
                .strip('"[]`')
            )
            if tbl and tbl not in scanned_tables and not tbl.startswith("sqlite_"):
                scanned_tables.append(tbl)

    if scans_table and scanned_tables:
        for tbl in scanned_tables:
            recommendations.append(
                f"Full table scan detected on '{tbl}'. If this table is large and "
                "query performance is critical, consider adding an index on filter or join columns."
            )
    if temp_btree:
        recommendations.append(
            "Query requires a temporary B-Tree for sorting or grouping. An index covering "
            "the ORDER BY or GROUP BY columns can eliminate sorting overhead."
        )
    if not recommendations and uses_index:
        recommendations.append("Query is efficiently utilizing available indexes.")

    observations = {
        "full_scan_detected": scans_table,
        "index_search_detected": uses_index,
        "covering_index_detected": covering_index_detected,
        "temporary_sort_detected": temp_btree,
    }

    return {
        "uses_index": uses_index,
        "scans_table": scans_table,
        "indexes_used": list(dict.fromkeys(indexes_used)),
        "scanned_tables": scanned_tables,
        "uses_temp_btree": temp_btree,
        "observations": observations,
        "confidence": "high" if rows else "heuristic",
        "recommendations": recommendations,
    }


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

    res = execute_guarded_query(
        db_path,
        statement,
        params,
        max_rows=max_rows,
        timeout_seconds=timeout_seconds,
        max_vm_steps=max_vm_steps,
        _allow_explain_plan=True,
    )
    if res.get("ok"):
        res["diagnostics"] = _analyze_query_plan(res.get("rows", []))
    return res


def inspect_schema_summary(
    db_path: str | Path,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
    max_tables: int = MAX_SCHEMA_TABLES,
    max_columns_per_table: int = MAX_COLUMNS,
) -> dict[str, Any]:
    """Provide a single-connection bounded summary of all tables, views, and schemas."""
    if isinstance(max_tables, bool) or not isinstance(max_tables, int) or max_tables <= 0:
        return _error("max_tables must be a positive integer.", "invalid_input")
    if max_tables > 10_000:
        return _error("max_tables exceeds maximum allowed limit (10000).", "invalid_input")

    if (
        isinstance(max_columns_per_table, bool)
        or not isinstance(max_columns_per_table, int)
        or max_columns_per_table <= 0
    ):
        return _error("max_columns_per_table must be a positive integer.", "invalid_input")
    if max_columns_per_table > 1_000:
        return _error(
            "max_columns_per_table exceeds maximum allowed limit (1000).", "invalid_input"
        )

    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 0
    ):
        return _error("timeout_seconds must be a non-negative number.", "invalid_input")
    if timeout_seconds > 300:
        return _error("timeout_seconds exceeds maximum allowed limit (300).", "invalid_input")

    if isinstance(max_vm_steps, bool) or not isinstance(max_vm_steps, int) or max_vm_steps <= 0:
        return _error("max_vm_steps must be a positive integer.", "invalid_input")

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

    started = time.monotonic()
    tables_dict: dict[str, Any] = {}
    truncated = False
    tables_truncated = False
    columns_truncated = False
    time_truncated = False
    response_truncated = False
    warnings: list[dict[str, Any]] = []

    try:

        def _fetch_rows(query: str, params: Any = ()) -> list[sqlite3.Row]:
            cur = connection.execute(query, params)
            try:
                return cur.fetchall()
            finally:
                cur.close()

        count_rows = _fetch_rows(
            "SELECT count(*) AS cnt FROM sqlite_schema "
            "WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'"
        )
        total_tables = int(count_rows[0]["cnt"]) if count_rows else 0

        table_rows = _fetch_rows(
            "SELECT name, type FROM sqlite_schema "
            "WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name LIMIT ?",
            (max_tables,),
        )

        if total_tables > max_tables:
            truncated = True
            tables_truncated = True
            warnings.append(
                {
                    "code": "table_count_capped",
                    "object": None,
                    "message": (
                        f"Database contains {total_tables} tables/views; "
                        f"summary capped at {max_tables}."
                    ),
                }
            )

        for row in table_rows:
            if (time.monotonic() - started) >= timeout_seconds:
                truncated = True
                time_truncated = True
                warnings.append(
                    {
                        "code": "timeout_reached",
                        "object": None,
                        "message": (
                            f"Schema summary timed out after {timeout_seconds}s and "
                            "was partially returned."
                        ),
                    }
                )
                break

            tbl_name = row["name"]
            tbl_type = row["type"]

            try:
                quoted = _quote_identifier(tbl_name)
                raw_cols_all = _fetch_rows(f"PRAGMA table_xinfo({quoted})")
            except Exception as exc:
                truncated = True
                warnings.append(
                    {
                        "code": "schema_object_inspection_failed",
                        "object": tbl_name,
                        "message": (
                            f"Could not inspect table_xinfo for '{tbl_name}': {type(exc).__name__}"
                        ),
                    }
                )
                tables_dict[tbl_name] = {
                    "type": tbl_type,
                    "status": "inspection_failed",
                    "columns": [],
                }
                continue

            if len(raw_cols_all) > max_columns_per_table:
                columns_truncated = True
                truncated = True

            raw_cols = raw_cols_all[:max_columns_per_table]
            columns = []
            for col in raw_cols:
                c_name = str(col["name"])
                is_sens = _is_sensitive_column(c_name)
                columns.append(
                    {
                        "name": c_name,
                        "type": col["type"],
                        "pk": bool(col["pk"]),
                        "masked": is_sens,
                        "default_redacted": is_sens and col["dflt_value"] is not None,
                    }
                )

            table_indexes = []
            try:
                raw_idx = _fetch_rows(f"PRAGMA index_list({quoted})")[:20]
                for idx in raw_idx:
                    table_indexes.append(
                        {
                            "name": str(idx["name"]),
                            "unique": bool(idx["unique"]),
                        }
                    )
            except Exception:
                pass

            table_relationships = []
            try:
                raw_fks = _fetch_rows(f"PRAGMA foreign_key_list({quoted})")[:20]
                for fk in raw_fks:
                    if fk.get("from") and fk.get("table"):
                        table_relationships.append(
                            {
                                "from_column": fk.get("from"),
                                "target_table": fk.get("table"),
                                "target_column": fk.get("to"),
                            }
                        )
            except Exception:
                pass

            tables_dict[tbl_name] = {
                "type": tbl_type,
                "columns": columns,
                "indexes": table_indexes,
                "relationships": table_relationships,
            }

        elapsed = round((time.monotonic() - started) * 1000, 3)
        status = (
            "complete"
            if not truncated
            and not any(w["code"] == "schema_object_inspection_failed" for w in warnings)
            else "partial"
        )
        warning_str = "; ".join(w["message"] for w in warnings) if warnings else None

        payload: dict[str, Any] = {
            "ok": True,
            "status": status,
            "tables": tables_dict,
            "table_count": len(tables_dict),
            "total_tables": total_tables,
            "truncated": truncated,
            "tables_truncated": tables_truncated,
            "columns_truncated": columns_truncated,
            "time_truncated": time_truncated,
            "response_truncated": response_truncated,
            "elapsed_ms": elapsed,
            "warnings": warnings,
        }
        if warning_str:
            payload["warning"] = warning_str

        while tables_dict and _serialized_size(payload) > MAX_RESULT_BYTES:
            last_key = next(reversed(tables_dict))
            del tables_dict[last_key]
            payload["table_count"] = len(tables_dict)
            payload["truncated"] = True
            payload["response_truncated"] = True
            payload["status"] = "partial"
            if not any(w.get("code") == "response_size_truncated" for w in warnings):
                warnings.append(
                    {
                        "code": "response_size_truncated",
                        "object": None,
                        "message": (
                            "Schema summary exceeded maximum response size and was truncated."
                        ),
                    }
                )
            payload["warning"] = "Schema summary exceeded maximum response size and was truncated."

        return payload

    except sqlite3.Error:
        return _error(
            "SQLite could not inspect the database schema.",
            "schema_inspection_failed",
        )
    finally:
        connection.close()


def create_server(
    db_path: str | Path,
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
) -> Any:
    """Create the official MCP SDK server with SQLite Guard tools and schema resources."""
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
        sql: Annotated[
            str,
            Field(description="Read-only SELECT, WITH, or VALUES SQL query to execute."),
        ],
        params: Annotated[
            dict[str, Any] | list[Any] | None,
            Field(
                default=None,
                description=(
                    "Optional query parameters as a list for positional ? placeholders, "
                    "or dict for named (:name, $name) placeholders."
                ),
            ),
        ] = None,
    ) -> str:
        """Run a read-only SELECT, WITH, or VALUES query with bound parameters."""
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
        """List user-created tables and views in the database."""
        result = list_tables(
            database,
            max_rows=max_rows,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
        )
        return json.dumps(result, ensure_ascii=False)

    @server.tool()
    def describe_database_table(
        table_name: Annotated[
            str,
            Field(description="The name of the database table or view to inspect."),
        ],
    ) -> str:
        """Inspect a table's schema, indexes, foreign keys, and masking metadata."""
        result = describe_table(
            database,
            table_name,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
        )
        return json.dumps(result, ensure_ascii=False)

    @server.tool()
    def explain_read_query(
        sql: Annotated[
            str,
            Field(description="Read-only SELECT, WITH, or VALUES SQL query to explain."),
        ],
        params: Annotated[
            dict[str, Any] | list[Any] | None,
            Field(
                default=None,
                description=(
                    "Optional query parameters as a list for positional ? placeholders, "
                    "or dict for named placeholders."
                ),
            ),
        ] = None,
    ) -> str:
        """Explain the query plan (EXPLAIN QUERY PLAN) for a read-only query."""
        result = explain_query(
            database,
            sql,
            params,
            max_rows=max_rows,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
        )
        return json.dumps(result, ensure_ascii=False)

    @server.resource("schema://summary")
    def database_schema_summary() -> str:
        """Provide a summary of all user-created tables, views, and column definitions."""
        result = inspect_schema_summary(
            database,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
        )
        return json.dumps(result, ensure_ascii=False)

    return server


def main(argv: list[str] | None = None) -> int:
    """Run the SQLite Guard MCP server over standard input/output or HTTP transports."""
    parser = argparse.ArgumentParser(
        prog="sqlite-guard-mcp",
        description="Read-only, security-hardened SQLite MCP server.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
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
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport to run (default: stdio).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host address to bind for HTTP/SSE transports (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind for HTTP/SSE transports (default: 8000).",
    )

    args = parser.parse_args(argv)

    if not args.db:
        parser.error("Provide --db or set the SQLITE_GUARD_DB environment variable.")

    if not 1 <= args.max_rows <= MAX_ROWS_HARD_LIMIT:
        parser.error(f"--max-rows must be between 1 and {MAX_ROWS_HARD_LIMIT}.")

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
    try:
        if args.transport == "stdio":
            server.run(transport="stdio")
        elif args.transport == "streamable-http":
            server.run(
                transport="streamable-http",
                host=args.host,
                port=args.port,
            )
        elif args.transport == "sse":
            server.run(
                transport="sse",
                host=args.host,
                port=args.port,
            )
    except (KeyboardInterrupt, EOFError):
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
