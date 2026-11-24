"""Read-only SQLite MCP server with bounded execution and credential masking."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field

from . import __version__
from .policy import AccessPolicy, default_policy, load_policy

MAX_SQL_LENGTH = 100_000
MAX_ROWS_HARD_LIMIT = 1_000
MAX_COLUMNS = 100
MAX_CELL_TEXT = 4_096
MAX_BLOB_BYTES = 4_096
MAX_RESULT_BYTES = 1_000_000

MAX_PARAMS_COUNT = 1_000
MAX_PARAMS_TOTAL_BYTES = 1_000_000
MAX_PARAM_KEY_LENGTH = 128
MAX_SEARCH_RESULTS = 50

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
        "foreign_key_check",
    }
)

_NO_ARGUMENT_PRAGMAS = frozenset(
    {
        "compile_options",
        "encoding",
        "data_version",
        "quick_check",
        "integrity_check",
        "schema_version",
        "page_size",
        "page_count",
        "foreign_key_check",
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

    if not normalized:
        return False

    if normalized in _SAFE_TOKEN_METRICS:
        return False

    parts = set(normalized.split("_"))

    if "token" in parts:
        return True

    if parts.intersection(_SENSITIVE_WORDS):
        return True

    padded = f"_{normalized}_"
    return any(f"_{phrase}_" in padded for phrase in _SENSITIVE_PHRASES)


def _create_authorizer(policy: AccessPolicy | None = None) -> Any:
    """Create a scoped SQLite authorizer callback enforcing policy and read-only protections."""
    effective_policy = policy or default_policy()

    def authorizer(
        action: int,
        arg1: str | None,
        arg2: str | None,
        _database_name: str | None,
        _source: str | None,
    ) -> int:
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

            if arg1 and not effective_policy.is_table_allowed(arg1):
                return sqlite3.SQLITE_DENY

            if arg1 and arg2 and not effective_policy.is_column_allowed(arg1, arg2):
                return sqlite3.SQLITE_DENY

            if table_name in _SCHEMA_TABLES and column_name == "sql":
                return sqlite3.SQLITE_IGNORE

            if (
                table_name in {"pragma_table_info", "pragma_table_xinfo"}
                and column_name == "dflt_value"
            ):
                return sqlite3.SQLITE_IGNORE

            if _is_sensitive_column(arg2) or (
                arg1 and arg2 and effective_policy.is_column_sensitive(arg1, arg2)
            ):
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

            if pragma in {"quick_check", "integrity_check"}:
                if arg2 is None or (isinstance(arg2, str) and arg2.isdigit()):
                    return sqlite3.SQLITE_OK

            if pragma in _NO_ARGUMENT_PRAGMAS and arg2 is None:
                return sqlite3.SQLITE_OK

            return sqlite3.SQLITE_DENY

        return sqlite3.SQLITE_DENY

    return authorizer


_authorize = _create_authorizer(default_policy())


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
            raise ValueError("Only SELECT, WITH, or VALUES queries can be explained.")

        return sql.strip()

    raise ValueError("Only read-only SELECT and WITH queries are allowed.")


def _validate_params(
    params: Any,
) -> dict[str, Any] | list[Any] | tuple[Any, ...]:
    """Validate SQLite scalar query parameters and enforce aggregate bounds."""
    if params is None:
        return ()

    if not isinstance(params, (dict, list, tuple)):
        raise ValueError("Query parameters must be an object, array, or null.")

    if len(params) > MAX_PARAMS_COUNT:
        raise ValueError(f"Query parameter count exceeds maximum limit of {MAX_PARAMS_COUNT}.")

    total_bytes = 0
    if isinstance(params, dict):
        for key in params:
            if not isinstance(key, str):
                raise ValueError("Named query parameter keys must be strings.")
            if len(key) > MAX_PARAM_KEY_LENGTH:
                raise ValueError(
                    f"Named parameter key length exceeds maximum limit of {MAX_PARAM_KEY_LENGTH}."
                )
            total_bytes += len(key.encode("utf-8"))
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
            total_bytes += 8
            continue

        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("Floating-point query parameters must be finite.")
            total_bytes += 8
            continue

        if isinstance(value, str):
            val_bytes = len(value.encode("utf-8"))
            if len(value) > MAX_CELL_TEXT:
                raise ValueError("A query parameter exceeds the maximum text length.")
            total_bytes += val_bytes
            continue

        if isinstance(value, bytes):
            if len(value) > MAX_BLOB_BYTES:
                raise ValueError("A BLOB query parameter exceeds the maximum byte length.")
            total_bytes += len(value)
            continue

        raise ValueError("Query parameters must contain only SQLite scalar values.")

    if total_bytes > MAX_PARAMS_TOTAL_BYTES:
        raise ValueError(
            f"Aggregate parameter size ({total_bytes} bytes) "
            f"exceeds limit of {MAX_PARAMS_TOTAL_BYTES} bytes."
        )

    return params


def _open_connection(
    db_path: str | Path,
    *,
    policy: AccessPolicy | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
) -> sqlite3.Connection:
    """Open an existing database in read-only mode with execution limits and authorizer."""
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
        connection.set_authorizer(_create_authorizer(policy))

        return connection

    except Exception:
        connection.close()
        raise


def _fetch_bounded_rows(
    cur: sqlite3.Cursor,
    limit: int,
) -> tuple[list[sqlite3.Row], bool]:
    """Retrieve up to limit+1 rows from an active cursor to safely detect truncation."""
    rows = cur.fetchmany(limit + 1)
    is_truncated = len(rows) > limit
    return rows[:limit], is_truncated


def _record_audit_event(
    audit_file: Path | str | None,
    tool_name: str,
    operation: str,
    *,
    sql: str | None = None,
    status: str = "success",
    row_count: int = 0,
    response_bytes: int = 0,
    duration_ms: float = 0.0,
    error_code: str | None = None,
    truncated: bool = False,
) -> None:
    """Safely append a privacy-safe audit record without leaking secrets."""
    if not audit_file:
        return
    try:
        path = Path(audit_file)
        fingerprint = None
        if sql:
            fingerprint = hashlib.sha256(sql.strip().encode("utf-8")).hexdigest()[:16]

        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_id": uuid.uuid4().hex[:12],
            "tool": tool_name,
            "operation": operation,
            "duration_ms": duration_ms,
            "status": status,
            "row_count": row_count,
            "response_bytes": response_bytes,
            "truncated": truncated,
        }
        if fingerprint:
            event["query_fingerprint"] = fingerprint
        if error_code:
            event["error_code"] = error_code

        line = json.dumps(event, ensure_ascii=False) + "\n"
        with path.open("a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


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

    response_truncated = False
    payload: dict[str, Any] = {
        "ok": True,
        "columns": limited_columns,
        "rows": safe_rows,
        "row_count": len(safe_rows),
        "truncated": truncated,
        "columns_truncated": columns_truncated,
        "response_truncated": response_truncated,
        "elapsed_ms": elapsed_ms,
    }

    while safe_rows and _serialized_size(payload) > MAX_RESULT_BYTES:
        safe_rows.pop()
        payload["row_count"] = len(safe_rows)
        payload["truncated"] = True
        payload["response_truncated"] = True

    if _serialized_size(payload) > MAX_RESULT_BYTES:
        payload["rows"] = []
        payload["row_count"] = 0
        payload["truncated"] = True
        payload["columns_truncated"] = True
        payload["response_truncated"] = True
        payload["warning"] = "The result exceeded maximum response size and was omitted."

    return payload


def execute_guarded_query(
    db_path: str | Path,
    sql: str,
    params: dict[str, Any] | list[Any] | tuple[Any, ...] | None = None,
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
    policy: AccessPolicy | None = None,
    audit_file: Path | str | None = None,
    _allow_explain_plan: bool = False,
) -> dict[str, Any]:
    """Execute one parameterized, read-only SQL statement."""
    started_total = time.perf_counter()

    if (
        isinstance(max_rows, bool)
        or not isinstance(max_rows, int)
        or not 1 <= max_rows <= MAX_ROWS_HARD_LIMIT
    ):
        err = _error(
            f"max_rows must be an integer between 1 and {MAX_ROWS_HARD_LIMIT}.",
            "invalid_limit",
        )
        _record_audit_event(
            audit_file,
            "read_query",
            "query",
            sql=sql,
            status="error",
            error_code="invalid_limit",
        )
        return err

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0.05 <= timeout_seconds <= 60
    ):
        err = _error("timeout_seconds must be between 0.05 and 60.", "invalid_limit")
        _record_audit_event(
            audit_file,
            "read_query",
            "query",
            sql=sql,
            status="error",
            error_code="invalid_limit",
        )
        return err

    if (
        isinstance(max_vm_steps, bool)
        or not isinstance(max_vm_steps, int)
        or not 1_000 <= max_vm_steps <= 100_000_000
    ):
        err = _error("max_vm_steps is outside the permitted range.", "invalid_limit")
        _record_audit_event(
            audit_file,
            "read_query",
            "query",
            sql=sql,
            status="error",
            error_code="invalid_limit",
        )
        return err

    try:
        statement = _validate_query(
            sql,
            allow_explain_plan=_allow_explain_plan,
        )
        bindings = _validate_params(params)

    except ValueError as exc:
        err = _error(str(exc), "invalid_input")
        _record_audit_event(
            audit_file,
            "read_query",
            "query",
            sql=sql,
            status="error",
            error_code="invalid_input",
        )
        return err

    try:
        connection = _open_connection(
            db_path,
            policy=policy,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
        )

    except FileNotFoundError:
        err = _error(
            "Database file was not found or is not a regular file.",
            "database_not_found",
        )
        _record_audit_event(
            audit_file,
            "read_query",
            "query",
            sql=sql,
            status="error",
            error_code="database_not_found",
        )
        return err

    except (sqlite3.Error, OSError, RuntimeError):
        err = _error(
            "Could not open the database in read-only mode.",
            "database_open_failed",
        )
        _record_audit_event(
            audit_file,
            "read_query",
            "query",
            sql=sql,
            status="error",
            error_code="database_open_failed",
        )
        return err

    started = time.perf_counter()
    cursor = None

    try:
        cursor = connection.execute(statement, bindings)
        selected, was_truncated = _fetch_bounded_rows(cursor, max_rows)

        columns = [item[0] for item in (cursor.description or [])]
        rows = [dict(row) for row in selected]

        elapsed = round(
            (time.perf_counter() - started) * 1000,
            3,
        )

        result = _bounded_result(
            columns,
            rows,
            was_truncated,
            elapsed,
        )
        duration_ms = round((time.perf_counter() - started_total) * 1000, 2)
        _record_audit_event(
            audit_file,
            "read_query",
            "query",
            sql=sql,
            status="success",
            row_count=result.get("row_count", 0),
            response_bytes=_serialized_size(result),
            duration_ms=duration_ms,
            truncated=result.get("truncated", False),
        )
        return result

    except sqlite3.ProgrammingError as exc:
        reason = str(exc).casefold()
        code = "invalid_input"
        msg = (
            "Only a single SQL statement can be executed at a time."
            if "one statement" in reason
            else f"SQLite parameter error: {exc}"
        )
        err = _error(msg, code)
        _record_audit_event(
            audit_file, "read_query", "query", sql=sql, status="error", error_code=code
        )
        return err

    except sqlite3.OperationalError as exc:
        reason = str(exc).casefold()
        if "not authorized" in reason or "prohibited" in reason:
            code = "blocked_operation"
            msg = "The SQLite authorizer blocked this operation."
        elif "interrupted" in reason:
            code = "query_budget_exceeded"
            msg = "The query exceeded its execution budget."
        else:
            code = "query_failed"
            msg = f"SQLite could not execute this query: {exc}"
        err = _error(msg, code)
        _record_audit_event(
            audit_file, "read_query", "query", sql=sql, status="error", error_code=code
        )
        return err

    except sqlite3.DatabaseError as exc:
        reason = str(exc).casefold()
        if "not authorized" in reason or "prohibited" in reason:
            code = "blocked_operation"
            msg = "The SQLite authorizer blocked this operation."
        else:
            code = "query_failed"
            msg = f"SQLite could not execute this query: {exc}"
        err = _error(msg, code)
        _record_audit_event(
            audit_file, "read_query", "query", sql=sql, status="error", error_code=code
        )
        return err

    except sqlite3.Error as exc:
        err = _error(f"SQLite could not execute this query: {exc}", "query_failed")
        _record_audit_event(
            audit_file, "read_query", "query", sql=sql, status="error", error_code="query_failed"
        )
        return err

    except OverflowError as exc:
        err = _error(f"Integer parameter overflow: {exc}", "invalid_input")
        _record_audit_event(
            audit_file, "read_query", "query", sql=sql, status="error", error_code="invalid_input"
        )
        return err

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
    policy: AccessPolicy | None = None,
    audit_file: Path | str | None = None,
) -> dict[str, Any]:
    """List user-created tables and views, filtered by active access policy."""
    effective_policy = policy or default_policy()
    res = execute_guarded_query(
        db_path,
        (
            "SELECT name, type FROM sqlite_schema "
            "WHERE type IN ('table', 'view') "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ),
        max_rows=max_rows,
        timeout_seconds=timeout_seconds,
        max_vm_steps=max_vm_steps,
        policy=effective_policy,
        audit_file=audit_file,
    )
    if res.get("ok"):
        filtered_rows = [
            row for row in res.get("rows", []) if effective_policy.is_table_allowed(row["name"])
        ]
        res["rows"] = filtered_rows
        res["row_count"] = len(filtered_rows)
    return res


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
    pk_columns: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Provide deterministic index intelligence, composite FK checking, and overlap diagnostics."""
    recommendations: list[str] = []
    unindexed_fks: list[str] = []

    indexed_leading_columns = set()
    index_column_signatures: list[tuple[str, tuple[str, ...]]] = []

    for idx in indexes:
        idx_cols = [
            str(c.get("name", ""))
            for c in idx.get("columns", [])
            if c.get("name") and c.get("key", 1) == 1
        ]
        if not idx_cols:
            idx_cols = [str(c.get("name", "")) for c in idx.get("columns", []) if c.get("name")]

        if idx_cols:
            indexed_leading_columns.add(idx_cols[0])
            index_column_signatures.append((str(idx.get("name", "")), tuple(idx_cols)))

    fk_groups: dict[int, list[dict[str, Any]]] = {}
    for fk in foreign_keys:
        fkid = fk.get("id", 0)
        fk_groups.setdefault(fkid, []).append(fk)

    for _fkid, group in fk_groups.items():
        sorted_group = sorted(group, key=lambda x: x.get("seq", 0))
        fk_cols = tuple(str(x.get("from", "")) for x in sorted_group if x.get("from"))
        if not fk_cols:
            continue

        is_supported = False
        for _, idx_cols in index_column_signatures:
            if len(idx_cols) >= len(fk_cols) and idx_cols[: len(fk_cols)] == fk_cols:
                is_supported = True
                break

        if not is_supported and pk_columns:
            if len(pk_columns) >= len(fk_cols) and pk_columns[: len(fk_cols)] == fk_cols:
                is_supported = True

        if not is_supported:
            fk_name = ", ".join(fk_cols)
            unindexed_fks.append(fk_name)
            if len(fk_cols) > 1:
                recommendations.append(
                    f"Composite foreign key ({fk_name}) lacks a supporting index with prefix "
                    f"({fk_name}). Adding an index on ({fk_name}) will optimize JOINs "
                    "and referential integrity checks."
                )
            else:
                recommendations.append(
                    f"Foreign key column '{fk_name}' lacks a supporting index with leading "
                    f"column '{fk_name}'. Adding an index on '{fk_name}' can improve JOIN "
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
    policy: AccessPolicy | None = None,
    audit_file: Path | str | None = None,
) -> dict[str, Any]:
    """Return table columns, indexes, foreign keys, and masking metadata."""
    effective_policy = policy or default_policy()
    started_total = time.perf_counter()

    if not isinstance(table_name, str) or not table_name.strip():
        err = _error("table_name must be a non-empty string.", "invalid_table_name")
        _record_audit_event(
            audit_file,
            "describe_database_table",
            "describe",
            status="error",
            error_code="invalid_table_name",
        )
        return err

    if not effective_policy.is_table_allowed(table_name):
        err = _error(f"Table '{table_name}' access is denied by policy.", "access_denied")
        _record_audit_event(
            audit_file,
            "describe_database_table",
            "describe",
            status="error",
            error_code="access_denied",
        )
        return err

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
            policy=effective_policy,
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
        cur_cols = connection.execute(f"PRAGMA table_xinfo({quoted_table})")
        try:
            raw_columns, columns_truncated = _fetch_bounded_rows(cur_cols, MAX_COLUMNS)
        finally:
            cur_cols.close()

        if not raw_columns:
            return _error(
                "The requested table or view does not exist.",
                "table_not_found",
            )

        columns = []
        pk_cols_list: list[tuple[int, str]] = []
        for row in raw_columns:
            col_name = str(row["name"])
            if not effective_policy.is_column_allowed(table_name, col_name):
                continue
            item = dict(row)
            is_sensitive = _is_sensitive_column(col_name) or effective_policy.is_column_sensitive(
                table_name, col_name
            )
            item["masked_by_guard"] = is_sensitive
            if is_sensitive:
                item["default_redacted"] = item.get("dflt_value") is not None
                item["dflt_value"] = None
            else:
                item["default_redacted"] = False
            pk_val = item.get("pk", 0)
            if pk_val > 0:
                pk_cols_list.append((pk_val, col_name))
            columns.append(item)

        pk_cols_sorted = tuple(x[1] for x in sorted(pk_cols_list, key=lambda x: x[0]))

        indexes = []
        cur_idx = connection.execute(f"PRAGMA index_list({quoted_table})")
        try:
            raw_indexes, indexes_truncated = _fetch_bounded_rows(cur_idx, MAX_INDEXES)
        finally:
            cur_idx.close()

        index_columns_truncated = False
        for index in raw_indexes:
            item = dict(index)
            quoted_index = _quote_identifier(str(item["name"]))
            cur_idx_cols = connection.execute(f"PRAGMA index_xinfo({quoted_index})")
            try:
                raw_idx_cols, idx_trunc = _fetch_bounded_rows(cur_idx_cols, MAX_INDEX_COLUMNS)
                if idx_trunc:
                    index_columns_truncated = True
                item["columns"] = [dict(r) for r in raw_idx_cols]
            finally:
                cur_idx_cols.close()
            indexes.append(item)

        cur_fk = connection.execute(f"PRAGMA foreign_key_list({quoted_table})")
        try:
            raw_fks, foreign_keys_truncated = _fetch_bounded_rows(cur_fk, MAX_FOREIGN_KEYS)
        finally:
            cur_fk.close()

        foreign_keys = [dict(row) for row in raw_fks]

        relationships = []
        for fk in foreign_keys:
            relationships.append(
                {
                    "from_column": fk.get("from"),
                    "target_table": fk.get("table"),
                    "target_column": fk.get("to"),
                    "on_update": fk.get("on_update"),
                    "on_delete": fk.get("on_delete"),
                }
            )

        index_intelligence = _analyze_indexes_for_table(
            columns,
            indexes,
            foreign_keys,
            pk_columns=pk_cols_sorted,
        )

        response_truncated = False
        payload: dict[str, Any] = {
            "ok": True,
            "table": table_name,
            "table_name": table_name,
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
            "response_truncated": response_truncated,
        }

        while payload["indexes"] and _serialized_size(payload) > MAX_RESULT_BYTES:
            payload["indexes"].pop()
            payload["indexes_truncated"] = True
            payload["truncated"] = True
            payload["response_truncated"] = True

        while payload["relationships"] and _serialized_size(payload) > MAX_RESULT_BYTES:
            payload["relationships"].pop()
            payload["truncated"] = True
            payload["response_truncated"] = True

        if _serialized_size(payload) > MAX_RESULT_BYTES:
            payload["relationships"] = []
            payload["indexes"] = payload["indexes"][:10]
            payload["response_truncated"] = True

        duration_ms = round((time.perf_counter() - started_total) * 1000, 2)
        _record_audit_event(
            audit_file,
            "describe_database_table",
            "describe",
            status="success",
            row_count=len(columns),
            response_bytes=_serialized_size(payload),
            duration_ms=duration_ms,
            truncated=payload.get("truncated", False),
        )
        return payload

    except sqlite3.Error:
        err = _error(
            "SQLite could not inspect this table's schema.",
            "schema_inspection_failed",
        )
        _record_audit_event(
            audit_file,
            "describe_database_table",
            "describe",
            status="error",
            error_code="schema_inspection_failed",
        )
        return err
    finally:
        connection.close()


def _analyze_query_plan(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Provide structured, evidence-based diagnostics for an EXPLAIN QUERY PLAN."""
    uses_index = False
    scans_table = False
    covering_index_detected = False
    automatic_index_detected = False
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
                elif (
                    "AUTOMATIC INDEX" in using_part.upper()
                    or "AUTOMATIC COVERING INDEX" in using_part.upper()
                ):
                    automatic_index_detected = True
        elif "USING INTEGER PRIMARY KEY" in detail_upper:
            uses_index = True

        if detail_upper.startswith("SCAN "):
            rest = detail[5:].strip()
            if rest.upper().startswith("TABLE "):
                rest = rest[6:].strip()
            parts = re.split(r"\s+USING\s+", rest, maxsplit=1, flags=re.IGNORECASE)
            table_part = (
                re.split(r"\s+AS\s+", parts[0], flags=re.IGNORECASE)[0].strip().strip('"[]`')
            )

            if len(parts) == 2:
                using_part = parts[1].strip()
                uses_index = True
                if using_part.upper().startswith("COVERING INDEX "):
                    covering_index_detected = True
                    idx_name = using_part[15:].split("(", 1)[0].strip().strip('"[]`')
                    if idx_name:
                        indexes_used.append(idx_name)
                elif using_part.upper().startswith("INDEX "):
                    idx_name = using_part[6:].split("(", 1)[0].strip().strip('"[]`')
                    if idx_name:
                        indexes_used.append(idx_name)
                elif (
                    "AUTOMATIC INDEX" in using_part.upper()
                    or "AUTOMATIC COVERING INDEX" in using_part.upper()
                ):
                    automatic_index_detected = True
            else:
                scans_table = True
                if (
                    table_part
                    and table_part not in scanned_tables
                    and not table_part.startswith("sqlite_")
                ):
                    scanned_tables.append(table_part)

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
    if automatic_index_detected:
        recommendations.append(
            "SQLite generated an ephemeral automatic index. Creating a permanent index will "
            "avoid recurring index construction overhead."
        )
    if not recommendations and uses_index:
        recommendations.append("Query is efficiently utilizing available indexes.")

    observations = {
        "full_scan_detected": scans_table,
        "index_search_detected": uses_index,
        "covering_index_detected": covering_index_detected,
        "temporary_sort_detected": temp_btree,
        "automatic_index_detected": automatic_index_detected,
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
    policy: AccessPolicy | None = None,
    audit_file: Path | str | None = None,
) -> dict[str, Any]:
    """Return SQLite's query plan and diagnostics for a SELECT or WITH query."""
    effective_policy = policy or default_policy()
    if not effective_policy.allow_explain_query:
        err = _error("Query explain plan is disabled by policy.", "access_denied")
        _record_audit_event(
            audit_file,
            "explain_read_query",
            "explain",
            sql=sql,
            status="error",
            error_code="access_denied",
        )
        return err

    try:
        statement = _validate_query(sql, explain=True)

    except ValueError as exc:
        err = _error(str(exc), "invalid_input")
        _record_audit_event(
            audit_file,
            "explain_read_query",
            "explain",
            sql=sql,
            status="error",
            error_code="invalid_input",
        )
        return err

    res = execute_guarded_query(
        db_path,
        statement,
        params,
        max_rows=max_rows,
        timeout_seconds=timeout_seconds,
        max_vm_steps=max_vm_steps,
        policy=policy,
        audit_file=audit_file,
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
    policy: AccessPolicy | None = None,
    audit_file: Path | str | None = None,
) -> dict[str, Any]:
    """Provide a single-connection bounded summary of all tables, views, and schemas."""
    effective_policy = policy or default_policy()
    started_total = time.perf_counter()

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
            policy=effective_policy,
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
        cur_count = connection.execute(
            "SELECT count(*) AS cnt FROM sqlite_schema "
            "WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'"
        )
        try:
            count_rows, _ = _fetch_bounded_rows(cur_count, 1)
            total_tables = int(count_rows[0]["cnt"]) if count_rows else 0
        finally:
            cur_count.close()

        cur_tables = connection.execute(
            "SELECT name, type FROM sqlite_schema "
            "WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name"
        )
        try:
            table_rows, tables_truncated = _fetch_bounded_rows(cur_tables, max_tables)
        finally:
            cur_tables.close()

        if total_tables > max_tables or tables_truncated:
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

            if not effective_policy.is_table_allowed(tbl_name):
                continue

            try:
                quoted = _quote_identifier(tbl_name)
                cur_cols = connection.execute(f"PRAGMA table_xinfo({quoted})")
                try:
                    raw_cols, col_trunc = _fetch_bounded_rows(cur_cols, max_columns_per_table)
                    if col_trunc:
                        columns_truncated = True
                        truncated = True
                finally:
                    cur_cols.close()
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

            columns = []
            for col in raw_cols:
                c_name = str(col["name"])
                if not effective_policy.is_column_allowed(tbl_name, c_name):
                    continue
                is_sens = _is_sensitive_column(c_name) or effective_policy.is_column_sensitive(
                    tbl_name, c_name
                )
                columns.append(
                    {
                        "name": c_name,
                        "type": col["type"],
                        "pk": bool(col["pk"]),
                        "masked": is_sens,
                        "default_redacted": is_sens and col["dflt_value"] is not None,
                    }
                )

            idx_list = []
            try:
                cur_idx = connection.execute(f"PRAGMA index_list({quoted})")
                try:
                    raw_idx, _ = _fetch_bounded_rows(cur_idx, 20)
                    idx_list = [dict(r)["name"] for r in raw_idx]
                finally:
                    cur_idx.close()
            except Exception as exc:
                warnings.append(
                    {
                        "code": "index_inspection_failed",
                        "object": tbl_name,
                        "message": (
                            f"Could not inspect indexes for '{tbl_name}': {type(exc).__name__}"
                        ),
                    }
                )

            fk_list = []
            try:
                cur_fk = connection.execute(f"PRAGMA foreign_key_list({quoted})")
                try:
                    raw_fk, _ = _fetch_bounded_rows(cur_fk, 20)
                    fk_list = [
                        {
                            "from": r["from"],
                            "table": r["table"],
                            "to": r["to"],
                        }
                        for r in raw_fk
                    ]
                finally:
                    cur_fk.close()
            except Exception as exc:
                warnings.append(
                    {
                        "code": "foreign_key_inspection_failed",
                        "object": tbl_name,
                        "message": (
                            f"Could not inspect foreign keys for '{tbl_name}': {type(exc).__name__}"
                        ),
                    }
                )

            tables_dict[tbl_name] = {
                "type": tbl_type,
                "columns": columns,
                "indexes": idx_list,
                "relationships": fk_list,
            }

        status = "partial" if (truncated or warnings) else "complete"

        payload = {
            "ok": True,
            "table_count": len(tables_dict),
            "tables": tables_dict,
            "status": status,
            "truncated": truncated,
            "tables_truncated": tables_truncated,
            "columns_truncated": columns_truncated,
            "time_truncated": time_truncated,
            "response_truncated": response_truncated,
            "warnings": warnings,
        }

        if tables_truncated:
            payload["warning"] = f"Table count was capped at {max_tables}."

        while tables_dict and _serialized_size(payload) > MAX_RESULT_BYTES:
            last_key = list(tables_dict.keys())[-1]
            del tables_dict[last_key]
            payload["table_count"] = len(tables_dict)
            payload["truncated"] = True
            payload["response_truncated"] = True
            payload["status"] = "partial"

        duration_ms = round((time.perf_counter() - started_total) * 1000, 2)
        _record_audit_event(
            audit_file,
            "schema://summary",
            "schema_summary",
            status="success",
            row_count=payload.get("table_count", 0),
            response_bytes=_serialized_size(payload),
            duration_ms=duration_ms,
            truncated=payload.get("truncated", False),
        )
        return payload

    finally:
        connection.close()


def get_database_overview(
    db_path: str | Path,
    *,
    policy: AccessPolicy | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
    audit_file: Path | str | None = None,
) -> dict[str, Any]:
    """Provide a compact, privacy-safe architectural overview of the SQLite database."""
    effective_policy = policy or default_policy()
    started_total = time.perf_counter()

    if not effective_policy.allow_database_overview:
        err = _error("Database overview is disabled by policy.", "access_denied")
        _record_audit_event(
            audit_file,
            "get_database_overview",
            "overview",
            status="error",
            error_code="access_denied",
        )
        return err

    try:
        connection = _open_connection(
            db_path,
            policy=effective_policy,
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
        cur = connection.cursor()

        cur.execute("PRAGMA schema_version")
        row = cur.fetchone()
        schema_version = int(row[0]) if row else 0

        cur.execute("PRAGMA page_size")
        row = cur.fetchone()
        page_size = int(row[0]) if row else 4096

        cur.execute("PRAGMA page_count")
        row = cur.fetchone()
        page_count = int(row[0]) if row else 0

        approximate_size_bytes = page_size * page_count

        cur.execute(
            "SELECT type, name FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'view', 'index', 'trigger')"
        )
        rows = cur.fetchall()

        table_count = 0
        view_count = 0
        index_count = 0
        trigger_count = 0

        for r in rows:
            obj_type = r["type"]
            name = r["name"]
            if obj_type == "table":
                if effective_policy.is_table_allowed(name):
                    table_count += 1
            elif obj_type == "view":
                if effective_policy.is_table_allowed(name):
                    view_count += 1
            elif obj_type == "index":
                index_count += 1
            elif obj_type == "trigger":
                trigger_count += 1

        elapsed_ms = round((time.perf_counter() - started_total) * 1000, 2)
        payload = {
            "ok": True,
            "sqlite_version": sqlite3.sqlite_version,
            "schema_version": schema_version,
            "page_size": page_size,
            "page_count": page_count,
            "approximate_size_bytes": approximate_size_bytes,
            "table_count": table_count,
            "view_count": view_count,
            "index_count": index_count,
            "trigger_count": trigger_count,
            "read_only": True,
            "elapsed_ms": elapsed_ms,
            "status": "complete",
        }
        _record_audit_event(
            audit_file,
            "get_database_overview",
            "overview",
            status="success",
            row_count=table_count + view_count,
            response_bytes=_serialized_size(payload),
            duration_ms=elapsed_ms,
        )
        return payload
    except Exception as exc:
        return _error(f"Database overview failed: {exc}", "overview_failed")
    finally:
        connection.close()


def search_database_schema(
    db_path: str | Path,
    query: str,
    *,
    max_results: int = MAX_SEARCH_RESULTS,
    policy: AccessPolicy | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
    audit_file: Path | str | None = None,
) -> dict[str, Any]:
    """Search database tables, views, columns, and indexes for matching keywords."""
    effective_policy = policy or default_policy()
    started_total = time.perf_counter()

    if not effective_policy.allow_schema_search:
        err = _error("Schema search is disabled by policy.", "access_denied")
        _record_audit_event(
            audit_file,
            "search_database_schema",
            "search",
            status="error",
            error_code="access_denied",
        )
        return err

    if not isinstance(query, str) or not query.strip():
        return _error("Search query must be a non-empty string.", "invalid_input")

    if len(query) > 256:
        return _error("Search query exceeds maximum length of 256.", "invalid_input")

    if (
        isinstance(max_results, bool)
        or not isinstance(max_results, int)
        or not 1 <= max_results <= 200
    ):
        return _error("max_results must be an integer between 1 and 200.", "invalid_input")

    try:
        connection = _open_connection(
            db_path,
            policy=effective_policy,
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

    target = query.strip().lower()
    matches: list[dict[str, Any]] = []
    truncated = False

    try:
        cur = connection.execute(
            "SELECT name, type FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'view', 'index') "
            "ORDER BY name"
        )
        schema_objects, _ = _fetch_bounded_rows(cur, 1000)
        cur.close()

        for obj in schema_objects:
            if len(matches) >= max_results:
                truncated = True
                break

            obj_name = obj["name"]
            obj_type = obj["type"]
            obj_lower = obj_name.lower()

            if obj_type in ("table", "view"):
                if not effective_policy.is_table_allowed(obj_name):
                    continue

                if target in obj_lower:
                    match_type = (
                        "exact"
                        if target == obj_lower
                        else ("prefix" if obj_lower.startswith(target) else "contains")
                    )
                    matches.append(
                        {
                            "object_type": obj_type,
                            "table_name": obj_name,
                            "name": obj_name,
                            "match_type": match_type,
                        }
                    )

                try:
                    cur_c = connection.execute(f"PRAGMA table_xinfo({_quote_identifier(obj_name)})")
                    raw_cols, _ = _fetch_bounded_rows(cur_c, MAX_COLUMNS)
                    cur_c.close()

                    for col in raw_cols:
                        if len(matches) >= max_results:
                            truncated = True
                            break
                        col_name = str(col["name"])
                        if not effective_policy.is_column_allowed(obj_name, col_name):
                            continue
                        col_lower = col_name.lower()
                        if target in col_lower:
                            match_type = (
                                "exact"
                                if target == col_lower
                                else ("prefix" if col_lower.startswith(target) else "contains")
                            )
                            matches.append(
                                {
                                    "object_type": "column",
                                    "table_name": obj_name,
                                    "name": col_name,
                                    "data_type": col["type"],
                                    "match_type": match_type,
                                }
                            )
                except Exception:
                    pass

            elif obj_type == "index":
                if target in obj_lower:
                    match_type = (
                        "exact"
                        if target == obj_lower
                        else ("prefix" if obj_lower.startswith(target) else "contains")
                    )
                    matches.append(
                        {
                            "object_type": "index",
                            "name": obj_name,
                            "match_type": match_type,
                        }
                    )

        elapsed_ms = round((time.perf_counter() - started_total) * 1000, 2)
        payload = {
            "ok": True,
            "query": query,
            "matches": matches,
            "match_count": len(matches),
            "truncated": truncated,
            "elapsed_ms": elapsed_ms,
        }

        while matches and _serialized_size(payload) > MAX_RESULT_BYTES:
            matches.pop()
            payload["match_count"] = len(matches)
            payload["truncated"] = True

        _record_audit_event(
            audit_file,
            "search_database_schema",
            "search",
            status="success",
            row_count=len(matches),
            response_bytes=_serialized_size(payload),
            duration_ms=elapsed_ms,
            truncated=truncated,
        )
        return payload
    finally:
        connection.close()


def check_database_health(
    db_path: str | Path,
    *,
    policy: AccessPolicy | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
    audit_file: Path | str | None = None,
) -> dict[str, Any]:
    """Execute safe read-only integrity, foreign key, and index health diagnostics."""
    effective_policy = policy or default_policy()
    started_total = time.perf_counter()

    if not effective_policy.allow_health_check:
        err = _error("Database health check is disabled by policy.", "access_denied")
        _record_audit_event(
            audit_file,
            "check_database_health",
            "health",
            status="error",
            error_code="access_denied",
        )
        return err

    try:
        connection = _open_connection(
            db_path,
            policy=effective_policy,
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

    checks: dict[str, Any] = {}
    recommendations: list[str] = []
    has_issues = False
    has_warnings = False

    try:
        cur_q = connection.execute("PRAGMA quick_check(10)")
        try:
            q_rows, _ = _fetch_bounded_rows(cur_q, 10)
            q_res = [r[0] for r in q_rows]
            if q_res == ["ok"]:
                checks["quick_check"] = {"status": "passed"}
            else:
                checks["quick_check"] = {"status": "failed", "details": q_res}
                has_issues = True
                recommendations.append("Database quick_check failed; verify disk or backup.")
        finally:
            cur_q.close()

        cur_fk = connection.execute("PRAGMA foreign_key_check")
        try:
            fk_rows, fk_trunc = _fetch_bounded_rows(cur_fk, 20)
            if not fk_rows:
                checks["foreign_key_check"] = {"status": "passed"}
            else:
                violations = [
                    {
                        "table": r[0],
                        "rowid": r[1],
                        "target_table": r[2],
                        "fkid": r[3],
                    }
                    for r in fk_rows
                ]
                checks["foreign_key_check"] = {
                    "status": "violations_found",
                    "violations": violations,
                    "truncated": fk_trunc,
                }
                has_issues = True
                recommendations.append(
                    f"Found {len(violations)} foreign key constraint violations."
                )
        finally:
            cur_fk.close()

        cur_tbl = connection.execute(
            "SELECT name FROM sqlite_schema "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
        try:
            tbl_rows, _ = _fetch_bounded_rows(cur_tbl, 50)
            table_names = [
                r["name"] for r in tbl_rows if effective_policy.is_table_allowed(r["name"])
            ]
        finally:
            cur_tbl.close()

        unindexed_fks_all = []
        duplicate_indexes_all = []

        for tbl in table_names:
            try:
                desc = describe_table(
                    db_path,
                    tbl,
                    policy=effective_policy,
                    timeout_seconds=timeout_seconds,
                    max_vm_steps=max_vm_steps,
                )
                if desc.get("ok"):
                    intel = desc.get("index_intelligence", {})
                    for ufk in intel.get("unindexed_foreign_keys", []):
                        unindexed_fks_all.append(f"{tbl}.{ufk}")
                    for rec in intel.get("recommendations", []):
                        if "Duplicate indexes" in rec or "is a prefix of" in rec:
                            duplicate_indexes_all.append(rec)
            except Exception:
                pass

        if unindexed_fks_all:
            has_warnings = True
            recommendations.append(
                f"Unindexed foreign keys found: {', '.join(unindexed_fks_all[:5])}."
            )
        if duplicate_indexes_all:
            has_warnings = True
            recommendations.extend(duplicate_indexes_all[:3])

        checks["index_health"] = {
            "unindexed_foreign_keys": unindexed_fks_all,
            "index_redundancies": duplicate_indexes_all,
        }

        overall_status = "healthy"
        if has_issues:
            overall_status = "issues_detected"
        elif has_warnings:
            overall_status = "warnings_detected"

        elapsed_ms = round((time.perf_counter() - started_total) * 1000, 2)
        payload = {
            "ok": True,
            "overall_status": overall_status,
            "checks": checks,
            "recommendations": list(dict.fromkeys(recommendations)),
            "elapsed_ms": elapsed_ms,
        }

        _record_audit_event(
            audit_file,
            "check_database_health",
            "health",
            status="success",
            duration_ms=elapsed_ms,
        )
        return payload
    finally:
        connection.close()


class BearerAuthMiddleware:
    """ASGI middleware enforcing Bearer token authentication."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self.token = token

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            auth_val = headers.get(b"authorization", b"").decode("latin-1", errors="replace")
            scheme, _, received_token = auth_val.partition(" ")
            if scheme.lower() != "bearer" or not hmac.compare_digest(
                received_token.strip(), self.token.strip()
            ):
                response_body = b'{"error":"Unauthorized: invalid or missing Bearer token."}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(response_body)).encode("ascii")),
                            (b"www-authenticate", b'Bearer realm="sqlite-guard-mcp"'),
                        ],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": response_body,
                    }
                )
                return
        await self.app(scope, receive, send)


def create_server(
    db_path: str | Path,
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_vm_steps: int = DEFAULT_MAX_VM_STEPS,
    policy: AccessPolicy | None = None,
    audit_file: Path | str | None = None,
    auth_token: str | None = None,
) -> Any:
    """Create the official MCP SDK server with SQLite Guard tools and schema resources."""
    from mcp.server.mcpserver import MCPServer

    database = Path(db_path).expanduser()
    effective_policy = policy or default_policy()

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
    server.auth_token = auth_token  # type: ignore[attr-defined]

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
            policy=effective_policy,
            audit_file=audit_file,
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
            policy=effective_policy,
            audit_file=audit_file,
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
            policy=effective_policy,
            audit_file=audit_file,
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
            policy=effective_policy,
            audit_file=audit_file,
        )
        return json.dumps(result, ensure_ascii=False)

    _db_overview = globals()["get_database_overview"]
    _schema_search = globals()["search_database_schema"]
    _health_check = globals()["check_database_health"]

    @server.tool()
    def get_database_overview() -> str:
        """Get a safe overview of database metrics (table count, size, schema version)."""
        result = _db_overview(
            database,
            policy=effective_policy,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
            audit_file=audit_file,
        )
        return json.dumps(result, ensure_ascii=False)

    @server.tool()
    def search_database_schema(
        query: Annotated[
            str,
            Field(
                description="Case-insensitive search term for tables, views, columns, or indexes."
            ),
        ],
        max_results: Annotated[
            int,
            Field(
                default=MAX_SEARCH_RESULTS,
                description="Maximum number of search matches to return (1-200).",
            ),
        ] = MAX_SEARCH_RESULTS,
    ) -> str:
        """Search database schema objects (tables, views, columns, indexes) by keyword."""
        result = _schema_search(
            database,
            query,
            max_results=max_results,
            policy=effective_policy,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
            audit_file=audit_file,
        )
        return json.dumps(result, ensure_ascii=False)

    @server.tool()
    def check_database_health() -> str:
        """Run read-only database health checks (quick_check, foreign keys, index health)."""
        result = _health_check(
            database,
            policy=effective_policy,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
            audit_file=audit_file,
        )
        return json.dumps(result, ensure_ascii=False)

    @server.resource("schema://summary")
    def database_schema_summary() -> str:
        """Provide a summary of all user-created tables, views, and column definitions."""
        result = inspect_schema_summary(
            database,
            timeout_seconds=timeout_seconds,
            max_vm_steps=max_vm_steps,
            policy=effective_policy,
            audit_file=audit_file,
        )
        return json.dumps(result, ensure_ascii=False)

    @server.tool()
    def simulate_candidate_index(
        sql: Annotated[
            str,
            Field(description="Read-only SELECT or WITH SQL query to optimize."),
        ],
        candidate_indexes: Annotated[
            list[str] | str,
            Field(
                description=(
                    "One or more 'CREATE [UNIQUE] INDEX ... ON table(...)' candidate statements."
                )
            ),
        ],
        params: Annotated[
            dict[str, Any] | list[Any] | None,
            Field(
                default=None,
                description="Optional parameters for the query.",
            ),
        ] = None,
    ) -> str:
        """Simulate candidate index performance on an isolated disposable database snapshot."""
        from sqlite_guard_mcp.index_lab import simulate_index

        result = simulate_index(
            database,
            sql,
            candidate_indexes,
            params,
            timeout_seconds=timeout_seconds,
            policy=effective_policy,
            audit_file=audit_file,
        )
        return json.dumps(result, ensure_ascii=False)

    @server.tool()
    def profile_database_table(
        table_name: Annotated[
            str,
            Field(description="Name of the table or view to profile."),
        ],
        max_sample_rows: Annotated[
            int,
            Field(
                default=1000,
                description="Maximum rows to sample for distinct count and cardinality.",
            ),
        ] = 1000,
    ) -> str:
        """Generate privacy-preserving statistical profiles (null %, cardinality, safe min/max)."""
        from sqlite_guard_mcp.profiler import profile_table

        result = profile_table(
            database,
            table_name,
            max_sample_rows=max_sample_rows,
            policy=effective_policy,
            audit_file=audit_file,
            timeout_seconds=timeout_seconds,
        )
        return json.dumps(result, ensure_ascii=False)

    @server.tool()
    def diff_database_schemas(
        target_db_path: Annotated[
            str,
            Field(description="File path of the second SQLite database to compare against."),
        ],
    ) -> str:
        """Compare the current database schema against another SQLite database to detect diffs."""
        from sqlite_guard_mcp.schema_diff import diff_schemas, snapshot_schema

        snap_a = snapshot_schema(database, policy=effective_policy, timeout_seconds=timeout_seconds)
        snap_b = snapshot_schema(
            target_db_path, policy=effective_policy, timeout_seconds=timeout_seconds
        )
        result = diff_schemas(snap_a, snap_b)
        return json.dumps(result, ensure_ascii=False)

    @server.tool()
    def review_migration_script(
        migration_sql: Annotated[
            str,
            Field(description="SQLite migration SQL script to analyze for safety and risk."),
        ],
    ) -> str:
        """Statically inspect a SQLite migration script for safety, table drops, and locks."""
        from sqlite_guard_mcp.schema_diff import review_migration

        result = review_migration(migration_sql)
        return json.dumps(result, ensure_ascii=False)

    @server.resource("schema://snapshot")
    def database_schema_snapshot() -> str:
        """Provide a complete canonical JSON snapshot of all tables, columns, indexes, and FKs."""
        from sqlite_guard_mcp.schema_diff import snapshot_schema

        result = snapshot_schema(
            database,
            policy=effective_policy,
            timeout_seconds=timeout_seconds,
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
        "--policy",
        default=os.environ.get("SQLITE_GUARD_POLICY"),
        help="Path to a TOML access policy configuration file.",
    )
    parser.add_argument(
        "--audit-log",
        default=os.environ.get("SQLITE_GUARD_AUDIT_LOG"),
        help="Path to append audit events (JSON Lines format).",
    )
    parser.add_argument(
        "--auth-token",
        default=os.environ.get("SQLITE_GUARD_AUTH_TOKEN"),
        help="Bearer authentication token for HTTP/SSE transports.",
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
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Run environment, SQLite, and database health diagnostics.",
    )
    parser.add_argument(
        "--validate-policy",
        action="store_true",
        help="Validate the policy file specified in --policy and exit.",
    )
    parser.add_argument(
        "--explain-policy-table",
        help="Table name to explain policy access for.",
    )
    parser.add_argument(
        "--explain-policy-column",
        help="Column name to explain policy access for (optional).",
    )

    args = parser.parse_args(argv)

    if args.doctor:
        from sqlite_guard_mcp.doctor import format_doctor_report, run_doctor

        diag = run_doctor(db_path=args.db, policy_path=args.policy)
        print(format_doctor_report(diag))
        return 0 if diag["status"] != "ERROR" else 1

    if args.validate_policy:
        if not args.policy:
            parser.error("--validate-policy requires --policy <file>.")
        try:
            load_policy(args.policy)
            print(f"Policy configuration '{args.policy}' is valid.")
            return 0
        except ValueError as exc:
            print(f"Policy configuration error: {exc}", file=sys.stderr)
            return 1

    if args.explain_policy_table:
        try:
            pol = load_policy(args.policy) if args.policy else default_policy()
            explanation = pol.explain_access(args.explain_policy_table, args.explain_policy_column)
            print(json.dumps(explanation, indent=2))
            return 0
        except ValueError as exc:
            print(f"Policy error: {exc}", file=sys.stderr)
            return 1

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

    policy = None
    if args.policy:
        try:
            policy = load_policy(args.policy)
        except ValueError as exc:
            parser.error(f"Policy configuration error: {exc}")

    server = create_server(
        database,
        max_rows=args.max_rows,
        timeout_seconds=args.timeout,
        max_vm_steps=args.max_vm_steps,
        policy=policy,
        audit_file=args.audit_log,
        auth_token=args.auth_token,
    )
    try:
        if args.transport == "stdio":
            server.run(transport="stdio")
        elif args.transport == "streamable-http":
            if args.auth_token:
                import uvicorn

                app = server.streamable_http_app(streamable_http_path="/mcp")
                wrapped = BearerAuthMiddleware(app, args.auth_token)
                uvicorn.run(wrapped, host=args.host, port=args.port)
            else:
                server.run(
                    transport="streamable-http",
                    host=args.host,
                    port=args.port,
                )
        elif args.transport == "sse":
            if args.auth_token:
                import uvicorn

                app = server.sse_app(sse_path="/sse", message_path="/messages")
                wrapped = BearerAuthMiddleware(app, args.auth_token)
                uvicorn.run(wrapped, host=args.host, port=args.port)
            else:
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
