"""Index Laboratory for SQLite Guard MCP.

Provides safe, isolated candidate index testing using disposable snapshots
via SQLite's backup API, comparing query plans and execution timing before
and after applying index proposals without ever touching the source database.
"""

from __future__ import annotations

import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from sqlite_guard_mcp.policy import AccessPolicy, default_policy
from sqlite_guard_mcp.server import (
    DEFAULT_MAX_ROWS,
    DEFAULT_TIMEOUT_SECONDS,
    _analyze_query_plan,
    _error,
    _record_audit_event,
    _validate_params,
    _validate_query,
)

_CREATE_INDEX_PATTERN = re.compile(
    r"^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"([A-Za-z0-9_\"`\[\]]+)\s+ON\s+([A-Za-z0-9_\"`\[\]]+)\s*\((.*?)\)\s*;?\s*$",
    re.IGNORECASE | re.DOTALL,
)


def _strip_quotes(name: str) -> str:
    """Strip quoting identifiers from table or index name."""
    s = name.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("`") and s.endswith("`")):
        return s[1:-1]
    if s.startswith("[") and s.endswith("]"):
        return s[1:-1]
    return s


def validate_candidate_index(index_sql: str) -> tuple[str, str, list[str]]:
    """Validate a candidate CREATE INDEX statement.

    Returns (index_name, table_name, columns_list) or raises ValueError.
    """
    match = _CREATE_INDEX_PATTERN.match(index_sql.strip())
    if not match:
        raise ValueError(
            "Candidate index statement must be a valid "
            "'CREATE [UNIQUE] INDEX ... ON table(col1, ...)' statement."
        )

    raw_index, raw_table, raw_cols = match.groups()
    index_name = _strip_quotes(raw_index)
    table_name = _strip_quotes(raw_table)

    cols = [_strip_quotes(c.strip().split()[0]) for c in raw_cols.split(",") if c.strip()]
    if not cols:
        raise ValueError("Candidate index must specify at least one target column.")

    return index_name, table_name, cols


def simulate_index(
    db_path: str | Path,
    sql: str,
    candidate_indexes: list[str] | str,
    params: dict[str, Any] | list[Any] | tuple[Any, ...] | None = None,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_sample_runs: int = 3,
    policy: AccessPolicy | None = None,
    audit_file: Path | str | None = None,
) -> dict[str, Any]:
    """Simulate query execution with candidate indexes on an isolated disposable database.

    Guarantees zero mutation to the source database by using an in-memory clone
    created through SQLite's online backup API.
    """
    effective_policy = policy or default_policy()

    if not effective_policy.allow_index_lab:
        err = _error("Index laboratory is disabled by policy.", "access_denied")
        _record_audit_event(
            audit_file,
            "simulate_index",
            "index_lab",
            sql=sql,
            status="error",
            error_code="access_denied",
        )
        return err

    # Normalize candidate index list
    if isinstance(candidate_indexes, str):
        candidates = [candidate_indexes]
    elif isinstance(candidate_indexes, list):
        candidates = candidate_indexes
    else:
        return _error("candidate_indexes must be a string or list of strings.", "invalid_input")

    if not candidates:
        return _error("At least one candidate index statement must be provided.", "invalid_input")

    # Validate query
    try:
        valid_sql = _validate_query(sql, explain=False)
        valid_params = _validate_params(params)
    except ValueError as exc:
        err = _error(str(exc), "invalid_input")
        _record_audit_event(
            audit_file,
            "simulate_index",
            "index_lab",
            sql=sql,
            status="error",
            error_code="invalid_input",
        )
        return err

    # Validate candidate indexes against policy
    validated_candidates = []
    for c_sql in candidates:
        try:
            idx_name, tbl_name, cols = validate_candidate_index(c_sql)
        except ValueError as exc:
            return _error(f"Invalid candidate index: {exc}", "invalid_input")

        if not effective_policy.is_table_allowed(tbl_name):
            err = _error(
                f"Candidate index references denied table '{tbl_name}'.",
                "access_denied",
            )
            _record_audit_event(
                audit_file,
                "simulate_index",
                "index_lab",
                sql=c_sql,
                status="error",
                error_code="access_denied",
            )
            return err

        for col in cols:
            if not effective_policy.is_column_allowed(tbl_name, col):
                err = _error(
                    f"Candidate index references denied column '{tbl_name}.{col}'.",
                    "access_denied",
                )
                _record_audit_event(
                    audit_file,
                    "simulate_index",
                    "index_lab",
                    sql=c_sql,
                    status="error",
                    error_code="access_denied",
                )
                return err

        validated_candidates.append(c_sql)

    db_file = Path(db_path)
    if not db_file.exists() or not db_file.is_file():
        return _error(f"Database file does not exist: {db_file.name}", "database_not_found")

    # Connect to source in read-only mode and clone into memory
    source_uri = f"file:{db_file.resolve().as_posix()}?mode=ro"
    try:
        source_conn = sqlite3.connect(source_uri, uri=True, timeout=timeout_seconds)
    except sqlite3.Error as exc:
        return _error(f"Failed to open source database in read-only mode: {exc}", "database_error")

    dest_conn = sqlite3.connect(":memory:")
    try:
        source_conn.backup(dest_conn)
    except sqlite3.Error as exc:
        dest_conn.close()
        source_conn.close()
        return _error(
            f"Failed to clone database into isolated memory copy: {exc}", "database_error"
        )
    finally:
        source_conn.close()

    dest_conn.row_factory = sqlite3.Row

    try:
        # 1. Baseline analysis
        explain_sql = f"EXPLAIN QUERY PLAN {valid_sql}"
        cursor = dest_conn.cursor()
        cursor.execute(explain_sql, valid_params)
        baseline_plan_rows = [dict(row) for row in cursor.fetchall()]
        baseline_analysis = _analyze_query_plan(baseline_plan_rows)

        # Measure baseline execution time
        baseline_times = []
        for _ in range(max_sample_runs):
            t0 = time.perf_counter()
            cursor.execute(valid_sql, valid_params)
            cursor.fetchmany(DEFAULT_MAX_ROWS)
            baseline_times.append(time.perf_counter() - t0)
        baseline_time_ms = (sorted(baseline_times)[len(baseline_times) // 2]) * 1000.0

        # 2. Apply candidate indexes in the disposable in-memory database
        applied_indexes = []
        for c_sql in validated_candidates:
            dest_conn.execute(c_sql)
            applied_indexes.append(c_sql)

        # 3. Candidate analysis
        cursor.execute(explain_sql, valid_params)
        candidate_plan_rows = [dict(row) for row in cursor.fetchall()]
        candidate_analysis = _analyze_query_plan(candidate_plan_rows)

        # Measure candidate execution time
        candidate_times = []
        for _ in range(max_sample_runs):
            t0 = time.perf_counter()
            cursor.execute(valid_sql, valid_params)
            cursor.fetchmany(DEFAULT_MAX_ROWS)
            candidate_times.append(time.perf_counter() - t0)
        candidate_time_ms = (sorted(candidate_times)[len(candidate_times) // 2]) * 1000.0

        # 4. Comparison synthesis
        baseline_scans = set(baseline_analysis.get("scans", []))
        candidate_scans = set(candidate_analysis.get("scans", []))
        scan_eliminated = bool(baseline_scans and not candidate_scans)
        scans_reduced = len(candidate_scans) < len(baseline_scans)

        candidate_searches = set(candidate_analysis.get("searches", []))
        plan_improved = (
            scan_eliminated
            or scans_reduced
            or (len(candidate_searches) > len(baseline_analysis.get("searches", [])))
        )

        timing_delta_ms = candidate_time_ms - baseline_time_ms
        if candidate_time_ms > 0:
            speedup_factor = baseline_time_ms / candidate_time_ms
        else:
            speedup_factor = 1.0

        recommendations = []
        if scan_eliminated:
            scans_str = ", ".join(sorted(baseline_scans))
            recommendations.append(
                f"Candidate index successfully eliminated full table scans on: {scans_str}."
            )
        elif scans_reduced:
            eliminated = sorted(baseline_scans - candidate_scans)
            recommendations.append(
                f"Candidate index eliminated full table scans on: {', '.join(eliminated)}."
            )

        if speedup_factor > 1.2:
            speedup_fmt = round(speedup_factor, 1)
            delta_fmt = round(timing_delta_ms, 3)
            recommendations.append(
                f"Execution latency improved by ~{speedup_fmt}x (median delta {delta_fmt} ms)."
            )
        elif timing_delta_ms > 0.5:
            recommendations.append(
                "Query latency did not improve measurably; "
                "index overhead may exceed scan benefit for this dataset size."
            )

        if not plan_improved:
            recommendations.append(
                "SQLite's query planner did not utilize the candidate index. "
                "Check column ordering or WHERE clause selectivity."
            )

        _record_audit_event(
            audit_file,
            "simulate_index",
            "index_lab",
            sql=sql,
            status="success",
        )

        return {
            "success": True,
            "source_database_unmodified": True,
            "query": sql,
            "candidate_indexes": applied_indexes,
            "baseline": {
                "plan": baseline_plan_rows,
                "analysis": baseline_analysis,
                "execution_time_ms": round(baseline_time_ms, 4),
            },
            "candidate": {
                "plan": candidate_plan_rows,
                "analysis": candidate_analysis,
                "execution_time_ms": round(candidate_time_ms, 4),
            },
            "comparison": {
                "plan_improved": plan_improved,
                "scan_eliminated": scan_eliminated,
                "timing_delta_ms": round(timing_delta_ms, 4),
                "speedup_factor": round(speedup_factor, 2),
            },
            "recommendations": recommendations,
        }

    except sqlite3.Error as exc:
        return _error(f"SQLite error during index simulation: {exc}", "execution_error")
    finally:
        dest_conn.close()
