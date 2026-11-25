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


def _synthesize_plan_comparison(
    baseline_plan_rows: list[dict[str, Any]],
    candidate_plan_rows: list[dict[str, Any]],
    baseline_analysis: dict[str, Any],
    candidate_analysis: dict[str, Any],
    candidate_index_names: list[str],
    baseline_time_ms: float,
    candidate_time_ms: float,
) -> tuple[dict[str, Any], list[str]]:
    """Compare baseline and candidate query plans using _analyze_query_plan() fields."""
    baseline_scanned_list = [str(t) for t in baseline_analysis.get("scanned_tables", [])]
    candidate_scanned_list = [str(t) for t in candidate_analysis.get("scanned_tables", [])]
    baseline_scans_table = bool(baseline_analysis.get("scans_table", bool(baseline_scanned_list)))
    candidate_scans_table = bool(
        candidate_analysis.get("scans_table", bool(candidate_scanned_list))
    )

    baseline_scanned_map = {t.lower(): t for t in baseline_scanned_list}
    candidate_scanned_map = {t.lower(): t for t in candidate_scanned_list}

    eliminated_scans = sorted(
        t for k, t in baseline_scanned_map.items() if k not in candidate_scanned_map
    )
    introduced_scans = sorted(
        t for k, t in candidate_scanned_map.items() if k not in baseline_scanned_map
    )
    remaining_scans = sorted(
        t for k, t in candidate_scanned_map.items() if k in baseline_scanned_map
    )

    scan_regression = bool(introduced_scans)
    scan_eliminated = bool(
        (baseline_scans_table or baseline_scanned_map)
        and not candidate_scans_table
        and not candidate_scanned_map
        and not scan_regression
    )
    scans_reduced = bool(
        eliminated_scans
        and not scan_regression
        and len(candidate_scanned_map) < len(baseline_scanned_map)
    )

    baseline_indexes_used = [str(i) for i in baseline_analysis.get("indexes_used", [])]
    candidate_indexes_used = [str(i) for i in candidate_analysis.get("indexes_used", [])]
    baseline_uses_index = bool(baseline_analysis.get("uses_index", bool(baseline_indexes_used)))
    candidate_uses_index = bool(candidate_analysis.get("uses_index", bool(candidate_indexes_used)))

    unique_candidate_names: list[str] = []
    seen_candidate_lower: set[str] = set()
    for name in candidate_index_names:
        key = name.lower()
        if key not in seen_candidate_lower:
            seen_candidate_lower.add(key)
            unique_candidate_names.append(name)

    selected_candidate_indexes = [
        idx for idx in candidate_indexes_used if idx.lower() in seen_candidate_lower
    ]
    selected_lower = {idx.lower() for idx in selected_candidate_indexes}
    unselected_candidate_indexes = [
        name for name in unique_candidate_names if name.lower() not in selected_lower
    ]
    existing_indexes_used = [
        idx for idx in candidate_indexes_used if idx.lower() not in selected_lower
    ]

    baseline_details = [str(r.get("detail", "")).strip() for r in baseline_plan_rows]
    candidate_details = [str(r.get("detail", "")).strip() for r in candidate_plan_rows]
    plan_changed = baseline_details != candidate_details

    baseline_obs = baseline_analysis.get("observations", {})
    candidate_obs = candidate_analysis.get("observations", {})

    baseline_temp_btree = bool(baseline_analysis.get("uses_temp_btree", False))
    candidate_temp_btree = bool(candidate_analysis.get("uses_temp_btree", False))
    temp_btree_eliminated = baseline_temp_btree and not candidate_temp_btree
    temp_btree_introduced = (not baseline_temp_btree) and candidate_temp_btree

    baseline_auto = bool(baseline_obs.get("automatic_index_detected", False))
    candidate_auto = bool(candidate_obs.get("automatic_index_detected", False))
    auto_index_eliminated = (
        baseline_auto and not candidate_auto and bool(selected_candidate_indexes)
    )

    baseline_covering = bool(baseline_obs.get("covering_index_detected", False))
    candidate_covering = bool(candidate_obs.get("covering_index_detected", False))
    covering_index_gained = (
        (not baseline_covering) and candidate_covering and bool(selected_candidate_indexes)
    )

    baseline_index_scan_only = (not baseline_scans_table) and any(
        d.upper().startswith("SCAN ") for d in baseline_details
    )
    candidate_has_search = any(d.upper().startswith("SEARCH ") for d in candidate_details)
    index_scan_upgraded = (
        baseline_index_scan_only and candidate_has_search and bool(selected_candidate_indexes)
    )

    plan_improved = bool(
        not scan_regression
        and (
            scan_eliminated
            or scans_reduced
            or (
                not temp_btree_introduced
                and (
                    temp_btree_eliminated
                    or auto_index_eliminated
                    or covering_index_gained
                    or index_scan_upgraded
                    or (
                        bool(selected_candidate_indexes)
                        and not baseline_uses_index
                        and candidate_uses_index
                    )
                )
            )
        )
    )

    if scan_regression:
        outcome = "scan_regression_detected"
    elif scan_eliminated:
        outcome = "scan_eliminated"
    elif plan_improved and selected_candidate_indexes:
        outcome = "candidate_index_selected"
    elif not plan_changed and existing_indexes_used and not selected_candidate_indexes:
        outcome = "existing_index_used"
    elif not plan_changed and not selected_candidate_indexes:
        outcome = "query_plan_unchanged"
    elif plan_changed and not plan_improved:
        outcome = "plan_changed_without_improvement"
    else:
        outcome = "candidate_index_not_selected"

    timing_delta_ms = candidate_time_ms - baseline_time_ms
    speedup_factor = baseline_time_ms / candidate_time_ms if candidate_time_ms > 0 else 1.0

    recommendations: list[str] = []
    if scan_regression:
        if eliminated_scans:
            recommendations.append(
                f"Candidate plan eliminated full table scan(s) on {', '.join(eliminated_scans)}, "
                f"but introduced new full table scan(s) on: {', '.join(introduced_scans)}."
            )
        else:
            recommendations.append(
                f"Candidate plan introduced new full table scan(s) on: "
                f"{', '.join(introduced_scans)}."
            )
        if selected_candidate_indexes:
            recommendations.append(
                f"Selected candidate index(es): {', '.join(selected_candidate_indexes)}."
            )
    elif scan_eliminated:
        scans_str = ", ".join(eliminated_scans) if eliminated_scans else "target table(s)"
        if selected_candidate_indexes:
            recommendations.append(
                f"SQLite selected candidate index(es) {', '.join(selected_candidate_indexes)} "
                f"and eliminated full table scan(s) on: {scans_str}."
            )
        else:
            recommendations.append(f"Candidate plan eliminated full table scan(s) on: {scans_str}.")
    elif scans_reduced:
        msg = (
            f"SQLite eliminated full table scan(s) on: {', '.join(eliminated_scans)}; "
            f"remaining full table scan(s) on: {', '.join(remaining_scans)}."
        )
        if selected_candidate_indexes:
            msg += f" Selected candidate index(es): {', '.join(selected_candidate_indexes)}."
        recommendations.append(msg)
    elif plan_improved:
        improvements: list[str] = []
        if temp_btree_eliminated:
            improvements.append("eliminated temporary B-tree sorting/grouping")
        if auto_index_eliminated:
            improvements.append("replaced an ephemeral automatic index")
        if covering_index_gained:
            improvements.append("enabled a covering index lookup")
        if index_scan_upgraded:
            improvements.append("upgraded a full index scan to an index search")
        if not improvements:
            improvements.append("enabled indexed access")
        recommendations.append(
            f"SQLite selected candidate index(es) {', '.join(selected_candidate_indexes)} "
            f"and {' and '.join(improvements)}."
        )
    elif existing_indexes_used and not selected_candidate_indexes:
        msg = (
            f"SQLite used existing index(es) ({', '.join(existing_indexes_used)}) "
            f"instead of proposed candidate index(es) ({', '.join(unselected_candidate_indexes)})."
        )
        if not plan_changed:
            msg += " Query plan remained unchanged."
        recommendations.append(msg)
    elif not plan_changed:
        recommendations.append(
            "Query plan remained unchanged; SQLite's query planner did not select "
            f"candidate index(es): {', '.join(unselected_candidate_indexes)}. "
            "Check column ordering or WHERE clause selectivity."
        )
    else:
        if selected_candidate_indexes:
            recommendations.append(
                f"Query plan changed and selected candidate index(es) "
                f"({', '.join(selected_candidate_indexes)}), but without sufficient structural "
                "evidence of improvement over the baseline plan."
            )
        else:
            recommendations.append(
                "Query plan changed without selecting proposed candidate index(es) and without "
                "sufficient evidence of improvement."
            )

    if selected_candidate_indexes and unselected_candidate_indexes:
        recommendations.append(
            f"Unused candidate index(es) not selected by SQLite: "
            f"{', '.join(unselected_candidate_indexes)}."
        )

    if speedup_factor > 1.2 and baseline_time_ms > 0:
        speedup_fmt = round(speedup_factor, 1)
        delta_fmt = round(timing_delta_ms, 3)
        recommendations.append(
            f"Observed execution latency improved by ~{speedup_fmt}x (median delta {delta_fmt} ms)."
        )
    elif timing_delta_ms > 0.5:
        recommendations.append(
            "Observed query latency did not improve measurably; "
            "index overhead may exceed scan benefit for this dataset size."
        )

    comparison = {
        "plan_improved": plan_improved,
        "scan_eliminated": scan_eliminated,
        "scans_reduced": scans_reduced,
        "scan_regression": scan_regression,
        "eliminated_scans": eliminated_scans,
        "introduced_scans": introduced_scans,
        "remaining_scans": remaining_scans,
        "candidate_indexes_selected": selected_candidate_indexes,
        "candidate_indexes_not_selected": unselected_candidate_indexes,
        "existing_indexes_used": existing_indexes_used,
        "plan_changed": plan_changed,
        "temp_btree_eliminated": temp_btree_eliminated,
        "covering_index_gained": covering_index_gained,
        "outcome": outcome,
        "timing_delta_ms": round(timing_delta_ms, 4),
        "speedup_factor": round(speedup_factor, 2),
    }
    return comparison, recommendations


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
    candidate_index_names = []
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
        candidate_index_names.append(idx_name)

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
        comparison, recommendations = _synthesize_plan_comparison(
            baseline_plan_rows=baseline_plan_rows,
            candidate_plan_rows=candidate_plan_rows,
            baseline_analysis=baseline_analysis,
            candidate_analysis=candidate_analysis,
            candidate_index_names=candidate_index_names,
            baseline_time_ms=baseline_time_ms,
            candidate_time_ms=candidate_time_ms,
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
            "comparison": comparison,
            "recommendations": recommendations,
        }

    except sqlite3.Error as exc:
        return _error(f"SQLite error during index simulation: {exc}", "execution_error")
    finally:
        dest_conn.close()
