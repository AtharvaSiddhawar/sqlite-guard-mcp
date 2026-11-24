"""Privacy-Preserving Data Profiling for SQLite Guard MCP.

Provides safe statistical summaries, null ratios, cardinality estimations,
and schema health diagnostics without ever leaking sensitive values or
violating column-level security policies.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from sqlite_guard_mcp.policy import AccessPolicy, default_policy
from sqlite_guard_mcp.server import (
    DEFAULT_TIMEOUT_SECONDS,
    _error,
    _is_sensitive_column,
    _quote_identifier,
    _record_audit_event,
)

_NUMERIC_TYPES = {"integer", "int", "real", "float", "double", "numeric", "decimal"}
_DATE_TYPES = {"date", "datetime", "timestamp"}


def _safe_serialize_value(val: Any) -> Any:
    """Ensure a scalar value is JSON serializable."""
    if val is None:
        return None
    if isinstance(val, (int, float, bool)):
        return val
    if isinstance(val, bytes):
        return f"<BLOB {len(val)} bytes>"
    return str(val)[:100]


def profile_table(
    db_path: str | Path,
    table_name: str,
    *,
    max_sample_rows: int = 1000,
    policy: AccessPolicy | None = None,
    audit_file: Path | str | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Generate a privacy-preserving statistical profile of a database table."""
    effective_policy = policy or default_policy()

    if not effective_policy.allow_profiling:
        err = _error("Data profiling is disabled by policy.", "access_denied")
        _record_audit_event(
            audit_file,
            "profile_table",
            "profiler",
            status="error",
            error_code="access_denied",
        )
        return err

    if not effective_policy.is_table_allowed(table_name):
        err = _error(f"Access to table '{table_name}' is denied by policy.", "access_denied")
        _record_audit_event(
            audit_file,
            "profile_table",
            "profiler",
            status="error",
            error_code="access_denied",
        )
        return err

    db_file = Path(db_path)
    if not db_file.exists() or not db_file.is_file():
        return _error(f"Database file does not exist: {db_file.name}", "database_not_found")

    source_uri = f"file:{db_file.resolve().as_posix()}?mode=ro"
    try:
        conn = sqlite3.connect(source_uri, uri=True, timeout=timeout_seconds)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        return _error(f"Failed to open database: {exc}", "database_error")

    try:
        cursor = conn.cursor()
        escaped_table = _quote_identifier(table_name)

        # Check table exists in sqlite_master
        cursor.execute(
            "SELECT type FROM sqlite_master WHERE (type='table' OR type='view') AND name = ?;",
            (table_name,),
        )
        row = cursor.fetchone()
        if not row:
            return _error(f"Table or view '{table_name}' not found.", "table_not_found")
        obj_type = row["type"]

        # Total row count
        cursor.execute(f"SELECT COUNT(*) AS cnt FROM {escaped_table};")  # noqa: S608
        total_rows = int(cursor.fetchone()["cnt"])

        # Fetch columns from table_info
        cursor.execute(f"PRAGMA table_info({escaped_table});")
        columns_info = cursor.fetchall()
        if not columns_info:
            return _error(f"Failed to read schema for table '{table_name}'.", "schema_error")

        columns_profile: dict[str, Any] = {}
        observations: list[str] = []

        for col in columns_info:
            col_name = str(col["name"])
            col_type = str(col["type"]).strip().lower()
            is_pk = bool(col["pk"])
            not_null = bool(col["notnull"])

            escaped_col = _quote_identifier(col_name)

            if not effective_policy.is_column_allowed(table_name, col_name):
                columns_profile[col_name] = {
                    "access_allowed": False,
                    "reason": "Column access denied by policy.",
                    "data_type": col_type,
                    "is_primary_key": is_pk,
                }
                continue

            is_sensitive = effective_policy.is_column_sensitive(
                table_name, col_name
            ) or _is_sensitive_column(col_name)

            # Compute NULL count
            cursor.execute(
                f"SELECT COUNT(*) AS null_cnt FROM {escaped_table} WHERE {escaped_col} IS NULL;"  # noqa: S608
            )
            null_count = int(cursor.fetchone()["null_cnt"])
            null_pct = round((null_count / total_rows * 100.0), 2) if total_rows > 0 else 0.0

            # Compute Distinct count (bounded sample or full if small)
            if total_rows <= max_sample_rows:
                cursor.execute(
                    f"SELECT COUNT(DISTINCT {escaped_col}) AS dist_cnt FROM {escaped_table};"  # noqa: S608
                )
            else:
                cursor.execute(
                    f"SELECT COUNT(DISTINCT {escaped_col}) AS dist_cnt FROM "  # noqa: S608
                    f"(SELECT {escaped_col} FROM {escaped_table} LIMIT {max_sample_rows});"
                )
            distinct_count = int(cursor.fetchone()["dist_cnt"])
            cardinality_ratio = round(distinct_count / total_rows, 4) if total_rows > 0 else 0.0

            if is_sensitive:
                columns_profile[col_name] = {
                    "access_allowed": True,
                    "is_sensitive": True,
                    "masked": True,
                    "data_type": col_type,
                    "is_primary_key": is_pk,
                    "nullable": not not_null,
                    "null_count": null_count,
                    "null_percentage": null_pct,
                    "distinct_count": distinct_count,
                    "cardinality_ratio": cardinality_ratio,
                    "min_value": None,
                    "max_value": None,
                    "sample_values": ["[REDACTED_SENSITIVE]"],
                }
                observations.append(
                    f"Column '{col_name}' is classified as sensitive and its values were masked."
                )
                continue

            # Non-sensitive profiling
            empty_string_count = 0
            min_val: Any = None
            max_val: Any = None

            if total_rows > 0:
                # Safe min/max
                try:
                    cursor.execute(
                        f"SELECT MIN({escaped_col}) AS min_v, MAX({escaped_col}) AS max_v "  # noqa: S608
                        f"FROM {escaped_table} WHERE {escaped_col} IS NOT NULL;"
                    )
                    min_max_row = cursor.fetchone()
                    if min_max_row:
                        min_val = _safe_serialize_value(min_max_row["min_v"])
                        max_val = _safe_serialize_value(min_max_row["max_v"])
                except sqlite3.Error:
                    pass

                # Empty string count for text columns
                if "char" in col_type or "text" in col_type or "clob" in col_type:
                    empty_sql = f"SELECT COUNT(*) AS empty_cnt FROM {escaped_table} WHERE {escaped_col} = '';"  # noqa: S608, E501
                    cursor.execute(empty_sql)
                    empty_string_count = int(cursor.fetchone()["empty_cnt"])

            # Non-sensitive sample values (up to 3 distinct values)
            sample_values: list[Any] = []
            if total_rows > 0:
                sample_sql = (
                    f"SELECT DISTINCT {escaped_col} AS val FROM {escaped_table} "  # noqa: S608
                    f"WHERE {escaped_col} IS NOT NULL LIMIT 3;"
                )
                cursor.execute(sample_sql)
                for s_row in cursor.fetchall():
                    sample_values.append(_safe_serialize_value(s_row["val"]))

            columns_profile[col_name] = {
                "access_allowed": True,
                "is_sensitive": False,
                "masked": False,
                "data_type": col_type,
                "is_primary_key": is_pk,
                "nullable": not not_null,
                "null_count": null_count,
                "null_percentage": null_pct,
                "distinct_count": distinct_count,
                "cardinality_ratio": cardinality_ratio,
                "empty_string_count": empty_string_count,
                "min_value": min_val,
                "max_value": max_val,
                "sample_values": sample_values,
            }

            # Rule-based diagnostics
            if null_pct == 100.0 and total_rows > 0:
                observations.append(f"Column '{col_name}' contains 100% NULL values.")
            elif distinct_count == total_rows and total_rows > 1 and not is_pk:
                observations.append(
                    f"Column '{col_name}' is fully unique (100% distinct) "
                    "and may be a candidate unique key."
                )
            elif (
                cardinality_ratio < 0.05
                and distinct_count > 1
                and distinct_count <= 10
                and total_rows > 50
            ):
                observations.append(
                    f"Column '{col_name}' has low cardinality "
                    f"({distinct_count} distinct values) and may represent an enumeration."
                )

        _record_audit_event(
            audit_file,
            "profile_table",
            "profiler",
            status="success",
        )

        return {
            "success": True,
            "table_name": table_name,
            "object_type": obj_type,
            "total_rows": total_rows,
            "columns_profiled": len(columns_profile),
            "columns": columns_profile,
            "observations": observations,
        }

    except sqlite3.Error as exc:
        return _error(f"Error profiling table '{table_name}': {exc}", "execution_error")
    finally:
        conn.close()
