"""Schema Snapshot, Diff and Migration Review for SQLite Guard MCP.

Provides canonical JSON schema snapshot generation, structural schema diffing,
and static safety review for SQLite migration scripts without executing SQL.
"""

from __future__ import annotations

import datetime
import re
import sqlite3
from pathlib import Path
from typing import Any

from sqlite_guard_mcp.policy import AccessPolicy, default_policy
from sqlite_guard_mcp.server import (
    DEFAULT_TIMEOUT_SECONDS,
    _error,
    _is_sensitive_column,
    _quote_identifier,
)

_DROP_TABLE_PATTERN = re.compile(
    r"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([A-Za-z0-9_\"`\[\]]+)", re.IGNORECASE
)
_DROP_COLUMN_PATTERN = re.compile(
    r"\bALTER\s+TABLE\s+([A-Za-z0-9_\"`\[\]]+)\s+DROP\s+COLUMN\s+([A-Za-z0-9_\"`\[\]]+)",
    re.IGNORECASE,
)
_ADD_NOT_NULL_NO_DEFAULT = re.compile(
    r"\bALTER\s+TABLE\s+([A-Za-z0-9_\"`\[\]]+)\s+ADD\s+(?:COLUMN\s+)?([A-Za-z0-9_\"`\[\]]+)\s+([^;]+?)\bNOT\s+NULL\b(?!.*DEFAULT)",
    re.IGNORECASE,
)
_DANGEROUS_PRAGMA_PATTERN = re.compile(
    r"\bPRAGMA\s+(?:writable_schema|cell_size_check|journal_mode\s*=\s*off)\b",
    re.IGNORECASE,
)
_DISABLE_FK_PRAGMA_PATTERN = re.compile(
    r"\bPRAGMA\s+foreign_keys\s*=\s*(?:OFF|0|false|no)\b",
    re.IGNORECASE,
)
_ATTACH_PATTERN = re.compile(r"\bATTACH\s+(?:DATABASE\s+)?", re.IGNORECASE)
_BEGIN_PATTERN = re.compile(r"\bBEGIN\b", re.IGNORECASE)
_COMMIT_PATTERN = re.compile(r"\bCOMMIT\b", re.IGNORECASE)


def snapshot_schema(
    db_path: str | Path,
    *,
    policy: AccessPolicy | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Capture a canonical, JSON-serializable snapshot of the database schema."""
    effective_policy = policy or default_policy()

    if not effective_policy.allow_schema_diff:
        return _error("Schema inspection/diff is disabled by policy.", "access_denied")

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

        # Get sqlite version
        cursor.execute("SELECT sqlite_version() AS ver;")
        sqlite_version = cursor.fetchone()["ver"]

        # Fetch all tables and views
        cursor.execute(
            """
            SELECT type, name, sql
            FROM sqlite_master
            WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'
            ORDER BY name;
            """
        )
        objects = cursor.fetchall()

        tables_data: dict[str, Any] = {}
        views_data: dict[str, Any] = {}

        for obj in objects:
            obj_name = obj["name"]
            obj_type = obj["type"]
            raw_sql = obj["sql"] or ""

            if not effective_policy.is_table_allowed(obj_name):
                continue

            escaped_name = _quote_identifier(obj_name)

            if obj_type == "view":
                views_data[obj_name] = {
                    "name": obj_name,
                    "sql": raw_sql,
                }
                continue

            # Fetch columns
            cursor.execute(f"PRAGMA table_info({escaped_name});")
            col_rows = cursor.fetchall()
            cols_list = []
            for c in col_rows:
                c_name = c["name"]
                if not effective_policy.is_column_allowed(obj_name, c_name):
                    continue

                dflt = c["dflt_value"]
                is_sens = effective_policy.is_column_sensitive(
                    obj_name, c_name
                ) or _is_sensitive_column(c_name)
                if is_sens and dflt is not None:
                    dflt = "[REDACTED]"

                cols_list.append(
                    {
                        "cid": c["cid"],
                        "name": c_name,
                        "type": c["type"].strip().upper(),
                        "notnull": bool(c["notnull"]),
                        "dflt_value": dflt,
                        "pk": bool(c["pk"]),
                        "sensitive": is_sens,
                    }
                )

            # Fetch indexes
            cursor.execute(f"PRAGMA index_list({escaped_name});")
            idx_rows = cursor.fetchall()
            indexes_list = []
            for idx in idx_rows:
                idx_name = idx["name"]
                is_unique = bool(idx["unique"])
                origin = idx["origin"] if "origin" in idx.keys() else "c"

                # Get index columns
                escaped_idx = _quote_identifier(idx_name)
                cursor.execute(f"PRAGMA index_info({escaped_idx});")
                idx_cols = [r["name"] for r in cursor.fetchall()]

                indexes_list.append(
                    {
                        "name": idx_name,
                        "unique": is_unique,
                        "origin": origin,
                        "columns": idx_cols,
                    }
                )

            # Fetch foreign keys
            cursor.execute(f"PRAGMA foreign_key_list({escaped_name});")
            fk_rows = cursor.fetchall()
            fks_list = []
            for fk in fk_rows:
                fks_list.append(
                    {
                        "id": fk["id"],
                        "seq": fk["seq"],
                        "target_table": fk["table"],
                        "from": fk["from"],
                        "to": fk["to"],
                        "on_update": fk["on_update"],
                        "on_delete": fk["on_delete"],
                    }
                )

            tables_data[obj_name] = {
                "name": obj_name,
                "columns": cols_list,
                "indexes": indexes_list,
                "foreign_keys": fks_list,
            }

        return {
            "success": True,
            "sqlite_version": sqlite_version,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "tables": tables_data,
            "views": views_data,
        }

    except sqlite3.Error as exc:
        return _error(f"Failed to capture schema snapshot: {exc}", "schema_error")
    finally:
        conn.close()


def diff_schemas(
    snapshot_a: dict[str, Any],
    snapshot_b: dict[str, Any],
) -> dict[str, Any]:
    """Compare two schema snapshots and detect added, removed, and modified elements."""
    if not snapshot_a.get("success") or not snapshot_b.get("success"):
        return _error("Both arguments must be successful schema snapshots.", "invalid_input")

    tables_a: dict[str, Any] = snapshot_a.get("tables", {})
    tables_b: dict[str, Any] = snapshot_b.get("tables", {})

    views_a: dict[str, Any] = snapshot_a.get("views", {})
    views_b: dict[str, Any] = snapshot_b.get("views", {})

    names_a = set(tables_a.keys())
    names_b = set(tables_b.keys())

    added_tables = sorted(names_b - names_a)
    removed_tables = sorted(names_a - names_b)
    common_tables = sorted(names_a & names_b)

    modified_tables: dict[str, Any] = {}
    breaking_changes: list[str] = []

    for t in removed_tables:
        breaking_changes.append(f"Table '{t}' was dropped.")

    for t in common_tables:
        t_a = tables_a[t]
        t_b = tables_b[t]

        cols_a = {c["name"]: c for c in t_a.get("columns", [])}
        cols_b = {c["name"]: c for c in t_b.get("columns", [])}

        c_names_a = set(cols_a.keys())
        c_names_b = set(cols_b.keys())

        added_cols = [cols_b[c] for c in sorted(c_names_b - c_names_a)]
        removed_cols = sorted(c_names_a - c_names_b)
        modified_cols = []

        for c_rem in removed_cols:
            breaking_changes.append(f"Column '{t}.{c_rem}' was dropped.")

        for c in sorted(c_names_a & c_names_b):
            col_a = cols_a[c]
            col_b = cols_b[c]

            changes = {}
            if col_a["type"] != col_b["type"]:
                changes["type_change"] = {"old": col_a["type"], "new": col_b["type"]}
            if col_a["notnull"] != col_b["notnull"]:
                changes["notnull_change"] = {"old": col_a["notnull"], "new": col_b["notnull"]}
                if not col_a["notnull"] and col_b["notnull"] and col_b.get("dflt_value") is None:
                    breaking_changes.append(
                        f"Column '{t}.{c}' became NOT NULL without a default value."
                    )
            if col_a["pk"] != col_b["pk"]:
                changes["primary_key_change"] = {"old": col_a["pk"], "new": col_b["pk"]}
                breaking_changes.append(f"Primary key status of '{t}.{c}' changed.")

            if changes:
                modified_cols.append({"column": c, "changes": changes})

        # Indexes diff
        idx_a = {i["name"]: i for i in t_a.get("indexes", [])}
        idx_b = {i["name"]: i for i in t_b.get("indexes", [])}
        added_indexes = sorted(set(idx_b.keys()) - set(idx_a.keys()))
        removed_indexes = sorted(set(idx_a.keys()) - set(idx_b.keys()))

        if added_cols or removed_cols or modified_cols or added_indexes or removed_indexes:
            modified_tables[t] = {
                "added_columns": added_cols,
                "removed_columns": removed_cols,
                "modified_columns": modified_cols,
                "added_indexes": added_indexes,
                "removed_indexes": removed_indexes,
            }

    # Views diff
    added_views = sorted(set(views_b.keys()) - set(views_a.keys()))
    removed_views = sorted(set(views_a.keys()) - set(views_b.keys()))
    for v in removed_views:
        breaking_changes.append(f"View '{v}' was dropped.")

    if breaking_changes:
        risk_level = "HIGH"
    elif modified_tables or removed_views:
        risk_level = "MEDIUM"
    elif added_tables or added_views:
        risk_level = "LOW"
    else:
        risk_level = "NO_CHANGE"

    return {
        "success": True,
        "risk_level": risk_level,
        "breaking_changes": breaking_changes,
        "tables": {
            "added": added_tables,
            "removed": removed_tables,
            "modified": modified_tables,
        },
        "views": {
            "added": added_views,
            "removed": removed_views,
        },
    }


def review_migration(migration_sql: str) -> dict[str, Any]:
    """Perform a static safety review of a SQLite migration script."""
    cleaned = migration_sql.strip()
    if not cleaned:
        return _error("Migration SQL cannot be empty.", "invalid_input")

    issues: list[dict[str, str]] = []
    detected_operations: list[str] = []

    # Check for destructive DROP TABLE
    drop_tables = _DROP_TABLE_PATTERN.findall(cleaned)
    for dt in drop_tables:
        detected_operations.append(f"DROP TABLE {dt}")
        issues.append(
            {
                "severity": "HIGH",
                "category": "destructive_operation",
                "message": f"Destructive operation: Table '{dt}' is permanently dropped.",
                "recommendation": (
                    "Ensure data backup exists before executing, or deprecate the table first."
                ),
            }
        )

    # Check for DROP COLUMN
    drop_cols = _DROP_COLUMN_PATTERN.findall(cleaned)
    for tbl, col in drop_cols:
        detected_operations.append(f"DROP COLUMN {tbl}.{col}")
        issues.append(
            {
                "severity": "HIGH",
                "category": "destructive_operation",
                "message": f"Destructive operation: Column '{col}' dropped from table '{tbl}'.",
                "recommendation": "Verify no active application code relies on this column.",
            }
        )

    # Check for ADD COLUMN NOT NULL without DEFAULT
    not_null_adds = _ADD_NOT_NULL_NO_DEFAULT.findall(cleaned)
    for match in not_null_adds:
        tbl = match[0]
        col = match[1]
        issues.append(
            {
                "severity": "HIGH",
                "category": "syntax_runtime_error",
                "message": (
                    f"Adding NOT NULL column '{col}' to table '{tbl}' without DEFAULT "
                    "will fail on non-empty tables in SQLite."
                ),
                "recommendation": (
                    "Provide a default value: "
                    "ALTER TABLE tbl ADD COLUMN col ... NOT NULL DEFAULT ...;"
                ),
            }
        )

    # Check for dangerous PRAGMAs
    dangerous_pragmas = _DANGEROUS_PRAGMA_PATTERN.findall(cleaned)
    for dp in dangerous_pragmas:
        issues.append(
            {
                "severity": "CRITICAL",
                "category": "dangerous_pragma",
                "message": f"Dangerous PRAGMA detected: '{dp}'.",
                "recommendation": (
                    "Never mutate system pragmas or disable integrity checks in migrations."
                ),
            }
        )

    # Check for disabling foreign_keys enforcement (warning for table-rebuild migrations)
    disabled_fks = _DISABLE_FK_PRAGMA_PATTERN.findall(cleaned)
    for dfk in disabled_fks:
        detected_operations.append(dfk)
        issues.append(
            {
                "severity": "MEDIUM",
                "category": "integrity_check_disabled",
                "message": (
                    f"Foreign key enforcement disabled via '{dfk}'. "
                    "Referential integrity violations can occur while disabled."
                ),
                "recommendation": (
                    "If performing a table-rebuild migration, verify integrity with "
                    "'PRAGMA foreign_key_check;' and re-enable 'PRAGMA foreign_keys = ON;' "
                    "before finishing."
                ),
            }
        )

    # Check for ATTACH DATABASE
    if _ATTACH_PATTERN.search(cleaned):
        issues.append(
            {
                "severity": "CRITICAL",
                "category": "security_risk",
                "message": "ATTACH DATABASE detected in migration script.",
                "recommendation": (
                    "Migrations must operate strictly within the target database file."
                ),
            }
        )

    # Check for transactions
    has_begin = bool(_BEGIN_PATTERN.search(cleaned))
    has_commit = bool(_COMMIT_PATTERN.search(cleaned))
    if not has_begin or not has_commit:
        issues.append(
            {
                "severity": "MEDIUM",
                "category": "transaction_safety",
                "message": (
                    "Migration script is not enclosed in an explicit transaction "
                    "(BEGIN ... COMMIT)."
                ),
                "recommendation": (
                    "Wrap all migration steps in 'BEGIN TRANSACTION;' and 'COMMIT;' for atomicity."
                ),
            }
        )

    # Determine overall risk level
    severities = {issue["severity"] for issue in issues}
    if "CRITICAL" in severities or "HIGH" in severities:
        risk_level = "DANGEROUS"
        safe = False
    elif "MEDIUM" in severities:
        risk_level = "WARNING"
        safe = True
    else:
        risk_level = "SAFE"
        safe = True

    return {
        "success": True,
        "safe": safe,
        "risk_level": risk_level,
        "detected_operations": detected_operations,
        "issues": issues,
        "summary": (
            f"Migration review complete. Risk level: {risk_level}. Found {len(issues)} issue(s)."
        ),
    }
