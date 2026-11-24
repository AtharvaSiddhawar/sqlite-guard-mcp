"""System and environment diagnostics for SQLite Guard MCP.

Provides CLI diagnostics, SQLite engine compile-option validation,
database integrity verification, and access policy health checks.
"""

from __future__ import annotations

import os
import platform
import sqlite3
import sys
from pathlib import Path
from typing import Any

from sqlite_guard_mcp.policy import load_policy

# SQLite compile options that improve security and feature coverage
_NOTABLE_COMPILE_OPTIONS = [
    "ENABLE_FTS5",
    "ENABLE_JSON1",
    "ENABLE_RTREE",
    "ENABLE_STAT4",
    "OMIT_LOAD_EXTENSION",
    "THREADSAFE",
]


def run_doctor(
    db_path: str | Path | None = None,
    policy_path: str | Path | None = None,
) -> dict[str, Any]:
    """Execute comprehensive environment, SQLite, database, and policy health diagnostics."""
    report: dict[str, Any] = {
        "status": "HEALTHY",
        "system": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": sys.version.split()[0],
            "python_executable": sys.executable,
        },
        "sqlite": {
            "version": sqlite3.sqlite_version,
            "compile_options": [],
            "notable_features": {},
        },
        "environment": {
            "SQLITE_GUARD_DB": os.environ.get("SQLITE_GUARD_DB"),
            "SQLITE_GUARD_POLICY": os.environ.get("SQLITE_GUARD_POLICY"),
            "SQLITE_GUARD_AUTH_TOKEN": bool(os.environ.get("SQLITE_GUARD_AUTH_TOKEN")),
            "SQLITE_GUARD_AUDIT_LOG": os.environ.get("SQLITE_GUARD_AUDIT_LOG"),
        },
        "database": None,
        "policy": None,
        "warnings": [],
        "errors": [],
    }

    # Inspect SQLite compile options via in-memory query
    try:
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("PRAGMA compile_options;")
        compile_opts = {row[0] for row in cursor.fetchall()}
        report["sqlite"]["compile_options"] = sorted(compile_opts)

        for opt in _NOTABLE_COMPILE_OPTIONS:
            has_opt = any(opt in o for o in compile_opts)
            report["sqlite"]["notable_features"][opt] = has_opt

        conn.close()
    except sqlite3.Error as exc:
        report["warnings"].append(f"Failed to query SQLite compile options: {exc}")

    # Inspect database if provided
    if db_path:
        db_p = Path(db_path).expanduser()
        db_info: dict[str, Any] = {
            "configured_path": str(db_path),
            "resolved_path": str(db_p.resolve()) if db_p.exists() else None,
            "exists": db_p.exists(),
            "is_file": db_p.is_file(),
            "size_bytes": db_p.stat().st_size if db_p.exists() and db_p.is_file() else None,
            "quick_check": None,
            "foreign_keys_status": None,
        }

        if not db_p.exists():
            report["errors"].append(f"Database path does not exist: {db_path}")
            report["status"] = "ERROR"
        elif not db_p.is_file():
            report["errors"].append(f"Database path is not a file: {db_path}")
            report["status"] = "ERROR"
        else:
            try:
                uri = f"file:{db_p.resolve().as_posix()}?mode=ro"
                db_conn = sqlite3.connect(uri, uri=True, timeout=5.0)
                db_cursor = db_conn.cursor()

                db_cursor.execute("PRAGMA quick_check(5);")
                qc_rows = [r[0] for r in db_cursor.fetchall()]
                db_info["quick_check"] = "ok" if qc_rows == ["ok"] else qc_rows
                if db_info["quick_check"] != "ok":
                    report["warnings"].append(
                        f"Database quick_check returned non-ok: {db_info['quick_check']}"
                    )
                    report["status"] = "DEGRADED"

                db_cursor.execute("PRAGMA foreign_key_check;")
                fk_violations = db_cursor.fetchall()
                db_info["foreign_key_violations_count"] = len(fk_violations)
                if fk_violations:
                    report["warnings"].append(
                        f"Database has {len(fk_violations)} foreign key integrity violation(s)."
                    )
                    report["status"] = "DEGRADED"

                db_conn.close()
            except sqlite3.Error as exc:
                report["errors"].append(f"Database connection error: {exc}")
                report["status"] = "ERROR"

        report["database"] = db_info

    # Inspect policy if provided
    if policy_path:
        pol_p = Path(policy_path).expanduser()
        pol_info: dict[str, Any] = {
            "configured_path": str(policy_path),
            "exists": pol_p.exists(),
            "valid": False,
            "details": None,
        }

        if not pol_p.exists():
            report["errors"].append(f"Policy file does not exist: {policy_path}")
            report["status"] = "ERROR"
        else:
            try:
                loaded_policy = load_policy(pol_p)
                pol_info["valid"] = True
                pol_info["details"] = {
                    "allow_tables_count": (
                        len(loaded_policy.allow_tables)
                        if loaded_policy.allow_tables is not None
                        else "ALL"
                    ),
                    "deny_tables_count": len(loaded_policy.deny_tables),
                    "wildcard_column_denies": sorted(loaded_policy.deny_columns_wildcard),
                    "sensitive_columns_count": len(loaded_policy.custom_sensitive_columns),
                    "features": {
                        "explain_query": loaded_policy.allow_explain_query,
                        "profiling": loaded_policy.allow_profiling,
                        "index_lab": loaded_policy.allow_index_lab,
                        "schema_diff": loaded_policy.allow_schema_diff,
                        "migration_review": loaded_policy.allow_migration_review,
                    },
                }
            except ValueError as exc:
                pol_info["valid"] = False
                pol_info["error"] = str(exc)
                report["errors"].append(f"Policy configuration error: {exc}")
                report["status"] = "ERROR"

        report["policy"] = pol_info

    return report


def format_doctor_report(report: dict[str, Any]) -> str:
    """Format doctor report into a human-readable CLI diagnostic summary."""
    sys_info = report["system"]
    lines = [
        "============================================================",
        f"  SQLite Guard MCP Doctor Diagnostic — Status: {report['status']}",
        "============================================================",
        f"Platform:       {sys_info['os']} {sys_info['release']} ({sys_info['machine']})",
        f"Python:         {sys_info['python_version']}",
        f"Executable:     {sys_info['python_executable']}",
        f"SQLite Version: {report['sqlite']['version']}",
    ]

    features = report["sqlite"].get("notable_features", {})
    feature_strs = [f"{k}: {'YES' if v else 'NO'}" for k, v in features.items()]
    lines.append(f"Engine Features: {', '.join(feature_strs)}")

    db = report.get("database")
    if db:
        lines.append("\n[Database Target]")
        lines.append(f"  Path:       {db.get('configured_path')}")
        lines.append(f"  Exists:     {'YES' if db.get('exists') else 'NO'}")
        if db.get("size_bytes") is not None:
            size_kb = round(db["size_bytes"] / 1024, 2)
            lines.append(f"  File Size:  {size_kb} KB")
        if db.get("quick_check") is not None:
            lines.append(f"  Integrity:  {db['quick_check']}")
        if db.get("foreign_key_violations_count") is not None:
            lines.append(f"  FK Errors:  {db['foreign_key_violations_count']}")

    pol = report.get("policy")
    if pol:
        lines.append("\n[Access Policy]")
        lines.append(f"  Path:       {pol.get('configured_path')}")
        lines.append(f"  Valid:      {'YES' if pol.get('valid') else 'NO'}")
        if pol.get("details"):
            det = pol["details"]
            lines.append(
                f"  Tables:     Allow={det['allow_tables_count']}, Deny={det['deny_tables_count']}"
            )
            if det.get("wildcard_column_denies"):
                lines.append(f"  Deny Cols:  {', '.join(det['wildcard_column_denies'])}")
            feat = det.get("features", {})
            feat_summary = (
                f"explain={feat.get('explain_query')}, "
                f"profile={feat.get('profiling')}, "
                f"index_lab={feat.get('index_lab')}"
            )
            lines.append(f"  Features:   {feat_summary}")

    if report["warnings"]:
        lines.append("\n[Warnings]")
        for w in report["warnings"]:
            lines.append(f"  - {w}")

    if report["errors"]:
        lines.append("\n[Errors]")
        for e in report["errors"]:
            lines.append(f"  - {e}")

    lines.append("============================================================")
    return "\n".join(lines)
