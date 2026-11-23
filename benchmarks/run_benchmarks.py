"""Reproducible performance benchmarking script for SQLite Guard MCP.

Generates a realistic synthetic database with diverse schemas, indexes, and records,
then measures latency and memory footprints across key operations.
"""

from __future__ import annotations

import sqlite3
import tempfile
import time
from pathlib import Path

from sqlite_guard_mcp.server import (
    check_database_health,
    describe_table,
    execute_guarded_query,
    explain_query,
    get_database_overview,
    inspect_schema_summary,
    search_database_schema,
)


def generate_synthetic_database(
    db_path: Path, num_tables: int = 50, rows_per_table: int = 500
) -> None:
    """Populate a synthetic benchmark database."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")

        # Base referenced table
        conn.execute(
            """
            CREATE TABLE org_units (
                unit_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        for i in range(1, 21):
            conn.execute("INSERT INTO org_units (unit_id, name) VALUES (?, ?)", (i, f"OrgUnit_{i}"))

        for t in range(num_tables):
            table_name = f"dataset_table_{t:03d}"
            conn.execute(
                f"""
                CREATE TABLE {table_name} (
                    id INTEGER PRIMARY KEY,
                    unit_id INTEGER,
                    code TEXT NOT NULL,
                    value REAL,
                    status TEXT,
                    api_key_token TEXT,
                    description TEXT,
                    FOREIGN KEY (unit_id) REFERENCES org_units(unit_id)
                );
                """
            )
            # Add selective indexes
            if t % 2 == 0:
                conn.execute(f"CREATE INDEX idx_{table_name}_code ON {table_name}(code);")
            if t % 3 == 0:
                conn.execute(
                    f"CREATE INDEX idx_{table_name}_composite ON {table_name}(unit_id, status);"
                )

            # Batch insert rows
            records = [
                (
                    r,
                    (r % 20) + 1,
                    f"CODE_{t}_{r}",
                    r * 1.5,
                    "active" if r % 2 == 0 else "pending",
                    f"secret_{t}_{r}",
                    f"Sample description text for record {r} in table {table_name}",
                )
                for r in range(1, rows_per_table + 1)
            ]
            conn.executemany(
                f"INSERT INTO {table_name} VALUES (?, ?, ?, ?, ?, ?, ?)",
                records,
            )
        conn.commit()
    finally:
        conn.close()


def run_benchmarks() -> dict[str, float]:
    """Execute timed micro-benchmarks."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "bench.sqlite"
        generate_synthetic_database(db_path, num_tables=30, rows_per_table=300)

        results = {}

        # 1. Database Overview
        start = time.perf_counter()
        for _ in range(50):
            get_database_overview(db_path)
        results["database_overview_ms"] = ((time.perf_counter() - start) / 50) * 1000

        # 2. Schema Summary Resource (Zero-Turn)
        start = time.perf_counter()
        for _ in range(10):
            inspect_schema_summary(db_path)
        results["schema_summary_ms"] = ((time.perf_counter() - start) / 10) * 1000

        # 3. Schema Search
        start = time.perf_counter()
        for _ in range(50):
            search_database_schema(db_path, "dataset_table_01")
        results["schema_search_ms"] = ((time.perf_counter() - start) / 50) * 1000

        # 4. Describe Table with Diagnostics
        start = time.perf_counter()
        for _ in range(50):
            describe_table(db_path, "dataset_table_000")
        results["describe_table_ms"] = ((time.perf_counter() - start) / 50) * 1000

        # 5. Explain Read Query
        start = time.perf_counter()
        for _ in range(50):
            explain_query(
                db_path,
                "SELECT * FROM dataset_table_000 WHERE code = ? AND unit_id = ?",
                params=["CODE_0_10", 5],
            )
        results["explain_read_query_ms"] = ((time.perf_counter() - start) / 50) * 1000

        # 6. Read Query Execution with Masking
        start = time.perf_counter()
        for _ in range(50):
            execute_guarded_query(
                db_path,
                "SELECT id, code, value, api_key_token FROM dataset_table_000 LIMIT 100",
            )
        results["read_query_ms"] = ((time.perf_counter() - start) / 50) * 1000

        # 7. Check Database Health
        start = time.perf_counter()
        for _ in range(10):
            check_database_health(db_path)
        results["database_health_ms"] = ((time.perf_counter() - start) / 10) * 1000

        return results


if __name__ == "__main__":
    print("Running SQLite Guard MCP Benchmarks...")
    res = run_benchmarks()
    for metric, val in res.items():
        print(f"  {metric:<30}: {val:8.3f} ms")
