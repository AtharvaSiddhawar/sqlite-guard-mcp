"""Comprehensive performance benchmarking harness for SQLite Guard MCP.

Measures latency percentiles (p50, p95, p99), execution overhead against raw SQLite,
peak memory allocation using tracemalloc, and outputs machine-readable JSON results.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any

from sqlite_guard_mcp.index_lab import simulate_index
from sqlite_guard_mcp.profiler import profile_table
from sqlite_guard_mcp.schema_diff import diff_schemas, review_migration, snapshot_schema
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
    db_path: Path, num_tables: int = 30, rows_per_table: int = 300
) -> None:
    """Populate a realistic synthetic benchmark database."""
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
            conn.execute(
                "INSERT INTO org_units (unit_id, name) VALUES (?, ?);",
                (i, f"OrgUnit_{i}"),
            )

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


def _percentiles(samples_ms: list[float]) -> dict[str, float]:
    """Calculate p50, p95, p99, and mean latency from samples in milliseconds."""
    sorted_samples = sorted(samples_ms)
    n = len(sorted_samples)
    if n == 0:
        return {"mean": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}

    def pct(p: float) -> float:
        k = (n - 1) * p
        f = int(k)
        c = f + 1 if f + 1 < n else f
        d = k - f
        return sorted_samples[f] + (sorted_samples[c] - sorted_samples[f]) * d

    return {
        "mean": round(sum(sorted_samples) / n, 3),
        "p50": round(pct(0.50), 3),
        "p95": round(pct(0.95), 3),
        "p99": round(pct(0.99), 3),
    }


def run_benchmarks(
    iterations: int = 50,
    output_json_path: Path | str | None = None,
) -> dict[str, Any]:
    """Execute timed benchmarks across raw SQLite, guarded tools, and memory profiling."""
    tracemalloc.start()
    benchmark_start_time = time.perf_counter()

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "bench.sqlite"
        generate_synthetic_database(db_path, num_tables=30, rows_per_table=300)

        results: dict[str, Any] = {
            "version": "0.2.3",
            "sqlite_version": sqlite3.sqlite_version,
            "iterations": iterations,
            "metrics": {},
        }

        # 0. Raw SQLite Baseline (Unbounded SELECT of 100 rows)
        raw_samples = []
        raw_conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            for _ in range(iterations):
                t0 = time.perf_counter()
                cur = raw_conn.cursor()
                cur.execute(
                    "SELECT id, code, value, api_key_token FROM dataset_table_000 LIMIT 100;"
                )
                cur.fetchall()
                cur.close()
                raw_samples.append((time.perf_counter() - t0) * 1000)
        finally:
            raw_conn.close()
        results["metrics"]["raw_sqlite_query"] = _percentiles(raw_samples)

        # 1. Guarded Read Query Execution with Masking
        guarded_samples = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            execute_guarded_query(
                db_path,
                "SELECT id, code, value, api_key_token FROM dataset_table_000 LIMIT 100;",
            )
            guarded_samples.append((time.perf_counter() - t0) * 1000)
        results["metrics"]["guarded_read_query"] = _percentiles(guarded_samples)

        # Compute Overhead Delta
        raw_p50 = results["metrics"]["raw_sqlite_query"]["p50"]
        guarded_p50 = results["metrics"]["guarded_read_query"]["p50"]
        results["metrics"]["overhead_delta_p50_ms"] = round(guarded_p50 - raw_p50, 3)

        # 2. Database Overview
        overview_samples = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            get_database_overview(db_path)
            overview_samples.append((time.perf_counter() - t0) * 1000)
        results["metrics"]["get_database_overview"] = _percentiles(overview_samples)

        # 3. Schema Summary Resource (Zero-Turn)
        summary_samples = []
        for _ in range(max(10, iterations // 5)):
            t0 = time.perf_counter()
            inspect_schema_summary(db_path)
            summary_samples.append((time.perf_counter() - t0) * 1000)
        results["metrics"]["schema_summary_resource"] = _percentiles(summary_samples)

        # 4. Schema Search
        search_samples = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            search_database_schema(db_path, "dataset_table_01")
            search_samples.append((time.perf_counter() - t0) * 1000)
        results["metrics"]["search_database_schema"] = _percentiles(search_samples)

        # 5. Describe Table with Diagnostics
        describe_samples = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            describe_table(db_path, "dataset_table_000")
            describe_samples.append((time.perf_counter() - t0) * 1000)
        results["describe_database_table"] = _percentiles(describe_samples)

        # 6. Explain Read Query
        explain_samples = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            explain_query(
                db_path,
                "SELECT * FROM dataset_table_000 WHERE code = ? AND unit_id = ?",
                params=["CODE_0_10", 5],
            )
            explain_samples.append((time.perf_counter() - t0) * 1000)
        results["metrics"]["explain_read_query"] = _percentiles(explain_samples)

        # 7. Check Database Health
        health_samples = []
        for _ in range(max(5, iterations // 10)):
            t0 = time.perf_counter()
            check_database_health(db_path)
            health_samples.append((time.perf_counter() - t0) * 1000)
        results["metrics"]["check_database_health"] = _percentiles(health_samples)

        # 8. Index Laboratory Simulation
        lab_samples = []
        for _ in range(max(5, iterations // 10)):
            t0 = time.perf_counter()
            simulate_index(
                db_path,
                "SELECT * FROM dataset_table_001 WHERE description = 'test';",
                "CREATE INDEX idx_bench_desc ON dataset_table_001(description);",
            )
            lab_samples.append((time.perf_counter() - t0) * 1000)
        results["metrics"]["simulate_candidate_index"] = _percentiles(lab_samples)

        # 9. Privacy-Preserving Profiler
        prof_samples = []
        for _ in range(max(10, iterations // 5)):
            t0 = time.perf_counter()
            profile_table(db_path, "dataset_table_000", max_sample_rows=300)
            prof_samples.append((time.perf_counter() - t0) * 1000)
        results["metrics"]["profile_database_table"] = _percentiles(prof_samples)

        # 10. Schema Snapshot & Diff
        snap1 = snapshot_schema(db_path)
        snap_samples = []
        for _ in range(max(10, iterations // 5)):
            t0 = time.perf_counter()
            snapshot_schema(db_path)
            snap_samples.append((time.perf_counter() - t0) * 1000)
        results["metrics"]["snapshot_schema"] = _percentiles(snap_samples)

        diff_samples = []
        for _ in range(max(10, iterations // 5)):
            t0 = time.perf_counter()
            diff_schemas(snap1, snap1)
            diff_samples.append((time.perf_counter() - t0) * 1000)
        results["metrics"]["diff_schemas"] = _percentiles(diff_samples)

        # 11. Static Migration Review
        mig_samples = []
        sample_migration = """
        BEGIN TRANSACTION;
        CREATE TABLE sample_new (id INTEGER PRIMARY KEY, note TEXT);
        CREATE INDEX idx_sample_note ON sample_new(note);
        COMMIT;
        """
        for _ in range(iterations):
            t0 = time.perf_counter()
            review_migration(sample_migration)
            mig_samples.append((time.perf_counter() - t0) * 1000)
        results["metrics"]["review_migration"] = _percentiles(mig_samples)

        # Memory Tracking
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        results["memory"] = {
            "current_kb": round(current_mem / 1024, 2),
            "peak_kb": round(peak_mem / 1024, 2),
            "peak_mb": round(peak_mem / (1024 * 1024), 2),
        }
        results["total_elapsed_seconds"] = round(time.perf_counter() - benchmark_start_time, 2)

        # Output to JSON if requested
        if output_json_path:
            out_p = Path(output_json_path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(json.dumps(results, indent=2), encoding="utf-8")

        return results


if __name__ == "__main__":
    print("Executing SQLite Guard MCP Production Benchmark Harness...")
    json_path = Path(__file__).parent / "results.json"
    res = run_benchmarks(iterations=50, output_json_path=json_path)

    print(
        "\n========================================================================================="
    )
    print(f" SQLite Guard MCP v{res['version']} — Benchmark Latency & Memory Profile")
    print(
        "========================================================================================="
    )
    hdr = f" {'Operation / Tool':<30} | {'p50 (ms)':>9} | {'p95 (ms)':>9} | {'Mean (ms)':>9}"
    print(hdr)
    print("--------------------------------------------------------------------------------")
    for op, data in res["metrics"].items():
        if isinstance(data, dict):
            row_str = f" {op:<30} | {data['p50']:9.3f} | {data['p95']:9.3f} | {data['mean']:9.3f}"
            print(row_str)
        else:
            print(f" {op:<30} | {data:9.3f}")

    print(
        "-----------------------------------------------------------------------------------------"
    )
    mem = res["memory"]
    print(f" Peak Memory Traced: {mem['peak_kb']} KB ({mem['peak_mb']} MB)")
    print(f" Machine-readable results exported to: {json_path}")
    print(
        "========================================================================================="
    )
