# PERFORMANCE BENCHMARKS & LATENCY EVALUATION

**Product**: SQLite Guard MCP (v0.2.3)  
**Date**: November 2026  
**Benchmarking Harness**: `benchmarks/run_benchmarks.py`  
**Machine-Readable Results**: `benchmarks/results.json`  
**Test Environment**: AMD Ryzen / Intel Core x86_64, Windows 11 / Linux, Python 3.12, SQLite 3.45+  

---

## 1. Methodology & Dataset Specification

Benchmarking evaluates latency, execution overhead, percentile distributions (p50, p95, p99), and memory efficiency using a deterministically generated synthetic SQLite database.

### Synthetic Database Parameters:
- **Table Count**: 30 relational dataset tables + 1 base organization table (`org_units`).
- **Column Count**: 7 columns per table (mix of `INTEGER PRIMARY KEY`, foreign keys, text codes, numeric values, status flags, credential token columns, and descriptive text).
- **Row Count**: 300 rows per table (9,000+ total rows).
- **Index Depth**: 20+ secondary indexes including single-column and multi-column composite indexes.
- **Foreign Keys**: Enabled (`PRAGMA foreign_keys = ON`), with cross-table relationships.
- **WAL Mode**: Enabled (`PRAGMA journal_mode = WAL`).

---

## 2. Operation Latency & Percentile Distributions

All operations were benchmarked across 10 to 50 warm iterations. Latencies are reported in milliseconds (ms) with median (p50), 95th percentile (p95), 99th percentile (p99), and arithmetic mean:

| Operation / Tool | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Description & Scope |
|---|:---:|:---:|:---:|:---:|---|
| **`raw_sqlite_query` (Baseline)** | 1.25 ms | 9.68 ms | 23.97 ms | 2.79 ms | Raw unbounded `sqlite3` cursor query fetching 100 rows without security controls. |
| **`guarded_read_query`** | 26.59 ms | 82.11 ms | 106.69 ms | 35.08 ms | Read-only URI mode, authorizer bytecode interception, credential masking, timeout progress handler, row capping, JSON bounds. |
| **`get_database_overview`** | 9.24 ms | 42.04 ms | 58.19 ms | 15.04 ms | Page size, page count, schema version, table/view/index counts. |
| **`describe_database_table`** | 10.96 ms | 45.20 ms | 62.10 ms | 18.25 ms | Full table metadata, column types, FK discovery, and index overlap analysis. |
| **`explain_read_query`** | 10.96 ms | 81.18 ms | 168.24 ms | 20.48 ms | `EXPLAIN QUERY PLAN` execution, table scan detection, and structured diagnostics. |
| **`search_database_schema`** | 20.52 ms | 38.48 ms | 106.74 ms | 25.14 ms | Case-insensitive search across all tables, views, columns, and indexes. |
| **`schema://summary` (Resource)** | 108.25 ms | 256.52 ms | 295.15 ms | 133.59 ms | Zero-turn inspection extracting complete schema definitions across 30 tables in one read. |
| **`check_database_health`** | 365.18 ms | 396.76 ms | 400.38 ms | 371.37 ms | Comprehensive `PRAGMA quick_check`, foreign key validation, and index redundancy analysis. |
| **`simulate_candidate_index`** | 19.83 ms | 25.27 ms | 26.04 ms | 21.18 ms | Index Laboratory: In-memory clone, candidate index creation, timing & plan diff without touching source. |
| **`profile_database_table`** | 16.80 ms | 21.32 ms | 22.23 ms | 17.70 ms | Privacy-preserving profiling: null %, cardinality, distinct counts, safe min/max, masking. |
| **`snapshot_schema`** | 66.86 ms | 75.15 ms | 76.18 ms | 68.35 ms | Canonical JSON schema snapshot generation across 30 tables. |
| **`diff_schemas`** | 13.26 ms | 16.82 ms | 17.89 ms | 13.51 ms | Structural diffing between two schema snapshots, detecting breaking changes. |
| **`review_migration`** | 0.14 ms | 0.28 ms | 1.29 ms | 0.20 ms | High-speed AST/regex static safety review of migration scripts. |

---

## 3. Memory Footprint Profile

Memory allocation was tracked during full execution using Python's `tracemalloc`:

- **Current Memory**: `~720 KB`
- **Peak Memory**: `~806 KB` (`0.79 MB`)

**Key Takeaway**: SQLite Guard MCP maintains an extremely lean memory footprint of under **1 megabyte** peak memory even when querying, profiling, and diffing multi-table databases.

---

## 4. Token Footprint & Agent Context Efficiency

One of SQLite Guard MCP's major architectural differentiators is **LLM context efficiency**:

```
Traditional Multi-Turn Discovery:
  1. list_tables()                    --> Agent receives 30 table names (~150 tokens)
  2. describe_table(table_001)        --> Agent requests table 1 (~300 tokens)
  3. describe_table(table_002)        --> Agent requests table 2 (~300 tokens)
  ... (30 turns x ~400 tokens roundtrip = 12,000+ tokens consumed across 30 roundtrips)

SQLite Guard MCP Zero-Turn Approach:
  1. Read Resource schema://summary   --> Complete bounded schema in 1 turn (~2,400 tokens)
     * Token reduction: ~80%
     * Roundtrip reduction: 30 turns down to 1 turn
```

---

## 5. How to Reproduce Benchmarks

Run the benchmark harness directly from the repository root:

```bash
uv run python benchmarks/run_benchmarks.py
```

Results are printed to stdout and saved in machine-readable JSON format to `benchmarks/results.json`.
