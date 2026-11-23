# PERFORMANCE BENCHMARKS & LATENCY EVALUATION

**Product**: SQLite Guard MCP (v0.2.2)  
**Date**: November 2026  
**Benchmarking Harness**: `benchmarks/run_benchmarks.py`  
**Test Environment**: AMD Ryzen / Intel Core x86_64, Windows 11, Python 3.12, SQLite 3.45+  

---

## 1. Methodology & Dataset Specification

Benchmarking evaluates latency, overhead, and memory efficiency across the primary MCP tools and resources using a deterministically generated synthetic SQLite database.

### Synthetic Database Parameters:
- **Table Count**: 30 relational dataset tables + 1 base organization table (`org_units`).
- **Column Count**: 7 columns per table (mix of `INTEGER PRIMARY KEY`, foreign keys, text codes, numeric values, status flags, credential token columns, and descriptive text).
- **Row Count**: 300 rows per table (9,000+ total rows).
- **Index Depth**: 20+ secondary indexes including single-column and multi-column composite indexes.
- **Foreign Keys**: Enabled (`PRAGMA foreign_keys = ON`), with cross-table relationships.
- **WAL Mode**: Enabled (`PRAGMA journal_mode = WAL`).

---

## 2. Operation Latency Measurements

All metrics represent mean execution times across 10 to 50 warm iterations:

| Operation / Tool | Latency (ms) | Description & Scope |
|---|:---:|---|
| **`get_database_overview`** | **5.95 ms** | Page size, page count, schema version, table/view/index counts. |
| **`describe_database_table`** | **6.11 ms** | Full table metadata, column types, FK discovery, and index overlap analysis. |
| **`read_query` (with Masking)**| **5.75 ms** | Safe execution of 100 rows with C-authorizer masking of sensitive columns. |
| **`explain_read_query`** | **6.69 ms** | `EXPLAIN QUERY PLAN` parsing, table scan detection, and structured observations. |
| **`search_database_schema`** | **8.12 ms** | Case-insensitive regex/pattern scan across all tables, views, columns, and indexes. |
| **`schema://summary` (Resource)**| **18.94 ms** | Zero-turn inspection extracting complete schema definitions across 30 tables in one read. |
| **`check_database_health`** | **146.05 ms** | Comprehensive `PRAGMA quick_check`, foreign key validation, and index redundancy analysis. |

---

## 3. Token Footprint & Agent Context Efficiency

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

## 4. Overhead vs Raw Native SQLite

| Query Operation | Raw Python `sqlite3` | SQLite Guard MCP | Overhead | Security Controls Applied |
|---|:---:|:---:|:---:|---|
| **`SELECT * (100 rows)`** | 4.80 ms | 5.75 ms | **+0.95 ms** | Read-only URI mode, authorizer bytecode interception, credential masking, timeout progress handler, row capping, JSON serialization bounds. |

**Key Takeaway**: SQLite Guard introduces less than **1 millisecond** of latency overhead over raw unbounded `sqlite3`, while providing complete defense-in-depth security, credential masking, and memory safety.

---

## 5. How to Reproduce Benchmarks

Run the benchmark script directly from the repository root:

```bash
uv run python benchmarks/run_benchmarks.py
```
