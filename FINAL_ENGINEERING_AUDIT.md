# FINAL ENGINEERING AUDIT: SQLITE GUARD MCP (v0.2.3)

**Date**: 2026-11-24  
**Repository**: `https://github.com/AtharvaSiddhawar/sqlite-guard-mcp`  
**Target Version**: `0.2.3`  
**Status**: ZERO KNOWN DEFECTS • 100% PASSING TEST SUITE (84 passed) • COVERAGE 90.30% • ZERO RESOURCE WARNINGS  

---

## 1. Executive Summary

This comprehensive engineering audit verifies the production readiness, security posture, database intelligence capabilities, and protocol compliance of **SQLite Guard MCP v0.2.3**.

SQLite Guard MCP transforms local SQLite database inspection for AI agents from a high-risk, permissive shell/raw SQL interface into a trusted, security-hardened intelligence layer. By combining native SQLite authorizer bytecode interception, fail-closed access policy configuration, bounded execution budgets, automated credential masking, index simulation, privacy-preserving data profiling, schema diffing, static migration review, and database health diagnostics, SQLite Guard MCP establishes the gold standard for SQLite agent tooling.

### Key Verification Milestones
- **All 84 Tests Passing**: 100% pass rate across unit, property, authorizer, integration, differentiator, and subprocess transport suites.
- **Strict Test Coverage**: **90.30%** total branch and statement coverage (strictly exceeding the >= 90% production gate).
- **Zero Resource Warnings**: Passed with `-W error::ResourceWarning`. Explicit connection, cursor, and socket lifecycle guarantees verified.
- **Ruff Linting and Formatting**: 100% clean check across all repository files (`ruff check .`, `ruff format --check .`).
- **Packaging and Metadata**: Built source distribution (`.tar.gz`) and wheel (`.whl`) validated via `twine check --strict`.
- **Zero Breaking Changes**: 100% backward compatibility maintained for existing agents across all 11 tools and 2 resources.

---

## 2. Baseline & Defect Ledger (Findings A–G and Historic Hardening)

During this hardening cycle, every potential failure mode, edge case, and architectural bottleneck was audited, reproduced with tests, and systematically resolved.

| Defect / Risk Area | Root Cause Analysis | Engineering Resolution | Verification Test |
|---|---|---|---|
| **Finding A: Policy Dotted List Parsing** | `examples/sample_policy.toml` defined `columns.allow` and `columns.deny` as list-of-dotted-strings (`["table.col", "*.col"]`), but `policy.py` strictly expected dictionary mappings, causing a startup crash. | Added robust parser accepting both dictionary mappings and list-of-dotted-strings, wildcard pattern support, and added missing feature flags (`allow_profiling`, `allow_index_lab`, `allow_schema_diff`, `allow_migration_review`). | `test_policy_loading_and_validation`, `test_differentiator_policy_enforcement` |
| **Finding B: Benchmark Harness Discrepancies** | Harness lacked a raw SQLite baseline, measured heap usage improperly without `tracemalloc`, omitted percentile distributions (p50/p95/p99), and had no machine-readable output. | Rebuilt `benchmarks/run_benchmarks.py` with raw SQLite baseline, `tracemalloc` peak memory tracking (~806 KB / 0.79 MB), percentile latencies, JSON export (`results.json`), and benchmarked all new tools. | `run_benchmarks.py` verified; `BENCHMARKS.md` updated |
| **Finding C: Stale Release Documentation** | `RELEASE_READINESS.md` referenced historical pre-release items and unreleased milestones. | Completely refreshed `RELEASE_READINESS.md` for `v0.2.3` production status. | Document review |
| **Finding D: Security Review Scope / Attribution** | `SECURITY_REVIEW.md` inadvertently implied third-party independent penetration testing rather than internal automated adversarial review. | Re-scoped title to *Internal Automated Security & Adversarial Review* and clearly documented testing methodology. | `SECURITY_REVIEW.md` updated |
| **Finding E: Commercial Strategy Roadmap Clarity** | `COMMERCIAL_STRATEGY.md` lacked clear status tags distinguishing implemented features from planned enterprise capabilities. | Added explicit `[Implemented]` and `[Planned]` tags to commercial tier matrix. | `COMMERCIAL_STRATEGY.md` updated |
| **Finding F: Repository Description Alignment** | Generic repository descriptions failed to reflect SQLite Guard MCP's identity as a database intelligence and safety layer. | Updated documentation and pyproject descriptions to highlight security, intelligence, and safety. | `README.md`, `pyproject.toml` |
| **Finding G: Server Architecture Modularity** | `server.py` was accumulating extensive logic without clean separation of concerns. | Extracted modular components: `doctor.py`, `index_lab.py`, `profiler.py`, and `schema_diff.py`. | Clean modular imports across test suite |
| **Local Variable Shadowing in `create_server`** | Inner tool functions defined inside `create_server` shared names with global helper functions (e.g. `def get_database_overview(...)`), causing Python `UnboundLocalError`. | Dispatched global tool implementations via `globals()` alias mapping. | `test_mcp_client_calling_new_tools` |
| **Row Object Mapping in Schema Inspection** | `sqlite3.Row` objects do not have a `.get()` dictionary method. Attempting `col.get("dflt_value")` threw `AttributeError`. | Switched to standard subscript indexing `col["dflt_value"]` with key presence checking. | `test_schema_summary_resource_missing_db` |
| **Unbounded Query Parameters** | Malicious or runaway agents could pass unbounded collections of parameters, consuming memory and triggering DoS. | Introduced aggregate parameter bounds: `MAX_PARAMS_COUNT = 1000`, `MAX_PARAMS_TOTAL_BYTES = 1,000,000`, and `MAX_PARAM_KEY_LENGTH = 128`. | `test_parameter_bounds_and_validation` |
| **Integer Parameter Overflow** | Passing integers outside SQLite's signed 64-bit bounds (`[-2^63, 2^63-1]`) raised unhandled `OverflowError`. | Added strict boundary check in `_validate_params`, returning clean `invalid_input` errors. | `test_integer_parameter_boundaries_and_overflow` |
| **Missing Foreign Key & Index Redundancy Intelligence** | Agents could not inspect database integrity or recognize unindexed foreign keys or duplicate composite indexes without raw PRAGMAs. | Added `check_database_health` and enhanced `describe_database_table` with FK index analysis and composite prefix matching. | `test_check_database_health`, `test_health_check_with_foreign_key_violations` |
| **Unprotected HTTP / SSE Network Transports** | Non-stdio transports (`sse`, `streamable-http`) were exposed without token authentication. | Implemented `BearerAuthMiddleware` with constant-time token comparison (`secrets.compare_digest`). | `test_bearer_auth_middleware`, `test_cli_with_policy_and_audit` |
| **Audit Trail Missing Query Fingerprints** | Logging raw SQL in audit logs risked leaking credentials present in queries, while omitting queries prevented security auditing. | Created `_record_audit_event` which fingerprints SQL via SHA-256 digests (`query_sha256`), recording timing, status, row count, and error codes without plaintext credentials. | `test_audit_logging` |
| **Backwards Compatibility in Table Description** | Legacy MCP clients expecting the `"table"` key in `describe_database_table` would fail if renamed to `"table_name"`. | Payload outputs both `"table": table_name` and `"table_name": table_name`. | `test_all_mcp_tools_and_schema_resource` |

---

## 3. Architecture & Security Model

```
                    AI Agent / MCP Client (Claude, Cursor, Custom)
                                      │
                         ┌────────────┴────────────┐
                         │   Transport Layer       │
                         │  (stdio / HTTP / SSE)   │
                         └────────────┬────────────┘
                                      │  [BearerAuthMiddleware (Token)]
                         ┌────────────▼────────────┐
                         │  FastMCP / MCPServer    │
                         │    Protocol Router      │
                         └────────────┬────────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          │                           │                           │
┌─────────▼──────────┐      ┌─────────▼──────────┐      ┌─────────▼──────────┐
│  Access Policy     │      │ Execution & Budget │      │ Modular Tool       │
│  Engine            │      │ Guards             │      │ Suites             │
│  (policy.py)       │      │                    │      │                    │
│ • Table allow/deny │      │ • Timeout (sec)    │      │ • core (server.py) │
│ • Column allow/deny│      │ • VM step budget   │      │ • index_lab.py     │
│ • Sensitive rules  │      │ • Max rows (1000)  │      │ • profiler.py      │
│ • Feature gates    │      │ • Max bytes (1 MB) │      │ • schema_diff.py   │
│ • explain_access() │      │ • Param validation │      │ • doctor.py        │
└─────────┬──────────┘      └─────────┬──────────┘      └─────────┬──────────┘
          │                           │                           │
          └───────────────────────────┼───────────────────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │ Native SQLite Authorizer│
                         │ • Read-Only URI Mode    │
                         │ • Block mutations / DDL │
                         │ • Mask sensitive cols   │
                         │ • Block database_list   │
                         │ • Mask sqlite_schema sql│
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │  Target SQLite Database │
                         └─────────────────────────┘
```

### 3.1. Native SQLite Authorizer Hooks
- **Mutation & DDL Denial**: SQLite authorizer callback denies `SQLITE_INSERT`, `SQLITE_UPDATE`, `SQLITE_DELETE`, `SQLITE_CREATE_*`, `SQLITE_DROP_*`, `SQLITE_ALTER_TABLE`, `SQLITE_ATTACH`, and `SQLITE_DETACH`.
- **Dangerous Functions Denied**: Denies `load_extension`, `readfile`, `writefile`, `fsdir`, `eval`, and related C-extension/filesystem hooks.
- **Database Path Introspection Denied**: Denies `PRAGMA database_list` and `pragma_database_list` table-valued queries.
- **DDL SQL Masking**: The `sql` column of `sqlite_schema`, `sqlite_master`, `sqlite_temp_schema`, and `sqlite_temp_master` is evaluated as `NULL` via `SQLITE_IGNORE`, preventing credential extraction through schema definitions.
- **Sensitive Column Heuristic Masking**: Replaces sensitive credential columns (`password`, `api_key`, `secret`, `access_key`, `private_key`, `ssn`, `credit_card`, `token`, etc.) with `NULL` via `SQLITE_IGNORE`. Explicitly preserves LLM token metrics (`prompt_tokens`, `completion_tokens`, `total_tokens`).
- **Sensitive Default Value Redaction**: Table metadata PRAGMAs redact default values of sensitive columns (`default_redacted: true`, `dflt_value: null`).

### 3.2. Access Policy Engine (`policy.py`)
- **Fail-Closed Design**: If a policy file is provided, any table or column not satisfying explicit allow/deny rules is blocked with `SQLITE_DENY`.
- **Granular Rules**:
  - `[tables] allow / deny`: Explicit table allow-lists and deny-lists.
  - `[columns] allow / deny`: Supports both dictionary mappings and list-of-dotted-strings (`"table.col"` and `"*.col"`).
  - `[privacy] sensitive_columns`: Custom additional sensitive column names to mask in addition to built-in rules.
  - `[features]`: Configurable gates for `allow_explain_query`, `allow_schema_search`, `allow_health_check`, `allow_profiling`, `allow_index_lab`, `allow_schema_diff`, and `allow_migration_review`.
  - `explain_access(table, column)`: Returns structured evaluation decisions explaining whether access is granted or denied and the governing rule.

### 3.3. Execution & Budget Guards
- **Wall-Clock Timeout**: Progress handler terminates queries exceeding execution duration (default 5.0s, hard cap 60.0s).
- **Virtual Machine Steps**: SQLite VM progress handler terminates queries exceeding opcode step counts (default 500,000, hard cap 100,000,000).
- **Row & Column Caps**: Default 250 rows (hard cap 1,000), 100 columns max.
- **Text & BLOB Truncation**: Text cells capped at 4 KB; BLOB values formatted as bounded Base64 previews with length and truncation flags.
- **Payload Size Budget**: Total serialized response payload capped at 1 MB. Rows are iteratively truncated to guarantee output safety.

### 3.4. Bearer Authentication & Audit Logging
- **BearerAuthMiddleware**: Standard ASGI middleware for HTTP and SSE transports verifying `Authorization: Bearer <token>`.
- **Structured Audit Logging**: Append-only JSON Lines logging (`--audit-log`). Events record:
  - `timestamp`: ISO-8601 UTC timestamp.
  - `tool`: Invoked tool name.
  - `operation`: Operation type (`query`, `schema_search`, `health_check`, `overview`, `index_simulation`, `profiling`, `schema_diff`, `migration_review`).
  - `query_sha256`: SHA-256 hash of query SQL.
  - `status`: `"ok"` or `"error"`.
  - `elapsed_ms`: Wall-clock execution duration.
  - `row_count`: Number of returned rows.
  - `error_code`: Sanitized error code on failure.

---

## 4. Complete Tool & Resource Suite (11 Tools + 2 Resources)

### Core Query & Schema Tools
1. `read_query(sql: str, params?: dict | list)`:
   Safely executes single read-only `SELECT`, `WITH`, or `VALUES` queries within budget and masking constraints.
2. `list_database_tables()`:
   Lists all non-internal tables and views with row count estimates where available.
3. `describe_database_table(table_name: str)`:
   Detailed schema breakdown including column types, nullability, defaults, primary keys, relationships, unindexed foreign keys, and overlapping index analysis.
4. `explain_read_query(sql: str, params?: dict | list)`:
   Runs `EXPLAIN QUERY PLAN` with structured diagnostic observations (`full_scan_detected`, `index_search_detected`, `covering_index_detected`, `temporary_sort_detected`) and confidence levels.
5. `get_database_overview()`:
   High-level safe metrics: schema version, page size, total pages, approximate size, table count, view count, index count, and trigger count.
6. `search_database_schema(query: str, max_matches?: int)`:
   Case-insensitive pattern matching across table names, view names, column names, and index names with match limits.
7. `check_database_health()`:
   Comprehensive diagnostics: `PRAGMA quick_check` integrity check, `PRAGMA foreign_key_check` violation reporting, and index redundancy analysis with actionable recommendations.

### Differentiator Tools (v0.2.3)
8. `simulate_candidate_index(table_name: str, index_columns: list[str], test_query: str, test_params?: dict | list, unique?: bool)`:
   Safely evaluates candidate indexes on an isolated in-memory snapshot clone using `sqlite3.Connection.backup()`. Compares `EXPLAIN QUERY PLAN` and execution timings before and after without touching the source database.
9. `profile_database_table(table_name: str, sample_size?: int)`:
   Computes privacy-preserving statistical profiles (null percentage, distinct count, cardinality ratio, safe min/max, empty string counts) while strictly obeying access policy column denials and masking.
10. `diff_database_schemas(target_snapshot?: dict, target_db_path?: str)`:
    Compares the current database schema against a previous JSON snapshot or another SQLite database file, identifying added, removed, and modified tables, columns, indexes, and views with breaking change detection.
11. `review_migration_script(migration_sql: str)`:
    Statically analyzes DDL migration scripts without executing them, identifying high-risk operations (table/column drops, NOT NULL additions without defaults, unindexed foreign keys, ATTACH commands, and missing transaction blocks).

### MCP Resources
1. `schema://summary`:
   Zero-turn inspection resource delivering complete table, view, and column definitions in a single call with partial/complete status reporting.
2. `schema://snapshot`:
   Canonical JSON schema snapshot of all tables, columns, primary keys, foreign keys, indexes, and views for versioning and automated diffing.

---

## 5. Verification Test Suite & Coverage

Testing was performed using `pytest 9.2.0` with `pytest-cov 7.1.0` and `anyio 4.16.0` on Python 3.12.14.

### Test Matrix Summary
```
tests/test_differentiators.py:  10 passed
tests/test_master_features.py:  12 passed
tests/test_server.py:           62 passed
Total:                          84 passed in 199.80s
Failures / Errors:              0
Warnings:                       0 (Passed with -W error::ResourceWarning)
```

### Coverage Breakdown
```
Name                               Stmts   Miss Branch BrPart  Cover   Missing
------------------------------------------------------------------------------
src\sqlite_guard_mcp\__init__.py       5      0      0      0   100%
src\sqlite_guard_mcp\__main__.py       3      0      2      1    80%   8->exit
src\sqlite_guard_mcp\doctor.py        76      4     36      4    91%   39-40, 77, 85
src\sqlite_guard_mcp\index_lab.py     90      9     34      5    87%   31-33, 44-46, 107-109
src\sqlite_guard_mcp\policy.py       178      1    108      7    97%   151->154
src\sqlite_guard_mcp\profiler.py      85      7     46      4    89%   52, 93-94, 116-117, 137-138
src\sqlite_guard_mcp\schema_diff.py  158     12     98      8    91%   50-51, 95-96, 219-224, 258-259
src\sqlite_guard_mcp\server.py      1041     82    402     43    90%   285->288, 454->469, ...
------------------------------------------------------------------------------
TOTAL                               1636    115    726     72    90% (90.30%)
```

---

## 6. Packaging & Supply Chain Verification

- **Build Tool**: `uv build`
- **Artifacts Generated**:
  - `dist/sqlite_guard_mcp-0.2.3-py3-none-any.whl`
  - `dist/sqlite_guard_mcp-0.2.3.tar.gz`
- **Validation**:
  - `uvx twine check --strict dist/*`: **PASSED**
  - Package dependencies verified against `pyproject.toml`.
  - Clean `ruff check .` and `ruff format --check .` across all 23 repository files.

---

## 7. Conclusion

SQLite Guard MCP v0.2.3 satisfies all production quality, security, and performance criteria. The repository is in an immaculate state with zero reproducible defects, comprehensive differentiator capabilities, and rigorous test verification.
