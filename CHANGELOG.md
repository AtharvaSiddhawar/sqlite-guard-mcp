# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3] - 2026-11-24

### Added
- **Index Laboratory (`simulate_candidate_index`)**: Safe candidate index testing on isolated disposable database snapshots using SQLite's online backup API. Compares `EXPLAIN QUERY PLAN` observations and execution latency before and after applying candidate index proposals without modifying the source database.
- **Privacy-Preserving Data Profiling (`profile_database_table`)**: Computes column-level null ratios, cardinality estimations, distinct counts, safe min/max bounds, and empty string counts while enforcing column security policies and masking sensitive credential columns.
- **Canonical Schema Snapshot & Diff (`snapshot_schema`, `diff_schemas`, `diff_database_schemas`)**: Generates canonical JSON schema snapshots and structural diffs between database states or environments, detecting added/removed tables, column alterations, missing indexes, and breaking changes.
- **Static Migration Safety Review (`review_migration`, `review_migration_script`)**: High-speed AST/regex static safety analysis for SQLite migration scripts without executing SQL. Detects destructive operations (`DROP TABLE`, `DROP COLUMN`), non-constant `NOT NULL` additions, missing transaction boundaries, dangerous PRAGMAs, and database attachment attempts.
- **System Doctor & Environment Diagnostics (`doctor.py`, `--doctor`)**: CLI diagnostic utility verifying platform, Python version, SQLite library version, compile options (`ENABLE_FTS5`, `ENABLE_JSON1`, `ENABLE_RTREE`), environment variables, and target database integrity (`quick_check`, foreign key checks).
- **Policy Validation & Explain Commands (`--validate-policy`, `--explain-policy-table`)**: CLI subcommands to validate policy files and explain access decisions for specific tables and columns.
- **Enhanced Access Policy Engine**: Added support for dotted `table.column` and wildcard `*.column` rules in `columns.allow` and `columns.deny`, as well as feature flag controls (`allow_profiling`, `allow_index_lab`, `allow_schema_diff`, `allow_migration_review`).
- **New MCP Resource**: Added `schema://snapshot` exposing full canonical schema definitions.

### Fixed
- **Policy Loading of Dotted Column Lists (Finding A)**: Resolved `ValueError: columns.allow must be a mapping of table name to column lists` when loading dotted lists from `examples/sample_policy.toml`.
- **Query Explain Feature Gate**: Enforced `allow_explain_query` policy check in `explain_query`.
- **Benchmark Suite Realism & Observability (Finding B)**: Rebuilt `benchmarks/run_benchmarks.py` to measure raw SQLite baseline latency, `tracemalloc` peak memory consumption (< 1 MB), and percentile latencies (p50, p95, p99), exporting machine-readable output to `benchmarks/results.json`.
- **Release Documentation Alignment (Finding C)**: Updated `RELEASE_READINESS.md` to reflect live PyPI state (`0.2.0`, `0.2.2`) and prepare for `0.2.3`.
- **Accurate Security Review Scope (Finding D)**: Updated `SECURITY_REVIEW.md` header to explicitly state internal automated adversarial review rather than an external independent audit.
- **Commercial Roadmap Clarification (Finding E)**: Updated `COMMERCIAL_STRATEGY.md` with explicit status indicators for implemented open-source core features versus planned commercial roadmap items.

## [0.2.2] - 2026-11-23

### Added
- **Fail-Closed Access Policy Engine**: Introduced `policy.py` supporting fine-grained TOML access configuration with table and column allow & deny rules, custom sensitive column masking, and feature gates (`allow_explain_query`, `allow_schema_search`, `allow_health_check`).
- **Database Intelligence Suite**:
  - `get_database_overview`: Safe database-level metrics including schema version, page count, page size, approximate size, and table/index/view counts.
  - `search_database_schema`: Rapid case-insensitive pattern search across tables, views, columns, and indexes.
  - `check_database_health`: Database health diagnostics including `quick_check`, `foreign_key_check`, and redundant composite index detection.
- **Bearer Token Authentication**: Added `BearerAuthMiddleware` securing HTTP and SSE endpoints with constant-time token verification (`--auth-token` or `SQLITE_GUARD_AUTH_TOKEN`).
- **Privacy-Safe Audit Logging**: Appends tamper-evident structured JSON Lines records containing SHA-256 query fingerprints, operation types, timing, row counts, and sanitized error codes without exposing sensitive plaintext query text.
- **Aggregate Parameter Bounds**: Enforces limits on parameter count (`MAX_PARAMS_COUNT = 1000`), total serialized parameter payload (`MAX_PARAMS_TOTAL_BYTES = 1,000,000`), and named parameter key length (`MAX_PARAM_KEY_LENGTH = 128`).
- **Integer Parameter Range Validation**: Validates that all integer query parameters strictly fit within SQLite's signed 64-bit integer range (`-9223372036854775808` to `9223372036854775807`), returning structured `invalid_input` errors instead of uncaught `OverflowError`.
- **Query Plan Diagnostics & Observability**: `explain_read_query` performs deterministic query plan analysis supporting spaces, quotes, and aliases in table/index names. Exposes structured `observations` (`full_scan_detected`, `index_search_detected`, `covering_index_detected`, `temporary_sort_detected`) and confidence levels.
- **Index Intelligence**: `describe_database_table` analyzes indexes to detect unindexed foreign keys and overlapping/duplicate composite index definitions with evidence-based recommendations.
- **Foreign Key Relationship Discovery**: `describe_database_table` includes resolved `relationships` metadata with referenced tables, columns, and update/delete actions.
- **Accurate Truncation Metadata**: Implemented limit-plus-one metadata retrieval distinguishing collections exactly at limits from truncated collections. Exposes explicit flags (`truncated`, `tables_truncated`, `columns_truncated`, `indexes_truncated`, `foreign_keys_truncated`, `response_truncated`, `time_truncated`).
- **Resilient Partial-Status Schema Summaries**: Refactored `schema://summary` to use bounded SQL queries and record structured warnings for uninspectable objects while preserving valid metadata with clear `status: "complete"` or `"partial"` reporting.
- **Clean Socket Lifecycle**: Graceful server shutdown in HTTP transport integration tests eliminating unclosed socket warnings.
- **Comprehensive Transport Testing**: Real integration tests covering `stdio` subprocess transport and `streamable-http` client transport.
- **CLI Options**: Added `--policy`, `--audit-log`, `--auth-token`, `--host`, and `--port` CLI options.

### Fixed
- **Resolved CI Lint Blocker in `__init__.py`**: Removed duplicate symbol redefinitions (`MAX_PARAMS_COUNT`, `MAX_PARAMS_TOTAL_BYTES`, `MAX_PARAM_KEY_LENGTH`) resolving Ruff `I001` and `F811` errors.
- **Release Workflow Coverage Source**: Aligned `--cov=src/sqlite_guard_mcp` in `.github/workflows/release.yml` with `pyproject.toml` and `ci.yml`.
- **Backward-Compatible Schema Payload**: Added dual `"table"` and `"table_name"` keys in `describe_table` to guarantee 100% backward compatibility for existing MCP agents.
- **Exception Ordering in `execute_guarded_query`**: Caught `sqlite3.ProgrammingError` before `sqlite3.DatabaseError` to prevent multi-statement and invalid parameter errors from being shadowed as generic database failures.
- **Coverage Configuration**: Resolved pytest-cov `CoverageWarning: Module sqlite_guard_mcp was previously imported, but not measured (module-not-measured)` by targeting the source directory `src/sqlite_guard_mcp`.
- **Schema Default Redaction**: Redacted sensitive default values in `PRAGMA table_xinfo` metadata across all tools and schema resources.

## [0.2.0] - 2026-11-16

### Added
- Initial security-hardened read-only SQLite Model Context Protocol (MCP) server.
- Support for `read_query`, `list_database_tables`, `describe_database_table`, and `explain_read_query` tools.
- Resource provider for `schema://summary`.
- SQLite authorizer blocking mutations, DDL, database attachment, and dangerous functions.
- Sensitive-column heuristic masking with token metric preservation.
