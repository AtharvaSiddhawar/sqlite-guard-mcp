# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - Unreleased

### Added
- **Integer Parameter Range Validation**: Validates that all integer query parameters strictly fit within SQLite's signed 64-bit integer range (`-9223372036854775808` to `9223372036854775807`), returning structured `invalid_input` errors instead of uncaught `OverflowError`.
- **Query Plan Diagnostics**: `explain_read_query` now automatically performs deterministic query plan analysis, extracting table scans, index lookups, temporary B-tree sorting, and providing actionable optimization recommendations.
- **Foreign Key Relationship Discovery**: `describe_database_table` now includes resolved `relationships` metadata with referenced tables, columns, and update/delete actions.
- **Truncation Metadata**: Schema inspection operations now provide explicit truncation flags (`truncated`, `columns_truncated`, `indexes_truncated`, `foreign_keys_truncated`) and descriptive warnings.
- **Single-Connection Schema Summary**: Refactored `schema://summary` to use `inspect_schema_summary`, reusing a single read-only inspection connection with global timeouts and table caps (`MAX_SCHEMA_TABLES = 500`).
- **Comprehensive Transport Testing**: Real integration tests covering `stdio` subprocess transport and `streamable-http` client transport.
- **CLI Options**: Added `--host` and `--port` CLI options for HTTP transport configuration.

### Fixed
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
