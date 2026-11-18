# SQLite Guard MCP

[![CI](https://github.com/AtharvaSiddhawar/sqlite-guard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/AtharvaSiddhawar/sqlite-guard-mcp/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A read-only, security-hardened [Model Context Protocol](https://modelcontextprotocol.io/) server for inspecting local SQLite databases. It leverages the official MCP Python SDK, SQLite's read-only URI mode, native SQLite authorizer enforcement, bounded query execution, and heuristic masking for sensitive columns and credentials.

> **Security note:** This is defense in depth, not an operating-system sandbox. The process can read any database file its operating-system account can access and that the operator configures. Column-name masking is heuristic and is not a substitute for database-level access controls. See [SECURITY.md](SECURITY.md).

## Features

- Standard MCP transports (`stdio`, `sse`, and `streamable-http`) through the official MCP Python SDK.
- HTTP / SSE Bearer Token Authentication via `BearerAuthMiddleware` (`--auth-token` or `SQLITE_GUARD_AUTH_TOKEN`).
- Read-only `SELECT`, `WITH`, and `VALUES` queries with strictly validated bound parameters.
- Built-in schema inspection & database intelligence:
  - `list_database_tables`: List tables and views.
  - `describe_database_table`: Detailed schema inspection with unindexed foreign keys and overlapping index diagnostics.
  - `explain_read_query`: Query plan diagnostics with structured observations and confidence metrics.
  - `get_database_overview`: High-level metrics (page count, schema version, table/index/view counts, approximate size).
  - `search_database_schema`: Bounded case-insensitive search across tables, views, columns, and indexes.
  - `check_database_health`: Quick integrity check, foreign key violation diagnostics, and index redundancy analysis.
- MCP Resource support: `schema://summary` provides zero-turn inspection of tables and schemas.
- Granular Access Policy Engine (`--policy` / `SQLITE_GUARD_POLICY`): Fail-closed TOML access rules for table/column allow & deny lists, custom sensitive column masking, and feature toggles.
- Tamper-evident Audit Logging (`--audit-log` / `SQLITE_GUARD_AUDIT_LOG`): Structured JSON Lines logging with SHA-256 query fingerprinting and privacy-safe metadata.
- Native SQLite authorizer strictly denies write operations, database attachments, dangerous functions (`load_extension`, `readfile`, `writefile`, `fsdir`, `eval`, etc.), and unapproved PRAGMAs.
- Database path introspection is blocked: `PRAGMA database_list` and `pragma_database_list` table-valued queries are denied at the authorizer boundary.
- Schema DDL definitions in `sqlite_schema` / `sqlite_master` have their `sql` column masked as `NULL` to prevent secret leakage through `CREATE TABLE` defaults and check constraints.
- Sensitive credential columns (`password`, `api_key`, `access_key`, `secret`, `private_key`, `credit_card`, etc.) are masked as `NULL` at SQLite's authorizer boundary.
- Sensitive default values in table metadata (`describe_database_table` and `schema://summary`) are redacted (`default_redacted: true`, `dflt_value: null`) while safe defaults are preserved.
- Usage token metrics (`prompt_tokens`, `completion_tokens`, `total_tokens`, etc.) are explicitly preserved.
- Hard resource bounds: query timeout, SQLite VM-step budget, row cap, column cap, text cell length cap, aggregate parameter byte/count caps, and total response byte size cap.
- BLOB values are returned as bounded Base64 previews rather than raw byte dumps.

## Requirements

- Python 3.11 or newer.
- The package installs the official `mcp` SDK 2.x and `pydantic` automatically.
- An existing SQLite database file readable by the current operating-system account.

## Install from source

```bash
git clone https://github.com/AtharvaSiddhawar/sqlite-guard-mcp.git
cd sqlite-guard-mcp
python -m pip install .
```

For development:

```bash
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
pytest --cov --cov-report=term-missing
python -m build
```

## Run

```bash
sqlite-guard-mcp --db "/absolute/path/to/database.sqlite"
```

Optional limits, policy, audit, and transport flags:

```bash
sqlite-guard-mcp --db "/path/to/database.sqlite" \
  --max-rows 250 \
  --timeout 2.0 \
  --max-vm-steps 250000 \
  --policy "/path/to/policy.toml" \
  --audit-log "/path/to/audit.jsonl" \
  --transport streamable-http \
  --host 127.0.0.1 \
  --port 8000 \
  --auth-token "your-bearer-secret"
```

You can also set environment variables:
- `SQLITE_GUARD_DB`: Path to database file.
- `SQLITE_GUARD_POLICY`: Path to TOML policy file.
- `SQLITE_GUARD_AUDIT_LOG`: Path to JSONL audit log file.
- `SQLITE_GUARD_AUTH_TOKEN`: Bearer token for HTTP/SSE transports.

Check version with `sqlite-guard-mcp --version`.

## Access Policy (TOML)

Fine-grained access control can be specified in a TOML policy file:

```toml
[tables]
allow = ["customers", "orders", "products"]
deny = ["admin_users", "internal_migrations"]

[columns]
allow = ["customers.id", "customers.name", "customers.created_at"]
deny = ["*.internal_notes", "orders.margin"]

[privacy]
sensitive_columns = ["ssn_custom", "secret_pin", "tax_identifier"]

[features]
allow_explain_query = true
allow_schema_search = true
allow_health_check = true
```

## Tools

| Tool | Purpose |
|---|---|
| `read_query(sql, params?)` | Run one read-only `SELECT`, `WITH`, or `VALUES` query with bound parameters. |
| `list_database_tables()` | List user-defined tables and views. |
| `describe_database_table(table_name)` | Inspect columns, types, primary keys, indexes, foreign keys, unindexed FKs, and index overlap. |
| `explain_read_query(sql, params?)` | Run `EXPLAIN QUERY PLAN` with structured observations and confidence scoring. |
| `get_database_overview()` | Get safe database metrics: schema version, page size, page count, table/index/view counts. |
| `search_database_schema(query, max_matches?)` | Search table names, column names, view names, and index names case-insensitively. |
| `check_database_health()` | Run quick integrity check, check foreign key integrity, and report redundant indexes. |

`params` accepts a JSON object for named parameters or an array for positional parameters. Example: `{"sql":"SELECT name FROM people WHERE id = ?","params":[7]}`.

## Resources

| Resource URI | Purpose |
|---|---|
| `schema://summary` | Provides a complete JSON summary of all tables, views, and columns without requiring multiple tool calls. |

## Masking behavior

The authorizer masks common credential and secret columns such as `password`, `passwd`, `pwd`, `secret`, `api_key`, `access_key`, `auth_key`, `private_key`, `client_secret`, `ssn`, `social_security`, `credit_card`, `card_number`, `cvv`, `bank_account`, and session tokens.

Common usage metrics such as `prompt_tokens`, `completion_tokens`, `input_tokens`, `output_tokens`, and `total_tokens` are intentionally not masked. These rules are name-based heuristics: review your schema and do not rely on them as an absolute data-loss-prevention system.

## Limits and behavior

- `SELECT`, `WITH`, and `VALUES` queries are accepted; mutations and write CTEs are rejected.
- `explain_read_query` accepts read-only queries and prepends `EXPLAIN QUERY PLAN` safely.
- The default row limit is 250, with a hard limit of 1,000.
- Query execution is strictly bounded by wall-clock timeout and SQLite VM-step budget.
- Text cells (4 KB max), BLOB previews (4 KB max), columns (100 max), and total serialized response size (1 MB max) are capped.
- Multiple SQL statements in one call are rejected by SQLite's single-statement execution boundary.

## Skill instructions

The agent-facing usage guide is in [`SKILL.md`](SKILL.md).

## License

MIT. See [LICENSE](LICENSE).
