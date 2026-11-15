
# SQLite Guard MCP

[![CI](https://github.com/AtharvaSiddhawar/sqlite-guard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/AtharvaSiddhawar/sqlite-guard-mcp/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A read-only [Model Context Protocol](https://modelcontextprotocol.io/) server for inspecting local SQLite databases. It uses the official MCP Python SDK, SQLite's read-only connection mode, a SQLite authorizer, bounded query execution, and heuristic masking for common credential column names.

> **Security note:** This is defense in depth, not an operating-system sandbox. The process can read any database file its operating-system account can access and that the operator configures. Column-name masking is heuristic and is not a substitute for database-level access controls. See [SECURITY.md](SECURITY.md).

## Features

- Standard MCP stdio transport through the official MCP Python SDK.
- Read-only `SELECT` and `WITH` queries with bound parameters.
- Separate schema, table-listing, and query-plan tools.
- SQLite authorizer denies write operations, attachment, and unapproved PRAGMAs.
- Common credential-like column names are returned as `NULL` at SQLite's authorizer boundary.
- Query timeout, SQLite VM-step budget, row cap, cell cap, and response-size cap.
- BLOB values are represented as bounded Base64 previews rather than raw bytes.

## Requirements

- Python 3.11 or newer.
- The package installs the official `mcp` SDK 2.x automatically.
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
pytest --cov --cov-report=term-missing
python -m build
```

## Run

```bash
sqlite-guard-mcp --db "/absolute/path/to/database.sqlite"
```

Optional limits:

```bash
sqlite-guard-mcp --db "/path/to/database.sqlite" --max-rows 250 --timeout 2 --max-vm-steps 250000
```

You can also set `SQLITE_GUARD_DB` and omit `--db`.

## MCP client configuration

Example Claude Desktop-style configuration (adjust the Python executable and database path for your computer):

```json
{
  "mcpServers": {
    "sqlite-guard": {
      "command": "sqlite-guard-mcp",
      "args": ["--db", "/absolute/path/to/database.sqlite"]
    }
  }
}
```

If the executable is not on the client's PATH, use the full path to the virtual environment's `sqlite-guard-mcp` executable.

## Tools

| Tool | Purpose |
|---|---|
| `read_query(sql, params?)` | Run one read-only `SELECT` or `WITH` query. |
| `list_database_tables()` | List user-defined tables and views. |
| `describe_database_table(table_name)` | Inspect columns, indexes, foreign keys, and masking metadata. |
| `explain_read_query(sql, params?)` | Run `EXPLAIN QUERY PLAN` for a read-only query. |

`params` accepts a JSON object for named parameters or an array for positional parameters. Example: `{"sql":"SELECT name FROM people WHERE id = ?","params":[7]}`.

## Masking behavior

The authorizer masks common names such as `password`, `passwd`, `secret`, `api_key`, `private_key`, `ssn`, `credential`, and common access/session/token fields. Common usage metrics such as `prompt_tokens`, `completion_tokens`, and `total_tokens` are intentionally not masked. These rules are name-based heuristics: review your own schema and do not rely on them as a complete data-loss-prevention system.

## Limits and behavior

- `SELECT` and `WITH` are accepted; writes and `EXPLAIN` statements are not.
- `explain_read_query` accepts only `SELECT` and `WITH` input and adds `EXPLAIN QUERY PLAN` itself.
- The default row limit is 250, with a hard cap of 1,000.
- Query execution is bounded by a timeout and SQLite VM-step budget.
- Text cells, BLOB previews, columns, and total serialized response size are capped.
- Multiple SQL statements in one call are rejected by SQLite's single-statement execution API.

## Skill instructions

The agent-facing usage guide is in [`SKILL.md`](SKILL.md).

## License

MIT. See [LICENSE](LICENSE).

