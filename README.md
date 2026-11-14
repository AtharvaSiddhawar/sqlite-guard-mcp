# sqlite-guard-mcp

[[https://github.com/AtharvaSiddhawar/sqlite-guard-mcp/actions/workflows/ci.yml/badge.svg]](https://github.com/AtharvaSiddhawar/sqlite-guard-mcp/actions/workflows/ci.yml)
[[https://img.shields.io/badge/python-3.10%2B-blue.svg]](https://github.com/AtharvaSiddhawar/sqlite-guard-mcp)
[[https://img.shields.io/badge/License-MIT-green.svg]](https://github.com/AtharvaSiddhawar/sqlite-guard-mcp/blob/main/LICENSE)

**A deterministic, zero-setup, sandboxed Model Context Protocol (MCP) server for local SQLite databases.**

Most SQLite MCP servers rely on naive regular-expression checks (`^\s*(SELECT|WITH)\b`) that fail against write-capable queries or `EXPLAIN DELETE`, dump sensitive columns (`password`, `api_key`, `secret_token`) straight into the LLM context on `SELECT *`, or lock up on unindexed Cartesian joins because agents cannot run `PRAGMA index_list` or `EXPLAIN QUERY PLAN`.

`sqlite-guard-mcp` enforces security directly at the SQLite C-API boundary using Python's standard library [`sqlite3.Connection.set_authorizer()`](https://www.sqlite.org/c3ref/set_authorizer.html) (SQLite Compile-Time Authorization Callbacks), `connection.setlimit()`, and `sqlite3.Connection.set_progress_handler()`—with **zero external runtime dependencies**.

## 10-Second Zero-Setup Quickstart (`uvx`)

Drop this block into your `claude_desktop_config.json` to run `sqlite-guard-mcp` directly via `uvx` without cloning a repo or managing virtual environments:

```json
{
  "mcpServers": {
    "sqlite-guard": {
      "command": "uvx",
      "args": [
        "--from",
        "git+[https://github.com/AtharvaSiddhawar/sqlite-guard-mcp](https://github.com/AtharvaSiddhawar/sqlite-guard-mcp)",
        "sqlite-guard-mcp",
        "--db",
        "/absolute/path/to/your/database.sqlite"
      ]
    }
  }
}
```

*(Once published to PyPI, you can omit `"--from", "git+https://..."` and run `"uvx", "sqlite-guard-mcp", "--db", "/path/to/db.sqlite"` directly.)*

## What `sqlite-guard-mcp` Enforces at the C-API Layer

| Security Layer | Mechanism in `src/sqlite_guard_mcp/server.py` | Protection Provided |
|---|---|---|
| Read-Only Descriptor & Defensive PRAGMAs | `mode=ro`, `PRAGMA query_only = ON`, `PRAGMA trusted_schema = OFF` | Prevents file creation, disk writes, and malicious SQL functions inside database schemas |
| Compile-Time Authorizer (`_authorize`) | `sqlite3_set_authorizer` | Blocks `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ATTACH`, `EXPLAIN DELETE`, and `PRAGMA` mutations at statement compilation |
| Precision C-API Secret Masking | Returns `sqlite3.SQLITE_IGNORE` on `sqlite3.SQLITE_READ` | Automatically masks `password`, `passwd`, `secret`, `api_key`, `private_key`, `ssn`, and `*_token` columns as `NULL` in compiled bytecode (blocking both `SELECT *` and blind `WHERE password LIKE ...` probes) while leaving benign LLM usage columns like `prompt_tokens` intact |
| Index & Query-Plan Introspection | Permits `PRAGMA table_info`, `PRAGMA index_list`, `PRAGMA index_info`, `PRAGMA foreign_key_list`, and `EXPLAIN QUERY PLAN` | Lets agents inspect indexes and verify query plans before running queries on large tables |
| Blocked Extension & File Functions | Denies `load_extension`, `readfile`, `writefile`, `fts3_tokenizer`, `randomblob`, `zeroblob` | Prevents local file exfiltration, shared-library execution, and memory exhaustion |
| C-API Structural & VM Time Limits | `connection.setlimit()` + `set_progress_handler()` (2.0s timeout / 250k VM steps) | Halts runaway cross joins and recursive CTE bombs deterministically with structured `"reason"` diagnostics |

## Exposed MCP Tools

Following the [MCP Server Tools Specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), `sqlite-guard-mcp` exposes four tools over stdio JSON-RPC 2.0:

- `read_query(sql, params?)`: Execute a parameterized `SELECT`, `WITH`, `EXPLAIN QUERY PLAN`, or allowed `PRAGMA` query with bounded row counts (`max_rows=250`) and automatic C-API `NULL` masking for sensitive columns.
- `list_tables()`: List all user tables and views in the database.
- `describe_table(table_name)`: Inspect columns (`PRAGMA table_info`), indexes (`PRAGMA index_list` and `PRAGMA index_info`), foreign keys (`PRAGMA foreign_key_list`), and whether each column is masked by `_authorize`.
- `explain_query(sql, params?)`: Run parameterized `EXPLAIN QUERY PLAN` on a query to verify whether SQLite will use an index (`SEARCH ... USING INDEX`) or perform a full-table scan (`SCAN`) before hitting the 2-second execution timeout.

## Local Development & Testing

```bash
git clone [https://github.com/AtharvaSiddhawar/sqlite-guard-mcp.git](https://github.com/AtharvaSiddhawar/sqlite-guard-mcp.git)
cd sqlite-guard-mcp
python3 -m unittest discover -s tests -v
```

## License

MIT License
