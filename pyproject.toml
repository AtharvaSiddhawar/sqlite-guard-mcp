# sqlite-guard-mcp

**A deterministic, zero-setup, sandboxed [Model Context Protocol (MCP)](https://modelcontextprotocol.io/specification/2026-07-28) server for local SQLite databases.**

Most SQLite MCP servers rely on naive regular-expression checks (`^\s*(SELECT|WITH)\b`) that fail against write-capable CTEs (`WITH changed AS (DELETE FROM people RETURNING id) SELECT * FROM changed`), dump sensitive columns (`password`, `api_key`, `secret`, `token`) straight into the LLM context on `SELECT *`, or lock up on unindexed Cartesian joins because agents cannot run `PRAGMA index_list` or `EXPLAIN QUERY PLAN`.

`sqlite-guard-mcp` enforces security directly at the SQLite C-API boundary using Python's standard library [`sqlite3.Connection.set_authorizer()`](https://docs.python.org/3/library/sqlite3.html) ([SQLite Compile-Time Authorization Callbacks](https://www.sqlite.org/c3ref/set_authorizer.html)), `connection.setlimit()`, and [`sqlite3.Connection.set_progress_handler()`](https://docs.python.org/3/library/sqlite3.html)—with **zero external runtime dependencies**.

## 10-Second Zero-Setup Quickstart (`uvx`)

You don't need to clone this repository, create a `.venv`, or hardcode local virtualenv paths. Drop this block directly into your `claude_desktop_config.json` (see the [MCP Getting Started Guide](https://modelcontextprotocol.io/docs/2026-07-28/getting-started/intro)) to run `sqlite-guard-mcp` in 10 seconds via `uvx`:

```json
{
  "mcpServers": {
    "sqlite-guard": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/AtharvaSiddhawar/sqlite-guard-mcp",
        "sqlite-guard-mcp",
        "--db",
        "/absolute/path/to/your/database.sqlite"
      ]
    }
  }
}
```

## What `sqlite-guard-mcp` Enforces at the C-API Layer

| Security Layer | Mechanism in `src/sqlite_guard_mcp/server.py` | Protection Provided |
| :--- | :--- | :--- |
| **Read-Only Descriptor & Defensive PRAGMAs** | `mode=ro`, `PRAGMA query_only = ON`, `PRAGMA trusted_schema = OFF` | Prevents file creation, disk writes, and malicious SQL functions inside database schemas |
| **Compile-Time Authorizer (`_authorize`)** | [`sqlite3_set_authorizer`](https://www.sqlite.org/c3ref/set_authorizer.html) | Blocks `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ATTACH`, and CTE write-smuggling (`WITH changed AS (DELETE ...)`) at statement preparation |
| **C-API Sensitive Column Masking** | Returns [`sqlite3.SQLITE_IGNORE`](https://www.sqlite.org/c3ref/c_deny.html) on `sqlite3.SQLITE_READ` | Automatically masks `password`, `passwd`, `token`, `secret`, `api_key`, `private_key`, and `ssn` columns as `NULL` in compiled bytecode—protecting both `SELECT *` and boolean blind `WHERE password LIKE ...` probes |
| **Index & Query-Plan Introspection** | Permits `PRAGMA table_info`, `PRAGMA index_list`, `PRAGMA index_info`, `PRAGMA foreign_key_list`, and `EXPLAIN QUERY PLAN` | Lets agents inspect indexes and verify query plans before running queries on large tables |
| **Blocked Extension & File Functions** | Denies `load_extension`, `readfile`, `writefile`, `fts3_tokenizer`, `randomblob`, `zeroblob` | Prevents local file exfiltration, shared-library execution, and memory exhaustion |
| **C-API Structural & VM Time Limits** | `connection.setlimit()` + `set_progress_handler()` (2.0s timeout / 250k VM steps) | Halts runaway cross joins and deeply nested expressions deterministically |

## Exposed MCP Tools

Following the [MCP Server Tools Specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), `sqlite-guard-mcp` exposes four tools over stdio JSON-RPC 2.0:

- `read_query(sql, params?)`: Execute a parameterized `SELECT`, `WITH`, `EXPLAIN QUERY PLAN`, or allowed `PRAGMA` query with bounded row counts (`max_rows=250`) and automatic C-API `NULL` masking for sensitive columns.
- `list_tables()`: List all user tables and views in the database.
- `describe_table(table_name)`: Inspect columns (`PRAGMA table_info`), indexes (`PRAGMA index_list` and `PRAGMA index_info`), foreign keys (`PRAGMA foreign_key_list`), and whether each column is masked by `_authorize`.
- `explain_query(sql, params?)`: Run `EXPLAIN QUERY PLAN` on a query to verify whether SQLite will use an index (`SEARCH ... USING INDEX`) or perform a full-table scan (`SCAN`) before hitting the 2-second execution timeout.

## Local Development & Testing

```bash
git clone https://github.com/AtharvaSiddhawar/sqlite-guard-mcp.git
cd sqlite-guard-mcp
python3 -m unittest discover -s tests -v
```

## License

MIT License
