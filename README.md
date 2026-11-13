# SQLite Guard MCP

A small, read-only [Model Context Protocol](https://modelcontextprotocol.io/)
server for exploring one local SQLite database. It gives MCP clients three tools:

- `list_tables` — list user tables and views.
- `describe_table` — inspect a table or view's columns.
- `query_database` — run one `SELECT` or `WITH` query.

## Safety defaults

- Opens the configured database with SQLite's read-only URI mode.
- Enables SQLite `query_only` and a restrictive authorizer.
- Rejects SQL that does not begin with `SELECT` or `WITH`.
- Blocks write actions and selected non-deterministic or sensitive functions.
- Caps results at 200 rows and query execution at two seconds.
- Uses no network services and stores no credentials.

This is a local developer tool, not a security boundary against a hostile machine
owner. Use it with a database copy if the data is sensitive.

## Requirements

- Python 3.11+
- An existing SQLite database file

## Install and run

From the repository directory:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
SQLITE_GUARD_DB=/absolute/path/to/database.sqlite python -m sqlite_guard_mcp
```

On Windows PowerShell, set the environment variable with:

```powershell
$env:SQLITE_GUARD_DB = "C:\path\to\database.sqlite"
python -m sqlite_guard_mcp
```

The server uses MCP's standard input/output transport. Run it through an MCP
client rather than as an interactive command-line application.

## Claude Desktop example

Add a server entry to the client's MCP configuration, replacing the paths with
your local paths:

```json
{
  "mcpServers": {
    "sqlite-guard": {
      "command": "/absolute/path/to/repo/.venv/bin/python",
      "args": ["-m", "sqlite_guard_mcp"],
      "env": {
        "SQLITE_GUARD_DB": "/absolute/path/to/database.sqlite"
      }
    }
  }
}
```

On Windows, use the path to `.venv\\Scripts\\python.exe`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT. Add a `LICENSE` file with the MIT license text if you want to distribute
this project under that license.