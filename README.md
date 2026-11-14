# SQLite Guard MCP

A read-only [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
server for exploring one local SQLite database. It gives MCP clients three tools:

- `list_tables` — list user tables and views.
- `describe_table` — inspect a table or view's columns.
- `query_database` — run one read-only `SELECT` or `WITH` query.

## Safety and limits

- Opens the configured database in SQLite read-only URI mode.
- Enables SQLite `query_only` and a restrictive authorizer.
- Rejects SQL that does not begin with `SELECT` or `WITH`.
- Blocks write actions and selected non-deterministic or sensitive functions.
- Caps results at 200 rows and query execution at two seconds by default.
- Applies additional SQLite limits where supported by the Python runtime.
- Uses no network services and stores no credentials.

This is a local developer tool, not a security boundary against a hostile machine
owner or a malicious SQLite extension. Use it with a database copy if the data is
sensitive.

## Requirements

- Python 3.10 or newer
- An existing SQLite database file

## Install and run

From the repository directory:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
SQLITE_GUARD_DB=/absolute/path/to/database.sqlite python -m sqlite_guard_mcp
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
$env:SQLITE_GUARD_DB = "C:\path\to\database.sqlite"
python -m sqlite_guard_mcp
```

The server uses MCP's standard input/output transport. Run it through an MCP
client rather than as an interactive command-line application.

## Claude Desktop example

After installing the package in the project's virtual environment, add a server
entry to your MCP client configuration. Replace the paths with your local paths.

macOS/Linux:

```json
{
  "mcpServers": {
    "sqlite-guard": {
      "command": "/absolute/path/to/repo/.venv/bin/sqlite-guard-mcp",
      "env": {
        "SQLITE_GUARD_DB": "/absolute/path/to/database.sqlite"
      }
    }
  }
}
```

Windows:

```json
{
  "mcpServers": {
    "sqlite-guard": {
      "command": "C:\\absolute\\path\\to\\repo\\.venv\\Scripts\\sqlite-guard-mcp.exe",
      "env": {
        "SQLITE_GUARD_DB": "C:\\path\\to\\database.sqlite"
      }
    }
  }
}
```

## Development

Install the development dependencies and run the test suite:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

Build the distribution locally with:

```bash
python -m build
```

## License

This project is distributed under the MIT License. See [LICENSE](LICENSE).
