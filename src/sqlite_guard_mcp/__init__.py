"""SQLite Guard MCP package.

A read-only, security-hardened SQLite MCP server for AI agents.
"""

__version__ = "0.2.1"

from .server import (
    DEFAULT_MAX_ROWS,
    DEFAULT_MAX_VM_STEPS,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_BLOB_BYTES,
    MAX_CELL_TEXT,
    MAX_COLUMNS,
    MAX_RESULT_BYTES,
    MAX_ROWS_HARD_LIMIT,
    MAX_SQL_LENGTH,
    create_server,
    describe_table,
    execute_guarded_query,
    explain_query,
    inspect_schema_summary,
    list_tables,
    main,
)

__all__ = [
    "DEFAULT_MAX_ROWS",
    "DEFAULT_MAX_VM_STEPS",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_BLOB_BYTES",
    "MAX_CELL_TEXT",
    "MAX_COLUMNS",
    "MAX_RESULT_BYTES",
    "MAX_ROWS_HARD_LIMIT",
    "MAX_SQL_LENGTH",
    "__version__",
    "create_server",
    "describe_table",
    "execute_guarded_query",
    "explain_query",
    "inspect_schema_summary",
    "list_tables",
    "main",
]
