"""SQLite Guard MCP package.

A read-only, security-hardened SQLite MCP server for AI agents.
"""

__version__ = "0.2.3"

from .index_lab import (
    simulate_index,
    validate_candidate_index,
)
from .policy import (
    AccessPolicy,
    default_policy,
    load_policy,
)
from .profiler import (
    profile_table,
)
from .schema_diff import (
    diff_schemas,
    review_migration,
    snapshot_schema,
)
from .server import (
    DEFAULT_MAX_ROWS,
    DEFAULT_MAX_VM_STEPS,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_BLOB_BYTES,
    MAX_CELL_TEXT,
    MAX_COLUMNS,
    MAX_PARAM_KEY_LENGTH,
    MAX_PARAMS_COUNT,
    MAX_PARAMS_TOTAL_BYTES,
    MAX_RESULT_BYTES,
    MAX_ROWS_HARD_LIMIT,
    MAX_SQL_LENGTH,
    check_database_health,
    create_server,
    describe_table,
    execute_guarded_query,
    explain_query,
    get_database_overview,
    inspect_schema_summary,
    list_tables,
    main,
    search_database_schema,
)

__all__ = [
    "DEFAULT_MAX_ROWS",
    "DEFAULT_MAX_VM_STEPS",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_BLOB_BYTES",
    "MAX_CELL_TEXT",
    "MAX_COLUMNS",
    "MAX_PARAMS_COUNT",
    "MAX_PARAMS_TOTAL_BYTES",
    "MAX_PARAM_KEY_LENGTH",
    "MAX_RESULT_BYTES",
    "MAX_ROWS_HARD_LIMIT",
    "MAX_SQL_LENGTH",
    "__version__",
    "AccessPolicy",
    "check_database_health",
    "create_server",
    "default_policy",
    "describe_table",
    "diff_schemas",
    "execute_guarded_query",
    "explain_query",
    "get_database_overview",
    "inspect_schema_summary",
    "list_tables",
    "load_policy",
    "main",
    "profile_table",
    "review_migration",
    "search_database_schema",
    "simulate_index",
    "snapshot_schema",
    "validate_candidate_index",
]
