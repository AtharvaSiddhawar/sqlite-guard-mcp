"""Bounded, read-only access to one SQLite database."""

from __future__ import annotations

import json
import math
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any

MAX_ROWS = 200
MAX_SQL_LENGTH = 100_000
QUERY_TIMEOUT_SECONDS = 2.0
PROGRESS_INTERVAL = 1_000

_READ_ACTIONS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
}
if hasattr(sqlite3, "SQLITE_RECURSIVE"):
    _READ_ACTIONS.add(sqlite3.SQLITE_RECURSIVE)

_BLOCKED_FUNCTIONS = {
    "current_date",
    "current_time",
    "current_timestamp",
    "fts3_tokenizer",
    "last_insert_rowid",
    "load_extension",
    "random",
    "randomblob",
    "readfile",
    "total_changes",
    "writefile",
}

_ALLOWED_QUERY_START = re.compile(r"^\s*(SELECT|WITH)\b", re.IGNORECASE)


def _json_default(value: Any) -> Any:
    """Convert SQLite values that JSON cannot encode by default."""
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}
    return str(value)


def _json_result(value: Any) -> str:
    """Encode a result as JSON text for MCP clients."""
    return json.dumps(value, ensure_ascii=False, default=_json_default)


class SQLiteGuard:
    """Read-only access to one SQLite database with bounded query execution."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        max_rows: int = MAX_ROWS,
        query_timeout_seconds: float = QUERY_TIMEOUT_SECONDS,
    ) -> None:
        path = Path(database_path).expanduser().resolve(strict=True)
        if not path.is_file():
            raise ValueError(f"Database path is not a file: {path}")
        if isinstance(max_rows, bool) or not isinstance(max_rows, int):
            raise ValueError("max_rows must be an integer between 1 and 1000")
        if not 1 <= max_rows <= 1_000:
            raise ValueError("max_rows must be between 1 and 1000")
        if (
            isinstance(query_timeout_seconds, bool)
            or not isinstance(query_timeout_seconds, (int, float))
            or not math.isfinite(query_timeout_seconds)
            or query_timeout_seconds <= 0
        ):
            raise ValueError("query_timeout_seconds must be a positive finite number")

        self.database_path = path
        self.max_rows = max_rows
        self.query_timeout_seconds = float(query_timeout_seconds)
        self._database_uri = f"{path.as_uri()}?mode=ro"

    @staticmethod
    def _authorize(
        action: int,
        arg1: str | None,
        arg2: str | None,
        _database: str | None,
        _trigger: str | None,
    ) -> int:
        """Allow reads, except for selected non-deterministic/sensitive functions."""
        if action in _READ_ACTIONS:
            if action == sqlite3.SQLITE_FUNCTION:
                function_name = (arg2 or arg1 or "").lower()
                if function_name in _BLOCKED_FUNCTIONS:
                    return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        # The server needs this pragma only for its table-description tool.
        if action == sqlite3.SQLITE_PRAGMA and (arg1 or "").lower() == "table_info":
            return sqlite3.SQLITE_OK

        return sqlite3.SQLITE_DENY

    def _connect(self) -> sqlite3.Connection:
        """Open a restricted connection to the configured database."""
        connection = sqlite3.connect(
            self._database_uri,
            uri=True,
            timeout=0.5,
            isolation_level=None,
        )
        try:
            connection.row_factory = sqlite3.Row

            # Apply restrictive SQLite limits where the runtime supports them.
            limits = (
                ("SQLITE_LIMIT_SQL_LENGTH", MAX_SQL_LENGTH),
                ("SQLITE_LIMIT_LENGTH", 2_000_000),
                ("SQLITE_LIMIT_COLUMN", 200),
                ("SQLITE_LIMIT_COMPOUND_SELECT", 50),
            )
            for limit_name, limit_value in limits:
                limit_id = getattr(sqlite3, limit_name, None)
                if limit_id is not None and hasattr(connection, "setlimit"):
                    connection.setlimit(limit_id, limit_value)

            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA trusted_schema = OFF")

            deadline = time.monotonic() + self.query_timeout_seconds
            connection.set_progress_handler(
                lambda: int(time.monotonic() >= deadline),
                PROGRESS_INTERVAL,
            )
            connection.set_authorizer(self._authorize)
            return connection
        except Exception:
            connection.close()
            raise

    def list_tables(self) -> str:
        """Return user tables and views as JSON."""
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT name, type
                    FROM sqlite_schema
                    WHERE type IN ('table', 'view')
                      AND name NOT LIKE 'sqlite_%'
                    ORDER BY name
                    """
                ).fetchall()

            return _json_result(
                [{"name": row["name"], "type": row["type"]} for row in rows]
            )
        except sqlite3.Error:
            return _json_result({"error": "Could not read the database schema."})

    def describe_table(self, table_name: str) -> str:
        """Return column details for a table or view as JSON."""
        if not isinstance(table_name, str) or not table_name or len(table_name) > 256:
            return _json_result({"error": "Provide a valid table name."})

        try:
            with closing(self._connect()) as connection:
                found = connection.execute(
                    """
                    SELECT name, type
                    FROM sqlite_schema
                    WHERE name = ? AND type IN ('table', 'view')
                    """,
                    (table_name,),
                ).fetchone()

                if found is None:
                    return _json_result({"error": "Table or view not found."})

                quoted_name = table_name.replace('"', '""')
                rows = connection.execute(
                    f'PRAGMA table_info("{quoted_name}")'
                ).fetchall()

            return _json_result(
                {
                    "name": found["name"],
                    "type": found["type"],
                    "columns": [
                        {
                            "name": row["name"],
                            "type": row["type"],
                            "not_null": bool(row["notnull"]),
                            "default": row["dflt_value"],
                            "primary_key_position": row["pk"],
                        }
                        for row in rows
                    ],
                }
            )
        except sqlite3.Error:
            return _json_result({"error": "Could not describe that table."})

    def query(self, sql: str) -> str:
        """Run one bounded read-only SELECT or WITH query and return JSON."""
        if not isinstance(sql, str) or len(sql) > MAX_SQL_LENGTH:
            return _json_result({"error": "SQL must be a string within the size limit."})

        if not _ALLOWED_QUERY_START.match(sql):
            return _json_result(
                {"error": "Only a single SELECT or WITH query is allowed."}
            )

        try:
            with closing(self._connect()) as connection:
                cursor = connection.execute(sql)
                if cursor.description is None:
                    return _json_result({"error": "The query did not return rows."})

                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchmany(self.max_rows + 1)
                truncated = len(rows) > self.max_rows
                rows = rows[: self.max_rows]

            return _json_result(
                {
                    "columns": columns,
                    "rows": [dict(row) for row in rows],
                    "truncated": truncated,
                    "max_rows": self.max_rows,
                }
            )
-        except sqlite3.Error as exc:
+        except (sqlite3.Error, sqlite3.Warning) as exc:
          )
