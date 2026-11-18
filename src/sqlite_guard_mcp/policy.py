"""Access policy engine for SQLite Guard MCP.

Provides configurable, deterministic, fail-closed read-access policies.
Supports table allow/deny lists, column allow/deny lists, and custom sensitive column overrides.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AccessPolicy:
    """Immutable access policy rules."""

    allow_tables: frozenset[str] | None = None
    deny_tables: frozenset[str] = field(default_factory=frozenset)
    allow_columns: dict[str, frozenset[str]] = field(default_factory=dict)
    deny_columns: dict[str, frozenset[str]] = field(default_factory=dict)
    custom_sensitive_columns: frozenset[str] = field(default_factory=frozenset)
    allow_database_overview: bool = True
    allow_schema_search: bool = True
    allow_health_check: bool = True

    def is_table_allowed(self, table_name: str) -> bool:
        """Return True if table read access is permitted."""
        tbl = table_name.lower()
        if tbl in self.deny_tables:
            return False
        if self.allow_tables is not None:
            return tbl in self.allow_tables
        return True

    def is_column_allowed(self, table_name: str, column_name: str) -> bool:
        """Return True if column read access is permitted."""
        if not self.is_table_allowed(table_name):
            return False

        tbl = table_name.lower()
        col = column_name.lower()

        # Deny rules take precedence
        if tbl in self.deny_columns and col in self.deny_columns[tbl]:
            return False

        # If column allow-list defined for this table, must be present
        if tbl in self.allow_columns:
            return col in self.allow_columns[tbl]

        return True

    def is_column_sensitive(self, table_name: str, column_name: str) -> bool:
        """Return True if column matches custom sensitive overrides."""
        col = column_name.lower()
        return col in self.custom_sensitive_columns


def default_policy() -> AccessPolicy:
    """Return the default permissive read-only policy with standard protections."""
    return AccessPolicy()


def load_policy(source: str | Path | dict[str, Any] | None) -> AccessPolicy:
    """Load and validate an AccessPolicy from a TOML file path, string, or dict.

    Fails closed on any invalid, unknown, or malformed configuration.
    """
    if source is None:
        return default_policy()

    if isinstance(source, (str, Path)):
        path = Path(source)
        if path.is_file():
            try:
                with path.open("rb") as f:
                    data = tomllib.load(f)
            except Exception as exc:
                raise ValueError(f"Failed to parse policy TOML file: {exc}") from exc
        else:
            # Try parsing as raw TOML string
            try:
                data = tomllib.loads(str(source))
            except Exception as exc:
                raise ValueError(
                    f"Policy path does not exist and TOML parse failed: {exc}"
                ) from exc
    elif isinstance(source, dict):
        data = source
    else:
        raise ValueError(f"Invalid policy source type: {type(source).__name__}")

    if not isinstance(data, dict):
        raise ValueError("Policy configuration must be a TOML table or dictionary.")

    allowed_keys = {
        "tables",
        "columns",
        "privacy",
        "features",
    }
    unknown_keys = set(data.keys()) - allowed_keys
    if unknown_keys:
        raise ValueError(
            f"Unknown policy configuration sections: {', '.join(sorted(unknown_keys))}"
        )

    # Parse tables section
    allow_tables: frozenset[str] | None = None
    deny_tables: set[str] = set()

    if "tables" in data:
        t_sec = data["tables"]
        if not isinstance(t_sec, dict):
            raise ValueError("The [tables] section must be a table.")

        if "allow" in t_sec:
            raw_allow = t_sec["allow"]
            if not isinstance(raw_allow, list) or not all(isinstance(x, str) for x in raw_allow):
                raise ValueError("tables.allow must be a list of table name strings.")
            allow_tables = frozenset(x.lower() for x in raw_allow)

        if "deny" in t_sec:
            raw_deny = t_sec["deny"]
            if not isinstance(raw_deny, list) or not all(isinstance(x, str) for x in raw_deny):
                raise ValueError("tables.deny must be a list of table name strings.")
            deny_tables.update(x.lower() for x in raw_deny)

    # Parse columns section
    allow_columns: dict[str, frozenset[str]] = {}
    deny_columns: dict[str, frozenset[str]] = {}

    if "columns" in data:
        c_sec = data["columns"]
        if not isinstance(c_sec, dict):
            raise ValueError("The [columns] section must be a table.")

        if "allow" in c_sec:
            raw_c_allow = c_sec["allow"]
            if not isinstance(raw_c_allow, dict):
                raise ValueError("columns.allow must be a mapping of table name to column lists.")
            for tbl, cols in raw_c_allow.items():
                if not isinstance(cols, list) or not all(isinstance(x, str) for x in cols):
                    raise ValueError(f"columns.allow.{tbl} must be a list of column strings.")
                allow_columns[tbl.lower()] = frozenset(x.lower() for x in cols)

        if "deny" in c_sec:
            raw_c_deny = c_sec["deny"]
            if not isinstance(raw_c_deny, dict):
                raise ValueError("columns.deny must be a mapping of table name to column lists.")
            for tbl, cols in raw_c_deny.items():
                if not isinstance(cols, list) or not all(isinstance(x, str) for x in cols):
                    raise ValueError(f"columns.deny.{tbl} must be a list of column strings.")
                deny_columns[tbl.lower()] = frozenset(x.lower() for x in cols)

    # Parse privacy section
    custom_sensitive: set[str] = set()
    if "privacy" in data:
        p_sec = data["privacy"]
        if not isinstance(p_sec, dict):
            raise ValueError("The [privacy] section must be a table.")
        if "custom_sensitive_columns" in p_sec:
            raw_sens = p_sec["custom_sensitive_columns"]
            if not isinstance(raw_sens, list) or not all(isinstance(x, str) for x in raw_sens):
                raise ValueError("privacy.custom_sensitive_columns must be a list of column names.")
            custom_sensitive.update(x.lower() for x in raw_sens)

    # Parse features section
    allow_overview = True
    allow_search = True
    allow_health = True

    if "features" in data:
        f_sec = data["features"]
        if not isinstance(f_sec, dict):
            raise ValueError("The [features] section must be a table.")
        if "allow_database_overview" in f_sec:
            val = f_sec["allow_database_overview"]
            if not isinstance(val, bool):
                raise ValueError("features.allow_database_overview must be a boolean.")
            allow_overview = val
        if "allow_schema_search" in f_sec:
            val = f_sec["allow_schema_search"]
            if not isinstance(val, bool):
                raise ValueError("features.allow_schema_search must be a boolean.")
            allow_search = val
        if "allow_health_check" in f_sec:
            val = f_sec["allow_health_check"]
            if not isinstance(val, bool):
                raise ValueError("features.allow_health_check must be a boolean.")
            allow_health = val

    return AccessPolicy(
        allow_tables=allow_tables,
        deny_tables=frozenset(deny_tables),
        allow_columns=allow_columns,
        deny_columns=deny_columns,
        custom_sensitive_columns=frozenset(custom_sensitive),
        allow_database_overview=allow_overview,
        allow_schema_search=allow_search,
        allow_health_check=allow_health,
    )
