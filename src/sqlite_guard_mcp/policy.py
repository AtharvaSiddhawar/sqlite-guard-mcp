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
    allow_columns_wildcard: frozenset[str] = field(default_factory=frozenset)
    deny_columns_wildcard: frozenset[str] = field(default_factory=frozenset)
    custom_sensitive_columns: frozenset[str] = field(default_factory=frozenset)
    allow_explain_query: bool = True
    allow_database_overview: bool = True
    allow_schema_search: bool = True
    allow_health_check: bool = True
    allow_profiling: bool = True
    allow_index_lab: bool = True
    allow_schema_diff: bool = True
    allow_migration_review: bool = True

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

        # Wildcard deny rules take precedence across all tables
        if col in self.deny_columns_wildcard:
            return False

        # Table-specific deny rules take precedence
        if tbl in self.deny_columns and col in self.deny_columns[tbl]:
            return False

        # Table-specific allow-list takes precedence if defined
        if tbl in self.allow_columns:
            return col in self.allow_columns[tbl]

        # Wildcard allow-list if present
        if self.allow_columns_wildcard:
            return col in self.allow_columns_wildcard

        return True

    def is_column_sensitive(self, table_name: str, column_name: str) -> bool:
        """Return True if column matches custom sensitive overrides."""
        col = column_name.lower()
        return col in self.custom_sensitive_columns

    def explain_access(self, table_name: str, column_name: str | None = None) -> dict[str, Any]:
        """Explain whether and why a table or column is allowed, denied, or masked."""
        tbl = table_name.lower()
        if tbl in self.deny_tables:
            return {
                "allowed": False,
                "reason": f"Table '{table_name}' matches deny_tables rule.",
                "table_allowed": False,
                "column_allowed": False if column_name else None,
                "is_sensitive": False,
            }
        if self.allow_tables is not None and tbl not in self.allow_tables:
            return {
                "allowed": False,
                "reason": f"Table '{table_name}' is not in allow_tables allow-list.",
                "table_allowed": False,
                "column_allowed": False if column_name else None,
                "is_sensitive": False,
            }

        if column_name is None:
            return {
                "allowed": True,
                "reason": f"Table '{table_name}' is allowed.",
                "table_allowed": True,
                "column_allowed": None,
                "is_sensitive": False,
            }

        col = column_name.lower()
        is_sens = self.is_column_sensitive(table_name, column_name)

        if col in self.deny_columns_wildcard:
            return {
                "allowed": False,
                "reason": f"Column '{column_name}' matches wildcard deny rule (*.{col}).",
                "table_allowed": True,
                "column_allowed": False,
                "is_sensitive": is_sens,
            }
        if tbl in self.deny_columns and col in self.deny_columns[tbl]:
            return {
                "allowed": False,
                "reason": f"Column '{table_name}.{column_name}' matches table column deny rule.",
                "table_allowed": True,
                "column_allowed": False,
                "is_sensitive": is_sens,
            }
        if tbl in self.allow_columns:
            if col not in self.allow_columns[tbl]:
                return {
                    "allowed": False,
                    "reason": (
                        f"Column '{column_name}' is not in allow_columns allow-list "
                        f"for table '{table_name}'."
                    ),
                    "table_allowed": True,
                    "column_allowed": False,
                    "is_sensitive": is_sens,
                }
        elif self.allow_columns_wildcard and col not in self.allow_columns_wildcard:
            return {
                "allowed": False,
                "reason": f"Column '{column_name}' is not in wildcard allow-list.",
                "table_allowed": True,
                "column_allowed": False,
                "is_sensitive": is_sens,
            }

        return {
            "allowed": True,
            "reason": f"Column '{table_name}.{column_name}' is allowed.",
            "table_allowed": True,
            "column_allowed": True,
            "is_sensitive": is_sens,
        }


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
    allow_cols_map: dict[str, set[str]] = {}
    deny_cols_map: dict[str, set[str]] = {}
    allow_wildcards: set[str] = set()
    deny_wildcards: set[str] = set()

    if "columns" in data:
        c_sec = data["columns"]
        if not isinstance(c_sec, dict):
            raise ValueError("The [columns] section must be a table.")

        if "allow" in c_sec:
            raw_c_allow = c_sec["allow"]
            if isinstance(raw_c_allow, list):
                if not all(isinstance(x, str) for x in raw_c_allow):
                    raise ValueError(
                        "columns.allow must be a mapping of table names to column lists, "
                        "or a list of 'table.column' strings."
                    )
                for item in raw_c_allow:
                    item_str = item.strip()
                    if "." not in item_str:
                        raise ValueError(
                            "columns.allow must be a mapping of table names to column lists, "
                            "or a list of 'table.column' strings."
                        )
                    tbl, col = item_str.split(".", 1)
                    tbl = tbl.strip().lower()
                    col = col.strip().lower()
                    if not tbl or not col:
                        raise ValueError(
                            "columns.allow must be a mapping of table names to column lists, "
                            "or a list of 'table.column' strings."
                        )
                    if tbl == "*":
                        allow_wildcards.add(col)
                    else:
                        allow_cols_map.setdefault(tbl, set()).add(col)
            elif isinstance(raw_c_allow, dict):
                for tbl, cols in raw_c_allow.items():
                    if not isinstance(cols, list) or not all(isinstance(x, str) for x in cols):
                        raise ValueError(f"columns.allow.{tbl} must be a list of column strings.")
                    tbl_lower = tbl.lower()
                    if tbl_lower == "*":
                        allow_wildcards.update(x.lower() for x in cols)
                    else:
                        allow_cols_map.setdefault(tbl_lower, set()).update(x.lower() for x in cols)
            else:
                raise ValueError(
                    "columns.allow must be a mapping of table names to column lists, "
                    "or a list of 'table.column' strings."
                )

        if "deny" in c_sec:
            raw_c_deny = c_sec["deny"]
            if isinstance(raw_c_deny, list):
                if not all(isinstance(x, str) for x in raw_c_deny):
                    raise ValueError(
                        "columns.deny must be a mapping of table names to column lists, "
                        "or a list of 'table.column' strings."
                    )
                for item in raw_c_deny:
                    item_str = item.strip()
                    if "." not in item_str:
                        raise ValueError(
                            "columns.deny must be a mapping of table names to column lists, "
                            "or a list of 'table.column' strings."
                        )
                    tbl, col = item_str.split(".", 1)
                    tbl = tbl.strip().lower()
                    col = col.strip().lower()
                    if not tbl or not col:
                        raise ValueError(
                            "columns.deny must be a mapping of table names to column lists, "
                            "or a list of 'table.column' strings."
                        )
                    if tbl == "*":
                        deny_wildcards.add(col)
                    else:
                        deny_cols_map.setdefault(tbl, set()).add(col)
            elif isinstance(raw_c_deny, dict):
                for tbl, cols in raw_c_deny.items():
                    if not isinstance(cols, list) or not all(isinstance(x, str) for x in cols):
                        raise ValueError(f"columns.deny.{tbl} must be a list of column strings.")
                    tbl_lower = tbl.lower()
                    if tbl_lower == "*":
                        deny_wildcards.update(x.lower() for x in cols)
                    else:
                        deny_cols_map.setdefault(tbl_lower, set()).update(x.lower() for x in cols)
            else:
                raise ValueError(
                    "columns.deny must be a mapping of table names to column lists, "
                    "or a list of 'table.column' strings."
                )

    allow_columns_frozen = {tbl: frozenset(cols) for tbl, cols in allow_cols_map.items()}
    deny_columns_frozen = {tbl: frozenset(cols) for tbl, cols in deny_cols_map.items()}

    # Parse privacy section
    custom_sensitive: set[str] = set()
    if "privacy" in data:
        p_sec = data["privacy"]
        if not isinstance(p_sec, dict):
            raise ValueError("The [privacy] section must be a table.")
        allowed_privacy_keys = {"custom_sensitive_columns", "sensitive_columns"}
        unknown_p_keys = set(p_sec.keys()) - allowed_privacy_keys
        if unknown_p_keys:
            raise ValueError(f"Unknown keys in [privacy]: {', '.join(sorted(unknown_p_keys))}")

        for k in ("custom_sensitive_columns", "sensitive_columns"):
            if k in p_sec:
                raw_sens = p_sec[k]
                if not isinstance(raw_sens, list) or not all(isinstance(x, str) for x in raw_sens):
                    raise ValueError(f"privacy.{k} must be a list of column names.")
                custom_sensitive.update(x.lower() for x in raw_sens)

    # Parse features section
    allowed_feature_flags = {
        "allow_explain_query",
        "allow_database_overview",
        "allow_schema_search",
        "allow_health_check",
        "allow_profiling",
        "allow_index_lab",
        "allow_schema_diff",
        "allow_migration_review",
    }
    feature_flags = {k: True for k in allowed_feature_flags}

    if "features" in data:
        f_sec = data["features"]
        if not isinstance(f_sec, dict):
            raise ValueError("The [features] section must be a table.")
        unknown_f_keys = set(f_sec.keys()) - allowed_feature_flags
        if unknown_f_keys:
            raise ValueError(
                f"Unknown feature flags in [features]: {', '.join(sorted(unknown_f_keys))}"
            )
        for k, v in f_sec.items():
            if not isinstance(v, bool):
                raise ValueError(f"features.{k} must be a boolean.")
            feature_flags[k] = v

    return AccessPolicy(
        allow_tables=allow_tables,
        deny_tables=frozenset(deny_tables),
        allow_columns=allow_columns_frozen,
        deny_columns=deny_columns_frozen,
        allow_columns_wildcard=frozenset(allow_wildcards),
        deny_columns_wildcard=frozenset(deny_wildcards),
        custom_sensitive_columns=frozenset(custom_sensitive),
        allow_explain_query=feature_flags["allow_explain_query"],
        allow_database_overview=feature_flags["allow_database_overview"],
        allow_schema_search=feature_flags["allow_schema_search"],
        allow_health_check=feature_flags["allow_health_check"],
        allow_profiling=feature_flags["allow_profiling"],
        allow_index_lab=feature_flags["allow_index_lab"],
        allow_schema_diff=feature_flags["allow_schema_diff"],
        allow_migration_review=feature_flags["allow_migration_review"],
    )
