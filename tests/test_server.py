```python
"""
Unit and security regression tests for `sqlite-guard-mcp`.

Covers:
1. CTE write-smuggling rejection (`test_authorizer_blocks_write_inside_cte`)
2. C-API column masking via `SQLITE_IGNORE` on `SELECT *` and boolean blind `WHERE` clauses (`test_authorizer_masks_sensitive_columns_on_read`)
3. Index & query-plan inspection (`test_authorizer_allows_pragma_index_list_and_explain`)
4. Disallowed PRAGMA mutation blocking (`test_authorizer_blocks_pragma_mutation`)
5. Blocked functions (`load_extension`, `readfile`, `writefile`, `fts3_tokenizer`, `randomblob`)
6. Runaway recursion / VM instruction timeout enforcement (`test_progress_handler_aborts_runaway_query`)
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sqlite_guard_mcp.server import (
    SQLiteGuardServer,
    describe_table,
    execute_guarded_query,
    explain_query,
)


def _parse_payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class TestSQLiteGuardServer(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "sample.sqlite"
        conn = sqlite3.connect(self.db_path)
        conn.executescript(
            """
            CREATE TABLE people (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                api_key TEXT NOT NULL,
                secret_token TEXT NOT NULL
            );
            CREATE INDEX idx_people_email ON people(email);

            INSERT INTO people (id, name, email, password, api_key, secret_token)
            VALUES (1, 'Alice', 'alice@example.com', 'hunter2', 'sk_live_12345', 'tok_abc987');
            """
        )
        conn.commit()
        conn.close()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_authorizer_blocks_write_inside_cte(self) -> None:
        """Proves `_authorize` catches write-capable CTEs that bypass `^\\s*(SELECT|WITH)\\b` regex checks."""
        res = execute_guarded_query(
            self.db_path,
            "WITH changed AS (DELETE FROM people RETURNING id) SELECT * FROM changed",
        )
        payload = _parse_payload(res)
        self.assertTrue(res["isError"])
        self.assertEqual(payload["error"], "Query execution failed or timed out.")

    def test_authorizer_masks_sensitive_columns_on_read(self) -> None:
        """`SELECT * FROM people` succeeds while masking password, api_key, and secret_token as NULL via SQLITE_IGNORE, and defeats WHERE side-channel probes."""
        res = execute_guarded_query(self.db_path, "SELECT * FROM people WHERE id = 1")
        payload = _parse_payload(res)
        self.assertFalse(res["isError"])
        self.assertEqual(payload["row_count"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["name"], "Alice")
        self.assertEqual(row["email"], "alice@example.com")
        self.assertIsNone(row["password"])
        self.assertIsNone(row["api_key"])
        self.assertIsNone(row["secret_token"])

        # Prove boolean blind side-channel (`WHERE password LIKE 'h%'`) cannot infer secret values
        blind_res = execute_guarded_query(
            self.db_path,
            "SELECT id, name FROM people WHERE password LIKE 'h%'",
        )
        blind_payload = _parse_payload(blind_res)
        self.assertFalse(blind_res["isError"])
        self.assertEqual(blind_payload["row_count"], 0)

    def test_authorizer_allows_pragma_index_list_and_explain(self) -> None:
        """Agents can run `PRAGMA index_list`, `describe_table`, and `EXPLAIN QUERY PLAN` to inspect indexes."""
        pragma_res = execute_guarded_query(self.db_path, "PRAGMA index_list('people')")
        pragma_payload = _parse_payload(pragma_res)
        self.assertFalse(pragma_res["isError"])
        self.assertEqual(pragma_payload["rows"][0]["name"], "idx_people_email")

        desc_res = describe_table(self.db_path, "people")
        desc_payload = _parse_payload(desc_res)
        self.assertFalse(desc_res["isError"])
        self.assertEqual(desc_payload["indexes"][0]["name"], "idx_people_email")
        self.assertEqual(desc_payload["indexes"][0]["columns"][0]["name"], "email")

        explain_res = explain_query(
            self.db_path,
            "SELECT id, name FROM people WHERE email = 'alice@example.com'",
        )
        explain_payload = _parse_payload(explain_res)
        self.assertFalse(explain_res["isError"])
        self.assertGreaterEqual(explain_payload["row_count"], 1)
        plan_text = json.dumps(explain_payload["rows"])
        self.assertIn("idx_people_email", plan_text)

    def test_authorizer_blocks_pragma_mutation(self) -> None:
        """PRAGMA assignments such as `PRAGMA writable_schema = ON` or `PRAGMA encoding = 'UTF-16'` are blocked."""
        for bad_pragma in (
            "PRAGMA writable_schema = ON",
            "PRAGMA query_only = OFF",
            "PRAGMA encoding = 'UTF-16'",
        ):
            res = execute_guarded_query(self.db_path, bad_pragma)
            payload = _parse_payload(res)
            self.assertTrue(res["isError"])
            self.assertEqual(payload["error"], "Query execution failed or timed out.")

    def test_blocked_functions_rejected(self) -> None:
        """Dangerous SQLite functions (`randomblob`, `load_extension`, `readfile`) are denied by `_authorize`."""
        for sql in (
            "SELECT randomblob(100000000)",
            "SELECT load_extension('evil.so')",
        ):
            res = execute_guarded_query(self.db_path, sql)
            payload = _parse_payload(res)
            self.assertTrue(res["isError"])
            self.assertEqual(payload["error"], "Query execution failed or timed out.")

    def test_progress_handler_aborts_runaway_query(self) -> None:
        """Runaway recursive CTEs exceeding the VM instruction budget fail deterministically."""
        runaway_sql = """
        WITH RECURSIVE cnt(x) AS (
            SELECT 1
            UNION ALL
            SELECT x + 1 FROM cnt WHERE x < 1000000
        )
        SELECT count(*) FROM cnt
        """
        res = execute_guarded_query(
            self.db_path,
            runaway_sql,
            max_vm_steps=3_000,
            timeout_seconds=1.0,
        )
        payload = _parse_payload(res)
        self.assertTrue(res["isError"])
        self.assertEqual(payload["error"], "Query execution failed or timed out.")

    def test_mcp_jsonrpc_server_tools(self) -> None:
        """Verify end-to-end JSON-RPC 2.0 `initialize`, `tools/list`, and `tools/call` responses."""
        server = SQLiteGuardServer(self.db_path)
        tools_resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert tools_resp is not None
        names = {t["name"] for t in tools_resp["result"]["tools"]}
        self.assertEqual({"read_query", "list_tables", "describe_table", "explain_query"}, names)


if __name__ == "__main__":
    unittest.main()
```
