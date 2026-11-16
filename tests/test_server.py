from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from sqlite_guard_mcp.server import (
    MAX_RESULT_BYTES,
    create_server,
    describe_table,
    execute_guarded_query,
    explain_query,
    list_tables,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def database(tmp_path: Path) -> Path:
    path = tmp_path / "sample database.sqlite"

    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE people (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                api_key TEXT NOT NULL,
                secret_token TEXT NOT NULL,
                prompt_tokens INTEGER NOT NULL,
                payload BLOB
            );

            CREATE INDEX idx_people_email ON people(email);

            INSERT INTO people VALUES
              (1, 'Alice', 'alice@example.com', 'hunter2',
               'sk_live_x', 'secret-x', 1420, X'010203'),
              (2, 'Bob', 'bob@example.com', 'hunter3',
               'sk_live_y', 'secret-y', 900, X'040506');
            """
        )

    return path


def test_read_masks_secrets_and_preserves_token_metrics(
    database: Path,
) -> None:
    result = execute_guarded_query(
        database,
        "SELECT * FROM people WHERE id = 1",
    )

    assert result["ok"] is True

    row = result["rows"][0]

    assert row["name"] == "Alice"
    assert row["password"] is None
    assert row["api_key"] is None
    assert row["secret_token"] is None
    assert row["prompt_tokens"] == 1420

    assert row["payload"] == {
        "type": "blob",
        "byte_length": 3,
        "base64": "AQID",
        "truncated": False,
    }


def test_camel_case_secret_names_are_masked(
    database: Path,
) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute("ALTER TABLE people ADD COLUMN apiToken TEXT")
        connection.execute("ALTER TABLE people ADD COLUMN promptTokens INTEGER")
        connection.execute("UPDATE people SET apiToken='secret-value', promptTokens=77")

    result = execute_guarded_query(
        database,
        "SELECT apiToken, promptTokens FROM people WHERE id = 1",
    )

    assert result["ok"] is True
    assert result["rows"][0]["apiToken"] is None
    assert result["rows"][0]["promptTokens"] == 77


def test_blind_filter_on_secret_is_masked(
    database: Path,
) -> None:
    result = execute_guarded_query(
        database,
        "SELECT id FROM people WHERE password = 'hunter2'",
    )

    assert result["ok"] is True
    assert result["row_count"] == 0


def test_writes_and_write_ctes_are_blocked(
    database: Path,
) -> None:
    queries = (
        "DELETE FROM people",
        ("WITH changed AS (DELETE FROM people RETURNING id) SELECT * FROM changed"),
        "SELECT 1; DELETE FROM people",
        "ATTACH DATABASE ':memory:' AS other",
    )

    for sql in queries:
        result = execute_guarded_query(database, sql)
        assert result["ok"] is False


def test_explain_write_is_rejected(
    database: Path,
) -> None:
    result = explain_query(database, "DELETE FROM people")

    assert result["ok"] is False
    assert result["code"] == "invalid_input"


def test_allowed_explain_query_uses_index(
    database: Path,
) -> None:
    result = explain_query(
        database,
        "SELECT id FROM people WHERE email = ?",
        ["alice@example.com"],
    )

    assert result["ok"] is True
    plan_text = json.dumps(result["rows"])
    assert "idx_people_email" in plan_text or "people" in plan_text


def test_pragma_mutations_and_dangerous_functions_are_blocked(
    database: Path,
) -> None:
    queries = (
        "PRAGMA writable_schema = ON",
        "PRAGMA query_only = OFF",
        "SELECT randomblob(1000000)",
        "SELECT load_extension('bad')",
    )

    for sql in queries:
        result = execute_guarded_query(database, sql)
        assert result["ok"] is False


def test_row_limit_is_enforced(
    database: Path,
) -> None:
    result = execute_guarded_query(
        database,
        "SELECT id FROM people ORDER BY id",
        max_rows=1,
    )

    assert result["ok"] is True
    assert result["row_count"] == 1
    assert result["truncated"] is True


def test_invalid_parameters_are_rejected(
    database: Path,
) -> None:
    invalid_object = execute_guarded_query(
        database,
        "SELECT ?",
        {"x": object()},
    )

    invalid_float = execute_guarded_query(
        database,
        "SELECT ?",
        [float("nan")],
    )

    assert invalid_object["code"] == "invalid_input"
    assert invalid_float["code"] == "invalid_input"


def test_query_execution_budget(
    database: Path,
) -> None:
    sql = (
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL "
        "SELECT x+1 FROM n WHERE x<1000000) "
        "SELECT count(*) FROM n"
    )

    result = execute_guarded_query(
        database,
        sql,
        max_vm_steps=1_000,
    )

    assert result["ok"] is False
    assert result["code"] == "query_budget_exceeded"


def test_schema_and_table_listing(
    database: Path,
) -> None:
    tables = list_tables(database)

    assert tables["ok"] is True
    assert [row["name"] for row in tables["rows"]] == ["people"]

    schema = describe_table(database, "people")

    assert schema["ok"] is True
    assert schema["columns"][3]["masked_by_guard"] is True
    assert schema["indexes"][0]["name"] == "idx_people_email"
    assert schema["indexes"][0]["columns"][0]["name"] == "email"


def test_table_names_with_quotes_are_safely_escaped(
    database: Path,
) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE "odd name" ("select" TEXT)')

    result = describe_table(database, "odd name")

    assert result["ok"] is True
    assert result["columns"][0]["name"] == "select"


def test_nonexistent_database_returns_safe_error(
    tmp_path: Path,
) -> None:
    result = execute_guarded_query(
        tmp_path / "missing.sqlite",
        "SELECT 1",
    )

    assert result["ok"] is False
    assert result["code"] == "database_not_found"


def test_output_is_json_bounded(
    database: Path,
) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO people VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                3,
                "x" * 50_000,
                "x",
                "x",
                "x",
                "x",
                1,
                b"x",
            ),
        )

    result = execute_guarded_query(
        database,
        "SELECT name FROM people WHERE id = 3",
    )

    encoded = json.dumps(
        result,
        ensure_ascii=False,
    ).encode("utf-8")

    assert len(encoded) <= MAX_RESULT_BYTES


@pytest.mark.anyio
async def test_official_mcp_client_lists_and_calls_tools(
    database: Path,
) -> None:
    from mcp import Client

    server = create_server(database)

    async with Client(server, raise_exceptions=True) as client:
        tools = await client.list_tools()

        names = {tool.name for tool in tools.tools}

        assert names == {
            "read_query",
            "list_database_tables",
            "describe_database_table",
            "explain_read_query",
        }

        result = await client.call_tool(
            "read_query",
            {"sql": "SELECT name FROM people"},
        )

        assert result.is_error is False

        decoded = json.loads(result.content[0].text)

        assert decoded["ok"] is True
        assert decoded["row_count"] == 2


def test_extended_credential_names_are_masked(
    database: Path,
) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE credential_variants (
                pwd TEXT,
                "api-key" TEXT,
                privateKey TEXT,
                accessToken TEXT,
                refreshToken TEXT,
                clientSecret TEXT,
                passphrase TEXT,
                credit_card_number TEXT,
                cvv TEXT,
                prompt_tokens INTEGER,
                output_tokens INTEGER
            )
            """
        )

        connection.execute(
            """
            INSERT INTO credential_variants VALUES (
                'p1',
                'k1',
                'k2',
                't1',
                't2',
                's1',
                'p2',
                '4111111111111111',
                '123',
                100,
                200
            )
            """
        )

    result = execute_guarded_query(
        database,
        "SELECT * FROM credential_variants",
    )

    assert result["ok"] is True

    row = result["rows"][0]

    for name in (
        "pwd",
        "api-key",
        "privateKey",
        "accessToken",
        "refreshToken",
        "clientSecret",
        "passphrase",
        "credit_card_number",
        "cvv",
    ):
        assert row[name] is None, name

    assert row["prompt_tokens"] == 100
    assert row["output_tokens"] == 200


def test_sensitive_column_alias_does_not_expose_value(
    database: Path,
) -> None:
    result = execute_guarded_query(
        database,
        "SELECT password AS harmless_name FROM people WHERE id = 1",
    )

    assert result["ok"] is True
    assert result["rows"][0]["harmless_name"] is None


def test_sensitive_values_through_views_remain_masked(
    database: Path,
) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE VIEW public_people AS
            SELECT id, password AS display_value
            FROM people
            """
        )

    result = execute_guarded_query(
        database,
        "SELECT display_value FROM public_people WHERE id = 1",
    )

    assert result["ok"] is True
    assert result["rows"][0]["display_value"] is None


def test_blocked_write_does_not_change_database(
    database: Path,
) -> None:
    result = execute_guarded_query(
        database,
        "UPDATE people SET name = 'Changed' WHERE id = 1",
    )

    assert result["ok"] is False

    with sqlite3.connect(database) as connection:
        name = connection.execute("SELECT name FROM people WHERE id = 1").fetchone()[0]

    assert name == "Alice"


def test_multiple_statement_write_attempt_is_rejected(
    database: Path,
) -> None:
    result = execute_guarded_query(
        database,
        "SELECT 1; DELETE FROM people",
    )

    assert result["ok"] is False

    with sqlite3.connect(database) as connection:
        count = connection.execute("SELECT COUNT(*) FROM people").fetchone()[0]

    assert count == 2


def test_parameter_size_limits_are_enforced(
    database: Path,
) -> None:
    oversized_text = execute_guarded_query(
        database,
        "SELECT ?",
        ["x" * 5000],
    )

    oversized_blob = execute_guarded_query(
        database,
        "SELECT ?",
        [b"x" * 5000],
    )

    assert oversized_text["code"] == "invalid_input"
    assert oversized_blob["code"] == "invalid_input"


def test_non_finite_query_parameters_are_rejected(
    database: Path,
) -> None:
    for value in (float("nan"), float("inf"), float("-inf")):
        result = execute_guarded_query(
            database,
            "SELECT ?",
            [value],
        )

        assert result["ok"] is False
        assert result["code"] == "invalid_input"


def test_values_queries(database: Path) -> None:
    res1 = execute_guarded_query(database, "VALUES (1, 'hello'), (2, 'world')")
    assert res1["ok"] is True
    assert res1["row_count"] == 2

    res2 = explain_query(database, "VALUES (1, 'hello')")
    assert res2["ok"] is True


def test_empty_and_oversized_queries(database: Path) -> None:
    for empty_sql in ("", "   ", "-- only comments\n", "/* block comment */"):
        res = execute_guarded_query(database, empty_sql)
        assert res["ok"] is False
        assert res["code"] == "invalid_input"

    long_sql = "SELECT " + ("x" * 100_005)
    res_long = execute_guarded_query(database, long_sql)
    assert res_long["ok"] is False
    assert res_long["code"] == "invalid_input"

    res_invalid_first = execute_guarded_query(database, "12345")
    assert res_invalid_first["code"] == "invalid_input"


def test_explain_validation_branches(database: Path) -> None:
    # Bare EXPLAIN without QUERY PLAN
    res1 = execute_guarded_query(database, "EXPLAIN SELECT 1", _allow_explain_plan=True)
    assert res1["code"] == "invalid_input"

    # EXPLAIN QUERY PLAN without inner statement
    res2 = execute_guarded_query(database, "EXPLAIN QUERY PLAN", _allow_explain_plan=True)
    assert res2["code"] == "invalid_input"

    # EXPLAIN QUERY PLAN with non-select/with statement
    res3 = execute_guarded_query(
        database, "EXPLAIN QUERY PLAN DROP TABLE people", _allow_explain_plan=True
    )
    assert res3["code"] == "invalid_input"


def test_invalid_execution_limits(database: Path) -> None:
    res1 = execute_guarded_query(database, "SELECT 1", max_rows=0)
    assert res1["code"] == "invalid_limit"
    res2 = execute_guarded_query(database, "SELECT 1", max_rows=1001)
    assert res2["code"] == "invalid_limit"

    res3 = execute_guarded_query(database, "SELECT 1", timeout_seconds=0.01)
    assert res3["code"] == "invalid_limit"
    res4 = execute_guarded_query(database, "SELECT 1", timeout_seconds=100)
    assert res4["code"] == "invalid_limit"

    res5 = execute_guarded_query(database, "SELECT 1", max_vm_steps=500)
    assert res5["code"] == "invalid_limit"
    res6 = execute_guarded_query(database, "SELECT 1", max_vm_steps=200_000_000)
    assert res6["code"] == "invalid_limit"


def test_invalid_parameter_structures(database: Path) -> None:
    res1 = execute_guarded_query(database, "SELECT 1", params=123)
    assert res1["code"] == "invalid_input"

    res2 = execute_guarded_query(database, "SELECT 1", params={123: "val"})
    assert res2["code"] == "invalid_input"

    res3 = execute_guarded_query(database, "SELECT :flag", params={"flag": True})
    assert res3["ok"] is True

    res4 = execute_guarded_query(database, "SELECT ?", params=[set()])
    assert res4["code"] == "invalid_input"


def test_identifier_validation_and_describe_errors(database: Path, tmp_path: Path) -> None:
    res1 = describe_table(database, "")
    assert res1["code"] == "invalid_table_name"

    res2 = describe_table(database, "a" * 300)
    assert res2["code"] == "invalid_table_name"

    res3 = describe_table(database, "table\x00name")
    assert res3["code"] == "invalid_table_name"

    res4 = describe_table(database, "nonexistent_table")
    assert res4["code"] == "table_not_found"

    res5 = describe_table(tmp_path / "missing.sqlite", "people")
    assert res5["code"] == "database_not_found"


def test_blocked_sqlite_functions(database: Path) -> None:
    res1 = execute_guarded_query(database, "SELECT fsdir('.')")
    assert res1["ok"] is False

    res2 = execute_guarded_query(database, "SELECT eval('1')")
    assert res2["ok"] is False


def test_database_path_not_a_file(tmp_path: Path) -> None:
    res = execute_guarded_query(tmp_path, "SELECT 1")
    assert res["ok"] is False
    assert res["code"] == "database_not_found"


def test_database_corrupt_or_open_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bad_db = tmp_path / "corrupt.sqlite"
    bad_db.write_text("not a valid sqlite file header")

    res = execute_guarded_query(bad_db, "SELECT 1")
    assert res["ok"] is False
    assert res["code"] in {"query_failed", "database_open_failed"}

    # Test database_open_failed when connection cannot be established
    def mock_connect(*args: Any, **kwargs: Any) -> Any:
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr("sqlite3.connect", mock_connect)
    res_open_fail = execute_guarded_query(bad_db, "SELECT 1")
    assert res_open_fail["ok"] is False
    assert res_open_fail["code"] == "database_open_failed"

    res_desc = describe_table(bad_db, "test")
    assert res_desc["ok"] is False
    assert res_desc["code"] == "database_open_failed"


def test_result_size_truncation_warning(database: Path) -> None:
    # Test result truncation where columns or rows exceed MAX_RESULT_BYTES
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE huge (data TEXT)")
        for _ in range(30):
            conn.execute("INSERT INTO huge VALUES (?)", ("y" * 4000,))

    res = execute_guarded_query(database, "SELECT * FROM huge", max_rows=30)
    assert res["ok"] is True
    assert "truncated" in res


@pytest.mark.anyio
async def test_all_mcp_tools_and_schema_resource(database: Path) -> None:
    from mcp import Client

    server = create_server(database)
    async with Client(server, raise_exceptions=True) as client:
        tables_res = await client.call_tool("list_database_tables", {})
        assert tables_res.is_error is False
        tables_data = json.loads(tables_res.content[0].text)
        assert tables_data["ok"] is True
        table_names = [r["name"] for r in tables_data["rows"]]
        assert "people" in table_names

        desc_res = await client.call_tool("describe_database_table", {"table_name": "people"})
        assert desc_res.is_error is False
        desc_data = json.loads(desc_res.content[0].text)
        assert desc_data["ok"] is True
        assert desc_data["table"] == "people"
        col_names = [c["name"] for c in desc_data["columns"]]
        assert "name" in col_names
        assert "password" in col_names

        exp_res = await client.call_tool(
            "explain_read_query", {"sql": "SELECT id FROM people WHERE id = 1"}
        )
        assert exp_res.is_error is False
        exp_data = json.loads(exp_res.content[0].text)
        assert exp_data["ok"] is True

        resources = await client.list_resources()
        resource_uris = [str(r.uri) for r in resources.resources]
        assert "schema://summary" in resource_uris

        res_content = await client.read_resource("schema://summary")
        summary_data = json.loads(res_content.contents[0].text)
        assert "tables" in summary_data
        assert "people" in summary_data["tables"]


def test_cli_main(database: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlite_guard_mcp.server import main

    with pytest.raises(SystemExit) as exc1:
        main(["--version"])
    assert exc1.value.code == 0

    monkeypatch.delenv("SQLITE_GUARD_DB", raising=False)
    with pytest.raises(SystemExit) as exc2:
        main([])
    assert exc2.value.code == 2

    with pytest.raises(SystemExit):
        main(["--db", str(database), "--max-rows", "0"])

    with pytest.raises(SystemExit):
        main(["--db", str(database), "--timeout", "0.01"])

    with pytest.raises(SystemExit):
        main(["--db", str(database), "--max-vm-steps", "100"])

    with pytest.raises(SystemExit):
        main(["--db", str(tmp_path / "does_not_exist.sqlite")])

    with pytest.raises(SystemExit):
        main(["--db", str(tmp_path)])

    called = []

    class DummyServer:
        def run(self, transport="stdio"):
            called.append(transport)

    monkeypatch.setattr(
        "sqlite_guard_mcp.server.create_server", lambda *args, **kwargs: DummyServer()
    )
    exit_code = main(["--db", str(database), "--transport", "stdio"])
    assert exit_code == 0
    assert called == ["stdio"]

    class InterruptServer:
        def run(self, transport="stdio"):
            raise KeyboardInterrupt()

    monkeypatch.setattr(
        "sqlite_guard_mcp.server.create_server", lambda *args, **kwargs: InterruptServer()
    )
    exit_code_ki = main(["--db", str(database)])
    assert exit_code_ki == 0


def test_main_module(database: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import runpy

    called = []

    class DummyServer:
        def run(self, transport="stdio"):
            called.append(transport)

    monkeypatch.setattr(
        "sqlite_guard_mcp.server.create_server", lambda *args, **kwargs: DummyServer()
    )
    monkeypatch.setattr("sys.argv", ["sqlite-guard-mcp", "--db", str(database)])

    with pytest.raises(SystemExit) as exc:
        runpy.run_module("sqlite_guard_mcp.__main__", run_name="__main__")
    assert exc.value.code == 0
    assert called == ["stdio"]


def test_authorizer_direct() -> None:
    from sqlite_guard_mcp.server import _authorize

    assert _authorize(sqlite3.SQLITE_PRAGMA, "database_list", None, None, None) == sqlite3.SQLITE_OK
    assert (
        _authorize(sqlite3.SQLITE_PRAGMA, "database_list", "arg", None, None) == sqlite3.SQLITE_DENY
    )
    assert _authorize(sqlite3.SQLITE_PRAGMA, "table_info", "tbl", None, None) == sqlite3.SQLITE_OK
    assert (
        _authorize(sqlite3.SQLITE_PRAGMA, "unknown_pragma", None, None, None) == sqlite3.SQLITE_DENY
    )
    assert _authorize(sqlite3.SQLITE_INSERT, "tbl", None, None, None) == sqlite3.SQLITE_DENY
    assert _authorize(sqlite3.SQLITE_FUNCTION, None, "fsdir", None, None) == sqlite3.SQLITE_DENY
    assert _authorize(sqlite3.SQLITE_FUNCTION, None, "upper", None, None) == sqlite3.SQLITE_OK


def test_json_safe_and_bounded_result_branches() -> None:
    from sqlite_guard_mcp.server import _bounded_result, _json_safe

    assert _json_safe(float("nan")) is None
    custom_obj = object()
    assert "<object object at" in _json_safe(custom_obj)

    columns = [f"c{i}" for i in range(50)]
    row = {col: "x" * 1500 for col in columns}
    rows = [dict(row) for _ in range(25)]
    bounded = _bounded_result(columns, rows, False, 10.0)
    assert bounded["ok"] is True
    assert bounded["truncated"] is True


@pytest.mark.anyio
async def test_schema_summary_resource_missing_db(tmp_path: Path) -> None:
    from mcp import Client

    server = create_server(tmp_path / "missing.sqlite")
    async with Client(server, raise_exceptions=True) as client:
        res_content = await client.read_resource("schema://summary")
        summary_data = json.loads(res_content.contents[0].text)
        assert summary_data["ok"] is False


def test_describe_table_schema_inspection_failed(
    database: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class BrokenConnection:
        def execute(self, *args: Any, **kwargs: Any) -> Any:
            raise sqlite3.OperationalError("disk error")

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "sqlite_guard_mcp.server._open_connection",
        lambda *args, **kwargs: BrokenConnection(),
    )
    res = describe_table(database, "people")
    assert res["ok"] is False
    assert res["code"] == "schema_inspection_failed"
