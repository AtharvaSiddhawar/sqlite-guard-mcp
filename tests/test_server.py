from __future__ import annotations

import contextlib
import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sqlite_guard_mcp.server import (
    MAX_RESULT_BYTES,
    SQLITE_INT64_MAX,
    SQLITE_INT64_MIN,
    create_server,
    describe_table,
    execute_guarded_query,
    explain_query,
    inspect_schema_summary,
    list_tables,
)


@contextlib.contextmanager
def open_test_connection(path: Path | str) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def database(tmp_path: Path) -> Path:
    path = tmp_path / "sample database.sqlite"

    with open_test_connection(path) as connection:
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
    with open_test_connection(database) as connection:
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
    with open_test_connection(database) as connection:
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
    with open_test_connection(database) as connection:
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
            "get_database_overview",
            "search_database_schema",
            "check_database_health",
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
    with open_test_connection(database) as connection:
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
    with open_test_connection(database) as connection:
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

    with open_test_connection(database) as connection:
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

    with open_test_connection(database) as connection:
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

    # Querying a table or schema forces SQLite to read page 1 from the corrupt file
    res = execute_guarded_query(bad_db, "SELECT * FROM sqlite_schema")
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
    with open_test_connection(database) as conn:
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


def test_main_module_help(monkeypatch: pytest.MonkeyPatch) -> None:
    import runpy

    monkeypatch.setattr("sys.argv", ["sqlite-guard-mcp", "--help"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("sqlite_guard_mcp.__main__", run_name="__main__")
    assert exc.value.code == 0


def test_authorizer_direct() -> None:
    from sqlite_guard_mcp.server import _authorize

    assert (
        _authorize(sqlite3.SQLITE_PRAGMA, "database_list", None, None, None) == sqlite3.SQLITE_DENY
    )
    assert (
        _authorize(sqlite3.SQLITE_PRAGMA, "database_list", "arg", None, None) == sqlite3.SQLITE_DENY
    )
    assert (
        _authorize(sqlite3.SQLITE_READ, "pragma_database_list", "seq", None, None)
        == sqlite3.SQLITE_DENY
    )
    assert (
        _authorize(sqlite3.SQLITE_READ, "sqlite_schema", "sql", None, None) == sqlite3.SQLITE_IGNORE
    )
    assert (
        _authorize(sqlite3.SQLITE_READ, "sqlite_master", "sql", None, None) == sqlite3.SQLITE_IGNORE
    )
    assert (
        _authorize(sqlite3.SQLITE_READ, "sqlite_temp_schema", "sql", None, None)
        == sqlite3.SQLITE_IGNORE
    )
    assert (
        _authorize(sqlite3.SQLITE_READ, "sqlite_temp_master", "sql", None, None)
        == sqlite3.SQLITE_IGNORE
    )
    assert (
        _authorize(sqlite3.SQLITE_READ, "pragma_table_info", "dflt_value", None, None)
        == sqlite3.SQLITE_IGNORE
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


def test_pragma_database_list_is_blocked(database: Path) -> None:
    res1 = execute_guarded_query(database, "PRAGMA database_list")
    assert res1["ok"] is False
    assert res1["code"] == "invalid_input"

    res2 = execute_guarded_query(database, "SELECT * FROM pragma_database_list")
    assert res2["ok"] is False
    assert res2["code"] == "blocked_operation"

    res3 = execute_guarded_query(database, "SELECT * FROM pragma_database_list()")
    assert res3["ok"] is False
    assert res3["code"] == "blocked_operation"


def test_schema_sql_definitions_are_masked(database: Path) -> None:
    res1 = execute_guarded_query(database, "SELECT name, sql FROM sqlite_schema")
    assert res1["ok"] is True
    assert res1["row_count"] > 0
    for row in res1["rows"]:
        assert row["sql"] is None

    res2 = execute_guarded_query(database, "SELECT name, sql FROM sqlite_master")
    assert res2["ok"] is True
    assert res2["row_count"] > 0
    for row in res2["rows"]:
        assert row["sql"] is None

    res3 = execute_guarded_query(
        database,
        "SELECT * FROM sqlite_master WHERE sql LIKE '%CREATE%'",
    )
    assert res3["ok"] is True
    assert res3["row_count"] == 0


def test_sensitive_default_values_are_redacted(database: Path) -> None:
    with open_test_connection(database) as conn:
        conn.execute(
            """
            CREATE TABLE app_config (
                id INTEGER PRIMARY KEY,
                service_name TEXT DEFAULT 'auth_svc',
                client_secret TEXT DEFAULT 'super_secret_shh_123',
                api_key TEXT DEFAULT 'api_live_abc',
                max_retries INTEGER DEFAULT 5
            )
            """
        )

    desc = describe_table(database, "app_config")
    assert desc["ok"] is True

    col_map = {c["name"]: c for c in desc["columns"]}

    assert col_map["service_name"]["masked_by_guard"] is False
    assert col_map["service_name"]["default_redacted"] is False
    assert col_map["service_name"]["dflt_value"] == "'auth_svc'"

    assert col_map["max_retries"]["masked_by_guard"] is False
    assert col_map["max_retries"]["default_redacted"] is False
    assert col_map["max_retries"]["dflt_value"] == "5"

    assert col_map["client_secret"]["masked_by_guard"] is True
    assert col_map["client_secret"]["default_redacted"] is True
    assert col_map["client_secret"]["dflt_value"] is None

    assert col_map["api_key"]["masked_by_guard"] is True
    assert col_map["api_key"]["default_redacted"] is True
    assert col_map["api_key"]["dflt_value"] is None

    # Verify table-valued pragma_table_info masks dflt_value
    pragma_res = execute_guarded_query(
        database,
        "SELECT name, dflt_value FROM pragma_table_info('app_config')",
    )
    assert pragma_res["ok"] is True
    for row in pragma_res["rows"]:
        assert row["dflt_value"] is None


@pytest.mark.anyio
async def test_schema_summary_resource_redacts_sensitive_defaults(database: Path) -> None:
    from mcp import Client

    with open_test_connection(database) as conn:
        conn.execute(
            """
            CREATE TABLE auth_settings (
                id INTEGER PRIMARY KEY,
                provider TEXT DEFAULT 'google',
                signing_key TEXT DEFAULT 'k_private_999'
            )
            """
        )

    server = create_server(database)
    async with Client(server, raise_exceptions=True) as client:
        res = await client.read_resource("schema://summary")
        summary = json.loads(res.contents[0].text)

        auth_cols = {c["name"]: c for c in summary["tables"]["auth_settings"]["columns"]}
        assert auth_cols["provider"]["masked"] is False
        assert auth_cols["provider"]["default_redacted"] is False

        assert auth_cols["signing_key"]["masked"] is True
        assert auth_cols["signing_key"]["default_redacted"] is True


def test_error_messages_do_not_leak_filesystem_paths(tmp_path: Path) -> None:
    fake_path = tmp_path / "deep" / "nested" / "missing.sqlite"
    res1 = execute_guarded_query(fake_path, "SELECT 1")
    assert res1["ok"] is False
    assert str(fake_path) not in res1["error"]
    assert str(tmp_path) not in res1["error"]

    res2 = execute_guarded_query(tmp_path, "SELECT 1")
    assert res2["ok"] is False
    assert str(tmp_path) not in res2["error"]

    corrupt = tmp_path / "corrupt_page.sqlite"
    corrupt.write_text("corrupted content not valid")
    res3 = execute_guarded_query(corrupt, "SELECT * FROM sqlite_schema")
    assert res3["ok"] is False
    assert str(corrupt) not in res3["error"]


def test_connection_and_cursor_lifecycle(database: Path) -> None:
    # Verify connection closure on success
    res_ok = execute_guarded_query(database, "SELECT 1")
    assert res_ok["ok"] is True

    # Verify connection closure on authorizer block
    res_block = execute_guarded_query(database, "PRAGMA database_list")
    assert res_block["ok"] is False

    # Verify connection closure on query error
    res_err = execute_guarded_query(database, "SELECT * FROM nonexistent_table")
    assert res_err["ok"] is False

    # Verify connection closure on describe_table success and error
    desc_ok = describe_table(database, "people")
    assert desc_ok["ok"] is True
    desc_err = describe_table(database, "nonexistent")
    assert desc_err["ok"] is False


def test_integer_parameter_boundaries_and_overflow(database: Path) -> None:
    # Test valid boundary values
    res_max = execute_guarded_query(database, "SELECT ?", [SQLITE_INT64_MAX])
    assert res_max["ok"] is True
    assert list(res_max["rows"][0].values())[0] == SQLITE_INT64_MAX

    res_min = execute_guarded_query(database, "SELECT ?", [SQLITE_INT64_MIN])
    assert res_min["ok"] is True
    assert list(res_min["rows"][0].values())[0] == SQLITE_INT64_MIN

    # Test values immediately outside boundaries
    res_overflow = execute_guarded_query(database, "SELECT ?", [SQLITE_INT64_MAX + 1])
    assert res_overflow["ok"] is False
    assert res_overflow["code"] == "invalid_input"
    assert "signed 64-bit integer range" in res_overflow["error"]

    res_underflow = execute_guarded_query(database, "SELECT ?", [SQLITE_INT64_MIN - 1])
    assert res_underflow["ok"] is False
    assert res_underflow["code"] == "invalid_input"
    assert "signed 64-bit integer range" in res_underflow["error"]

    # Test boolean parameters are preserved and not rejected
    res_bool = execute_guarded_query(database, "SELECT ?, ?", [True, False])
    assert res_bool["ok"] is True


def test_exception_hierarchy_and_classification(database: Path) -> None:
    # Multiple statements should return invalid_input (ProgrammingError)
    res_multi = execute_guarded_query(database, "SELECT 1; SELECT 2")
    assert res_multi["ok"] is False
    assert res_multi["code"] == "invalid_input"

    # Parameter count mismatch should return invalid_input (ProgrammingError)
    res_param_mismatch = execute_guarded_query(database, "SELECT ?, ?", [1])
    assert res_param_mismatch["ok"] is False
    assert res_param_mismatch["code"] == "invalid_input"

    # Nonexistent table should return query_failed (OperationalError)
    res_missing_table = execute_guarded_query(database, "SELECT * FROM nonexistent_table_xyz")
    assert res_missing_table["ok"] is False
    assert res_missing_table["code"] == "query_failed"

    # Comment-only query should return invalid_input
    res_comment = execute_guarded_query(database, "-- this is only a comment\n/* block */")
    assert res_comment["ok"] is False
    assert res_comment["code"] == "invalid_input"

    # Invalid max_vm_steps should return invalid_limit
    res_vm = execute_guarded_query(database, "SELECT 1", max_vm_steps=500)
    assert res_vm["ok"] is False
    assert res_vm["code"] == "invalid_limit"


def test_query_plan_diagnostics(database: Path) -> None:
    # Test query using index
    res_idx = explain_query(database, "SELECT name FROM people WHERE email = 'test'")
    assert res_idx["ok"] is True
    assert "diagnostics" in res_idx
    diag_idx = res_idx["diagnostics"]
    assert diag_idx["uses_index"] is True
    assert "idx_people_email" in diag_idx["indexes_used"]
    assert len(diag_idx["recommendations"]) > 0

    # Test full table scan
    res_scan = explain_query(database, "SELECT name FROM people WHERE name = 'Alice'")
    assert res_scan["ok"] is True
    diag_scan = res_scan["diagnostics"]
    assert diag_scan["scans_table"] is True
    assert "people" in diag_scan["scanned_tables"]
    assert any("Full table scan" in r for r in diag_scan["recommendations"])

    # Test temporary sorting
    res_sort = explain_query(database, "SELECT name FROM people ORDER BY name")
    assert res_sort["ok"] is True
    assert res_sort["diagnostics"]["uses_temp_btree"] is True


def test_describe_table_relationships_and_truncation(database: Path) -> None:
    with open_test_connection(database) as conn:
        conn.execute(
            """
            CREATE TABLE orders (
                order_id INTEGER PRIMARY KEY,
                user_id INTEGER,
                amount REAL,
                FOREIGN KEY(user_id) REFERENCES people(id) ON UPDATE CASCADE ON DELETE SET NULL
            )
            """
        )

    desc = describe_table(database, "orders")
    assert desc["ok"] is True
    assert desc["truncated"] is False
    assert desc["columns_truncated"] is False
    assert desc["indexes_truncated"] is False
    assert desc["foreign_keys_truncated"] is False
    assert len(desc["relationships"]) == 1
    rel = desc["relationships"][0]
    assert rel["from_column"] == "user_id"
    assert rel["target_table"] == "people"
    assert rel["target_column"] == "id"
    assert rel["on_update"] == "CASCADE"
    assert rel["on_delete"] == "SET NULL"


def test_inspect_schema_summary_architecture(database: Path) -> None:
    # Direct function call
    summary = inspect_schema_summary(database)
    assert summary["ok"] is True
    assert summary["table_count"] >= 1
    assert "people" in summary["tables"]
    assert summary["truncated"] is False

    # Add a second table to test table cap truncation
    with open_test_connection(database) as conn:
        conn.execute("CREATE TABLE extra_table (id INTEGER PRIMARY KEY);")

    # Test max_tables cap truncation
    summary_trunc = inspect_schema_summary(database, max_tables=1)
    assert summary_trunc["ok"] is True
    assert summary_trunc["table_count"] == 1
    assert summary_trunc["truncated"] is True
    assert "capped at 1" in summary_trunc["warning"]

    # Test timeout truncation
    summary_timeout = inspect_schema_summary(database, timeout_seconds=0.0)
    assert summary_timeout["ok"] is True
    assert summary_timeout["truncated"] is True


@pytest.mark.anyio
async def test_real_stdio_subprocess_transport(database: Path) -> None:
    import sys

    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "sqlite_guard_mcp", "--db", str(database)],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert init.server_info.name == "sqlite-guard-mcp"

            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            assert "read_query" in tool_names
            assert "describe_database_table" in tool_names

            query_res = await session.call_tool(
                "read_query",
                {"sql": "SELECT name, password FROM people WHERE id = 1"},
            )
            data = json.loads(query_res.content[0].text)
            assert data["ok"] is True
            assert data["rows"][0]["name"] == "Alice"
            assert data["rows"][0]["password"] is None


@pytest.mark.anyio
async def test_real_streamable_http_transport(database: Path) -> None:
    import socket

    import anyio
    import uvicorn
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    sock = socket.socket()
    sock.bind(("", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = create_server(database)
    starlette_app = server.streamable_http_app(streamable_http_path="/mcp")
    config = uvicorn.Config(starlette_app, host="127.0.0.1", port=port, log_level="warning")
    u_server = uvicorn.Server(config)

    async with anyio.create_task_group() as tg:
        tg.start_soon(u_server.serve)
        while not u_server.started:
            await anyio.sleep(0.05)

        try:
            async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as (read, write):
                async with ClientSession(read, write) as session:
                    init = await session.initialize()
                    assert init.server_info.name == "sqlite-guard-mcp"

                    tools = await session.list_tools()
                    assert any(t.name == "read_query" for t in tools.tools)

                    res = await session.call_tool(
                        "read_query",
                        {"sql": "SELECT name FROM people WHERE id = 2"},
                    )
                    data = json.loads(res.content[0].text)
                    assert data["ok"] is True
                    assert data["rows"][0]["name"] == "Bob"
        finally:
            u_server.should_exit = True


def test_cli_host_and_port_options(database: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlite_guard_mcp.server import main

    captured = {}

    class MockServer:
        def run(self, transport="stdio", **kwargs):
            captured["transport"] = transport
            captured["kwargs"] = kwargs

    monkeypatch.setattr(
        "sqlite_guard_mcp.server.create_server",
        lambda *args, **kwargs: MockServer(),
    )

    exit_code = main(
        [
            "--db",
            str(database),
            "--transport",
            "streamable-http",
            "--host",
            "0.0.0.0",
            "--port",
            "8888",
        ]
    )
    assert exit_code == 0
    assert captured["transport"] == "streamable-http"
    assert captured["kwargs"] == {"host": "0.0.0.0", "port": 8888}

    exit_code_sse = main(
        [
            "--db",
            str(database),
            "--transport",
            "sse",
            "--host",
            "127.0.0.1",
            "--port",
            "9000",
        ]
    )
    assert exit_code_sse == 0
    assert captured["transport"] == "sse"
    assert captured["kwargs"] == {"host": "127.0.0.1", "port": 9000}


def test_comprehensive_resource_lifecycle(database: Path) -> None:
    # 1. Successful query
    assert execute_guarded_query(database, "SELECT 1")["ok"] is True

    # 2. ProgrammingError (multi-statement)
    assert execute_guarded_query(database, "SELECT 1; SELECT 2")["ok"] is False

    # 3. OperationalError (syntax error)
    assert execute_guarded_query(database, "SELECT FROM")["ok"] is False

    # 4. Authorizer block
    assert execute_guarded_query(database, "PRAGMA database_list")["ok"] is False

    # 5. Schema summary
    assert inspect_schema_summary(database)["ok"] is True

    # 6. Describe table
    assert describe_table(database, "people")["ok"] is True

    # 7. Explain query
    assert explain_query(database, "SELECT * FROM people")["ok"] is True


def test_schema_inspection_argument_validation(database: Path) -> None:
    # Invalid table_name
    assert describe_table(database, "")["code"] == "invalid_table_name"
    assert describe_table(database, "   ")["code"] == "invalid_table_name"
    assert describe_table(database, 123)["code"] == "invalid_table_name"  # type: ignore

    # Invalid timeout
    assert describe_table(database, "people", timeout_seconds=-1)["code"] == "invalid_input"
    assert describe_table(database, "people", timeout_seconds=999)["code"] == "invalid_input"
    assert describe_table(database, "people", timeout_seconds=True)["code"] == "invalid_input"  # type: ignore

    # Invalid max_vm_steps
    assert describe_table(database, "people", max_vm_steps=-5)["code"] == "invalid_input"
    assert describe_table(database, "people", max_vm_steps=True)["code"] == "invalid_input"  # type: ignore

    # Invalid inspect_schema_summary arguments
    assert inspect_schema_summary(database, max_tables=0)["code"] == "invalid_input"
    assert inspect_schema_summary(database, max_tables=-1)["code"] == "invalid_input"
    assert inspect_schema_summary(database, max_tables=True)["code"] == "invalid_input"  # type: ignore
    assert inspect_schema_summary(database, max_tables=99999)["code"] == "invalid_input"
    assert inspect_schema_summary(database, max_columns_per_table=0)["code"] == "invalid_input"
    assert inspect_schema_summary(database, max_columns_per_table=9999)["code"] == "invalid_input"
    assert inspect_schema_summary(database, timeout_seconds=-0.5)["code"] == "invalid_input"
    assert inspect_schema_summary(database, timeout_seconds=1000)["code"] == "invalid_input"
    assert inspect_schema_summary(database, max_vm_steps=0)["code"] == "invalid_input"


def test_describe_table_index_intelligence_and_overlapping(database: Path) -> None:
    with open_test_connection(database) as conn:
        conn.execute(
            """
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER NOT NULL,
                order_date TEXT NOT NULL,
                total REAL NOT NULL,
                FOREIGN KEY(customer_id) REFERENCES people(id)
            );
            """
        )
        # Duplicate/overlapping indexes on orders
        conn.execute("CREATE INDEX idx_orders_date ON orders(order_date);")
        conn.execute("CREATE INDEX idx_orders_date_total ON orders(order_date, total);")

    desc = describe_table(database, "orders")
    assert desc["ok"] is True
    intel = desc["index_intelligence"]
    assert "customer_id" in intel["unindexed_foreign_keys"]
    assert any("Foreign key column 'customer_id'" in r for r in intel["recommendations"])
    assert any("prefix of composite index" in r for r in intel["recommendations"])


def test_query_plan_diagnostic_observations_and_quoted_identifiers(database: Path) -> None:
    with open_test_connection(database) as conn:
        conn.execute(
            'CREATE TABLE "order items" (id INTEGER PRIMARY KEY, item_name TEXT NOT NULL);'
        )
        conn.execute('CREATE INDEX "idx_item_name" ON "order items"(item_name);')

    # Query with quoted identifier and full table scan
    res = explain_query(database, 'SELECT * FROM "order items"')
    assert res["ok"] is True
    diag = res["diagnostics"]
    assert diag["scans_table"] is True
    assert diag["observations"]["full_scan_detected"] is True
    assert "order items" in diag["scanned_tables"]

    # Query utilizing covering index
    res_idx = explain_query(
        database, 'SELECT item_name FROM "order items" WHERE item_name = ?', ["widget"]
    )
    assert res_idx["ok"] is True
    diag_idx = res_idx["diagnostics"]
    assert diag_idx["uses_index"] is True
    assert diag_idx["observations"]["index_search_detected"] is True
    assert "idx_item_name" in diag_idx["indexes_used"]


def test_schema_summary_partial_status_and_complete_status(tmp_path: Path) -> None:
    db = tmp_path / "test_partial.sqlite"
    with open_test_connection(db) as conn:
        conn.execute("CREATE TABLE t1 (id INTEGER PRIMARY KEY);")
        conn.execute("CREATE TABLE t2 (id INTEGER PRIMARY KEY);")

    # Complete summary
    summary = inspect_schema_summary(db)
    assert summary["ok"] is True
    assert summary["status"] == "complete"
    assert summary["table_count"] == 2
    assert summary["truncated"] is False
    assert len(summary["warnings"]) == 0

    # Partial summary via max_tables cap
    summary_part = inspect_schema_summary(db, max_tables=1)
    assert summary_part["ok"] is True
    assert summary_part["status"] == "partial"
    assert summary_part["table_count"] == 1
    assert summary_part["truncated"] is True
    assert summary_part["tables_truncated"] is True
    assert any(w["code"] == "table_count_capped" for w in summary_part["warnings"])


def test_describe_table_truncation_and_byte_budget(
    database: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sqlite_guard_mcp.server.MAX_COLUMNS", 2)
    monkeypatch.setattr("sqlite_guard_mcp.server.MAX_INDEXES", 1)
    monkeypatch.setattr("sqlite_guard_mcp.server.MAX_FOREIGN_KEYS", 1)
    monkeypatch.setattr("sqlite_guard_mcp.server.MAX_INDEX_COLUMNS", 1)

    desc = describe_table(database, "people")
    assert desc["ok"] is True
    assert desc["columns_truncated"] is True
    assert desc["truncated"] is True

    # Test byte budget truncation
    monkeypatch.setattr("sqlite_guard_mcp.server.MAX_RESULT_BYTES", 300)
    desc_bytes = describe_table(database, "people")
    assert desc_bytes["ok"] is True
    assert desc_bytes["response_truncated"] is True


def test_schema_summary_byte_budget_and_object_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "broken_view.sqlite"
    with open_test_connection(db) as conn:
        conn.execute("CREATE TABLE t_temp (id INT);")
        conn.execute("CREATE VIEW v_broken AS SELECT * FROM t_temp;")
        conn.execute("DROP TABLE t_temp;")

    # When inspecting v_broken, table_xinfo fails because t_temp is missing
    res_fail = inspect_schema_summary(db)
    assert res_fail["ok"] is True
    assert res_fail["status"] == "partial"
    assert any(w["code"] == "schema_object_inspection_failed" for w in res_fail["warnings"])

    # Test response size truncation in inspect_schema_summary
    monkeypatch.setattr("sqlite_guard_mcp.server.MAX_RESULT_BYTES", 300)
    res = inspect_schema_summary(db)
    assert res["ok"] is True
    assert res["response_truncated"] is True
    assert res["truncated"] is True


def test_duplicate_indexes_detection(tmp_path: Path) -> None:
    db = tmp_path / "dup_idx.sqlite"
    with open_test_connection(db) as conn:
        conn.execute("CREATE TABLE items (id INT, code TEXT);")
        conn.execute("CREATE INDEX idx1 ON items(code);")
        conn.execute("CREATE INDEX idx2 ON items(code);")

    desc = describe_table(db, "items")
    assert desc["ok"] is True
    assert any(
        "Duplicate indexes detected" in r for r in desc["index_intelligence"]["recommendations"]
    )
