
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

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
        connection.execute(
            "ALTER TABLE people ADD COLUMN apiToken TEXT"
        )
        connection.execute(
            "ALTER TABLE people ADD COLUMN promptTokens INTEGER"
        )
        connection.execute(
            "UPDATE people SET apiToken='secret-value', promptTokens=77"
        )

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
        (
            "WITH changed AS "
            "(DELETE FROM people RETURNING id) "
            "SELECT * FROM changed"
        ),
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
    assert "idx_people_email" in json.dumps(result["rows"])


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
    assert [
        row["name"] for row in tables["rows"]
    ] == ["people"]

    schema = describe_table(database, "people")

    assert schema["ok"] is True
    assert schema["columns"][3]["masked_by_guard"] is True
    assert schema["indexes"][0]["name"] == "idx_people_email"
    assert schema["indexes"][0]["columns"][0]["name"] == "email"


def test_table_names_with_quotes_are_safely_escaped(
    database: Path,
) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            'CREATE TABLE "odd name" ("select" TEXT)'
        )

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

        names = {
            tool.name
            for tool in tools.tools
        }

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
        name = connection.execute(
            "SELECT name FROM people WHERE id = 1"
        ).fetchone()[0]

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
        count = connection.execute(
            "SELECT COUNT(*) FROM people"
        ).fetchone()[0]

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
