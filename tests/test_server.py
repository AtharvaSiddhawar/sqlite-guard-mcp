import json
import sqlite3

from sqlite_guard_mcp import SQLiteGuard


def make_database(path):
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE people (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            );
            INSERT INTO people (name) VALUES ('Ada'), ('Grace'), ('Linus');
            """
        )


def test_lists_and_describes_tables(tmp_path):
    database = tmp_path / "example.db"
    make_database(database)
    guard = SQLiteGuard(database)

    assert json.loads(guard.list_tables()) == [
        {"name": "people", "type": "table"}
    ]

    description = json.loads(guard.describe_table("people"))
    assert description["columns"][0]["name"] == "id"
    assert description["columns"][0]["primary_key_position"] == 1


def test_query_returns_rows_and_truncates_at_limit(tmp_path):
    database = tmp_path / "example.db"
    make_database(database)
    guard = SQLiteGuard(database, max_rows=2)

    result = json.loads(guard.query("SELECT id, name FROM people ORDER BY id"))

    assert len(result["rows"]) == 2
    assert result["truncated"] is True
    assert result["rows"][0]["name"] == "Ada"


def test_rejects_writes_and_multiple_statements(tmp_path):
    database = tmp_path / "example.db"
    make_database(database)
    guard = SQLiteGuard(database)

    assert "Only a single SELECT or WITH" in json.loads(
        guard.query("DELETE FROM people")
    )["error"]
    assert json.loads(guard.query("SELECT 1; SELECT 2"))["error"]


def test_authorizer_blocks_write_inside_cte(tmp_path):
    database = tmp_path / "example.db"
    make_database(database)
    guard = SQLiteGuard(database)

    result = json.loads(
        guard.query(
            "WITH changed AS (DELETE FROM people RETURNING id) "
            "SELECT * FROM changed"
        )
    )
    assert result["error"]


def test_blocks_random_function(tmp_path):
    database = tmp_path / "example.db"
    make_database(database)
    guard = SQLiteGuard(database)

    assert json.loads(guard.query("SELECT random()"))["error"]


def test_database_is_not_modified(tmp_path):
    database = tmp_path / "example.db"
    make_database(database)
    guard = SQLiteGuard(database)

    result = json.loads(guard.query("SELECT COUNT(*) AS count FROM people"))
    assert result["rows"][0]["count"] == 3

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM people").fetchone()[0] == 3


def test_rejects_missing_database(tmp_path):
    missing_database = tmp_path / "missing.db"

    try:
        SQLiteGuard(missing_database)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected a missing database path to be rejected")


def test_requires_database_path_for_module_entrypoint(tmp_path):
    import os
    import subprocess
    import sys

    env = os.environ.copy()
    env.pop("SQLITE_GUARD_DB", None)

    result = subprocess.run(
        [sys.executable, "-m", "sqlite_guard_mcp"],
        env=env,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )

    assert result.returncode == 2
    assert "Set SQLITE_GUARD_DB" in result.stderr
