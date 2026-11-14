import json
import sqlite3

from sqlite_guard_mcp.server import SQLiteGuard


def make_database(path):
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE people (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );
        INSERT INTO people (name) VALUES ('Ada'), ('Grace'), ('Linus');
        """
    )
    connection.commit()
    connection.close()


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
            "WITH changed AS (DELETE FROM people RETURNING id) SELECT * FROM changed"
        )
    )
    assert result["error"]