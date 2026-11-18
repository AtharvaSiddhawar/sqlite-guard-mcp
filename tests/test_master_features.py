"""Comprehensive tests for policy engine, database intelligence, audit logging, and transports."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from sqlite_guard_mcp.policy import AccessPolicy, default_policy, load_policy
from sqlite_guard_mcp.server import (
    MAX_PARAM_KEY_LENGTH,
    MAX_PARAMS_COUNT,
    BearerAuthMiddleware,
    check_database_health,
    create_server,
    describe_table,
    execute_guarded_query,
    get_database_overview,
    inspect_schema_summary,
    list_tables,
    main,
    search_database_schema,
)


def _init_test_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(
            """
            CREATE TABLE departments (
                dept_id INTEGER PRIMARY KEY,
                dept_name TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE employees (
                emp_id INTEGER PRIMARY KEY,
                dept_id INTEGER,
                name TEXT NOT NULL,
                salary REAL,
                ssn_token TEXT,
                ssn_custom TEXT,
                secret_pin TEXT,
                FOREIGN KEY (dept_id) REFERENCES departments(dept_id)
            );
            """
        )
        conn.execute("CREATE INDEX idx_emp_name ON employees(name);")
        conn.execute("CREATE INDEX idx_emp_name_salary ON employees(name, salary);")
        conn.execute(
            """
            CREATE TABLE project_assignments (
                proj_id INTEGER,
                emp_id INTEGER,
                role TEXT,
                PRIMARY KEY (proj_id, emp_id),
                FOREIGN KEY (emp_id) REFERENCES employees(emp_id)
            );
            """
        )
        conn.execute(
            """
            CREATE VIEW emp_summary AS
            SELECT emp_id, name, dept_name
            FROM employees JOIN departments USING (dept_id);
            """
        )
        conn.execute("INSERT INTO departments VALUES (1, 'Engineering');")
        conn.execute(
            "INSERT INTO employees VALUES (101, 1, 'Alice', 95000, 'tok_1', 'custom', '1234');"
        )
        conn.execute("INSERT INTO project_assignments VALUES (10, 101, 'Lead');")
        conn.commit()
    finally:
        conn.close()


def test_policy_loading_and_validation(tmp_path: Path) -> None:
    # Test default policy
    p_def = default_policy()
    assert p_def.is_table_allowed("employees") is True
    assert p_def.is_column_allowed("employees", "salary") is True
    assert p_def.is_column_sensitive("employees", "salary") is False

    # Test load from None
    assert load_policy(None) == p_def

    # Test load from invalid type
    with pytest.raises(ValueError, match="Invalid policy source type"):
        load_policy(12345)  # type: ignore[arg-type]

    # Test invalid configuration table
    with pytest.raises(ValueError, match="Unknown policy configuration sections"):
        load_policy("[unknown_section]\nfoo = 'bar'")

    # Test invalid section types
    with pytest.raises(ValueError, match="The \\[tables\\] section must be a table"):
        load_policy("tables = 'not a table'")

    with pytest.raises(ValueError, match="tables.allow must be a list"):
        load_policy("[tables]\nallow = 'not a list'")

    with pytest.raises(ValueError, match="tables.deny must be a list"):
        load_policy("[tables]\ndeny = 42")

    with pytest.raises(ValueError, match="The \\[columns\\] section must be a table"):
        load_policy("columns = 123")

    with pytest.raises(ValueError, match="columns.allow must be a mapping"):
        load_policy("[columns]\nallow = ['not', 'a', 'dict']")

    with pytest.raises(ValueError, match="columns.allow.employees must be a list"):
        load_policy("[columns.allow]\nemployees = 'col'")

    with pytest.raises(ValueError, match="columns.deny must be a mapping"):
        load_policy("[columns]\ndeny = 'invalid'")

    with pytest.raises(ValueError, match="columns.deny.employees must be a list"):
        load_policy("[columns.deny]\nemployees = 999")

    with pytest.raises(ValueError, match="The \\[privacy\\] section must be a table"):
        load_policy("privacy = 'text'")

    with pytest.raises(ValueError, match="privacy.custom_sensitive_columns must be a list"):
        load_policy("[privacy]\ncustom_sensitive_columns = 'not a list'")

    with pytest.raises(ValueError, match="The \\[features\\] section must be a table"):
        load_policy("features = 'invalid'")

    with pytest.raises(ValueError, match="features.allow_database_overview must be a boolean"):
        load_policy("[features]\nallow_database_overview = 'yes'")

    with pytest.raises(ValueError, match="features.allow_schema_search must be a boolean"):
        load_policy("[features]\nallow_schema_search = 1")

    with pytest.raises(ValueError, match="features.allow_health_check must be a boolean"):
        load_policy("[features]\nallow_health_check = 0")

    # Test valid TOML file loading
    policy_file = tmp_path / "valid_policy.toml"
    policy_file.write_text(
        """
        [tables]
        allow = ["departments", "employees"]
        deny = ["departments"]

        [columns.allow]
        employees = ["emp_id", "dept_id", "name", "salary", "ssn_custom"]

        [columns.deny]
        employees = ["salary"]

        [privacy]
        custom_sensitive_columns = ["ssn_custom"]

        [features]
        allow_database_overview = true
        allow_schema_search = false
        allow_health_check = true
        """,
        encoding="utf-8",
    )

    pol = load_policy(policy_file)
    # Deny table takes precedence over allow
    assert pol.is_table_allowed("departments") is False
    assert pol.is_table_allowed("employees") is True
    assert pol.is_table_allowed("project_assignments") is False

    # Deny column takes precedence over allow
    assert pol.is_column_allowed("employees", "salary") is False
    assert pol.is_column_allowed("employees", "name") is True
    assert pol.is_column_allowed("employees", "secret_pin") is False
    assert pol.is_column_allowed("departments", "dept_name") is False

    # Privacy overrides
    assert pol.is_column_sensitive("employees", "ssn_custom") is True
    assert pol.is_column_sensitive("employees", "name") is False

    # Feature flags
    assert pol.allow_database_overview is True
    assert pol.allow_schema_search is False
    assert pol.allow_health_check is True

    # Test invalid file path with unparseable string
    with pytest.raises(ValueError, match="Policy path does not exist and TOML parse failed"):
        load_policy("nonexistent/missing_file.toml = {[")

    # Load from dict directly
    dict_pol = load_policy({"tables": {"allow": ["t1"]}})
    assert dict_pol.is_table_allowed("t1") is True

    # Load with invalid scalar string in TOML
    with pytest.raises(ValueError, match="Policy path does not exist and TOML parse failed"):
        load_policy("123")

    # Corrupt TOML file
    bad_toml = tmp_path / "bad.toml"
    bad_toml.write_text("invalid = = = toml", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to parse policy TOML file"):
        load_policy(bad_toml)


def test_authorizer_and_query_enforcement_with_policy(tmp_path: Path) -> None:
    db = tmp_path / "policy_test.sqlite"
    _init_test_db(db)

    # Policy denying departments table and employees.salary column
    pol = AccessPolicy(
        deny_tables=frozenset(["departments"]),
        deny_columns={"employees": frozenset(["salary"])},
        custom_sensitive_columns=frozenset(["ssn_custom"]),
    )

    # Query allowed table and allowed column
    res_ok = execute_guarded_query(db, "SELECT name FROM employees WHERE emp_id = 101", policy=pol)
    assert res_ok["ok"] is True
    assert res_ok["rows"][0]["name"] == "Alice"

    # Query custom sensitive column -> masked as None
    res_sens = execute_guarded_query(
        db, "SELECT ssn_custom FROM employees WHERE emp_id = 101", policy=pol
    )
    assert res_sens["ok"] is True
    assert res_sens["rows"][0]["ssn_custom"] is None

    # Query denied table -> authorizer blocks operation
    res_tbl_denied = execute_guarded_query(db, "SELECT * FROM departments", policy=pol)
    assert res_tbl_denied["ok"] is False
    assert res_tbl_denied["code"] == "blocked_operation"

    # Query denied column -> authorizer blocks operation
    res_col_denied = execute_guarded_query(
        db, "SELECT salary FROM employees WHERE emp_id = 101", policy=pol
    )
    assert res_col_denied["ok"] is False
    assert res_col_denied["code"] == "blocked_operation"

    # List tables hides denied table
    tables = list_tables(db, policy=pol)
    assert tables["ok"] is True
    table_names = [r["name"] for r in tables["rows"]]
    assert "employees" in table_names
    assert "departments" not in table_names

    # Describe table denies denied table
    desc_denied = describe_table(db, "departments", policy=pol)
    assert desc_denied["ok"] is False
    assert desc_denied["code"] == "access_denied"

    # Describe table omits denied column and marks custom sensitive column
    desc_emp = describe_table(db, "employees", policy=pol)
    assert desc_emp["ok"] is True
    col_dict = {c["name"]: c for c in desc_emp["columns"]}
    assert "name" in col_dict
    assert "salary" not in col_dict  # denied column omitted
    assert col_dict["ssn_custom"]["masked_by_guard"] is True

    # Inspect schema summary skips denied table and denied columns
    summary = inspect_schema_summary(db, policy=pol)
    assert summary["ok"] is True
    assert "departments" not in summary["tables"]
    assert "employees" in summary["tables"]
    emp_cols = {c["name"] for c in summary["tables"]["employees"]["columns"]}
    assert "salary" not in emp_cols


def test_parameter_bounds_and_validation(tmp_path: Path) -> None:
    db = tmp_path / "param_test.sqlite"
    _init_test_db(db)

    # Exceed maximum parameter count
    oversized_params = [1] * (MAX_PARAMS_COUNT + 1)
    res_count = execute_guarded_query(db, "SELECT 1", oversized_params)
    assert res_count["ok"] is False
    assert res_count["code"] == "invalid_input"
    assert "count exceeds maximum limit" in res_count["error"]

    # Exceed named parameter key length
    long_key = "k" * (MAX_PARAM_KEY_LENGTH + 1)
    res_key = execute_guarded_query(db, "SELECT 1", {long_key: "val"})
    assert res_key["ok"] is False
    assert res_key["code"] == "invalid_input"
    assert "key length exceeds maximum limit" in res_key["error"]

    # Exceed aggregate parameter bytes
    large_chunks = {f"k_{i}": "x" * 4000 for i in range(300)}  # ~1.2 MB
    res_agg = execute_guarded_query(db, "SELECT 1", large_chunks)
    assert res_agg["ok"] is False
    assert res_agg["code"] == "invalid_input"
    assert "Aggregate parameter size" in res_agg["error"]


def test_get_database_overview(tmp_path: Path) -> None:
    db = tmp_path / "overview_test.sqlite"
    _init_test_db(db)

    # Normal overview
    ov = get_database_overview(db)
    assert ov["ok"] is True
    assert ov["sqlite_version"]
    assert ov["schema_version"] >= 1
    assert ov["table_count"] == 3
    assert ov["view_count"] == 1
    assert ov["index_count"] >= 2
    assert ov["page_size"] > 0
    assert ov["page_count"] > 0
    assert ov["approximate_size_bytes"] > 0
    assert ov["read_only"] is True
    assert ov["status"] == "complete"

    # Overview disabled by policy
    disabled_pol = AccessPolicy(allow_database_overview=False)
    ov_denied = get_database_overview(db, policy=disabled_pol)
    assert ov_denied["ok"] is False
    assert ov_denied["code"] == "access_denied"

    # Overview missing db
    ov_missing = get_database_overview(tmp_path / "nonexistent.sqlite")
    assert ov_missing["ok"] is False
    assert ov_missing["code"] == "database_not_found"


def test_search_database_schema(tmp_path: Path) -> None:
    db = tmp_path / "search_test.sqlite"
    _init_test_db(db)

    # Validation errors
    err1 = search_database_schema(db, "")
    assert err1["ok"] is False
    assert err1["code"] == "invalid_input"

    err2 = search_database_schema(db, "x" * 300)
    assert err2["ok"] is False
    assert err2["code"] == "invalid_input"

    err3 = search_database_schema(db, "name", max_results=0)
    assert err3["ok"] is False
    assert err3["code"] == "invalid_input"

    # Successful search for "name"
    res = search_database_schema(db, "name")
    assert res["ok"] is True
    matches = res["matches"]
    assert any(m["object_type"] == "column" and m["name"] == "name" for m in matches)
    assert any(m["object_type"] == "column" and m["name"] == "dept_name" for m in matches)
    assert any(m["object_type"] == "index" and m["name"] == "idx_emp_name" for m in matches)

    # Search with policy denying department table
    pol = AccessPolicy(deny_tables=frozenset(["departments"]))
    res_filtered = search_database_schema(db, "dept", policy=pol)
    assert res_filtered["ok"] is True
    # departments table must NOT be in matches
    dept_matches = [
        m
        for m in res_filtered["matches"]
        if m["object_type"] == "table" and m["name"] == "departments"
    ]
    assert len(dept_matches) == 0

    # Search disabled by policy
    no_search_pol = AccessPolicy(allow_schema_search=False)
    res_denied = search_database_schema(db, "emp", policy=no_search_pol)
    assert res_denied["ok"] is False
    assert res_denied["code"] == "access_denied"

    # Search missing db
    res_missing = search_database_schema(tmp_path / "not_there.sqlite", "test")
    assert res_missing["ok"] is False
    assert res_missing["code"] == "database_not_found"


def test_check_database_health(tmp_path: Path) -> None:
    db = tmp_path / "health_test.sqlite"
    _init_test_db(db)

    # Initial check on database with redundant index idx_emp_name (prefix of idx_emp_name_salary)
    health = check_database_health(db)
    assert health["ok"] is True
    assert health["checks"]["quick_check"]["status"] == "passed"
    assert health["checks"]["foreign_key_check"]["status"] == "passed"
    assert health["overall_status"] == "warnings_detected"
    assert any("is a prefix of composite index" in r for r in health["recommendations"])

    # Health check disabled by policy
    no_health_pol = AccessPolicy(allow_health_check=False)
    health_denied = check_database_health(db, policy=no_health_pol)
    assert health_denied["ok"] is False
    assert health_denied["code"] == "access_denied"

    # Health check missing db
    health_missing = check_database_health(tmp_path / "no_file.sqlite")
    assert health_missing["ok"] is False
    assert health_missing["code"] == "database_not_found"


@pytest.mark.anyio
async def test_bearer_auth_middleware() -> None:
    async def dummy_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = BearerAuthMiddleware(dummy_app, token="secret-token-123")

    # Request without Authorization header -> 401
    sent_msgs = []

    async def mock_send(msg):
        sent_msgs.append(msg)

    scope_no_auth = {"type": "http", "headers": []}
    await middleware(scope_no_auth, None, mock_send)
    assert sent_msgs[0]["status"] == 401
    assert b"Unauthorized" in sent_msgs[1]["body"]

    # Request with invalid token -> 401
    sent_msgs.clear()
    scope_bad_auth = {
        "type": "http",
        "headers": [(b"authorization", b"Bearer wrong-token")],
    }
    await middleware(scope_bad_auth, None, mock_send)
    assert sent_msgs[0]["status"] == 401

    # Request with valid token -> 200
    sent_msgs.clear()
    scope_good_auth = {
        "type": "http",
        "headers": [(b"authorization", b"Bearer secret-token-123")],
    }
    await middleware(scope_good_auth, None, mock_send)
    assert sent_msgs[0]["status"] == 200
    assert sent_msgs[1]["body"] == b"ok"


def test_audit_logging(tmp_path: Path) -> None:
    db = tmp_path / "audit_test.sqlite"
    _init_test_db(db)
    audit_file = tmp_path / "audit.jsonl"

    res = execute_guarded_query(
        db,
        "SELECT name FROM employees WHERE emp_id = 101",
        audit_file=audit_file,
    )
    assert res["ok"] is True
    assert audit_file.exists()

    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["tool"] == "read_query"
    assert event["status"] == "success"
    assert event["row_count"] == 1
    assert "query_fingerprint" in event
    # Ensure raw parameters and raw results are NOT in audit event
    assert "Alice" not in lines[0]


def test_cli_with_policy_and_audit(tmp_path: Path) -> None:
    db = tmp_path / "cli_db.sqlite"
    _init_test_db(db)

    policy_file = tmp_path / "policy.toml"
    policy_file.write_text("[tables]\nallow = ['employees']\n", encoding="utf-8")
    audit_file = tmp_path / "cli_audit.jsonl"

    # Test invalid policy file path exiting with error code 2
    with pytest.raises(SystemExit) as exc1:
        main(["--db", str(db), "--policy", str(tmp_path / "missing.toml")])
    assert exc1.value.code == 2

    # Test create_server with policy and audit file
    pol = load_policy(policy_file)
    server = create_server(db, policy=pol, audit_file=audit_file, auth_token="tok123")
    assert server.auth_token == "tok123"


@pytest.mark.anyio
async def test_mcp_client_calling_new_tools(tmp_path: Path) -> None:
    from mcp import Client

    db = tmp_path / "mcp_tools_db.sqlite"
    _init_test_db(db)

    server = create_server(db)
    async with Client(server, raise_exceptions=True) as client:
        # Call get_database_overview
        ov_res = await client.call_tool("get_database_overview", {})
        assert ov_res.is_error is False
        ov_data = json.loads(ov_res.content[0].text)
        assert ov_data["ok"] is True
        assert ov_data["table_count"] >= 1

        # Call search_database_schema
        search_res = await client.call_tool("search_database_schema", {"query": "employees"})
        assert search_res.is_error is False
        search_data = json.loads(search_res.content[0].text)
        assert search_data["ok"] is True
        assert len(search_data["matches"]) >= 1

        # Call check_database_health
        health_res = await client.call_tool("check_database_health", {})
        assert health_res.is_error is False
        health_data = json.loads(health_res.content[0].text)
        assert health_data["ok"] is True
        assert "checks" in health_data


def test_health_check_with_foreign_key_violations(tmp_path: Path) -> None:
    db = tmp_path / "fk_violation.sqlite"
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA foreign_keys = OFF;")
        conn.execute("CREATE TABLE parent (id INT PRIMARY KEY);")
        conn.execute(
            "CREATE TABLE child (id INT, pid INT, FOREIGN KEY(pid) REFERENCES parent(id));"
        )
        conn.execute("INSERT INTO child VALUES (1, 999);")
        conn.commit()
    finally:
        conn.close()

    res = check_database_health(db)
    assert res["ok"] is True
    assert res["overall_status"] == "issues_detected"
    assert res["checks"]["foreign_key_check"]["status"] == "violations_found"
    assert any("foreign key constraint violations" in r for r in res["recommendations"])


def test_coverage_gap_closers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlite_guard_mcp.server import (
        _bounded_result,
        _is_sensitive_column,
        _validate_params,
        explain_query,
    )

    # 1. Non-alphanumeric column name normalization
    assert _is_sensitive_column("___") is False
    assert _is_sensitive_column("$$$") is False

    # 2. Parameter validation with None, float, and bytes
    params = [None, 3.14159, b"binary_payload", 100, "text"]
    validated = _validate_params(params)
    assert validated == params

    # 3. Policy error paths
    with pytest.raises(ValueError, match="Invalid policy source type"):
        load_policy(12345)  # type: ignore[arg-type]

    # Non-dict parsed toml (mocking tomllib.loads to return non-dict)
    monkeypatch.setattr("tomllib.loads", lambda s: "string_not_dict")
    with pytest.raises(ValueError, match="Policy configuration must be a TOML table"):
        load_policy("[dummy]")

    # 4. sqlite3.Error branch in execute_guarded_query
    db = tmp_path / "err_test.sqlite"
    _init_test_db(db)
    res = execute_guarded_query(db, "SELECT * FROM nonexistent_table_xyz_123")
    assert res["ok"] is False
    assert res["code"] == "query_failed"

    # 5. CLI transports with auth token (mocking uvicorn.run)
    called = []

    def mock_uvicorn_run(*args, **kwargs):
        called.append((kwargs.get("host"), kwargs.get("port")))

    import sys

    monkeypatch.setitem(sys.modules, "uvicorn", type("UvicornMod", (), {"run": mock_uvicorn_run})())

    args_http = [
        "--db",
        str(db),
        "--transport",
        "streamable-http",
        "--auth-token",
        "token-secret",
        "--port",
        "9876",
    ]
    code = main(args_http)
    assert code == 0
    assert called == [("127.0.0.1", 9876)]

    called.clear()
    args_sse = [
        "--db",
        str(db),
        "--transport",
        "sse",
        "--auth-token",
        "token-secret",
        "--port",
        "9877",
    ]
    code = main(args_sse)
    assert code == 0
    assert called == [("127.0.0.1", 9877)]

    # 6. KeyboardInterrupt handling in main
    def mock_server_run(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr("mcp.server.mcpserver.MCPServer.run", mock_server_run)
    code = main(["--db", str(db), "--transport", "stdio"])
    assert code == 0

    # 7. Payload exceeding MAX_RESULT_BYTES in _bounded_result
    # When MAX_RESULT_BYTES is tiny, even empty rows payload exceeds limit
    from sqlite_guard_mcp import server as srv_mod

    monkeypatch.setattr(srv_mod, "MAX_RESULT_BYTES", 50)
    b_res = _bounded_result(
        ["col1"],
        [{"col1": "a" * 100}],
        truncated=False,
        elapsed_ms=1.0,
    )
    assert b_res["response_truncated"] is True
    assert b_res["rows"] == []
    assert "exceeded maximum response size" in b_res["warning"]

    # 8. Index scan in explain_query
    conn = sqlite3.connect(db)
    try:
        conn.execute("CREATE INDEX idx_emp_salary ON employees(salary);")
        conn.commit()
    finally:
        conn.close()

    eq_res = explain_query(db, "SELECT salary FROM employees WHERE salary > 50000 ORDER BY salary")
    assert eq_res["ok"] is True
