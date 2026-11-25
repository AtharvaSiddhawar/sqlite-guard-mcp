"""Tests for SQLite Guard MCP differentiators:

Index Laboratory, Data Profiler, Schema Snapshot & Diff, Migration Review,
and CLI Doctor / Policy Explanation.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sqlite_guard_mcp.doctor import format_doctor_report, run_doctor
from sqlite_guard_mcp.index_lab import simulate_index, validate_candidate_index
from sqlite_guard_mcp.policy import AccessPolicy
from sqlite_guard_mcp.profiler import profile_table
from sqlite_guard_mcp.schema_diff import diff_schemas, review_migration, snapshot_schema
from sqlite_guard_mcp.server import create_server, main


def _create_differentiator_test_db(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(
            """
            CREATE TABLE customers (
                customer_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT,
                api_key TEXT,
                credit_score REAL,
                internal_notes TEXT,
                status TEXT DEFAULT 'active'
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE orders (
                order_id INTEGER PRIMARY KEY,
                customer_id INTEGER,
                order_date TEXT,
                amount REAL,
                FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
            );
            """
        )
        conn.execute(
            """
            CREATE VIEW customer_order_view AS
            SELECT c.customer_id, c.name, o.order_id, o.amount
            FROM customers c JOIN orders o ON c.customer_id = o.customer_id;
            """
        )

        # Insert test records
        for i in range(1, 101):
            conn.execute(
                """
                INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    i,
                    f"Customer {i}",
                    f"user{i}@example.com" if i % 10 != 0 else None,
                    f"key_secret_{i}",
                    600.0 + i,
                    f"Internal note {i}",
                    "active" if i % 2 == 0 else "inactive",
                ),
            )
            conn.execute(
                """
                INSERT INTO orders VALUES (?, ?, '2026-01-01', ?);
                """,
                (i, i, 50.0 + i * 2),
            )
        conn.commit()
    finally:
        conn.close()


def test_index_lab_validation_and_simulation(tmp_path: Path) -> None:
    db_file = tmp_path / "test_lab.db"
    _create_differentiator_test_db(db_file)

    # Validate candidate index parser
    idx_name, tbl_name, cols = validate_candidate_index(
        "CREATE INDEX idx_customers_status ON customers(status)"
    )
    assert idx_name == "idx_customers_status"
    assert tbl_name == "customers"
    assert cols == ["status"]

    with pytest.raises(ValueError, match="Candidate index statement must be a valid"):
        validate_candidate_index("DROP TABLE customers;")

    with pytest.raises(ValueError, match="Candidate index must specify at least one target column"):
        validate_candidate_index("CREATE INDEX idx_bad ON customers()")

    # Simulate index on query that originally does a scan
    query = "SELECT * FROM customers WHERE status = 'active';"
    candidate = "CREATE INDEX idx_cust_status ON customers(status);"

    res = simulate_index(db_file, query, candidate)
    assert res["success"] is True
    assert res["source_database_unmodified"] is True
    assert "baseline" in res
    assert "candidate" in res
    assert "comparison" in res
    assert isinstance(res["recommendations"], list)

    # Test policy enforcement on index lab
    restricted_policy = AccessPolicy(
        allow_tables=frozenset({"orders"}),
        allow_index_lab=True,
    )
    denied_res = simulate_index(db_file, query, candidate, policy=restricted_policy)
    assert denied_res.get("ok") is False
    assert denied_res["code"] == "access_denied"

    # Test index lab disabled by policy
    disabled_policy = AccessPolicy(allow_index_lab=False)
    dis_res = simulate_index(db_file, query, candidate, policy=disabled_policy)
    assert dis_res.get("ok") is False
    assert dis_res["code"] == "access_denied"

    # Test invalid query in index lab
    inv_res = simulate_index(db_file, "DELETE FROM customers;", candidate)
    assert inv_res.get("ok") is False
    assert inv_res["code"] == "invalid_input"

    # Test non-existent database
    missing_res = simulate_index(tmp_path / "missing.db", query, candidate)
    assert missing_res.get("ok") is False
    assert missing_res["code"] == "database_not_found"


def test_profiler(tmp_path: Path) -> None:
    db_file = tmp_path / "test_prof.db"
    _create_differentiator_test_db(db_file)

    # Profile customers table
    prof = profile_table(db_file, "customers")
    assert prof["success"] is True
    assert prof["table_name"] == "customers"
    assert prof["total_rows"] == 100
    assert "columns" in prof
    cols = prof["columns"]

    # Check non-sensitive column profiling
    assert cols["name"]["nullable"] is False
    assert cols["customer_id"]["is_primary_key"] is True
    assert cols["customer_id"]["distinct_count"] == 100
    assert cols["status"]["cardinality_ratio"] < 0.05
    assert len(cols["status"]["sample_values"]) > 0

    # Check sensitive credential column masking
    assert cols["api_key"]["is_sensitive"] is True
    assert cols["api_key"]["masked"] is True
    assert cols["api_key"]["min_value"] is None
    assert cols["api_key"]["max_value"] is None
    assert cols["api_key"]["sample_values"] == ["[REDACTED_SENSITIVE]"]

    # Check null percentages on email
    assert cols["email"]["null_count"] == 10
    assert cols["email"]["null_percentage"] == 10.0

    # Test policy with denied table
    policy = AccessPolicy(deny_tables=frozenset({"customers"}))
    den_prof = profile_table(db_file, "customers", policy=policy)
    assert den_prof.get("ok") is False
    assert den_prof["code"] == "access_denied"

    # Test profiling disabled
    dis_policy = AccessPolicy(allow_profiling=False)
    dis_prof = profile_table(db_file, "customers", policy=dis_policy)
    assert dis_prof.get("ok") is False
    assert dis_prof["code"] == "access_denied"

    # Test non-existent table
    miss_prof = profile_table(db_file, "non_existent_table")
    assert miss_prof.get("ok") is False
    assert miss_prof["code"] == "table_not_found"


def test_schema_snapshot_diff_and_migration_review(tmp_path: Path) -> None:
    db_file_a = tmp_path / "db_a.db"
    _create_differentiator_test_db(db_file_a)

    db_file_b = tmp_path / "db_b.db"
    conn_b = sqlite3.connect(db_file_b)
    try:
        conn_b.execute(
            """
            CREATE TABLE customers (
                customer_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT,
                phone TEXT NOT NULL DEFAULT '000-0000',
                status TEXT
            );
            """
        )
        conn_b.execute("CREATE INDEX idx_cust_email ON customers(email);")
        conn_b.commit()
    finally:
        conn_b.close()

    snap_a = snapshot_schema(db_file_a)
    assert snap_a["success"] is True
    assert "customers" in snap_a["tables"]
    assert "orders" in snap_a["tables"]
    assert "customer_order_view" in snap_a["views"]

    snap_b = snapshot_schema(db_file_b)
    assert snap_b["success"] is True

    # Diff schemas
    diff = diff_schemas(snap_a, snap_b)
    assert diff["success"] is True
    assert "orders" in diff["tables"]["removed"]
    assert "customer_order_view" in diff["views"]["removed"]
    assert "customers" in diff["tables"]["modified"]

    cust_mod = diff["tables"]["modified"]["customers"]
    added_col_names = [c["name"] for c in cust_mod["added_columns"]]
    assert "phone" in added_col_names
    assert "api_key" in cust_mod["removed_columns"]
    assert diff["risk_level"] in {"HIGH", "MEDIUM"}

    # Review migration scripts
    safe_sql = """
    BEGIN TRANSACTION;
    CREATE TABLE audit_events (
        event_id INTEGER PRIMARY KEY,
        created_at TEXT NOT NULL
    );
    CREATE INDEX idx_audit_created ON audit_events(created_at);
    COMMIT;
    """
    rev_safe = review_migration(safe_sql)
    assert rev_safe["success"] is True
    assert rev_safe["safe"] is True
    assert rev_safe["risk_level"] == "SAFE"

    dangerous_sql = """
    DROP TABLE customers;
    ALTER TABLE orders ADD COLUMN legacy_code TEXT NOT NULL;
    PRAGMA writable_schema = ON;
    ATTACH DATABASE 'other.db' AS other;
    """
    rev_danger = review_migration(dangerous_sql)
    assert rev_danger["success"] is True
    assert rev_danger["safe"] is False
    assert rev_danger["risk_level"] == "DANGEROUS"
    assert len(rev_danger["issues"]) >= 3


def test_doctor_and_cli_subcommands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_file = tmp_path / "doctor_test.db"
    _create_differentiator_test_db(db_file)

    pol_file = tmp_path / "test_pol.toml"
    pol_file.write_text(
        """
        [tables]
        allow = ["customers", "orders"]
        deny = ["secret_table"]

        [columns]
        deny = ["*.internal_notes", "customers.credit_score"]

        [privacy]
        sensitive_columns = ["api_key"]

        [features]
        allow_explain_query = true
        allow_profiling = true
        allow_index_lab = true
        """
    )

    # Test run_doctor
    doc = run_doctor(db_file, pol_file)
    assert doc["status"] == "HEALTHY"
    assert doc["database"]["quick_check"] == "ok"
    assert doc["policy"]["valid"] is True

    report_text = format_doctor_report(doc)
    assert "SQLite Guard MCP Doctor Diagnostic" in report_text
    assert "customers" in report_text or "Allow=2" in report_text

    # Test CLI --doctor
    ret_doctor = main(["--doctor", "--db", str(db_file), "--policy", str(pol_file)])
    assert ret_doctor == 0

    # Test CLI --validate-policy
    ret_val = main(["--validate-policy", "--policy", str(pol_file)])
    assert ret_val == 0

    # Test CLI --explain-policy-table
    ret_exp = main(
        [
            "--policy",
            str(pol_file),
            "--explain-policy-table",
            "customers",
            "--explain-policy-column",
            "internal_notes",
        ]
    )
    assert ret_exp == 0
    captured = capsys.readouterr()
    assert "matches wildcard deny rule" in captured.out


@pytest.mark.anyio
async def test_mcp_server_new_differentiator_tools(tmp_path: Path) -> None:

    db_file = tmp_path / "mcp_diff.db"
    _create_differentiator_test_db(db_file)

    server = create_server(db_file)
    # Verify tool registration on server
    tools = await server.list_tools()
    tool_names = {t.name for t in tools}
    assert "simulate_candidate_index" in tool_names
    assert "profile_database_table" in tool_names
    assert "diff_database_schemas" in tool_names
    assert "review_migration_script" in tool_names

    # Verify resource registration
    resources = await server.list_resources()
    resource_uris = {str(r.uri) for r in resources}
    assert "schema://summary" in resource_uris
    assert "schema://snapshot" in resource_uris


def test_policy_explain_branches() -> None:
    policy = AccessPolicy(
        allow_tables=frozenset({"allowed_table", "partial_table"}),
        deny_tables=frozenset({"blocked_table"}),
        allow_columns={"partial_table": frozenset({"col_a", "col_b"})},
        deny_columns={"partial_table": frozenset({"secret_col"})},
        allow_columns_wildcard=frozenset({"common_id"}),
        deny_columns_wildcard=frozenset({"restricted_meta"}),
        custom_sensitive_columns=frozenset({"token"}),
    )

    # 1. Denied table
    res1 = policy.explain_access("blocked_table")
    assert res1["allowed"] is False
    assert "deny_tables" in res1["reason"]

    # 2. Table not in allow-list
    res2 = policy.explain_access("unknown_table")
    assert res2["allowed"] is False
    assert "allow_tables allow-list" in res2["reason"]

    # 3. Table allowed without column specified
    res3 = policy.explain_access("allowed_table")
    assert res3["allowed"] is True
    assert res3["column_allowed"] is None

    # 4. Wildcard deny column
    res4 = policy.explain_access("allowed_table", "restricted_meta")
    assert res4["allowed"] is False
    assert "wildcard deny rule" in res4["reason"]

    # 5. Table column deny
    res5 = policy.explain_access("partial_table", "secret_col")
    assert res5["allowed"] is False
    assert "matches table column deny rule" in res5["reason"]

    # 6. Column not in allow-list
    res6 = policy.explain_access("partial_table", "other_col")
    assert res6["allowed"] is False
    assert "not in allow_columns allow-list" in res6["reason"]

    # 7. Column allowed and sensitive
    res7 = policy.explain_access("partial_table", "col_a")
    assert res7["allowed"] is True
    assert res7["is_sensitive"] is False

    # 8. Wildcard allow column
    policy_wild_allow = AccessPolicy(
        allow_tables=frozenset({"tbl"}),
        allow_columns_wildcard=frozenset({"safe_id"}),
    )
    res8 = policy_wild_allow.explain_access("tbl", "safe_id")
    assert res8["allowed"] is True
    res8_den = policy_wild_allow.explain_access("tbl", "other")
    assert res8_den["allowed"] is False


def test_doctor_and_cli_edge_cases(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # 1. Database path does not exist
    doc1 = run_doctor(tmp_path / "nonexistent.db")
    assert doc1["status"] == "ERROR"
    assert len(doc1["errors"]) > 0

    # 2. Database path is a directory
    dir_path = tmp_path / "somedir"
    dir_path.mkdir()
    doc2 = run_doctor(dir_path)
    assert doc2["status"] == "ERROR"

    # 3. Policy file does not exist
    doc3 = run_doctor(policy_path=tmp_path / "missing_policy.toml")
    assert doc3["status"] == "ERROR"

    # 4. Policy file is invalid TOML
    bad_pol = tmp_path / "bad.toml"
    bad_pol.write_text("[tables\ninvalid syntax")
    doc4 = run_doctor(policy_path=bad_pol)
    assert doc4["status"] == "ERROR"

    # 5. Database with foreign key violation
    fk_db = tmp_path / "fk_corrupt.db"
    conn = sqlite3.connect(fk_db)
    conn.execute("PRAGMA foreign_keys = OFF;")
    conn.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY);")
    conn.execute("CREATE TABLE child (id INTEGER PRIMARY KEY, p_id INTEGER REFERENCES parent(id));")
    conn.execute("INSERT INTO child VALUES (1, 999);")
    conn.commit()
    conn.close()

    doc5 = run_doctor(fk_db)
    assert doc5["status"] == "DEGRADED"
    assert doc5["database"]["foreign_key_violations_count"] == 1

    # CLI tests
    assert main(["--validate-policy", "--policy", str(bad_pol)]) == 1
    assert main(["--explain-policy-table", "customers", "--policy", str(bad_pol)]) == 1
    with pytest.raises(SystemExit):
        main(["--validate-policy"])


def test_index_lab_more_branches(tmp_path: Path) -> None:
    db_file = tmp_path / "index_lab_branches.db"
    _create_differentiator_test_db(db_file)

    # Candidate with denied column
    policy = AccessPolicy(
        allow_tables=frozenset({"customers"}),
        deny_columns={"customers": frozenset({"status"})},
        allow_index_lab=True,
    )
    res = simulate_index(
        db_file,
        "SELECT * FROM customers WHERE status = 'active';",
        "CREATE INDEX idx_c ON customers(status);",
        policy=policy,
    )
    assert res.get("ok") is False
    assert res["code"] == "access_denied"

    # Invalid candidate indexes type
    res_inv = simulate_index(db_file, "SELECT 1;", 12345)  # type: ignore[arg-type]
    assert res_inv.get("ok") is False

    # Empty candidate list
    res_empty = simulate_index(db_file, "SELECT 1;", [])
    assert res_empty.get("ok") is False


def test_profiler_and_schema_diff_more_branches(tmp_path: Path) -> None:
    db_file = tmp_path / "prof_branches.db"
    conn = sqlite3.connect(db_file)
    conn.execute(
        """
        CREATE TABLE items (
            item_id INTEGER PRIMARY KEY,
            dead_col TEXT,
            text_col TEXT,
            num_col REAL
        );
        """
    )
    for i in range(1, 20):
        conn.execute(
            "INSERT INTO items VALUES (?, NULL, ?, ?);",
            (i, "" if i % 2 == 0 else f"item_{i}", i * 1.5),
        )
    conn.commit()
    conn.close()

    # Profile items table
    p = profile_table(db_file, "items")
    assert p["success"] is True
    cols = p["columns"]
    assert cols["dead_col"]["null_percentage"] == 100.0
    assert cols["text_col"]["empty_string_count"] > 0
    assert cols["num_col"]["min_value"] == 1.5

    # Schema diff breaking changes
    snap1 = {
        "success": True,
        "tables": {
            "t1": {
                "columns": [
                    {"name": "c1", "type": "INTEGER", "notnull": False, "pk": False},
                    {"name": "c2", "type": "TEXT", "notnull": False, "pk": False},
                ],
                "indexes": [{"name": "idx_c1"}],
            }
        },
        "views": {"v1": {}},
    }
    snap2 = {
        "success": True,
        "tables": {
            "t1": {
                "columns": [
                    {"name": "c1", "type": "TEXT", "notnull": True, "dflt_value": None, "pk": True},
                ],
                "indexes": [],
            }
        },
        "views": {},
    }
    diff = diff_schemas(snap1, snap2)
    assert diff["risk_level"] == "HIGH"
    assert len(diff["breaking_changes"]) >= 3

    # Review migration empty
    assert review_migration("   ")["ok"] is False


def test_comprehensive_branch_coverage(tmp_path: Path) -> None:
    db_file = tmp_path / "branch_cov.db"
    conn = sqlite3.connect(db_file)
    conn.execute(
        """
        CREATE TABLE secure_data (
            id INTEGER PRIMARY KEY,
            col_allowed TEXT,
            col_denied TEXT,
            api_secret TEXT DEFAULT 'super_secret_dflt'
        );
        """
    )
    conn.execute("INSERT INTO secure_data VALUES (1, 'val', 'den', 'secret');")
    conn.commit()
    conn.close()

    # Quoting styles in validate_candidate_index
    idx1, tbl1, col1 = validate_candidate_index(
        "CREATE INDEX `idx_a` ON `secure_data`(`col_allowed`)"
    )
    assert idx1 == "idx_a"
    idx2, tbl2, col2 = validate_candidate_index(
        "CREATE INDEX [idx_b] ON [secure_data]([col_allowed])"
    )
    assert idx2 == "idx_b"

    # Schema diff error branches
    dis_pol = AccessPolicy(allow_schema_diff=False)
    assert snapshot_schema(db_file, policy=dis_pol)["ok"] is False
    assert snapshot_schema(tmp_path / "nonexistent.db")["ok"] is False

    # Snapshot with column and table policy
    pol_sec = AccessPolicy(
        allow_tables=frozenset({"secure_data"}),
        deny_columns={"secure_data": frozenset({"col_denied"})},
        custom_sensitive_columns=frozenset({"api_secret"}),
    )
    snap = snapshot_schema(db_file, policy=pol_sec)
    assert snap["success"] is True
    cols = {c["name"]: c for c in snap["tables"]["secure_data"]["columns"]}
    assert "col_denied" not in cols
    assert cols["api_secret"]["dflt_value"] == "[REDACTED]"

    # Diff with invalid snapshots
    assert diff_schemas({"success": False}, snap)["ok"] is False

    # Diff with identical snapshots -> NO_CHANGE
    diff_same = diff_schemas(snap, snap)
    assert diff_same["risk_level"] == "NO_CHANGE"

    # Profiler with column policy
    prof = profile_table(db_file, "secure_data", policy=pol_sec)
    assert prof["success"] is True
    assert prof["columns"]["col_denied"]["access_allowed"] is False
    assert prof["columns"]["api_secret"]["is_sensitive"] is True

    # Doctor formatting with warnings and errors
    doc_err = run_doctor(tmp_path / "missing.db", policy_path=tmp_path / "missing.toml")
    rep = format_doctor_report(doc_err)
    assert "[Errors]" in rep


def _create_index_lab_regression_db(db_path: Path) -> None:
    """Create a realistic isolated database for genuine query-plan regression tests."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE order_items (
                order_item_id INTEGER PRIMARY KEY,
                order_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                notes TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE orders_existing (
                order_id INTEGER PRIMARY KEY,
                customer_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                region TEXT NOT NULL,
                notes TEXT
            );
            """
        )
        conn.execute("CREATE INDEX idx_existing_customer ON orders_existing(customer_id);")

        conn.execute(
            """
            CREATE TABLE small_t (
                id INTEGER PRIMARY KEY,
                k INTEGER NOT NULL,
                tag TEXT NOT NULL
            );
            """
        )
        conn.execute("CREATE INDEX idx_small_k ON small_t(k);")
        conn.execute(
            """
            CREATE TABLE large_t (
                id INTEGER PRIMARY KEY,
                k INTEGER NOT NULL,
                tag TEXT NOT NULL
            );
            """
        )

        conn.executemany(
            "INSERT INTO order_items VALUES (?, ?, ?, ?, ?, ?);",
            [
                (i, (i % 50) + 1, (i % 25) + 1, (i % 5) + 1, 9.99, f"note_{i}")
                for i in range(1, 201)
            ],
        )
        conn.executemany(
            "INSERT INTO orders_existing VALUES (?, ?, ?, ?, ?);",
            [
                (i, (i % 40) + 1, "paid" if i % 2 == 0 else "pending", f"r_{i % 10}", f"n_{i}")
                for i in range(1, 201)
            ],
        )
        conn.executemany(
            "INSERT INTO small_t VALUES (?, ?, ?);",
            [(i, i, "keep") for i in range(1, 6)],
        )
        conn.executemany(
            "INSERT INTO large_t VALUES (?, ?, ?);",
            [(i, (i % 5) + 1, "keep") for i in range(1, 501)],
        )
        conn.commit()
    finally:
        conn.close()


def test_index_lab_regression_scan_elimination(tmp_path: Path) -> None:
    """Test A: Verified reproduction — scan eliminated and candidate index selected."""
    db_file = tmp_path / "reg_scan_elim.db"
    _create_index_lab_regression_db(db_file)

    query = (
        "SELECT order_item_id, order_id, product_id, quantity FROM order_items WHERE product_id = ?"
    )
    candidate = "CREATE INDEX idx_order_items_product_id ON order_items(product_id)"
    res = simulate_index(db_file, query, candidate, params=[1])

    assert res["success"] is True
    assert res["baseline"]["analysis"]["scans_table"] is True
    assert "order_items" in res["baseline"]["analysis"]["scanned_tables"]
    assert res["baseline"]["analysis"]["uses_index"] is False

    cand_plan_details = " ".join(r["detail"] for r in res["candidate"]["plan"]).upper()
    assert "SEARCH" in cand_plan_details
    assert "IDX_ORDER_ITEMS_PRODUCT_ID" in cand_plan_details
    assert res["candidate"]["analysis"]["scans_table"] is False
    assert res["candidate"]["analysis"]["uses_index"] is True
    assert "idx_order_items_product_id" in res["candidate"]["analysis"]["indexes_used"]

    comp = res["comparison"]
    assert comp["scan_eliminated"] is True
    assert comp["plan_improved"] is True
    assert comp["scan_regression"] is False
    assert comp["eliminated_scans"] == ["order_items"]
    assert comp["introduced_scans"] == []
    assert comp["candidate_indexes_selected"] == ["idx_order_items_product_id"]
    assert comp["candidate_indexes_not_selected"] == []
    assert comp["outcome"] == "scan_eliminated"

    rec_text = " ".join(res["recommendations"])
    assert "idx_order_items_product_id" in rec_text
    assert "order_items" in rec_text
    assert "did not utilize" not in rec_text.lower()
    assert "did not select" not in rec_text.lower()


def test_index_lab_regression_candidate_not_utilized(tmp_path: Path) -> None:
    """Test B: Irrelevant candidate index is not utilized and not falsely reported."""
    db_file = tmp_path / "reg_unused.db"
    _create_index_lab_regression_db(db_file)

    query = "SELECT order_item_id, product_id FROM order_items WHERE product_id = ?"
    candidate = "CREATE INDEX idx_order_items_notes ON order_items(notes)"
    res = simulate_index(db_file, query, candidate, params=[1])

    assert res["success"] is True
    comp = res["comparison"]
    assert comp["scan_eliminated"] is False
    assert comp["plan_improved"] is False
    assert comp["plan_changed"] is False
    assert comp["candidate_indexes_selected"] == []
    assert comp["candidate_indexes_not_selected"] == ["idx_order_items_notes"]
    assert comp["outcome"] == "query_plan_unchanged"

    rec_text = " ".join(res["recommendations"]).lower()
    assert "idx_order_items_notes" in rec_text
    assert "did not select" in rec_text


def test_index_lab_regression_existing_index_used(tmp_path: Path) -> None:
    """Test C: Existing index continues to be used instead of unrelated candidate index."""
    db_file = tmp_path / "reg_existing.db"
    _create_index_lab_regression_db(db_file)

    query = "SELECT order_id, customer_id FROM orders_existing WHERE customer_id = ?"
    candidate = "CREATE INDEX idx_orders_status ON orders_existing(status)"
    res = simulate_index(db_file, query, candidate, params=[5])

    assert res["success"] is True
    comp = res["comparison"]
    assert comp["scan_eliminated"] is False
    assert comp["plan_improved"] is False
    assert comp["plan_changed"] is False
    assert comp["candidate_indexes_selected"] == []
    assert comp["candidate_indexes_not_selected"] == ["idx_orders_status"]
    assert comp["existing_indexes_used"] == ["idx_existing_customer"]
    assert comp["outcome"] == "existing_index_used"

    rec_text = " ".join(res["recommendations"])
    assert "idx_existing_customer" in rec_text
    assert "idx_orders_status" in rec_text


def test_index_lab_regression_multiple_candidate_indexes(tmp_path: Path) -> None:
    """Test D: Multiple candidate indexes separate selected from unused indexes."""
    db_file = tmp_path / "reg_multi.db"
    _create_index_lab_regression_db(db_file)

    query = "SELECT order_id, region FROM orders_existing WHERE region = ?"
    candidates = [
        "CREATE INDEX idx_orders_region ON orders_existing(region)",
        "CREATE INDEX idx_orders_notes ON orders_existing(notes)",
    ]
    res = simulate_index(db_file, query, candidates, params=["r_1"])

    assert res["success"] is True
    comp = res["comparison"]
    assert comp["scan_eliminated"] is True
    assert comp["plan_improved"] is True
    assert comp["candidate_indexes_selected"] == ["idx_orders_region"]
    assert comp["candidate_indexes_not_selected"] == ["idx_orders_notes"]

    rec_text = " ".join(res["recommendations"])
    assert "idx_orders_region" in rec_text
    assert "idx_orders_notes" in rec_text


def test_index_lab_regression_no_scan_regression(tmp_path: Path) -> None:
    """Test E: Eliminating a scan on one table does not conceal a new scan elsewhere."""
    db_file = tmp_path / "reg_join_flip.db"
    _create_index_lab_regression_db(db_file)

    query = (
        "SELECT small_t.id, large_t.id FROM small_t "
        "JOIN large_t ON small_t.k = large_t.k "
        "WHERE small_t.tag = 'keep' AND large_t.tag = 'keep'"
    )
    candidate = "CREATE INDEX idx_large_k ON large_t(k)"
    res = simulate_index(db_file, query, candidate)

    assert res["success"] is True
    assert res["baseline"]["analysis"]["scanned_tables"] == ["large_t"]
    assert res["candidate"]["analysis"]["scanned_tables"] == ["small_t"]

    comp = res["comparison"]
    assert comp["eliminated_scans"] == ["large_t"]
    assert comp["introduced_scans"] == ["small_t"]
    assert comp["scan_regression"] is True
    assert comp["scan_eliminated"] is False
    assert comp["plan_improved"] is False
    assert comp["outcome"] == "scan_regression_detected"

    rec_text = " ".join(res["recommendations"])
    assert "small_t" in rec_text
    assert "large_t" in rec_text


def test_index_lab_regression_temp_btree_and_covering_improvement(tmp_path: Path) -> None:
    """Candidate index eliminating temp B-tree and gaining covering index is detected."""
    db_file = tmp_path / "reg_temp_btree.db"
    _create_index_lab_regression_db(db_file)

    # Baseline uses idx_existing_customer + temp B-tree for ORDER BY status
    query = "SELECT status FROM orders_existing WHERE customer_id = ? ORDER BY status"
    candidate = "CREATE INDEX idx_orders_cust_status ON orders_existing(customer_id, status)"
    res = simulate_index(db_file, query, candidate, params=[1])

    assert res["success"] is True
    assert res["baseline"]["analysis"]["uses_temp_btree"] is True
    assert res["candidate"]["analysis"]["uses_temp_btree"] is False

    comp = res["comparison"]
    assert comp["temp_btree_eliminated"] is True
    assert comp["covering_index_gained"] is True
    assert comp["plan_improved"] is True
    assert comp["candidate_indexes_selected"] == ["idx_orders_cust_status"]
    assert comp["outcome"] == "candidate_index_selected"
    rec_text = " ".join(res["recommendations"])
    assert "idx_orders_cust_status" in rec_text
    assert "temporary b-tree" in rec_text.lower()


def test_index_lab_regression_plan_changed_without_improvement(tmp_path: Path) -> None:
    """Distinguish query plan change without structural improvement (e.g., duplicate index)."""
    db_file = tmp_path / "reg_plan_changed.db"
    _create_index_lab_regression_db(db_file)

    query = "SELECT order_id FROM orders_existing WHERE customer_id = ?"
    # Exact duplicate of idx_existing_customer; SQLite switches to the newer duplicate index
    candidate = "CREATE INDEX idx_dup_customer ON orders_existing(customer_id)"
    res = simulate_index(db_file, query, candidate, params=[1])

    assert res["success"] is True
    comp = res["comparison"]
    assert comp["scan_eliminated"] is False
    assert comp["scan_regression"] is False
    if comp["plan_changed"]:
        assert comp["plan_improved"] is False
        assert comp["outcome"] == "plan_changed_without_improvement"


def test_index_lab_regression_source_db_isolation(tmp_path: Path) -> None:
    """Test F: Source database schema, index count, and contents remain untouched."""
    db_file = tmp_path / "reg_isolation.db"
    _create_index_lab_regression_db(db_file)

    def _inspect_source() -> tuple[int, list[tuple[str, str, str]], list[str]]:
        conn = sqlite3.connect(db_file)
        try:
            schema_ver = conn.execute("PRAGMA schema_version;").fetchone()[0]
            master_rows = conn.execute(
                "SELECT type, name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name;"
            ).fetchall()
            idx_rows = [r[0] for r in conn.execute("PRAGMA index_list('order_items');").fetchall()]
            return schema_ver, master_rows, idx_rows
        finally:
            conn.close()

    before_ver, before_master, before_indexes = _inspect_source()

    res = simulate_index(
        db_file,
        "SELECT order_item_id FROM order_items WHERE product_id = ?",
        "CREATE INDEX idx_order_items_product_id ON order_items(product_id)",
        params=[1],
    )
    assert res["success"] is True
    assert res["source_database_unmodified"] is True

    after_ver, after_master, after_indexes = _inspect_source()
    assert after_ver == before_ver
    assert after_master == before_master
    assert after_indexes == before_indexes
    assert "idx_order_items_product_id" not in after_indexes


def test_review_migration_pragma_foreign_keys_off() -> None:
    """PRAGMA foreign_keys = OFF emits a MEDIUM warning without blocking rebuilds."""
    rebuild_sql = """
    PRAGMA foreign_keys = OFF;
    BEGIN TRANSACTION;
    CREATE TABLE items_new (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
    DROP TABLE items_old;
    ALTER TABLE items_new RENAME TO items_old;
    PRAGMA foreign_key_check;
    COMMIT;
    PRAGMA foreign_keys = ON;
    """
    res = review_migration(rebuild_sql)
    assert res["success"] is True
    fk_issues = [i for i in res["issues"] if i["category"] == "integrity_check_disabled"]
    assert len(fk_issues) == 1
    assert fk_issues[0]["severity"] == "MEDIUM"

    # Standalone PRAGMA foreign_keys = OFF with transaction yields WARNING (not SAFE)
    fk_only_sql = """
    PRAGMA foreign_keys = OFF;
    BEGIN TRANSACTION;
    CREATE TABLE audit_log (id INTEGER PRIMARY KEY);
    COMMIT;
    """
    res_warn = review_migration(fk_only_sql)
    assert res_warn["success"] is True
    assert res_warn["risk_level"] == "WARNING"
    assert res_warn["safe"] is True
    assert any(i["category"] == "integrity_check_disabled" for i in res_warn["issues"])

    # PRAGMA foreign_keys = ON alone does not trigger warning
    fk_on_sql = """
    PRAGMA foreign_keys = ON;
    BEGIN TRANSACTION;
    CREATE TABLE audit_log (id INTEGER PRIMARY KEY);
    COMMIT;
    """
    res_on = review_migration(fk_on_sql)
    assert res_on["risk_level"] == "SAFE"
    assert res_on["issues"] == []
