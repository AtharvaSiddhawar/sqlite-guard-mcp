# INTERNAL AUTOMATED SECURITY & ADVERSARIAL REVIEW

**Product**: SQLite Guard MCP  
**Evaluated Version**: `0.2.3`  
**Evaluation Scope**: Threat Modeling, Bytecode Authorizer Analysis, Adversarial Attack Resistance, and Supply Chain Security  
**Date**: November 2026  
**Auditor**: Internal Autonomous Security & Adversarial Testing Suite (Automated internal adversarial evaluation; not an external third-party audit)  

---

## 1. Threat Model & Attack Surface Analysis

AI agents equipped with database execution tools represent an unprecedented attack surface. Because LLMs are susceptible to prompt injection, indirect instruction override, and hallucinated SQL queries, the database tool must assume that **every incoming request may be hostile or malicious**.

```
    [Untrusted Agent Prompt / Indirect Injection]
                           │
                           ▼
                  [Incoming Tool Call]
                           │
       ┌───────────────────┴───────────────────┐
       ▼                                       ▼
[Malformed Parameters]                  [Hostile SQL Query]
• Memory exhaustion (1M params)         • DROP / DELETE / UPDATE
• Integer overflow (> 2^63-1)           • ATTACH DATABASE '/etc/shadow'
• Non-finite float exploitation         • load_extension('/path/evil.so')
• Oversized BLOB attacks                • readfile('/etc/passwd')
                                        • PRAGMA database_list (path leak)
                                        • SELECT sql FROM sqlite_schema
                                        • SELECT password FROM users
```

### 1.1. Identified Threat Vectors

| Vector ID | Threat Description | Attacker Objective | Risk Level (Unmitigated) |
|:---:|---|---|:---:|
| **THR-01** | **Database Mutation & Destruction** | `DROP TABLE`, `DELETE FROM`, or `UPDATE` executed via direct SQL or write CTEs. | **CRITICAL** |
| **THR-02** | **Arbitrary Code Execution via Extensions** | Executing `load_extension()` or similar SQLite hooks to execute native shellcode. | **CRITICAL** |
| **THR-03** | **Host Filesystem Exfiltration** | Using SQLite filesystem functions (`readfile`, `fsdir`) to read host files outside the database. | **HIGH** |
| **THR-04** | **Database Attachment Attacks** | Executing `ATTACH DATABASE` to attach sensitive OS files or secondary databases. | **HIGH** |
| **THR-05** | **DDL Credential Extraction** | Reading `sqlite_schema.sql` to harvest plaintext credentials defined in `DEFAULT` clauses or constraints. | **HIGH** |
| **THR-06** | **Credential Data Exposure** | Querying sensitive user columns (`password`, `api_key`, `secret`, `ssn`) directly or via subqueries. | **HIGH** |
| **THR-07** | **Host Path Disclosure** | Calling `PRAGMA database_list` or parsing error messages to map server directory hierarchies. | **MEDIUM** |
| **THR-08** | **Denial of Service via Heavy Queries** | Executing Cartesian joins or unbounded recursive CTEs to lock CPU and consume memory. | **MEDIUM** |
| **THR-09** | **Parameter Buffer Exhaustion** | Passing millions of parameters or multi-megabyte payloads to trigger Out-Of-Memory crashes. | **MEDIUM** |
| **THR-10** | **Integer Overflow Vulnerability** | Passing integers outside signed 64-bit bounds causing Python/SQLite overflow exceptions. | **MEDIUM** |
| **THR-11** | **Unauthenticated Remote Access** | Exposing HTTP or SSE endpoints across a network without authentication. | **HIGH** |

---

## 2. Multi-Layer Defense-in-Depth Architecture

SQLite Guard MCP implements 8 distinct security layers to neutralize these threats:

```
Layer 1: Parameter & Input Validation
         ├── Scalar validation, Int64 bounds, finite float enforcement
         └── Count (1,000), Payload (1 MB), Key length (128 chars) limits
                  │
Layer 2: Statement Parsing & AST Gate
         └── Single statement boundary, read-only keyword verification (SELECT/WITH/VALUES)
                  │
Layer 3: Read-Only URI & Connection Isolation
         └── SQLite URI: file:...?...mode=ro&immutable=1, PRAGMA query_only = ON
                  │
Layer 4: Native SQLite C-Level Authorizer
         ├── Denies SQLITE_INSERT, UPDATE, DELETE, ALTER, DROP, CREATE, ATTACH
         ├── Blocks load_extension, readfile, writefile, fsdir, eval
         ├── Blocks PRAGMA database_list
         ├── Masks sqlite_schema.sql to NULL via SQLITE_IGNORE
         └── Masks sensitive columns to NULL via SQLITE_IGNORE
                  │
Layer 5: Fail-Closed Access Policy Engine
         └── TOML allow/deny rules enforced at authorizer read boundary
                  │
Layer 6: Execution & Virtual Machine Budget
         └── Progress Handler: Wall-clock timeout (5.0s) + VM step limit (500,000)
                  │
Layer 7: Response Size & Cell Bounding
         └── Row cap (250), Column cap (100), Cell text (4KB), Response payload (1 MB)
                  │
Layer 8: Transport Authentication & Audit Trail
         └── BearerAuthMiddleware (token) + JSONL logging with SHA-256 query digests
```

---

## 3. Adversarial Attack Verification Ledger

The following adversarial test vectors were constructed and verified against SQLite Guard MCP:

| Test ID | Adversarial Test Payload | Expected Enforcement | Observed Behavior | Test Reference |
|:---:|---|---|---|---|
| **ADV-01** | `DELETE FROM people WHERE id = 1` | Authorizer blocks mutation | `sqlite3.DatabaseError: not authorized` | `test_writes_and_write_ctes_are_blocked` |
| **ADV-02** | `WITH del AS (DELETE FROM people RETURNING *) SELECT * FROM del` | Authorizer blocks write CTE | Query blocked with authorizer denial | `test_writes_and_write_ctes_are_blocked` |
| **ADV-03** | `SELECT load_extension('malicious.so')` | Block dangerous function | Denied at authorizer level | `test_pragma_mutations_and_dangerous_functions_are_blocked` |
| **ADV-04** | `ATTACH DATABASE '/etc/passwd' AS shadow` | Block database attachment | Denied with authorizer error | `test_writes_and_write_ctes_are_blocked` |
| **ADV-05** | `PRAGMA database_list` | Block path introspection | `authorizer_blocked` error returned | `test_pragma_database_list_is_blocked` |
| **ADV-06** | `SELECT * FROM pragma_database_list` | Block table-valued pragma | Denied at authorizer read boundary | `test_pragma_database_list_is_blocked` |
| **ADV-07** | `SELECT sql FROM sqlite_schema` | Mask DDL passwords | `sql` column returns `None` (`NULL`) | `test_schema_sql_definitions_are_masked` |
| **ADV-08** | `SELECT password, api_key FROM users` | Mask credential values | Values masked to `None` (`NULL`) | `test_read_masks_secrets_and_preserves_token_metrics` |
| **ADV-09** | `SELECT secret AS safe_name FROM credentials` | Prevent alias bypass | Masked to `None` regardless of alias | `test_sensitive_column_alias_does_not_expose_value` |
| **ADV-10** | `SELECT * FROM view_over_secrets` | Prevent view bypass | View columns masked to `None` | `test_sensitive_values_through_views_remain_masked` |
| **ADV-11** | `params=[9223372036854775808]` | Reject 64-bit integer overflow | Returns structured `invalid_input` error | `test_integer_parameter_boundaries_and_overflow` |
| **ADV-12** | `params=[float('inf')]` | Reject non-finite floats | Returns structured `invalid_input` error | `test_non_finite_query_parameters_are_rejected` |
| **ADV-13** | Multiple statements `SELECT 1; DROP TABLE users;` | Reject statement chaining | Caught by single statement boundary | `test_multiple_statement_write_attempt_is_rejected` |
| **ADV-14** | Recursive Cartesian join `WITH RECURSIVE c(x) ...` | Terminate run-away queries | Progress handler terminates via timeout/VM steps | `test_query_execution_budget` |
| **ADV-15** | HTTP request without `Bearer` header | Reject unauthenticated access | HTTP 401 Unauthorized returned | `test_bearer_auth_middleware` |

---

## 4. Clear Security Boundaries & Operator Guidance

1. **Not an Operating System Sandbox**: SQLite Guard MCP operates within the operating system process permissions of the executing user. If the host process account has access to sensitive files, the operator must configure appropriate filesystem permissions (`chmod`, file ACLs).
2. **Heuristic Masking Notice**: Column-name masking relies on documented regex patterns (`password`, `secret`, `api_key`, `token`, `ssn`, etc.). While highly effective for standard schemas, heuristic masking cannot guarantee the detection of secrets stored in non-standard column names (e.g., `user_data_field_9`). Operators should utilize the Access Policy engine (`policy.toml`) to enforce explicit column allow-lists.
3. **Least Privilege Deployment**: Deploy SQLite Guard MCP in dedicated read-only containers or service accounts with access restricted exclusively to the target database file.
