# Security Policy

## Supported versions

Security fixes are applied to the latest release. Users should upgrade to the latest version.

## Reporting a vulnerability

Please do not publish exploitable details in a public issue. Contact the repository owner privately through GitHub's security advisory feature. Include the affected version, a concise impact description, and a minimal reproduction where safe.

## Security design and limitations

SQLite Guard opens the configured database using SQLite's read-only URI mode, enables `query_only`, disables trusted schema, installs a SQLite authorizer, applies SQLite resource limits where supported, and uses a progress handler to bound query work. Sensitive columns are masked at SQLite's authorizer boundary when their names match the documented patterns.

Key protections in version 0.2.1 include:
- **Database-path introspection denied:** `PRAGMA database_list` and table-valued `pragma_database_list` are rejected by authorizer policy to avoid exposing filesystem paths.
- **Schema DDL SQL masking:** The `sql` column of `sqlite_schema`, `sqlite_master`, `sqlite_temp_schema`, and `sqlite_temp_master` is evaluated as `NULL` via the SQLite authorizer, preventing extraction of plaintext passwords or credentials defined in `DEFAULT` clauses or constraints.
- **Sensitive default redaction:** `describe_database_table` and `schema://summary` redact sensitive default values (`dflt_value: null`, `default_redacted: true`) while preserving non-sensitive defaults and types.
- **Connection and cursor lifecycle safety:** Connections and cursors are explicitly closed across all normal and exception execution paths to eliminate resource leaks and Python 3.13 ResourceWarnings.
- **Error message sanitization:** Error responses sanitize filesystem paths and file URIs.

This is defense in depth, not a complete operating-system sandbox. The server can read any database file that the process account can access and that the operator explicitly configures. Run it with least-privilege filesystem permissions and do not point it at databases containing data the connected AI client must not see. Column-name masking is heuristic and cannot guarantee detection of every secret field; review schema names and access controls before use. Do not describe heuristic masking as guaranteed data-loss prevention or an OS boundary.
