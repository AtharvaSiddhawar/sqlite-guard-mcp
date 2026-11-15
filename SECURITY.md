# Security Policy

## Supported versions

Security fixes are applied to the latest release. Users should upgrade to the latest version.

## Reporting a vulnerability

Please do not publish exploitable details in a public issue. Contact the repository owner privately through GitHub's security advisory feature. Include the affected version, a concise impact description, and a minimal reproduction where safe.

## Security design and limitations

SQLite Guard opens the configured database using SQLite's read-only URI mode, enables `query_only`, disables trusted schema, installs a SQLite authorizer, applies SQLite resource limits where supported, and uses a progress handler to bound query work. Sensitive columns are masked at SQLite's authorizer boundary when their names match the documented patterns.

This is defense in depth, not a complete operating-system sandbox. The server can read any database file that the process account can access and that the operator explicitly configures. Run it with least-privilege filesystem permissions and do not point it at databases containing data the connected AI client must not see. Column-name masking is heuristic and cannot guarantee detection of every secret field; review schema names and access controls before use.
