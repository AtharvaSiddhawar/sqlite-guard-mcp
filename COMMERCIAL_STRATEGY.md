# COMMERCIAL STRATEGY & SUSTAINABILITY MODEL

**Product**: SQLite Guard MCP  
**Repository**: `https://github.com/AtharvaSiddhawar/sqlite-guard-mcp`  
**License**: MIT (Preserved for Open Source Core)  
**Status**: Strategic Commercial Framework & Tier Architecture  

---

## 1. Product Philosophy & Core Tenets

SQLite Guard MCP adheres to a strict open-source sustainability doctrine:
1. **Never cripple open-source functionality**: All core database inspection, security boundaries, native authorizer hooks, credential masking, and database intelligence remain permanently free under the permissive MIT license.
2. **No artificial paywalls or deceptive limits**: We do not impose arbitrary row limits, trial timeouts, or nagware on the open-source CLI/MCP server.
3. **Value-driven commercial tiers**: Commercial revenue is generated from features that enterprise teams, security operations, and professional developers genuinely require: fleet-wide policy synchronization, centralized compliance audit aggregation, and multi-agent coordination.
4. **Local-first security**: Enterprise extensions never compromise the zero-trust, read-only guarantees of the core database engine.

---

## 2. Feature & Tier Matrix

| Capability | Current Status | Community (Open Source / MIT) | Developer Pro | Team & Enterprise |
|---|:---:|:---:|:---:|:---:|
| **License** | Active | MIT | Commercial Developer | Commercial Enterprise |
| **MCP Transports** | Implemented | stdio, SSE, streamable-http | stdio, SSE, streamable-http | stdio, SSE, streamable-http |
| **All 11 Core Tools & 2 Resources** | Implemented | Included (Full Access) | Included (Full Access) | Included (Full Access) |
| **Native SQLite Authorizer** | Implemented | Full Bytecode Enforcement | Full Bytecode Enforcement | Full Bytecode Enforcement |
| **Credential & DDL Masking** | Implemented | Heuristic + Policy Rules | Heuristic + Policy Rules | Heuristic + Policy Rules |
| **Local TOML Access Policy** | Implemented | File-based (`--policy`) | File-based (`--policy`) | Signed Policy Bundles / HTTPS Sync |
| **Local Audit Logging** | Implemented | Append-only JSON Lines | Append-only JSON Lines | Real-time SIEM Forwarder (Splunk, Datadog) |
| **Query Plan & Index Diagnostics**| Implemented | CLI / MCP Tool Output | CLI + Interactive Workbench | Fleet-wide Index Optimization Reports |
| **Database Health Check** | Implemented | `PRAGMA quick_check` & FKs | Integrated Diagnostic Views | Continuous Schema Drift Detection |
| **Index Laboratory (`simulate_candidate_index`)** | Implemented | Safe disposable snapshot simulation | Integrated with Workbench UI | Automated Index CI Pipeline |
| **Privacy-Preserving Profiler** | Implemented | Cardinality, null %, masked stats | Visual distribution charts | Enterprise PII Scan Reports |
| **Schema Snapshot & Diff** | Implemented | Canonical JSON & Structural Diff | Visual Schema Diff View | Continuous Drift Alerting |
| **Static Migration Review** | Implemented | AST/Regex Safety & Lock Risk | Safe Migration Playbooks | Automated PR Gatekeeper |
| **CLI Doctor & Policy Explain** | Implemented | Comprehensive diagnostic report | Integrated health status | Fleet policy audit CLI |
| **Local Developer Workbench UI** | Planned | Optional CLI launcher | Interactive Visual Dashboard | Team Workspace & Shared Catalogs |
| **Central Fleet Management** | Planned | N/A | N/A | Central Policy & Configuration Server |
| **Support & Maintenance** | Active | Community GitHub Issues | Priority Email Support | Dedicated Enterprise SLA & Security Advisory |

---

## 3. Product Tier Descriptions

### 3.1. Community (Open Source)
The foundational tier designed for individual developers, AI researchers, and open-source contributors using tools like Claude Code, Cursor, Windsurf, or Google Antigravity.
- Distributed on PyPI (`pip install sqlite-guard-mcp`, `uvx sqlite-guard-mcp`).
- Comprehensive defense-in-depth: read-only URI mode, native authorizer hooks, credential masking, aggregate parameter memory bounds.
- 7 specialized tools and 1 resource (`schema://summary`) providing deep query plan diagnostics, unindexed FK warnings, and composite index redundancy detection.
- Standalone execution with zero external network or account dependencies.

### 3.2. Developer Pro
Geared towards independent software engineers, consultants, and database administrators managing numerous SQLite databases across local and embedded environments.
- **Local Interactive Workbench**: A zero-dependency localhost web UI visualizing database ER diagrams, query plan trees, and index overlap diagnostics.
- **Visual Schema Diff**: Static comparison of schema snapshots before and after application migrations.
- **Diagnostic Export Reports**: One-click generation of formatted Markdown and HTML database audits.

### 3.3. Team & Enterprise
Built for security-conscious engineering organizations deploying AI agents across hundreds of developer workstations.
- **Central Policy Distribution**: Secure HTTPS endpoint delivering cryptographically signed TOML policies to ensure least-privilege database access across engineering teams.
- **Centralized Audit Aggregation**: Real-time streaming of tamper-evident SHA-256 query digests to organizational SIEMs (Datadog, Splunk, Amazon CloudWatch) for compliance auditing without leaking customer data.
- **CI/CD Migration Gatekeeper**: GitHub Action plugin analyzing pull requests for risky SQLite migration scripts, unindexed foreign keys, or redundant composite indexes.

---

## 4. Monetization Roadmap & Architecture

```
                               ┌─────────────────────────────────┐
                               │   Enterprise Fleet Controller   │
                               │  (Central Policy & Audit Agg)   │
                               └────────────────┬────────────────┘
                                                │ HTTPS / mTLS
              ┌─────────────────────────────────┼─────────────────────────────────┐
              │                                 │                                 │
    ┌─────────▼──────────┐            ┌─────────▼──────────┐            ┌─────────▼──────────┐
    │ Developer Station 1│            │ Developer Station 2│            │ CI/CD Pipeline     │
    │  [SQLite Guard]    │            │  [SQLite Guard]    │            │  [Migration Guard] │
    │ • Signed Policy    │            │ • Signed Policy    │            │ • Static Schema    │
    │ • Audit Digest     │            │ • Audit Digest     │            │   Diff Analysis    │
    └────────────────────┘            └────────────────────┘            └────────────────────┘
```

### Phase 1: Open Source Dominance & Community Traction (Months 1–6)
- Maintain 100% test coverage and zero-defect quality across Python 3.11–3.13.
- Register with official MCP directories (Smithery, MCP Registry, Awesome-MCP).
- Establish benchmark superiority over competing implementations.

### Phase 2: Developer Pro & Local Workbench (Months 6–12)
- Release lightweight local workbench interface.
- Provide pre-configured templates for Django, SQLAlchemy, and Prisma SQLite databases.

### Phase 3: Enterprise Fleet Security (Months 12+)
- Introduce signed policy bundles and enterprise SIEM audit connectors.
- Offer commercial support contracts for regulated industries (healthcare, finance, defense).
