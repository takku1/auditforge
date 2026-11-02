# AuditForge

A static SOC 2 / multi-framework compliance auditor, plus a workspace of
open-source GRC knowledge bases (NIST OSCAL, ComplianceAsCode, OWASP ASVS,
MITRE ATT&CK, the Secure Controls Framework crosswalk, and more) kept locally
in sync and indexed into one queryable control catalog.

## What's here

- **`scripts/audit_repo.py`** — dependency-free regex scanner over a target
  directory. Maps every finding to a SOC 2 Common Criteria control. Supports
  human-readable, JSON, SARIF (GitHub code scanning), and Markdown output,
  baseline diffing, and CI-style `--fail-on` gating.
- **`scripts/universal_audit.py`** — orchestrates external OSS scanners
  (Checkov, Semgrep, Trivy, the OSV API) per `config/compliance_config.yaml`
  and unifies their findings against the same control catalog.
- **`scripts/sync_frameworks.py`** — regenerates `scripts/framework_metadata.json`,
  a derived index of 300+ framework families / 40k+ controls, from the
  read-only knowledge-base clones below.
- **`scripts/build_document_catalog.py`** — builds `scripts/document_catalog.db`,
  a real SQLite database of the ~300 tracked standards themselves (name,
  issuing body, genuine official source URL, redistribution-rights
  classification) — not templates, not crosswalk references. Can also fetch
  and locally cache the raw document for anything classified
  `public_domain`/`free_to_access`; refuses to fetch anything else.
- **`scripts/build_rulepack.py`** — a separate tool that emits a host-posture
  rule pack consumed by a sibling project; unrelated to the repo scanner above
  beyond sharing a control-tagging convention.

### Agentic layer

- **`scripts/build_vector_index.py`** — builds `scripts/vector_index.db`, a
  local sqlite-vec semantic-search index over every control and every cached
  document, using a local CPU embedding model (no external API, no GPU).
- **`scripts/mcp_server.py`** — an MCP server exposing the knowledge base
  (semantic search, exact lookup, framework crosswalk, the audit scanner,
  and free CISA KEV/EPSS/NVD vulnerability intelligence) as agent tools.
  Registered automatically for Claude Code via `.mcp.json`.
- **`scripts/vuln_intel.py`** — free, no-API-key client for CISA's Known
  Exploited Vulnerabilities catalog, FIRST.org's EPSS scores, and NVD CVE
  detail, with a local TTL cache.
- **`.claude/skills/auditforge/SKILL.md`** — the same capability packaged as
  a standalone skill with CLI fallbacks, for sessions without the MCP server
  connected.

## Quick start

```bash
# Core auditor/knowledge-base (no agentic-layer deps required).
# Use a project-local venv on every platform - never the system Python.
# A venv created on Linux (bin/, lib64) does NOT work on Windows and vice
# versa; if you switch OSes, delete .venv/ and recreate it below.
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# .venv/bin/python -m pip install -r requirements.txt          # macOS/Linux

# Pull every knowledge-base clone to latest (first run: clones them)
pwsh scripts/update_sources.ps1        # Windows PowerShell 5.1+ / pwsh

# Scan a repo
python scripts/audit_repo.py <path-to-target> --fail-on HIGH

# ...or install the auditor as a console script (same venv; works from any
# directory because the output path fix in run-3 §3.6 resolves relative
# sbom/report paths against the scan target, not the CWD)
.venv/Scripts/python.exe -m pip install -e .   # Windows
# .venv/bin/python -m pip install -e .          # macOS/Linux
auditforge <path-to-target> --fail-on HIGH

# Regenerate the framework control index after a KB update
python scripts/sync_frameworks.py

# Rebuild the document catalog (metadata + real source URLs, no fetching)
python scripts/build_document_catalog.py

# Cache the raw text of specific documents (only ever fetches
# public_domain/free_to_access - refuses anything else)
python scripts/build_document_catalog.py --skip-build --cache <FDI> [<FDI> ...]
# ...or bulk-cache every eligible not-yet-cached document:
python scripts/build_document_catalog.py --skip-build --cache-all

# Run the test suite
python -m pytest scripts/
```

### Agentic layer setup

The MCP server and vector index need extra deps (`mcp`, `sentence-transformers`,
`sqlite-vec`, `pypdf`) — install these into a **project-local venv**, never a
global/system Python (they can pin dependency versions that conflict with
unrelated projects on the same machine):

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# .venv/bin/python -m pip install -r requirements.txt          # macOS/Linux

# Build the semantic index (run after any framework_metadata.json /
# document_catalog.db update)
.venv/Scripts/python.exe scripts/build_vector_index.py
```

Claude Code auto-detects `.mcp.json` and launches `scripts/mcp_server.py`
using that venv's interpreter. See `.claude/skills/auditforge/SKILL.md` for
the full tool list and CLI equivalents.

## Project docs

- **`CLAUDE.md`** — the Foundational Mandates every change here is held to
  (encryption, secrets, SDLC hygiene, IAM, logging), plus the full Workspace
  Layout table and Review Loop.
- **`ROADMAP.md`** — the single incomplete-work registry; every open item
  has cited evidence.
- **`docs/STATUS.md`** — current phase, active focus, architecture summary,
  last updated.
- **`docs/`** — field-test reports and audit write-ups, each with the
  ROADMAP items it produced.

## License

AuditForge's own code (`scripts/`, `config/`, `docs/`) is MIT-licensed — see
`LICENSE`. Every other top-level directory is an independent third-party
clone under its own upstream license (see `LICENSE` and `CLAUDE.md`'s
Workspace Layout table) — do not redistribute those.
