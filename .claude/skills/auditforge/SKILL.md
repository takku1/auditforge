---
name: auditforge
description: "SOC 2 / multi-framework GRC knowledge base and static compliance auditor for this repo - 42k+ controls across 300+ framework families (SOC2, NIST 800-53/171, CSF 2.0, ISO 27001, GDPR, HIPAA, PCI DSS, CIS, MITRE ATT&CK, FedRAMP 20x, ~300 more), semantic control search, a document catalog with cached full text, free vulnerability intelligence (CISA KEV/EPSS/NVD), and the audit_repo.py static scanner. Use when asked to audit code for compliance, look up or crosswalk a control/framework, check if a CVE is being actively exploited, or refresh the knowledge base."
trigger: /auditforge
---

# /auditforge

AuditForge is both an MCP server (`scripts/mcp_server.py`, auto-registered
via `.mcp.json` when Claude Code opens this repo) and a standalone CLI - this
skill works whether or not the MCP connection is live, so it's portable to
any session or agent that can run shell commands against this repo, not just
ones with MCP wired up.

**Prefer the MCP tools when connected** (they hit `scripts/vector_index.db`
directly - sub-second, no full-file loads): `search_controls`, `get_control`,
`list_frameworks`, `crosswalk_rule`, `crosswalk_control`, `search_documents`,
`get_document`, `run_audit`, `kev_lookup`, `epss_lookup`, `nvd_lookup`. If
those tools aren't available in this session, fall back to the CLI below -
same underlying data, just slower to invoke per-call.

## One-time setup (if `.venv/` doesn't exist yet)

```
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# .venv/bin/python -m pip install -r requirements.txt          # macOS/Linux
```

Never install these deps (`mcp`, `sentence-transformers`, `sqlite-vec`,
`pypdf`) into a global/system Python - see CLAUDE.md Workspace Layout.

## Refreshing the knowledge base

```
pwsh scripts/update_sources.ps1              # pull all cloned KBs + regen framework_metadata.json
.venv/Scripts/python.exe scripts/build_document_catalog.py --cache-all   # bulk-cache eligible doc text
.venv/Scripts/python.exe scripts/build_vector_index.py                  # rebuild semantic index (run after either of the above)
```

`framework_metadata.json`, `document_catalog.db`, and `vector_index.db` are
all DERIVED - regenerate them, never hand-edit.

## CLI equivalents of the MCP tools

```
# Semantic search over ~42k controls (same engine as search_controls MCP tool)
.venv/Scripts/python.exe -c "
import sys; sys.path.insert(0, 'scripts')
from mcp_server import search_controls
import json; print(json.dumps(search_controls('<query>', top_k=5), indent=2))
"

# Compliance scan (the CLAUDE.md Review Loop's mandated check)
.venv/Scripts/python.exe scripts/audit_repo.py <path> --fail-on HIGH

# Vulnerability intel for one CVE (KEV + EPSS combined)
.venv/Scripts/python.exe scripts/vuln_intel.py --enrich CVE-2024-3400

# Document catalog lookup
.venv/Scripts/python.exe -c "
import sqlite3; c = sqlite3.connect('scripts/document_catalog.db')
print(c.execute('SELECT * FROM documents WHERE fdi = ?', ('<fdi>',)).fetchone())
"
```

## Key facts an agent using this skill should know

- **All data is real and sourced online**, not fabricated: NIST OSCAL,
  MITRE ATT&CK STIX, OWASP ASVS, ComplianceAsCode YAML, the Secure Controls
  Framework crosswalk workbook, and FedRAMP's `FedRAMP/rules` repo (the
  current 20x Key Security Indicators model - the old Rev5 baseline-profile
  repo, `GSA/fedramp-automation`, no longer exists as of 2026-09-09).
- **Licensing is enforced, not advisory**: `document_catalog.db.license_status`
  gates what `build_document_catalog.py --cache`/`--cache-all` will ever
  fetch (`public_domain`/`free_to_access` only) - it refuses
  `copyrighted_registration_required`/`unknown` with zero network call.
  Respect the same gate in anything you build on top of this.
- **`crosswalk_rule` vs `crosswalk_control`**: the former is an exact,
  hand-authored mapping (audit_repo.py rule ID -> real framework clauses) -
  trustworthy as a citation. The latter is nearest-neighbor semantic
  similarity between two frameworks' control text - a starting point for
  human verification, never cite it as authoritative - and it only works
  when BOTH sides have real control text. It does NOT work well against the
  ~248 `SCF_*`-prefixed families (Secure Controls Framework crosswalk
  columns, e.g. `SCF_GENERAL_ISO_27001_2022`): their indexed "text" is bare
  clause numbers like `"4.2 4.2(a)"`, not descriptions, so there's nothing
  meaningful to match against. Semantic search over those families is
  equally unreliable. `get_control()` still works on them for an exact
  lookup if you already know the SCF control ID.
- **Vulnerability prioritization**: OSV (via `universal_audit.py`) tells you
  a dependency has *a* known vulnerability; `kev_lookup`/`epss_lookup` tell
  you whether that vulnerability is one anyone is actually exploiting -
  combine both before recommending urgent remediation.
- See `ROADMAP.md` for open gaps (HITRUST/SOC1 have no machine-readable
  open source and are structurally unlike the other catalogued frameworks;
  CIS Controls v8.1 master Excel is registration-gated) and
  `docs/STATUS.md` for current architecture/phase.
