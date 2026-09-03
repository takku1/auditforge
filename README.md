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

## Quick start

```bash
pip install -r requirements.txt

# Pull every knowledge-base clone to latest (first run: clones them)
pwsh scripts/update_sources.ps1        # Windows PowerShell 5.1+ / pwsh

# Scan a repo
python scripts/audit_repo.py <path-to-target> --fail-on HIGH

# Regenerate the framework control index after a KB update
python scripts/sync_frameworks.py

# Rebuild the document catalog (metadata + real source URLs, no fetching)
python scripts/build_document_catalog.py

# Cache the raw text of specific documents (only ever fetches
# public_domain/free_to_access - refuses anything else)
python scripts/build_document_catalog.py --skip-build --cache <FDI> [<FDI> ...]

# Run the test suite
python -m pytest scripts/
```

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
