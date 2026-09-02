# STATUS

## Current Phase
Building out the multi-framework knowledge base and the static SOC 2 auditor
in parallel. Core engine (`scripts/audit_repo.py`) is field-tested and
stable; framework-metadata indexing (`scripts/sync_frameworks.py`) and the
sibling RoninAI rule-pack builder (`scripts/build_rulepack.py`) are newer and
still growing coverage.

## Active Focus
Closing the gap backlog from two field tests (roninai 2026-08-25, searchtool
2026-09-02 — see `docs/field-test-*.md`): the R-008..R-024 rule-engine gaps
(credentialed connection strings, git tracked/untracked awareness, history
scanning, compiled-language danger idioms, etc.) — see ROADMAP.md. The
framework-coverage audit (`docs/framework-coverage-audit-2026-09-02.md`) is
done: `framework_metadata.json` now indexes 303 framework families / 42,082
controls (up from 11/2075). Remaining open item there is R-027 (HITRUST CSF,
FFIEC CAT, SOC 1/SSAE 18 — genuine blind spots with no local source yet).

## Architecture Summary
`scripts/audit_repo.py` is a dependency-free regex scanner that maps findings
to SOC 2 Common Criteria controls (human/JSON/SARIF/markdown output, baseline
diffing, CI gating). `scripts/universal_audit.py` + `auditor/` orchestrate
external OSS tools (Checkov/Semgrep/Trivy/OSV) per
`config/compliance_config.yaml`. `scripts/sync_frameworks.py` regenerates the
derived `scripts/framework_metadata.json` control index from read-only KB
clones — NIST OSCAL (800-53/800-171/CSF2), ASVS, MITRE ATT&CK Enterprise
(697 techniques), every `compliance-as-code/controls/*.yml` file
auto-discovered (47 families: CIS, STIG, Essential Eight, BSI, ANSSI, CCN,
ISM, SRG, per-product NIST overlays), and the full Secure Controls Framework
crosswalk workbook via openpyxl (248 focal-document frameworks - ISO
27001/27017/27018/27701/42001, GDPR, DORA, NIS2, CMMC 2.0, FedRAMP R5, TISAX,
SOX, GLBA, NYDFS 500, LGPD, PIPEDA, and ~230 more - each keyed by SCF control
ID to that framework's mapped clause). Only OWASP Top 10:2025 stays a
presence-only flag (its OSIB export is a CWE-linkage graph, not a flat
control list - deliberate, not an oversight). `scripts/build_rulepack.py` is
a separate tool that emits a host-posture rule pack (`ronin.rulepack/v1`)
consumed by the sibling RoninAI project, tagged against NIST 800-171, SOC 2,
and CIS control refs.

## Key Decisions
- Knowledge-base clones are independent git clones, deliberately **not**
  submodules (ADR-301, enforced by
  `docs/architecture/modules/workspace-hygiene/checks.ps1`) — pull-to-update
  via `scripts/update_sources.ps1`, never hand-edited, never committed.
- 2026-09-02: `scripts/update_sources.ps1`'s source registry is scoped
  strictly to what CLAUDE.md's Workspace Layout table documents. Removed
  `Anthropic-Cybersecurity-Skills` (unofficial third-party repo pretending to
  be Anthropic-affiliated, not in the documented layout, no compliance
  relevance) from the registry, `.gitignore`, and `checks.ps1`. `firefox` was
  flagged in the same pass but kept — confirmed by the user as an
  intentional test-case target for this project, not a compliance KB.
- `framework_metadata.json` is fully derived — regenerate via
  `python scripts/sync_frameworks.py`, never hand-edit (per CLAUDE.md).

## Deprecated/Legacy
- `nist-csf/`, `gdpr-checklist/`, `security-templates/` are legacy/reference
  clones per CLAUDE.md — superseded by the OSCAL catalogs, ComplianceAsCode,
  and the SCF crosswalk for anything that needs structured, machine-readable
  control data.

## Last Updated
2026-09-02
