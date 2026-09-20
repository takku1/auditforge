# STATUS

## Current Phase
The multi-framework knowledge base and static SOC 2 auditor (Phase 1) are
stable. Phase 2 — an agentic layer on top of that knowledge base — is now
live: an MCP server, a local semantic-search index, free vulnerability
intelligence, and a standalone Claude Code skill, so an AI agent can query
the ~47k-control knowledge base directly instead of an operator shelling out
to CLIs and parsing text by hand.

## Active Focus
As of 2026-09-20 the ROADMAP's Ready table is down to four still-pending
items, each with a cause: R-027 (HITRUST — genuinely blocked, no open
machine-readable source exists), R-049 (freshness watch, no action yet —
EU CRA obligations live 2026-09-11, CMMC Phase 2 mandatory cert starts
2026-11-10), R-057 (FFIEC IT Examination Handbook booklets — needs
document-cache + section-parser wiring), and R-058 (SOC 1 / SSAE 18 —
AICPA-paywalled, no open source). Everything else landed, including the
2026-09-20 full-capture expansion (`framework_metadata.json` verified at
48,061 controls / 336 families, STIG+FFIEC-seeded): NIST AI 600-1 GenAI Profile (GENAI, 115),
NIST AI RMF base text (AIRMF, 72), eight OWASP families (API, MOBILE, LLM,
AGENTIC, MCP, K8S, CICD at 10 each; MASVS at 24; flagship Top 10:2025 as
`top10`, 10), MITRE ATLAS (224), DOE C2M2 v2.1 (349), CWE (969) / CAPEC
(615) / D3FEND (271), MITRE SAF RHEL 8/9 STIG baselines (SAF_RHEL8 375 /
SAF_RHEL9 452), the DISA STIG XCCDF parser (no-op until a quarterly zip is
dropped into `references/disa-stig/`), CISA CPG 2.0 (34), CVSS v4 metrics
(32), SAMM v2 (278), NIST SP 800-63-4 (356), CCM v4.1 minimal IDs+titles
(207, Fair-Use-only, bundle never committed), and document-catalog-only rows
for CIRCIA, the CMMC 2.0 guides, the DISA STIG library, and C2M2.

The earlier second pass prompted by "lets get all of this completed" closed
(R-007, R-010, R-013, R-014, R-017, R-021, R-023, R-024, R-030, R-041, plus
R-047, found this session):
- **R-013/R-014/R-017/R-023** — `audit_repo.py`/`auditor/` core hardening:
  git-history secret scanning (`--history`), `.soc2rc.yml` per-repo config,
  skip-count transparency (oversized/binary files no longer silently
  indistinguishable from "scanned clean"), and a warning when a report is
  written inside the directory being scanned.
- **R-010/R-021** — dependency scanning: workspace-wide (not just root)
  across 6 ecosystems (PyPI/npm/crates.io/Go/RubyGems/Packagist), plus
  `cargo audit` (RUSTSEC) as a fourth external engine alongside
  Checkov/Semgrep/Trivy.
- **R-030** — MITRE ATT&CK ICS (97) and Mobile (124) techniques indexed as
  their own framework families, alongside the existing Enterprise (697).
- **R-041** — retried failed document caches (155/167 now cached) and
  manually verified all 21 "suspect landing page" flags from R-040: 16 were
  real access-walls/bot-blocks (deleted), 5 were genuinely real content
  (kept); added `_looks_blocked()` so future runs catch these automatically.
- **R-047** — a real bug found by live-testing the agentic layer, not a unit
  test: semantic search over the ~248 SCF-crosswalk families was
  near-useless (their indexed text is bare clause numbers). Fixed with an
  exact token-join through the SCF's own shared control-ID structure
  (`scf_crosswalk_tokens`, 75,924 rows) instead of embedding similarity —
  `crosswalk_control()` now picks the right method automatically per target.
- **R-007** — the audit engine (previously explicitly out-of-scope for
  `docs/architecture/SYSTEM.md`) now has its own sibling Contract Tree at
  `docs/architecture-engine/`. Found and worked around two real parser
  quirks in `recurspec` 0.2.0 along the way (see ROADMAP R-007's evidence
  column) — both fixed by adjusting this project's SYSTEM.md formatting,
  not by patching the tool.

Prior round (still current): the agentic layer, prompted by "build the
agentic layer... check online to see if we're missing any other
frameworks... make sure the agentic layer knows how to access things
quickly in the db":
- **`scripts/vuln_intel.py`** — free CISA KEV / FIRST.org EPSS / NVD API 2.0
  client with a local TTL cache (R-042). Answers "is this OSV finding
  actually being exploited," which OSV alone doesn't.
- **`scripts/build_vector_index.py` + `scripts/mcp_server.py`** (R-043) —
  sqlite-vec semantic index (`scripts/vector_index.db`, gitignored/derived,
  ~47k controls + cached documents' chunked text, `BAAI/bge-small-en-v1.5`
  local CPU embeddings) behind an MCP server exposing `search_controls`,
  `get_control`, `list_frameworks`, `crosswalk_rule`, `crosswalk_control`,
  `search_documents`, `get_document`, `run_audit`, `kev_lookup`,
  `epss_lookup`, `nvd_lookup`. Registered for Claude Code via `.mcp.json`.
  Framework-filtered search uses vec0 partition keys (true partitioned KNN,
  not a post-hoc filter over an unfiltered top-k) — see ROADMAP R-043.
- **`.claude/skills/auditforge/SKILL.md`** (R-044) — the same capability
  packaged as a standalone, git-tracked skill with CLI fallbacks, so it works
  in any session, not only one with the MCP server connected.
- **Framework coverage, re-checked online**: FedRAMP's old Rev5
  baseline-profile repo (`GSA/fedramp-automation`) is confirmed gone — real
  404, verified via `git ls-remote`, not a research artifact. FedRAMP moved
  to the "20x" Key Security Indicators model; wired in its actual current
  source (`github.com/FedRAMP/rules`) as 46 new `FEDRAMP20X:*` controls
  (RF-003, closed). HITRUST CSF re-confirmed still gated (RF unchanged, no
  false optimism). FFIEC's old CAT tool sunset 2025-08-31 — no longer a
  framework to track at all (its own replacement guidance points at NIST
  CSF 2.0 and CIS Controls, both already indexed).
- **Bulk document caching (R-040)**: 154/167 eligible documents now cached
  (was 1/167) — 114MB of real regulatory/standards text in
  `scripts/document_cache/` (gitignored). 13 failures tracked as R-041.
- **Isolated `.venv/`** (R-045): the agentic-layer deps were briefly
  installed into the machine's global Python and found to conflict with
  unrelated projects (`vllm`, `parlant`, `opencompass`) pinned there —
  reverted, moved to a project-local venv. Never install these globally.

## New capability: the document catalog
`scripts/build_document_catalog.py` builds `scripts/document_catalog.db` — a
SQLite database of the ~300 tracked standards *themselves* (not their
parsed controls, and not the generic policy-wording templates in
`comply`/`jupiterone-policies`): real name, issuing body, genuine official
source URL, and a conservative redistribution-rights classification
(`public_domain` / `free_to_access` / `copyrighted_registration_required` /
`unknown`, defaulting to the most restrictive when unverified). It can fetch
and locally cache the raw document (`scripts/document_cache/`, gitignored)
for anything classified `public_domain` or `free_to_access` — and refuses,
with zero network call, for anything else. The `.db` itself is tracked in
git like `framework_metadata.json`; the cached document bodies are not.

## Architecture Summary
`scripts/audit_repo.py` is a dependency-free regex scanner that maps findings
to SOC 2 Common Criteria controls (human/JSON/SARIF/markdown output, baseline
diffing, CI gating). `scripts/universal_audit.py` + `auditor/` orchestrate
external OSS tools (Checkov/Semgrep/Trivy/OSV) per
`config/compliance_config.yaml`. `scripts/sync_frameworks.py` regenerates the
derived `scripts/framework_metadata.json` control index (48,061 controls /
336 families as of 2026-09-20, STIG+FFIEC-seeded) from read-only KB clones — NIST OSCAL
(800-53/800-171/CSF2), ASVS (442), MITRE ATT&CK Enterprise (697) + ICS (97)
+ Mobile (124) + MITRE ATLAS (224, YAML mappings, not STIX), every
`compliance-as-code/controls/*.yml` file
auto-discovered (47 families: CIS, STIG, Essential Eight, BSI, ANSSI, CCN,
ISM, SRG, per-product NIST overlays), and the full Secure Controls Framework
crosswalk workbook via openpyxl (248 focal-document frameworks - ISO
27001/27017/27018/27701/42001, GDPR, DORA, NIS2, CMMC 2.0, FedRAMP R5, TISAX,
SOX, GLBA, NYDFS 500, LGPD, PIPEDA, and ~230 more - each keyed by SCF control
ID to that framework's mapped clause), and FedRAMP 20x's Key Security
Indicators from `github.com/FedRAMP/rules` (46 indicators, each mapped to its
NIST 800-53 control IDs), MITRE SAF baselines from
`github.com/mitre` (`mitre-saf-cis/`: AWS (64), Azure (159), EKS (35), GCP
(60), GKE (25) CIS benchmarks plus RHEL 8 (375) / RHEL 9 (452) STIG
baselines - Apache-2.0, each carrying its title, overview prose, and mapped
NIST 800-53 IDs), the OWASP lane (flagship Top 10:2025 as `top10` plus API,
Mobile, LLM, Agentic, MCP, K8s, CI/CD Top 10s and MASVS, parsed from the
cloned markdown via `_parse_owasp_categories`), NIST AI 600-1 GenAI Profile
(GENAI, 115) and AI RMF 1.0 base text (AIRMF, 72) from reference PDFs, DOE
C2M2 v2.1 (349), CWE (969) / CAPEC (615) / D3FEND (271) machine-readable
exports, CISA CPG 2.0 (34), CVSS v4 metrics (32), SAMM v2 (278), NIST SP
800-63-4 (356), CCM v4.1 minimal IDs+titles (207, Fair-Use-only), and the
DISA STIG XCCDF parser over `references/disa-stig/` (no-op until a quarterly
zip is dropped in; RHEL 8/9 overlap covered executably by the SAF baselines).
`scripts/build_rulepack.py` is a separate tool
that emits a host-posture rule pack (`ronin.rulepack/v1`) consumed by the
sibling RoninAI project, tagged against NIST 800-171, SOC 2, and CIS control
refs.

On top of that knowledge base, the agentic layer: `scripts/build_vector_index.py`
regenerates `scripts/vector_index.db` (sqlite-vec; derived, gitignored, ~450MB
- too large for git, trivially rebuildable) by embedding every control and
every cached document chunk with a local CPU model
(`BAAI/bge-small-en-v1.5`, 384-dim). `scripts/mcp_server.py` serves that index
plus `scripts/vuln_intel.py` (CISA KEV/EPSS/NVD, locally cached) as MCP tools
over stdio, registered for Claude Code via `.mcp.json`. The same capability is
also packaged as a standalone skill at `.claude/skills/auditforge/SKILL.md`
with CLI fallbacks for sessions without the MCP connection. All agentic-layer
Python deps live in a project-local `.venv/` — never the system Python.

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
- 2026-09-09: `scripts/vector_index.db` is derived like `framework_metadata.json`
  but deliberately **not** git-tracked (unlike that file) — it's ~450MB,
  which is impractical for git and trivially regenerable in a few minutes via
  `python scripts/build_vector_index.py`. `document_catalog.db` stays tracked
  (small, metadata-only) while `scripts/document_cache/` (raw cached bodies)
  stays gitignored, same as before.
- 2026-09-09: FedRAMP's old Rev5 baseline-profile source
  (`GSA/fedramp-automation`) was confirmed genuinely gone, not a lookup
  error — `git ls-remote` returns "Repository not found". FedRAMP has moved
  to a "20x" Key Security Indicators model; `github.com/FedRAMP/rules` is its
  actual current machine-readable source and is now cloned as `fedramp-rules/`.
- 2026-09-20: Wired MITRE SAF CIS baselines (`mitre-saf-cis/`,
  `github.com/mitre` Apache-2.0 - license text verified before cloning):
  `aws-foundations-cis-baseline` (64 controls), `azure-foundations-cis-baseline`
  (159), `eks-cis-cluster-baseline` (35), `gcp-cis-benchmark` (60),
  `gke-cis-benchmark` (25), plus the RHEL 8 (375) / RHEL 9 (452) STIG baselines
  (ROADMAP R-103), parsed by
  `sync_frameworks.py::_parse_saf_inspec()` into `SAF_AWS`/`SAF_AZURE`/`SAF_EKS`/
  `SAF_GCP`/`SAF_GKE`/`SAF_RHEL8`/`SAF_RHEL9` families
  (`framework_metadata.json` verified at 48,061 controls / 336 families on
  2026-09-20, STIG+FFIEC-seeded). CIS Controls OSCAL (proprietary CIS Terms of Use) and the CSA CCM
  bundle (Fair-Use-only, gated zip) were deliberately NOT fetched - kill-switch
  blocks stand. HITRUST CSF has no machine-readable open source and no SCF
  focal-document column (workbook scanned: 0 HITRUST rows of 255) - full text
  stays out per the MyCSF gate (ROADMAP R-027).

## Deprecated/Legacy
- `nist-csf/`, `gdpr-checklist/`, `security-templates/` are legacy/reference
  clones per CLAUDE.md — superseded by the OSCAL catalogs, ComplianceAsCode,
  and the SCF crosswalk for anything that needs structured, machine-readable
  control data.

## Last Updated
2026-09-20
