# AuditForge Engine (L0)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

The code that actually detects and reports findings: a dependency-free
regex-based static scanner, an orchestrator over external OSS scanners
(Checkov/Semgrep/Trivy/OSV/cargo-audit), the framework-metadata/document-
catalog derivation pipeline, and the MCP/semantic-search agentic layer built
on top of that knowledge base. This is a sibling tree to
`docs/architecture/SYSTEM.md` (the knowledge-base/session-updater tree),
which explicitly declares the engine out of scope for itself — see ROADMAP
R-007. Splitting them keeps "which frameworks do we track" (data-freshness
concern) separate from "how do we detect and report findings" (detection-
logic concern); they change for different reasons and were previously
uncontracted for that reason, not by oversight.

Does not own: which frameworks/controls exist (owns only how they're parsed
and searched, not their authoring — `docs/architecture/SYSTEM.md` owns
that), CI/CD wiring (`.github/workflows/ci.yml` is workspace-hygiene's).

## 2. Sub-System Decomposition

Non-terminal; child links below.

- [auditor-core](modules/auditor-core/SYSTEM.md) — the shared detection/
  scanning engine (`scripts/auditor/`) both CLI entrypoints call into.
- [cli-entrypoints](modules/cli-entrypoints/SYSTEM.md) — `audit_repo.py` /
  `universal_audit.py`, thin argument-parsing wrappers over auditor-core.
- [framework-sync](modules/framework-sync/SYSTEM.md) — derives
  `scripts/framework_metadata.json`/`scripts/document_catalog.db` from the knowledge-base
  clones; consumed by auditor-core's crosswalk reporting and by the
  agentic-layer's index.
- [agentic-layer](modules/agentic-layer/SYSTEM.md) — MCP server, semantic
  search index, and free vulnerability intelligence built on top of
  framework-sync's derived data.
- [verification-lifecycle](modules/verification-lifecycle/SYSTEM.md) —
  candidate → confirmed/needs_validation/rejected state machine,
  adversarial review, and sandboxed PoC execution (v2, planned).
- [coverage-hunting](modules/coverage-hunting/SYSTEM.md) — per-run
  coverage ledger, critic waves, budget discipline, additive runs (v2,
  planned).
- [holistic-skill](modules/holistic-skill/SYSTEM.md) — the single
  agent-facing skill composing all of the above into one guided or
  full-audit workflow (v2, partially built).

## 3. Interface Contracts

- **Inputs:** a target directory to scan; `config/compliance_config.yaml`; the knowledge-base clones owned by `docs/architecture/SYSTEM.md`'s tree, including `oscal-content/`, `compliance-as-code/`, `attack-stix-data/`, `secure-controls-framework/`, `fedramp-rules/`, `asvs/`, `owasp-top10/`.
- **Outputs:** findings (text/JSON/SARIF/Markdown), `scripts/framework_metadata.json`, `scripts/document_catalog.db`, `scripts/vector_index.db`, MCP tool responses, v2 run artifacts (`architecture.md`, `coverage-ledger.json`, `findings.json`, derived reports under `reports/security-audit/<repo>/run-<N>/`).

## 4. Invariants (EARS + Epistemic Stage)

- **[Ubiquitous]** THE SYSTEM SHALL never execute dynamic code (`eval`/`exec`)
  on scanned or fetched content.
  - `EvidenceStage:` Sampled
- **[Ubiquitous]** THE SYSTEM SHALL never invoke a subprocess with
  `shell=True` and interpolated input (R-034; `test_run_trivy` asserts
  `shell` absent from `subprocess.run` kwargs).
  - `EvidenceStage:` Sampled
- **[Ubiquitous]** THE SYSTEM SHALL run entirely on free/open data sources
  and tools — no paid API keys required for any code path to function
  (optional `NVD_API_KEY` only raises a rate limit).
  - `EvidenceStage:` Observed
- **[Conditional]** IF an external scanner binary is not on PATH THEN THE
  SYSTEM SHALL report it as unavailable rather than silently returning zero
  findings (R-035; `test_run_trivy_skips_when_binary_missing`).
  - `EvidenceStage:` Sampled

## 5. Architectural Decisions (ADRs)

- **ADR-101:** Split from `docs/architecture/SYSTEM.md` as a sibling tree
  rather than a child node, because the engine predates that tree's contract
  and was explicitly declared out of scope for it (ROADMAP R-007) — grafting
  it in as a child would have required either fabricating history the L0
  never actually had, or silently changing that L0's own "does not own"
  clause's meaning.
- **ADR-102:** Module boundaries follow actual shared-code structure, not a
  1:1 file-per-node mapping (`recurspec reconcile plan` proposes one leaf
  per source file - 23 files here). `scripts/auditor/*.py` is one cohesive
  package with a single public test seam (`python -m pytest
  scripts/test_audit_repo.py scripts/test_universal_audit.py`); contracting
  it as 7 independent leaf nodes would misrepresent its actual coupling and
  invent 7 separate measurement gates where only one real one exists.
- **ADR-201 (v2):** Adversarial verification on top of the intelligence
  base — Cloudflare's methodology (finder ≠ checker, verdict discipline,
  coverage ledger, sandboxed PoC-or-`needs_validation`) is adopted as three
  new L1 modules rather than replacing anything: the deterministic engines
  and 48k-control knowledge base are the moat, verification is the missing
  second half. Rebuilding the skill verbatim was rejected (no compliance
  citations, no Phase 0, Node validators); porting its methodology onto our
  stack was chosen (teardown `docs/current/security-audit-skill-review.md`
  §4).
- **ADR-202 (v2):** One holistic skill — compliance, hunting, verification,
  intel, freshness, and reporting are modes/phases of a single
  agent-facing workflow (`holistic-skill`), because a real audit needs all
  of them against one target in one run. Today's `security-audit` skill
  folds in as a thin alias, not a second maintained skill.

## Child index

| Child | Class | Terminal |
| --- | --- | --- |
| modules/auditor-core | BUILD (pre-existing, field-tested) | yes |
| modules/cli-entrypoints | BUILD (trivial+stable glue) | yes |
| modules/framework-sync | BUILD (pre-existing, field-tested) | yes |
| modules/agentic-layer | BUILD (new, 2026-09-09) | yes |
| modules/verification-lifecycle | BUILD (v2, planned) | no |
| modules/coverage-hunting | BUILD (v2, planned) | no |
| modules/holistic-skill | BUILD (v2, partially built) | no |
