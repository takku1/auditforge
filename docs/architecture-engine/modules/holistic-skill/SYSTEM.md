# Holistic Skill (L1)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

The single agent-facing tool: one skill spanning compliance audit,
deterministic hygiene scanning, coverage-led vulnerability hunting,
adversarial verification, prioritized reporting, remediation advice, and
freshness — modes select depth, not different tools. Owns the skill text
(`.claude/skills/auditforge/SKILL.md`, mirrored to `plugin/auditforge/`),
the run-phase protocol (Phase 0 → recon → hunt → verify → report), the run
artifact convention (`reports/security-audit/<repo>/run-<N>/`), the plugin
commands (`/audit`, `/freshness`), and the single-agent fallback (no
subagents: recon, one hunting pass per attack class, fresh-context
self-review).

Composes — never reimplements — [auditor-core](../auditor-core/SYSTEM.md)
(candidates in), [coverage-hunting](../coverage-hunting/SYSTEM.md) (units
and critics), [verification-lifecycle](../verification-lifecycle/SYSTEM.md)
(verdicts), and [framework-sync](../framework-sync/SYSTEM.md) (compliance
citations per confirmed finding). Today's two skills (`auditforge` +
`security-audit`) merge here; `security-audit` becomes a thin alias during
transition (ADR-222).

Does not own: detection logic, verdicts, coverage state, control data —
only the workflow that binds them and the prose that drives the agent.

Status: merged 2026-11-02 (R-140) — the six phases live in the
canonical `auditforge` skill (recon → `coverage.py init`, critic/budget
waves, fresh-context verification with documented disproof attempts,
`ledger.py verdict` guards, `poc_sandbox.py`, derived reporting,
`coverage.py carry` additive runs); `security-audit` is a thin alias.
Still open: the single-agent fallback quality bar (first fallback run
decides), and the juice-shop head-to-head that exercises the whole
workflow (R-141).

## 2. Sub-System Decomposition

Atomic leaf (BUILD — skill prose + run convention; the composed modules
own their machinery).

## 3. Interface Contracts

- **Inputs:** user request (guidance question vs full-audit trigger phrases); target directory; profile (quick/standard/deep).
- **Outputs:** `architecture.md`, `coverage-ledger.json`, `findings.json`, `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md` under `reports/security-audit/<repo>/run-<N>/`, plus `run_status` (complete, or incomplete with the exact reason); guidance answers in guidance mode (read-only, no artifacts).
- **Run shape:** full-audit run directory holds `architecture.md` (≤1000 words), the validated ledgers, validator-clean `findings.json`, and reports derived from verified records. The skill states its mode up front, every run.

## 4. Invariants (EARS + Epistemic Stage)

- **[Ubiquitous]** THE SYSTEM SHALL run Phase 0 (deterministic sweep +
  KEV/EPSS enrich + crosswalk attach) first in every full audit, before
  any agentic recon or hunting. (The skill text exists today; enforcement
  of the ordering is procedural until run-conformance checks land.)
  - `EvidenceStage:` Observed
- **[Ubiquitous]** THE SYSTEM SHALL derive reports from verified records
  and the coverage ledger, never write findings prose first and
  backfill records.
  - `EvidenceStage:` Unknown
- **[Ubiquitous]** THE SYSTEM SHALL declare `run_status` (complete, or
  incomplete with the exact reason) on every full-audit run.
  - `EvidenceStage:` Unknown
- **[Ubiquitous]** THE SYSTEM SHALL advise remediation (PoC test +
  proposed diff per confirmed high/critical) and SHALL NOT apply patches
  itself — human merges, never the model (harness-blog fail-to-pass gate).
  - `EvidenceStage:` Unknown
- **[Ubiquitous]** THE SYSTEM SHALL attach a compliance citation (SOC 2 +
  NIST/OWASP/ASVS/MITRE row) to every `confirmed` finding via
  `crosswalk_rule`/`search_controls` — the citation Cloudflare's schema
  cannot express.
  - `EvidenceStage:` Unknown
- **[Conditional]** IF no subagents are available THEN THE SYSTEM SHALL run
  the single-agent fallback (recon, one pass per attack class,
  fresh-context self-review) rather than thinning phases silently.
  - `EvidenceStage:` Unknown

## 5. Architectural Decisions (ADRs)

- **ADR-221:** One holistic skill, not a skill per discipline — the user
  asked for a completely holistic tool. Compliance, hunting,
  verification, intel, freshness, and reporting are modes/phases of one
  workflow because a real audit needs all of them against the same target
  in one run; splitting them re-creates the "which tool do I run"
  problem the plugin was built to end.
- **ADR-222:** Merge, don't fork — today's `security-audit` skill folds
  into `auditforge` (attack-class packs, six phases, validators move
  over); `security-audit` remains as a thin alias until callers migrate.
  Rationale: two skills with overlapping triggers cause mode confusion;
  the alias preserves the Cloudflare-derived entry vocabulary ("security
  audit this codebase") with zero maintenance (one-line pointer).
- **ADR-223:** Plugin stays the distribution unit (skills + commands + MCP
  server as one installable), local flow stays first-class — per
  `docs/current/tooling-direction.md` §3. OPEN (carried): marketplace
  repo location/name.

## 6. Leaf Execution & Test Seam

- **Implementation Files:** `.claude/skills/auditforge/SKILL.md`
  (canonical post-merge home), `.claude/skills/security-audit/SKILL.md`
  (thin alias, ADR-222), `plugin/auditforge/commands/audit.md`,
  `plugin/auditforge/commands/freshness.md`,
  `docs/security/attack-classes/` (+ `ATTRIBUTION.md`),
  `scripts/report-schema.json`, `scripts/validate_findings.py`,
  `scripts/validate_coverage_ledger.py`,
  `scripts/test_validate_audit_skill.py`, `scripts/sync_skills.py`
  (canonical → distributable skill-copy sync; no dedicated test file —
  covered by the drift gate below)
- **Test Surface Seam:** `scripts/test_validate_audit_skill.py`
  (`test_skill_copies_in_sync` is the copy-drift gate),
  `scripts/sync_skills.py --check`,
  `muse skills validate` on the skill directory, `muse plugins validate`
  on `plugin/auditforge` (run via those CLIs, exit 0)

## 7. Measurement Seams

- **Primary Metric:** holistic-run acceptance — a full audit on juice-shop
  produces validator-clean artifacts with a declared run_status and at
  least one traced `confirmed` or an honest all-`needs_validation` set.
- **Evaluation Gate:** validator scripts exit 0 on run artifacts; skill +
  plugin validate clean; pytest for validators.
- **Correctness Backpressure:** benchmark scorecard (see v2 plan):
  OWASP Benchmark Youden's J for the deterministic SAST lane (published
  static-tool ceiling ≈ 0.39 for calibration, not as a pass/fail bar);
  juice-shop head-to-head runs measuring precision/recall/FP/runtime with
  ground-truth honesty rules (no recall claims without ground truth).
- **Telemetry Surface:** none.
- **Branching Policy:** n/a — direct commits to `main`.

## 8. Technology Resolution

- **Decision class:** BUILD (skill prose orchestrating in-repo modules;
  no product sells "one skill over this project's exact engine set").
- **Alternatives considered:**
  | Option | Why not |
  | --- | --- |
  | Keep two skills permanently | overlapping triggers, mode confusion, double maintenance for one workflow |
  | Adopt Cloudflare skill verbatim | no compliance citations, no deterministic Phase 0, Node validators, `~/` artifact paths — the port already settled this (teardown §7) |
  | Closed-loop auto-remediation in the pipeline | rejected in tooling-direction §3: patch → re-scan → verify lives in the skill with human merge, never as engine side effect |
- **Fit gap:** ledger/verification/budget wiring is prose-only until the
  sibling modules land — the skill references contracts, not code, and
  says so where the seam is unbuilt.
- **Exit cost:** LOW — markdown prose + JSON run artifacts.
- **Cost model:** $0 marginal (model calls are the caller's).
- **Liability transferred:** none.
- **Operational owner:** us.
- **Failure mode:** phase theater — phases declared done without their
  artifacts (ledger unvalidated, findings unvalidated, no run_status).
  Mitigated by validator gates after every mutation and the derived-report
  rule; the skill states gates as commands, not advice (Trail of Bits
  rule: flags are properties of code, not instructions a model can drop).
- **Open questions:** single-agent fallback quality bar — **[OPEN DESIGN
  DECISION]**: what minimum evidence does a fallback run require before it
  may claim `complete`? Resolve with the first fallback run on juice-shop.
