# Verification Lifecycle (L1)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

Turns candidates into verdicts. Owns the finding state machine
(candidate → `confirmed` / `needs_validation` / `rejected`), the
adversarial verification protocol (the checker is never the finder), the
sandboxed proof-of-concept execution boundary, and the schema contracts
that enforce verdict discipline (`scripts/report-schema.json`,
`scripts/validate_findings.py`). Consumes candidates from
[auditor-core](../auditor-core/SYSTEM.md) (Phase-0 deterministic sweep) and
[coverage-hunting](../coverage-hunting/SYSTEM.md) (hunter leads); publishes
verdicts to the finding ledger (`scripts/ledger.py`) and to
[holistic-skill](../holistic-skill/SYSTEM.md) for reporting.

Does not own: candidate discovery (auditor-core's engines, hunters'
judgment), compliance citation text (framework-sync's), report rendering
(reporting.py renders; this module decides what is reportable).

Status: mostly built (R-137/R-138, 2026-11-02). Schema + validators
exist (R-133 ports); `scripts/ledger.py` is the finding store with
verdict/disproof columns (P7), a `transitions` table, fail-closed verdict
guards (finder≠verifier, confirmed-needs-evidence,
rejected/needs_validation-need-reason, same-verifier material replacement
rejected), and ingest-time material-change demotion; `scripts/poc_sandbox.py`
is the Docker-only hardened PoC runner with refuse-to-run. Still open:
non-Docker sandbox backends (gVisor/bubblewrap Linux ladder) and the
two-model cross-check upgrade (single-model fresh-context is the v2 bar).

## 2. Sub-System Decomposition

Atomic leaf (BUILD — the ledger-store and poc-sandbox seams exist;
the remaining sub-areas below stay prose until code with its own test
seam exists, per ADR-102: no invented nodes without seams).

Planned sub-areas (not nodes yet): `verdicts` (state machine + schema
enforcement), `adversarial-review` (fresh-context assignment,
material-replacement re-verification, two-model cross-check),
`poc-sandbox` (execution ladder + refuse-to-run fallback, see ADR-202).

## 3. Interface Contracts

- **Inputs:** candidates with (principal, accepted input, control crossed,
  boundary, observed result); prior ledger verdicts for additive runs.
- **Outputs:** `findings.json` records conforming to `report-schema.json`
  (validator exit 0); ledger state transitions
  (open → confirmed / needs_validation + blocker / rejected + disproof);
  PoC artifacts (test + proposed diff, human merges — never auto-applied).

## 4. Invariants (EARS + Epistemic Stage)

- **[Ubiquitous]** THE SYSTEM SHALL assign every candidate to a verifier
  whose context did not produce it (finder ≠ checker; Cloudflare Phase-3/5
  rule, harness two-model cross-check).
  - `EvidenceStage:` Unknown
- **[Ubiquitous]** THE SYSTEM SHALL NOT record a severity on a
  `needs_validation` verdict, and SHALL record its exact unresolved fact
  plus a local/deployment validation plan.
  - `EvidenceStage:` Unknown
- **[Conditional]** IF no sandbox backend is available THEN THE SYSTEM
  SHALL record `needs_validation` and SHALL NOT execute target-controlled
  code (refuse-to-run, not best-effort execution).
  - `EvidenceStage:` Unknown
- **[Ubiquitous]** THE SYSTEM SHALL run every PoC against the untouched
  target (no source edits to make exploits land) with dummy
  principals/fixtures/secrets, no live probing without owner approval.
  - `EvidenceStage:` Unknown
- **[Conditional]** IF a verification replaces root cause, trace, impact,
  or severity (promotion to `confirmed` included) THEN THE SYSTEM SHALL
  route the replacement to another independent verifier.
  - `EvidenceStage:` Unknown
- **[Ubiquitous]** THE SYSTEM SHALL derive severity from observed impact
  (critical = unauth code exec / full data-store takeover), never from
  checklist deviation; `overall <= impact` always holds.
  - `EvidenceStage:` Unknown
- **[Ubiquitous]** THE SYSTEM SHALL reject a `verdict` command whose
  `--verifier` equals the finding's recorded `finder`, exit 3, and record
  nothing (`test_verdict_rejects_self_verification`).
  - `EvidenceStage:` Sampled
- **[Ubiquitous]** THE SYSTEM SHALL require `--evidence` for `confirmed`
  and `--reason` for every verdict transition, exit 3 otherwise, and
  append every accepted transition to the `transitions` table
  (`test_verdict_transition_logged` and the guard tests).
  - `EvidenceStage:` Sampled
- **[Conditional]** IF a re-ingest changes a `confirmed`/`rejected`
  finding's evidence fields (file/line/snippet) THEN THE SYSTEM SHALL
  demote it to `needs_validation` with a material-change reason and log
  the transition (`test_material_change_demotes_confirmed`).
  - `EvidenceStage:` Sampled
- **[Conditional]** IF `poc_sandbox` has no working backend or image THEN
  it SHALL exit 4 with a `needs_validation` payload and SHALL NOT execute
  anything; `--record` writes only `needs_validation`, never `confirmed`
  (`test_refusal_without_backend`, `test_refusal_records_needs_validation`).
  - `EvidenceStage:` Sampled

## 5. Architectural Decisions (ADRs)

- **ADR-201:** Verdicts over flat findings — `confirmed /
  needs_validation / rejected` (vendored MIT schema, stdlib validators,
  no Node) replaces the current implicit-"confirmed" flat list. Rationale:
  deterministic scanners over-report by design (e.g. SDLC004 is
  deliberately LOW "flag for review"); the honest home for ambiguous hits
  is a blocked state with an exact blocker, not a severity.
- **ADR-202:** Docker `--network none` as the required PoC sandbox backend;
  absent Docker means `needs_validation`, never unprotected execution.
  Rationale: 2026 sandbox guidance converges on strongest-available-first
  with refuse-when-none (bwrap/nsjail/gVisor ladders); Docker is the only
  backend available on both this project's dev host (Windows) and its CI
  (ubuntu-latest). gVisor/bubblewrap are the documented hardening path for
  Linux-only deployments, not v2 scope.
- **ADR-203:** Static analysis stays a machine stage, never hunter tooling
  — Cloudflare's own data (zero Semgrep invocations by hunters in a month)
  plus this repo's Phase-0 design already settle this: engines feed
  candidates *in*, agents never invoke scanners mid-hunt.

## 6. Leaf Execution & Test Seam

- **Implementation Files:** `scripts/ledger.py`,
  `scripts/test_ledger.py` (SQLite store keyed by (repo, fingerprint);
  verdict/disproof/finder/evidence columns; `verdict` /
  `list --verdict` / `stats --by-verdict` / `transitions` seam; ingest
  demotion on material change), `scripts/poc_sandbox.py`,
  `scripts/test_poc_sandbox.py` (hardened Docker runner: network-none,
  resource cage, cap-drop, read-only rootfs, two-mount boundary,
  pre-pulled images only; refusal exits 4 with a needs_validation
  payload; `--record` never confirms).
- **Test Surface Seam:** `scripts/test_ledger.py`,
  `scripts/test_poc_sandbox.py` (run via `python -m pytest`; includes
  guard-violation, self-verification, demotion, migration, refusal,
  flag-hardening, timeout-kill, and fixture-to-confirmed e2e tests).
- Still planned: non-Docker backends, two-model cross-check; the
  budget-`incomplete` run_status rule belongs to coverage-hunting.

## 7. Measurement Seams

- **Primary Metric:** validation survival (candidates → confirmed), tracked
  per run like the VDH harness (their 20,799 → 12,057 → 7,245) — a
  collapsing survival rate means the hunters are noisy, not that the
  verifiers are strict.
- **Evaluation Gate:** `validate_findings.py` exit 0 on every
  `findings.json`; `python -m pytest scripts/test_ledger.py
  scripts/test_poc_sandbox.py` (exit 0); one fixture-to-confirmed e2e in
  `test_poc_sandbox.py` (stub-backend, no daemon needed); one
  sandboxed-PoC end-to-end on juice-shop stays the live-backend proof
  (already cloned as the auditor's test target; needs a real daemon).
- **Correctness Backpressure:** shallow-run detection — a run with zero
  candidates requeues hunting rather than reporting "clean".
- **Telemetry Surface:** none (local runs, no telemetry by design).
- **Branching Policy:** n/a — direct commits to `main`.

## 8. Technology Resolution

- **Decision class:** BUILD (protocol + stdlib state machine over the
  existing `ledger.py` SQLite store; Docker CLI as the sandbox backend).
- **Justification:** verdict discipline and adversarial assignment are
  project-specific workflow rules no off-the-shelf product encodes; the
  ledger store and schema validators already exist in-repo.
- **Alternatives considered:**
  | Option | Why not |
  | --- | --- |
  | Cloudflare `.cjs` validators as-is | adds a Node.js requirement to a zero-dependency scanner philosophy; stdlib ports already done (R-133) |
  | Per-tool MCP sandbox servers (e.g. code-runner MCP) | 2026 CVE-2026-5029 (RCE in a code-runner MCP server) is the cautionary tale: execution belongs behind our own narrow boundary, not a third-party tool |
  | Firecracker/microVM now | heavier than v2 needs; documented hardening path, revisit for multi-tenant use |
- **Fit gap:** two-model cross-check needs a second model route this project
  does not have — single-model fresh-context verification is the v2 bar,
  cross-model the stated upgrade.
- **Exit cost:** LOW — protocol text in the skill + a small state machine;
  no stored format beyond the already-vendored schema.
- **Cost model:** $0 marginal (local compute + Docker; model calls are the
  caller's, unchanged).
- **Operational owner:** us.
- **Failure mode:** a verifier that rubber-stamps collapses the whole
  lifecycle into finder-grades-own-homework — mitigated by the
  material-replacement re-verification rule and the survival metric, not
  by trusting any single check.
- **Open questions:** none structural; backend ladder order on Linux-only
  hosts (Docker vs bwrap first) is an **[OPEN DESIGN DECISION]** — resolve
  with a Linux-host PoC timing/isolation test before hardening.
