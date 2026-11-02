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

Status: partially built. Schema + validators exist (R-133 ports) and
`scripts/ledger.py` is the finding store with verdict/disproof columns
(P7 ledger-verdict wiring); the state-machine transitions, adversarial
protocol enforcement, and sandbox backend do not yet.

## 2. Sub-System Decomposition

Atomic leaf (BUILD — partially built: the ledger-store seam exists;
the sub-areas below stay prose until code with its own test seam exists,
per ADR-102: no invented nodes without seams).

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
  verdict/disproof columns and the
  `verdict`/`list --verdict`/`stats --by-verdict` seam, P7).
- **Test Surface Seam:** `scripts/test_ledger.py` (run via
  `python -m pytest`; verdict-machine/adversarial/sandbox tests still
  planned).
- Still planned: verdict-machine unit tests (including
  malformed-verifier-output rejection and budget-`incomplete` run_status),
  adversarial-assignment tests (finder-context exclusion), sandbox refusal
  tests (no-backend → `needs_validation`, no execution).

## 7. Measurement Seams

- **Primary Metric:** validation survival (candidates → confirmed), tracked
  per run like the VDH harness (their 20,799 → 12,057 → 7,245) — a
  collapsing survival rate means the hunters are noisy, not that the
  verifiers are strict.
- **Evaluation Gate (planned):** `validate_findings.py` exit 0 on every
  `findings.json`; `python -m pytest scripts/test_ledger.py` (exit 0,
  store seam); pytest suite for the state machine; one sandboxed-PoC
  end-to-end on juice-shop (already cloned as the auditor's test target).
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
