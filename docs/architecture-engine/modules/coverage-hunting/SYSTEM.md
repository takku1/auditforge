# Coverage Hunting (L1)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

Answers "what didn't we look at" — for exploit paths, not just controls.
Owns the per-run coverage ledger (one unit per entry-surface × trust-
boundary × subsystem × attack-class), the critic/gapfill waves that find
missed coverage, hunt priority ordering under a budget, and additive runs
(prior ledgers/finding
s target gaps, revalidate changed source, carry current-source evidence).
Unifies two lenses in one ledger family: exploit-path coverage (did we test
this attack path?) and control coverage (does this domain have its required
controls? — the existing `gap_analysis.py` 12-domain profiles).

Does not own: verdicts on what hunters find (verification-lifecycle's),
the domain control catalogs themselves (framework-sync's), hunter judgment
(the skill's prompts).

Status: partially built. `validate_coverage_ledger.py` +
`gap_analysis.py` (12-domain must-build profiles over
`scripts/gap_profiles.json`, ADR-211) exist; the per-run ledger, critics,
budget discipline, and additive-run rules do not yet.

## 2. Sub-System Decomposition

Atomic leaf (BUILD — planned, not yet implemented; sub-areas below stay
prose until code with its own test seam exists, per ADR-102: no invented
nodes without seams).

Planned sub-areas (not nodes yet): `coverage-ledger` (per-run unit
schema, validated after every mutation), `critics` (gap re-scan after
every hunter wave; unassigned units explicitly `deferred`), 
`additive-runs` (`prior_status` taxonomy, carry vs revalidation).

## 3. Interface Contracts

- **Inputs:** recon output (surfaces, principals, boundaries, deployment
  reality); Phase-0 deterministic candidates; prior run ledgers.
- **Outputs:** `coverage-ledger.json` (validator exit 0 after every
  mutation); hunter work units in priority order (unauth surfaces first,
  highest-value boundaries next); explicit `deferred` list with reasons;
  run `budget` accounting (max invocations, reserve recon + critics +
  validation before hunting).

## 4. Invariants (EARS + Epistemic Stage)

- **[Ubiquitous]** THE SYSTEM SHALL end every coverage unit in an explicit
  terminal state — `covered`, `candidate`, `blocked`, `deferred` (with
  reason), `out_of_scope`, or `not_applicable`. No unit is silently
  dropped; "scanned clean" is distinguishable from "never looked at".
  - `EvidenceStage:` Unknown
- **[Ubiquitous]** THE SYSTEM SHALL validate the ledger after creating it
  and after every later update (`validate_coverage_ledger.py` exit 0).
  - `EvidenceStage:` Unknown
- **[Conditional]** IF the run budget is exhausted THEN THE SYSTEM SHALL
  mark remaining units `deferred`, never thin evidence silently; a run that
  cannot cover its reserve (recon + critics + validation) SHALL declare
  `run_status: incomplete` with the exact reason.
  - `EvidenceStage:` Unknown
- **[Ubiquitous]** THE SYSTEM SHALL order hunters by exposure (unauthenticated
  surfaces first, highest-value boundaries next) — profiles
  (quick/standard/deep) change breadth, never the evidence bar.
  - `EvidenceStage:` Unknown
- **[Ubiquitous]** THE SYSTEM SHALL keep deterministic scanners as candidate
  feedstock (Phase 0), never as hunter-invoked tooling mid-hunt.
  (Cloudflare's own measurement: zero hunter scanner invocations in a
  month — teardown §4 row 11.)
  - `EvidenceStage:` Observed

## 5. Architectural Decisions (ADRs)

- **ADR-211:** One ledger family, two lenses — per-run exploit-path units
  and `gap_analysis.py` domain must-build profiles share the unit/state
  vocabulary but not the same file: `coverage-ledger.json` (per-run, under
  `reports/`, gitignored) vs domain profiles (stable, committed). Rationale:
  run coverage is ephemeral evidence; domain requirements are durable
  knowledge. Union reporting reads both.
- **ADR-212:** Critics over completeness claims — every hunter wave is
  followed by a critic pass hunting for missed units, because a single run
  finds roughly half of what repeated runs find (Cloudflare test-run data).
  Shallow-run detection (zero candidates → requeue) is the cheap backstop.
- **ADR-213:** Additive by fingerprint — prior-run carry/revalidation keys
  off the existing stable finding fingerprints
  (`Finding.fingerprint`, sha1 of rule+file+snippet) plus ledger
  `prior_status`; no new identity infrastructure.

## 6. Leaf Execution & Test Seam

- **Implementation Files:** `scripts/gap_analysis.py`,
  `scripts/test_gap_analysis.py` (the domain-profile half: target
  capabilities vs repo evidence, framework citations live from
  framework-sync's index).
- **Test Surface Seam:** `scripts/test_gap_analysis.py` (run via
  `python -m pytest`; per-run-ledger/critic/budget/additive tests still
  planned).
- Still planned: ledger-state tests (no silent
drops — every seeded unit accounted for), validator-after-mutation tests,
budget-exhaustion tests (`deferred`, never thinned), additive-run tests
(carry same-source, revalidate changed-source, rejected-claim scoping).

## 7. Measurement Seams

- **Primary Metric:** coverage growth per run (units covered + candidates
  per wave) and gapfill yield (critic-found units that produce candidates)
  — Cloudflare's coverage-cell growth on held-out repos is the precedent.
- **Evaluation Gate (planned):** `validate_coverage_ledger.py` exit 0;
  `python -m pytest scripts/test_gap_analysis.py` (exit 0); pytest for
  state machine + critics on fixture repos; juice-shop full-run ledger
  review (eyeballed once, then fixture-locked).
- **Correctness Backpressure:** the `deferred`-with-reason list is reviewed,
  not just the findings — a growing deferred list with boilerplate reasons
  means the budget model is wrong.
- **Telemetry Surface:** none.
- **Branching Policy:** n/a — direct commits to `main`.

## 8. Technology Resolution

- **Decision class:** BUILD (ledger schema + critic procedure over the
  existing validators and `gap_profiles.json`; SQLite persistence via the
  `ledger.py` pattern when runs need resume — VDH `run_id/repo/stage` keying).
- **Justification:** coverage units are defined by the target's own
  surfaces × boundaries, which no off-the-shelf tracker knows; the
  validators and domain profiles already exist in-repo.
- **Alternatives considered:**
  | Option | Why not |
  | --- | --- |
  | Full VDH fleet harness (Gapfill/Dedup/Trace/Feedback stages, SQLite resume) | fleet economics for 128 repos; single-repo runs need the ledger + critic wave only (teardown §4 row 2) |
  | Cross-repo Trace (dependency-graph Trace) | no fleet; the single-repo cousin (OSV + SBOM dependency walk) already exists |
- **Fit gap:** deterministic root-cause dedup shortlister (inverted index
  over files/functions/boundaries/rare tokens, agent adjudicates) is
  designed but unbuilt — duplicate root causes across rules (e.g. SEC001 +
  TRUFFLEHOG_VERIFIED_SECRET) stay separate until then.
- **Exit cost:** LOW — JSON ledger + validator scripts; no lock-in.
- **Cost model:** $0 marginal (local only; model calls are the caller's).
- **Operational owner:** us.
- **Failure mode:** ledger theater — units marked `covered` that were only
  glanced at. Mitigated by critics + the rule that `rejected` never covers
  its unit; residual risk is honest about being procedural, not technical.
- **Open questions:** SQLite run persistence now or later — **[OPEN DESIGN
  DECISION]**: file-per-run JSON first (simpler, matches current
  `reports/` convention); promote to `ledger.db`-style SQLite keyed by
  (`run_id`, `repo`, `stage`) when resume-without-redo matters. Evidence to
  resolve: first crashed long run.
