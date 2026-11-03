# R-141 Benchmark Protocol (frozen 2026-11-02)

Measures whether AuditForge finds vulnerabilities, not how much code it
has. Benchmark infrastructure only: no detection rules change under this
protocol. Design inputs: the branch-review evaluation plan and the
`ai-evaluation` skill (claim-first, representative + negative cases,
independent oracles, matched states, no tuning on held-out, reported
uncertainty, no fabricated runs).

## Claim under test

The full verification lifecycle (scanner + hunter + independent
verification) yields higher *confirmed-finding precision* than the
deterministic scanner alone, without collapsing discovery recall. The
scanner + hunter ablation measures discovery gain; the full lifecycle
measures verification quality. Verification is not a detection stage: a
full-lifecycle run may report FEWER confirmed vulnerabilities because it
rejects weak candidates. That is scored as an improvement (precision up),
not a regression (recall is measured separately on discovery).

## Tracks

| Track | Target (pinned, see manifest) | Primary measurement |
| ----- | ----------------------------- | ------------------- |
| A: Static detection | OWASP Benchmark, pinned revision (external toolchain; adapter-ready, execution where Java/Maven exists) | Precision, recall, F1, Youden's J on labeled cases |
| B: Realistic application | OWASP Juice Shop, pinned git SHA (held-out, sealed) | Validated findings, false positives, coverage |
| C: Adversarial workflow | Curated vulnerable + safe cases | Novel discoveries, verification survival |
| D: Operational | All three targets | Runtime, token usage, budget compliance |

## Configurations (ablations)

1. `scanner-only`: `audit_repo.py` native rules, headless, no agents.
2. `scanner-hunter`: deterministic sweep + agent hunting recorded via
   `record` (findings + coverage ledger + execution metadata).
3. `full-lifecycle`: hunter output plus independent verification
   (`ledger.py verdict` chain, `poc_sandbox` artifacts where applicable).

Discovery recall is scored on candidates (scanner findings +
hunter leads); confirmed precision is scored on `confirmed` verdicts only.
Report them side by side, never blended.

## Ground truth and splits

- Ground truth schema: `benchmark/ground-truth/<target>.json` with
  `vulns[]` (id, file, line, cwe, rule, notes) and `safe[]` (id, file,
  line, notes — regions where the auditor must abstain).
- `calibration/`: synthetic fixture (`benchmark/fixtures/farm/`). Tuning
  is allowed here and only here.
- `held-out/`: Juice Shop cases curated by code reading, never scanned
  with AuditForge during curation. Sealed at manifest version: any
  tuning informed by held-out results invalidates the split and must be
  declared in the limitations report.
- Matching: same relative file, line ±3, AND (rule equal OR shared CWE
  via `framework_mappings.json`). Each finding claims its nearest vuln
  (rule equality breaks ties); each vuln is claimed once — adjacent
  vulns sharing a window must not starve each other (calibration caught
  greedy first-match doing exactly that). A finding in a safe window is
  a false positive regardless of rule.
- Located vs classified: a vuln with any finding in its window counts as
  `located` even when the rule/CWE is wrong; `misclassified` lists those
  IDs. Taxonomy gaps (no native rule for a bug class) show up here, not
  hidden inside recall.
- Youden's J is reported on the labeled safe sample only (TNR from
  abstention cases), labeled as such — never as a population claim.

## Execution metadata (fail-closed)

Every scored run records: target + pinned revision, tool versions,
config, model + prompts hash (agent configs), budget declared vs used,
duration, full artifacts (findings.json, coverage ledger, transitions).
`record` and `score` refuse (exit 2) when ground truth, target revision,
or required metadata is missing, or when the run revision differs from
the ground-truth revision. Environment failures are counted, never
silently dropped. Repeat stochastic agent runs as budget permits; report
sample size; repeated samples of one case are not independent tasks.

## Fair comparison (Cloudflare)

Match model, target revision, available tools, and budget. Capabilities
one workflow lacks are marked `n/a (capability absent)`, never scored
zero. Publish per-track deltas plus the limitations report; warts stay in.

## Release of results

`scorecard` emits the metrics table; `limitations` emits what is missing,
unmeasured, or uncertain (including stub-vs-live sandbox status and
held-out seal state). No recall claims without ground truth. No tuning
after seeing held-out results.
