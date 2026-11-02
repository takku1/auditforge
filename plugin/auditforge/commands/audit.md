---
description: Run the full AuditForge security + compliance audit on a target directory
argument-hint: <target-path> [--fast]
---

Run the full AuditForge audit against `$ARGUMENTS` (default: current project).
This command fronts the `auditforge` skill's six-phase workflow ("Full
security audit"); the skill text is authoritative when they differ.

1. Fast pre-pass: `audit_repo.py <target> --fail-on HIGH` (seconds, CI-gate).
2. Full sweep: `universal_audit.py <target> --format json` (all engines;
   pass `--engines semgrep,osv,trivy` after `--fast` for the minutes-long
   SAST+SCA subset instead).
3. Enrich every CVE: `kev_lookup` / `epss_lookup` (exploited-in-the-wild
   outranks severity-alone).
4. Cite compliance per finding: `crosswalk_rule` + `search_controls`.
5. Ingest into the ledger: `ledger.py ingest --repo <name> --run-id <id> --audit-json report.json`
   so re-finds reopen records instead of spawning duplicates.
6. Must-build gaps: `gap_analysis.py <target> --domain auto` (or
   `run_gap_analysis`) - every `must-build gap` is a finding, not advice.
7. Policy coverage: `policy_audit.py <target>` (or `audit_policy_docs`) -
   every `missing (must)` policy is a governance finding.
8. Coverage-led hunting: `coverage.py init` from recon, hunt per unit,
   `coverage.py critic` after every wave, `coverage.py budget` against the
   profile reserve - unworked units stay `planned`, never silently `covered`.
9. Adversarial verification: fresh-context verifiers (hunter never
   validates; `verdict` rejects finder==verifier), documented disproof
   attempts, `poc_sandbox.py` for high/critical PoCs, `ledger.py verdict`
   with `--evidence`. Refusal or inconclusive output means
   `needs_validation`, never `confirmed`.
10. Validate artifacts: `validate_findings.py` /
    `validate_coverage_ledger.py` after every mutation; `check_freshness.py
    --skip-kev` if the KB was touched.
11. Report run_status honestly: `complete`, or `incomplete`/`partial` with
    the exact reason (missing engines, skipped files, exhausted budget).
    Never claim a clean bill on a partial run.
