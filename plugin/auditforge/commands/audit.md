---
description: Run the full AuditForge security + compliance audit on a target directory
argument-hint: <target-path> [--fast]
---

Run the full AuditForge audit against `$ARGUMENTS` (default: current project).
Full sweep is the default: native scanner, all 12 universal engines in
parallel with per-engine timeouts, KEV/EPSS enrichment, and unified JSON
output with run_status.

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
8. Validate artifacts: `validate_findings.py` / `validate_coverage_ledger.py`
   before handing off; `check_freshness.py --skip-kev` if the KB was touched.
9. Report run_status honestly: `complete`, or `partial` with the exact
   reason (missing engines, skipped files). Never claim a clean bill on a
   partial run.
