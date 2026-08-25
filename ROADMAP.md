# ROADMAP

Sole incomplete-work registry for AuditForge.

## Ready

| ID | Item | Notes |
| --- | --- | --- |
| R-007 | Contract the audit-engine surface (`universal_audit.py`, `auditor/` package, its test seams) via `recurspec reconcile plan` into a sibling subtree | closes the 4 `structure.public.uncontracted` findings; engine was declared out of scope for the current tree |

## Blocked

(none)

## Blocked

(none)

## Deferred — Research Frontiers

| ID | Uncertainty | Unblocks when |
| --- | --- | --- |
| RF-001 | CIS Controls v8.1 master Excel: registration-gated, no-redistribution license. Machine-readable CIS currently via ComplianceAsCode platform files only. | CIS publishes an API or grants redistribution-friendly licensing; or user manually downloads the Excel into `references/` (then wire a parser) |
| RF-002 | CSA CCM v4 machine-readable bundle: free internal use, commercial embedding $15k–30k/yr. | project needs cloud-control coverage beyond SCF/800-53 and accepts license terms |
| RF-003 | FedRAMP Rev5 baselines: official repo deleted (404); community OSCAL mirrors exist. | a concrete FedRAMP audit need appears; then pin OSCAL-Foundation/fedramp-resources |
| RF-004 | HHS NPRM (Jan 2025) may rewrite HIPAA Security Rule text. | final rule published → refresh ComplianceAsCode hipaa.yml / eCFR pull |

## Completed

| ID | Item | Evidence |
| --- | --- | --- |
| R-001 | sync_frameworks.py indexes OSCAL (800-53 R5 / 800-171 R3 / CSF 2.0), CaC HIPAA/PCI YAML, ASVS JSON → 2075 controls, 11 families | sync run log |
| R-002 | update_sources.ps1: pull-or-clone registry (17 sources) + tool inventory + sync | end-to-end run, exit 0, 7 updated |
| R-003 | git init + .gitignore; zero clone/report paths tracked | workspace-hygiene checks.ps1 PASS |
| R-004 | reports/ canonicalized (user pre-removed old root artifacts); config output_dir=reports | root_stray_artifacts = 0 |
| R-005 | requirements.txt (PyYAML, requests, python-dotenv) | import coverage check PASS |
| R-006 | CLAUDE.md/GEMINI.md session-start + layout documented | docs reviewed |
