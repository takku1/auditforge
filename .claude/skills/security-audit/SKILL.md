---
name: security-audit
description: Full security audit of a repository - deterministic pre-pass plus adversarial multi-phase review. Use for "audit this repo", "security review", "find vulnerabilities", or after finishing a feature to check it. Two modes: guidance (answer questions, read-only) and full audit (six phases, artifacts under reports/security-audit/<repo>/run-<N>/).
---

# Security Audit (AuditForge port)

Adapted from Cloudflare's MIT-licensed `security-audit-skill`
(reference clone: `resources/security-audit-skill/`, report schema vendored
as `scripts/report-schema.json`). Keeps their six phases, adversarial
validation, coverage ledger, and severity discipline; adds what they lack:

- **Phase 0 deterministic sweep** (this repo's scanners + intel) feeds
  candidates *in* - agents never run scanners mid-hunt.
- **Compliance citation per confirmed finding** via `framework_mappings.json`
  (SOC 2 + NIST + OWASP/ASVS + MITRE), not just a severity.
- **Stdlib Python validators** (`scripts/validate_findings.py`,
  `scripts/validate_coverage_ledger.py`) - no Node.js required.
- Artifacts under `reports/` (gitignored) instead of `~/`.

## Modes

- **Guidance (default):** answer security questions from the code. Read-only.
  Do not create artifacts. Say which mode you are in.
- **Full audit:** all six phases below. Say so up front, with the target and
  the run directory (`reports/security-audit/<repo>/run-<N>/`, N increments).

## Phase 0 - deterministic sweep (always first in full audits)

1. `python scripts/audit_repo.py <target> --json` - native findings with
   file:line. Every `SEC001`/`TRUFFLEHOG_*` hit is a candidate with exact
   location; `SDLC004`-style "flag for review" hits seed the ledger.
2. `python scripts/universal_audit.py <target> --format json --engines semgrep,osv,trivy` -
   SAST + SCA baseline. Escalate to the full engine set for deep profile.
3. KEV/EPSS enrich for every CVE (`kev_lookup`, `epss_lookup`) - exploited in
   the wild outranks severity-alone.
4. `crosswalk_rule` each candidate rule ID - attach the compliance row now;
   `search_controls` for the control text.

Record everything in `coverage-ledger.json` (one unit per entry surface x
trust boundary x subsystem x attack class, statuses planned/in_progress/
covered/candidate/blocked/deferred/out_of_scope/not_applicable).

## Phases 1-2 - recon + hunting

Recon: what the target is, principals and trust levels, entry surfaces and
sinks, deployment reality. Seed the ledger; write `architecture.md` (1000
words max). Hunt in priority order: unauthenticated surfaces first,
highest-value boundaries next. Companion attack-class packs live in
`docs/security/attack-classes/` (vendored MIT upstream, see ATTRIBUTION.md)
- apply the pack whose
`When to use` gate matches (`AI-AND-LLM`, `CLIENT-SIDE`,
`CLOUD-AND-DEPLOYMENT`, `DATA-ISOLATION-AND-LIFECYCLE`,
`DESKTOP-MOBILE-AND-LOCAL-IPC`, `MEMORY-SAFETY-AND-BINARY`,
`PROTOCOLS-RPC-AND-MESSAGING`, `RESOURCE-EXHAUSTION-AND-AVAILABILITY`,
`SUPPLY-CHAIN-AND-RELEASE`, `WEB-PROTOCOL-AND-AUTH`) plus
`HUNTING.md`/`ATTACK-CLASSES.md` for method.

Single-agent fallback: when no subagents are available, do recon, then one
hunting pass per attack class, then self-review with a fresh context
(re-read the candidate files before judging).

## Phases 3-5 - adversarial validation (the load-bearing part)

- A finding's hunter NEVER validates it. A fresh verifier re-reads the
  exact files and tries to *refute* each candidate.
- `confirmed` needs: lower-trust principal, accepted input, control,
  crossed boundary, concrete observed result, severity with anchors
  (critical = unauth code exec / full data-store takeover / account
  takeover), PoC-grade `execution` for high/critical, remediation, and the
  compliance row from Phase 0.
- `needs_validation` (exact blocker + local/deployment plan, NO severity)
  is the honest home for anything Phase 0 flagged that you cannot prove.
- `rejected` keeps its disproof so future runs don't repeat it.
- Run both validators after Phase 4 AND after every Phase-5 replacement:
  `python scripts/validate_findings.py findings.json`,
  `python scripts/validate_coverage_ledger.py coverage-ledger.json`.
  Malformed verifier output is discarded unrepaired; budget shortfall flips
  `run_status` to `incomplete` with the exact reason - never thin evidence.

## Phase 6 - report (derived from records, never the reverse)

`assessment.md` derives from `findings.json` + ledger; `run_status:
complete|incomplete` is stated up front. Priority-ordered remediations,
each with owner action. Additive runs: read the prior run's ledger first;
unchanged confirmations carry (`prior_confirmed_same_source`),
changed-source units become revalidation, `rejected` suppresses only the
failed claim.

## Hard rules (violate these and the run is invalid)

- Unverified input is the vulnerability until proven otherwise; if Layer A
  prevents the attack, missing Layer B is a hardening note, not a finding.
- Severity only on `confirmed`; overall never exceeds demonstrated impact.
- No live probing without owner approval; dummy principals/fixtures only.
  Sandbox or record `needs_validation`.
- Target-neutral prose: no "Cloudflare"/product names in artifacts.
- Read-only on the target repo; run `audit_repo.py --fail-on HIGH` on any
  code you write here before finishing.
