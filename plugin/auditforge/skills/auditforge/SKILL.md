---
name: auditforge
description: "Holistic security audit for a repository - compliance, deterministic scanning, coverage-led vulnerability hunting, adversarial verification, and reporting in one workflow. Also a SOC 2 / multi-framework GRC knowledge base (48k+ controls, 330+ families), semantic control search, document catalog, free vuln intel (CISA KEV/EPSS/NVD), and the audit_repo.py static scanner. Use when asked to audit code, find vulnerabilities, review security, check compliance, look up a control, or refresh the knowledge base."
trigger: /auditforge
---

# /auditforge

> Plugin copy. Canonical source: `.claude/skills/auditforge/SKILL.md` in the
> AuditForge repo - reconcile on bump (same pin-and-reconcile habit as
> `resources/`).

AuditForge is both an MCP server (`scripts/mcp_server.py`, auto-registered
via `.mcp.json` when Claude Code opens this repo) and a standalone CLI - this
skill works whether or not the MCP connection is live, so it's portable to
any session or agent that can run shell commands against this repo, not just
ones with MCP wired up.

**Prefer the MCP tools when connected** (they hit `scripts/vector_index.db`
directly - sub-second, no full-file loads): `search_controls`, `get_control`,
`list_frameworks`, `crosswalk_rule`, `crosswalk_control`, `search_documents`,
`get_document`, `run_audit`, `run_universal_audit`, `engine_status`,
`audit_policy_docs`, `run_gap_analysis`, `ledger_stats`,
`validate_findings_report`, `validate_coverage_ledger_report`,
`check_freshness`, `kev_lookup`, `epss_lookup`, `nvd_lookup`. If
those tools aren't available in this session, fall back to the CLI below -
same underlying data, just slower to invoke per-call.

## One-time setup (if `.venv/` doesn't exist yet)

```
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# .venv/bin/python -m pip install -r requirements.txt          # macOS/Linux
```

Never install these deps (`mcp`, `sentence-transformers`, `sqlite-vec`,
`pypdf`) into a global/system Python - see CLAUDE.md Workspace Layout.

## Refreshing the knowledge base

```
pwsh scripts/update_sources.ps1              # pull all cloned KBs + regen framework_metadata.json
.venv/Scripts/python.exe scripts/build_document_catalog.py --cache-all   # bulk-cache eligible doc text
.venv/Scripts/python.exe scripts/build_vector_index.py                  # rebuild semantic index (run after either of the above)
```

`framework_metadata.json`, `document_catalog.db`, and `vector_index.db` are
all DERIVED - regenerate them, never hand-edit.

## CLI equivalents of the MCP tools

```
# Semantic search over ~47k controls (same engine as search_controls MCP tool)
.venv/Scripts/python.exe -c "
import sys; sys.path.insert(0, 'scripts')
from mcp_server import search_controls
import json; print(json.dumps(search_controls('<query>', top_k=5), indent=2))
"

# Compliance scan (the CLAUDE.md Review Loop's mandated check)
.venv/Scripts/python.exe scripts/audit_repo.py <path> --fail-on HIGH

# Full multi-engine sweep (same as run_universal_audit MCP tool)
.venv/Scripts/python.exe scripts/universal_audit.py <path> --format json

# Must-build gap analysis: what this stack SHOULD have vs what it has
.venv/Scripts/python.exe scripts/gap_analysis.py <path> --domain auto

# Governance/policy document coverage (15-policy catalog + live citations)
.venv/Scripts/python.exe scripts/policy_audit.py <path>

# Finding lifecycle + validators (same as ledger_stats / validate_* tools)
.venv/Scripts/python.exe scripts/ledger.py stats --repo <name>
.venv/Scripts/python.exe scripts/validate_findings.py findings.json
.venv/Scripts/python.exe scripts/validate_coverage_ledger.py coverage-ledger.json

# Knowledge-stack freshness gate (same as check_freshness MCP tool)
.venv/Scripts/python.exe scripts/check_freshness.py --skip-kev

# Vulnerability intel for one CVE (KEV + EPSS combined)
.venv/Scripts/python.exe scripts/vuln_intel.py --enrich CVE-2024-3400

# Document catalog lookup
.venv/Scripts/python.exe -c "
import sqlite3; c = sqlite3.connect('scripts/document_catalog.db')
print(c.execute('SELECT * FROM documents WHERE fdi = ?', ('<fdi>',)).fetchone())
"
```

## Key facts an agent using this skill should know

- **All data is real and sourced online**, not fabricated: NIST OSCAL,
  MITRE ATT&CK STIX, OWASP ASVS, ComplianceAsCode YAML, the Secure Controls
  Framework crosswalk workbook, and FedRAMP's `FedRAMP/rules` repo (the
  current 20x Key Security Indicators model - the old Rev5 baseline-profile
  repo, `GSA/fedramp-automation`, no longer exists as of 2026-09-09).
- **Licensing is enforced, not advisory**: `document_catalog.db.license_status`
  gates what `build_document_catalog.py --cache`/`--cache-all` will ever
  fetch (`public_domain`/`free_to_access` only) - it refuses
  `copyrighted_registration_required`/`unknown` with zero network call.
  Respect the same gate in anything you build on top of this.
- **`crosswalk_rule` vs `crosswalk_control`**: the former is an exact,
  hand-authored mapping (audit_repo.py rule ID -> real framework clauses) -
  trustworthy as a citation. The latter is nearest-neighbor semantic
  similarity between two frameworks' control text - a starting point for
  human verification, never cite it as authoritative - and it only works
  when BOTH sides have real control text. Against the ~248 `SCF_*`-prefixed
  families (Secure Controls Framework crosswalk columns, e.g.
  `SCF_GENERAL_ISO_27001_2022`) it routes to an exact token-join through the
  SCF's own shared control-ID structure (`scf_crosswalk_tokens`) instead of
  embedding similarity, because their indexed "text" is bare clause numbers
  like `"4.2 4.2(a)"`, not descriptions. Pure semantic search over those
  families is still unreliable. `get_control()` still works on them for an
  exact lookup if you already know the SCF control ID.
- **New lanes since the agentic layer (all verified in
  `framework_metadata.json`, 48,061 controls / 336 families, STIG+FFIEC-seeded)**: the OWASP
  lane (`top10` flagship 2025 + API, MOBILE, LLM, AGENTIC, MCP, K8S, CICD,
  MASVS families), MITRE ATLAS (AI adversary tactics), NIST AI RMF base
  text (AIRMF) + GenAI Profile (GENAI), DOE C2M2 v2.1, CWE/CAPEC/D3FEND
  machine-readable exports, CISA CPG 2.0, CVSS v4 metrics, SAMM v2, NIST SP
  800-63-4, SAF RHEL 8/9 STIG baselines, DISA STIG XCCDF requirements
  (RHEL 8/9 quarterly zips seeded in gitignored `references/disa-stig/`),
  and the FFIEC InfoSec booklet (41-section FFIEC family). Hybrid
  `search_controls` (R-106): exact control-ID hits (`match="exact"`) lead
  vector neighbors (`match="semantic"`) - trust an exact hit and stop.
  Catalog-only rows (no control text yet): CIRCIA, CMMC 2.0 assessment/scoping
  guides.
- **Vulnerability prioritization**: OSV (via `universal_audit.py`) tells you
  a dependency has *a* known vulnerability; `kev_lookup`/`epss_lookup` tell
  you whether that vulnerability is one anyone is actually exploiting -
  combine both before recommending urgent remediation.
- See `ROADMAP.md` for open gaps (HITRUST R-027 and SOC 1/SSAE 18 R-058
  have no machine-readable open source; CIS Controls v8.1 master Excel is
  registration-gated and CCM v4.1 is indexed minimally as IDs+titles only
  under Fair-Use terms) and `docs/STATUS.md` for current architecture/phase.

## Full security audit (six phases, one workflow)

Two modes. **Guidance (default):** answer security questions from the code.
Read-only, no artifacts, say which mode you are in. **Full audit:** all six
phases below against one target in one run. Say so up front with the target
and the run directory (`reports/security-audit/<repo>/run-<N>/`, N
increments). Deterministic tools do bookkeeping; agents do judgment. Never
the reverse.

### Phase 0 - deterministic sweep (always first)

1. `audit_repo.py <target> --json` - native findings with file:line.
2. `universal_audit.py <target> --format json` (scope engines per profile).
3. KEV/EPSS enrich every CVE - exploited in the wild outranks severity.
4. `crosswalk_rule` each candidate rule ID - attach the compliance row now.
5. Ingest into the finding ledger (origin is the deterministic sweep):
   `ledger.py ingest --repo <name> --run-id r<N> --audit-json report.json`.
   Findings enter `unreviewed`; re-ingest preserves verdicts (additive).

### Phases 1-2 - recon + coverage-led hunting

Recon: target purpose, principals and trust levels, entry surfaces, sinks,
deployment reality. Write `architecture.md` (1000 words max). Partition
recon into hunt units - one per entry-surface x trust-boundary x subsystem
x attack-class - with `coverage.py init --recon-json recon.json --out
coverage-ledger.json --profile <quick|standard|deep>`; validate it
(`validate_coverage_ledger.py`), and join domain posture
(`gap_analysis.py` + `coverage.py union`) so hunting starts where required
controls are missing or flaws already fired. Hunt unauthenticated surfaces
first, highest-value boundaries next, using the attack-class packs in
`docs/security/attack-classes/` whose `When to use` gate matches.
After every wave run `coverage.py critic` and hunt what it lists -
unworked units stay `planned`, never silently `covered`.
`coverage.py budget` tells you when the critic + validation reserve is
gone: then declare `run_status: incomplete` with the exact reason, never
thin evidence. Single-agent fallback: recon, one pass per attack class,
then fresh-context self-review (re-read the candidate files).

### Phases 3-5 - adversarial verification (the load-bearing part)

A finding's hunter NEVER validates it - `ledger.py verdict` rejects
finder==verifier (exit 3). Identity difference alone is not independence:
the verifier starts from the candidate record plus evidence fields ONLY
(never the hunter's notes), re-reads the exact files with a fresh context,
and MUST document a disproof attempt - what was tried to refute the
candidate and why it failed. A `confirmed` without a recorded disproof
attempt is invalid; record it in the verdict reason.
`confirmed` needs lower-trust principal, accepted input, control, crossed
boundary, concrete observed result, severity with anchors (critical =
unauth code exec / full data-store takeover / account takeover), PoC-grade
execution for high/critical (`poc_sandbox.py run`; refusal or inconclusive
output means `needs_validation`, never `confirmed`), remediation, and the
compliance row. `needs_validation` (exact blocker + local/deployment plan,
NO severity) is the honest home for anything unprovable. `rejected` keeps
its disproof so future runs don't repeat it. Replacing root cause, trace,
impact, or severity routes to ANOTHER independent verifier. Run both
validators after every mutation; malformed verifier output is discarded
unrepaired.

### Phase 6 - report (derived from records, never the reverse)

`assessment.md` derives from `findings.json` + the coverage ledger;
`run_status: complete|incomplete` goes up front. Priority-ordered
remediations, each with owner action. Additive runs: `coverage.py carry`
stamps `prior_status` from the prior ledger (same-source carries,
changed-source revalidates, rejected claims rescope); `rejected`
suppresses only the failed claim.

## Coverage ledger CLI (same data as the validate MCP tool)

```
.venv/Scripts/python.exe scripts/coverage.py init --recon-json recon.json --out coverage-ledger.json --profile standard
.venv/Scripts/python.exe scripts/coverage.py critic --ledger coverage-ledger.json
.venv/Scripts/python.exe scripts/coverage.py budget --ledger coverage-ledger.json --profile standard
.venv/Scripts/python.exe scripts/coverage.py carry --prior old.json --ledger new.json --changed changed.json --out carried.json
.venv/Scripts/python.exe scripts/coverage.py union --ledger coverage-ledger.json --gap-report gap.json
.venv/Scripts/python.exe scripts/ledger.py verdict --repo <n> --fingerprint <fp> --verdict confirmed --run-id v1 --reason "...; disproof tried: ...; failed because: ..." --verifier <id> --evidence <artifact>
.venv/Scripts/python.exe scripts/ledger.py transitions --repo <n> --fingerprint <fp>
.venv/Scripts/python.exe scripts/poc_sandbox.py check
.venv/Scripts/python.exe scripts/poc_sandbox.py run --cmd "<poc>" --workdir <target> --outdir <artifacts> --artifacts-root <repo>/reports --record --repo <n> --fingerprint <fp> --run-id <id> --db <ledger.db> --verifier <id>
```

`--record` writes only `needs_validation`. Confirming is always a separate
`ledger.py verdict --verdict confirmed` with the artifact as `--evidence`
and an independent `--verifier`.
