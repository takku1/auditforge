# Security-audit-skill teardown: Cloudflare vs AuditForge + integration plan

Source: `resources/security-audit-skill/` (cloned 2026-11-02 from
`github.com/cloudflare/security-audit-skill`, MIT — reference clone,
gitignored via `resources/`). Companion blog:
`Build your own vulnerability harness` (2026-06-18, the VDH/VVS fleet
system this skill seeded). Landscape cross-checks: Trail of Bits
`trailofbits/skills` marketplace, `solanabr/auditor-skill` (vendor+pin
pattern), Oct-2026 AI-audit-tool comparisons.

## 1. What was reviewed

Cloudflare skill (`resources/security-audit-skill/skills/security-audit/`,
19 files):

| File | Lines | Role |
| --- | --- | --- |
| `SKILL.md` | 126 | Modes, sandbox spec, write isolation, profiles, budget gate, core principles |
| `RECONNAISSANCE.md` | 119 | 4 parallel recon agents, prior-run carry rules, `architecture.md` (≤1000 words), coverage-ledger seeding |
| `HUNTING.md` | 205 | Hunter prompt contract, defensive method, promotion procedure, coverage critics |
| `ATTACK-CLASSES.md` | 110 | Core classes (injection, access control, resource/file, crypto/secrets, …) + router to 10 companions |
| 10 companions (`AI-AND-LLM`, `CLIENT-SIDE`, `CLOUD-AND-DEPLOYMENT`, `SUPPLY-CHAIN-AND-RELEASE`, …) | ~50–70 each | `When to use` gate + `Core discipline` + attack classes + `Validation rules`, injected verbatim into prompts |
| `VALIDATION-AND-REPORTING.md` | 138 | Phases 3–6: adversarial validation, `findings.json`, Phase-5 record verification, report derivation |
| `report-schema.json` | 461 | `confirmed` / `needs_validation` / `rejected` contracts (`additionalProperties: false`) |
| `validate-findings.cjs` / `validate-coverage-ledger.cjs` | 711 / 800 | Zero-dependency validators (Node stdlib only) |
| `validate-findings.test.cjs` / `validate-coverage-ledger.test.cjs` | 589 / 664 | Validator unit tests + producer fixtures |

AuditForge side (this repo): `scripts/auditor/` (`__init__.py`,
`models.py`, `rules.py` — 32 `Rule()` entries / 24 rule IDs, `scanners.py`,
`orchestrator.py`, `reporting.py`, `baseline.py`), `scripts/audit_repo.py`,
`scripts/universal_audit.py`, `scripts/vuln_intel.py`,
`scripts/mcp_server.py` (11 tools), `scripts/framework_metadata.json`
(48,061 controls / 336 families), `scripts/framework_mappings.json`,
`scripts/document_catalog.db`, `scripts/vector_index.db` (gitignored, ~450MB),
`.claude/skills/auditforge/SKILL.md`.

## 2. How AuditForge's audit is set up today

Three layers, all deterministic, no agentic validation loop:

1. **Native regex scanner** — `audit_repo.py` → `auditor.audit_directory()`
   (`scripts/auditor/__init__.py:28`). 24 rule IDs (SEC001–009, IAM001,
   ENC001–002, NET001–004, SDLC001–005, PII001, CFG001, LOG001) with SOC 2
   controls on the `Rule` (`models.py:6`), extended to NIST/HIPAA/MITRE/OWASP
   citations at report time via `reporting.rule_frameworks()` +
   `framework_mappings.json` (R-037). Outputs: text/JSON/SARIF/markdown,
   `--fail-on` CI gate, `--baseline` diffing, `--history` git-secret scan,
   `.soc2rc.yml` per-repo config, git-aware remediation
   (`Finding.effective_remediation`, `models.py:54`), test-context downgrades.
2. **External-engine orchestrator** — `universal_audit.py` →
   `UniversalAuditor` (`orchestrator.py:9`): Checkov, Semgrep
   (`p/security-audit`, `p/secrets`, `p/default`), Trivy, OSV (workspace-wide,
   6 ecosystems), `cargo-audit` (RUSTSEC), TruffleHog (verified secrets only),
   OpenSSF Scorecard, Nuclei, bounded GET-only DAST + SPF/DKIM/DMARC, read-only
   cloud posture, SBOM/license. `engine_availability()` reports what actually
   ran. Every engine output mapped through `framework_mappings.json`.
3. **Knowledge + intel + agentic access** — `framework_metadata.json`
   (regenerate via `sync_frameworks.py`, never hand-edit), `document_catalog.db`
   (license-gated caching), `vector_index.db` (sqlite-vec + FTS5 hybrid R-106),
   `vuln_intel.py` (CISA KEV / EPSS / NVD, TTL-cached — answers "is it being
   exploited", which OSV alone doesn't), `mcp_server.py` (11 tools:
   `search_controls`, `get_control`, `list_frameworks`, `crosswalk_rule`,
   `crosswalk_control`, `search_documents`, `get_document`, `run_audit`,
   `kev_lookup`, `epss_lookup`, `nvd_lookup`), `.claude/skills/auditforge/`
   (same capability with CLI fallbacks for sessions without MCP).

What this setup lacks is everything in §3: no coverage model ("what didn't we
look at" is unanswerable), no finding lifecycle (flat list, implicit
"confirmed", no blocked-lead state), no adversarial review (the finder grades
its own homework), no resumability (a crashed run restarts from zero), no
cost/coverage instrumentation.

## 3. How the Cloudflare skill works (the parts worth stealing)

Six phases, two modes. **Guidance mode** (default: answer questions, no files)
vs **full audit mode** (all six phases, artifacts under
`~/security-audit-skill/<repo>/run-<N>/`, outside the target). Key mechanisms:

- **Phase 1 recon → coverage ledger.** Four parallel `research` agents
  (product/stack, principals/authority, entry-surfaces/sinks,
  execution/deployment visibility), then the parent synthesizes
  `architecture.md` (hard ≤1000-word cap) and seeds `coverage-ledger.json`:
  one unit per (entry surface x trust boundary x subsystem x attack class),
  with stable `coverage_id`s (RFC 3986-encoded canonical refs joined by `::`,
  lexicographically sorted, duplicates fail). Statuses: `planned /
  in_progress / covered / candidate / blocked / deferred / out_of_scope /
  not_applicable`. Coverage critics re-scan for gaps after every hunter wave;
  unassigned units are explicitly `deferred` with a reason — never silently
  dropped.
- **Adversarial validation (Phases 3 + 5).** The hunter never validates its own
  candidate: a fresh `general` verifier tries to *refute* it (Phase 3), then a
  second fresh `research` verifier re-checks the final record (Phase 5).
  Material replacements (promotion to `confirmed`, changed root cause/trace/
  impact/severity) go to yet another independent verifier. Malformed verifier
  output is discarded unrepaired; budget shortfall flips `run_status` to
  `incomplete` with an exact reason rather than silently thinning evidence.
- **Verdict discipline via schema.** `confirmed` (full trace + bounded observed
  result + severity + PoC-grade `execution` + `remediation`), `needs_validation`
  (exact blocker + `validation_plan.local`/`deployment`, **no severity**),
  `rejected` (disproof retained so future runs don't repeat it). Severity
  anchors are behavior-based (critical = unauth code exec / full data-store
  takeovers); `overall <= impact`. Both validators run after Phase 4 *and*
  after every Phase-5 replacement.
- **Threat-model-first filing.** Every candidate names lower-trust principal,
  accepted input, control, crossed boundary, affected principal/resource, and
  concrete observed result. Confirmed findings ship a PoC test against the
  *untouched* codebase (no source edits to make exploits land) plus a proposed
  patch — the harness blog's words: what reaches review is "a verified bug, a
  working test, and a functional git diff."
- **Execution safety as spec, not vibes.** OS sandbox (no net, allowlisted env,
  read-only target/toolchain, scratch-only writes, CPU/mem/wall-clock caps),
  dummy principals/fixtures/secrets, no live probing, and an 11-step
  trusted-parent artifact-promotion procedure injected verbatim into every
  hunter/verifier prompt. Missing controls means don't execute; record
  `needs_validation`.
- **Additive runs.** Prior ledgers/findings are read before planning, with a
  `prior_status` taxonomy (`prior_confirmed_same_source`,
  `prior_confirmed_changed_source`, `prior_needs_validation`, ...). Unchanged
  confirmations are carried (re-verified, hunters exclude only that root cause);
  changed-source units become revalidation work; `rejected` suppresses only the
  failed claim, never its unit's coverage.
- **Budget as a coverage instrument.** `budget` (max agent invocations) in
  `run-metadata.json`; strict gate reserves recon + critics + validation
  *before* hunting; hunters assigned in priority order (unauth surfaces first,
  highest-value boundaries next); overruns mark units `deferred`, never thin
  silently. Quick/standard/deep profiles change breadth, never the evidence bar.

The fleet harness blog adds what the single-repo skill can't: **VDH stages**
(Gapfill critics, Dedup agents, cross-repo Trace via dependency graph, Feedback
prompt-rewriting, Report-as-script), **SQLite persistence keyed by (`run_id`,
`repo`, `stage`)** so any stage resumes without redoing work, **two-model
cross-checking** (different model validates than hunts), **deterministic-then-
agent dedup** (inverted index over files/functions/boundaries/rare tokens gives
a short candidate list, agent adjudicates; 5,442 of 13,841 folded as dupes),
**VVS contextual judgment** (reachable *in prod*? wrong repo? latent?) on a
different model, **Fixer with fail-to-pass gate** (human merges, never the
model), **shallow-hunter detection** (zero findings means requeue), and honesty
about metrics (no recall claims; track validation survival 20,799 to 12,057 to
7,245 actionable, coverage-cell growth on held-out repos). Two hard-won
lessons: (a) *don't wire static analysis into hunters* — their Semgrep
integration got zero invocations in a month (agents read and run code instead);
the Wishlist was the most-used tool. (b) *persistence before parallelism* —
stream findings as they happen; classify response text, not just exception
types.

## 4. What they do better — adopted, adapted, or deliberately skipped

| # | Idea | Verdict for AuditForge | Why |
| --- | --- | --- | --- |
| 1 | Adversarial validation (finder is never the checker, Phase 3 + Phase 5) | **Adopt** — core of the new skill | Our pipeline has no LLM review step at all; deterministic tools over-report by design (e.g. SDLC004 is deliberately LOW "flag for review"). A refute-first verifier pass is the highest-value addition. |
| 2 | Coverage ledger (planned/covered/deferred/out_of_scope, critics, gapfill) | **Adopt (light)** — ledger schema + critics in skill; SQLite persistence deferred | "Scanned clean" currently can't distinguish "looked, nothing there" from "never looked". R-013's skip-count transparency was the same instinct at file level. Full Gapfill loop is overkill for single-repo runs — keep the ledger + critic wave. |
| 3 | confirmed / needs_validation / rejected + schema validators | **Adopt** — `scripts/report-schema.json` vendored (MIT, attributed), `scripts/validate_findings.py` + `scripts/validate_coverage_ledger.py` stdlib ports (no Node dep) | Our findings are flat and implicitly "confirmed". The `needs_validation` state (exact blocker + local/deployment plan, no severity) is the honest home for today's ambiguous hits. Ports keep the repo's zero-dependency scanner philosophy — their `.cjs` files would add a Node requirement. |
| 4 | Threat-model-first filing + PoC-against-untouched-code + patch-per-finding | **Adopt bar, adapt form** — required fields in skill; PoC required only for high/critical `confirmed` | Full PoC-per-finding is fleet-harness economics; for us, requiring boundary+principal+observed-result kills the same vacuous-findings class at near-zero cost. |
| 5 | Sandbox + promotion spec for target-controlled execution | **Adopt as policy text** in skill | Our `universal_audit.py` *runs* Nuclei/DAST/cloud polling — live traffic by design, with placeholder-target guards and GET-only bounds. The skill's explicit boundary (dummy principals, no live probing without owner approval, sandbox-or-`needs_validation`) is stricter and should govern agentic use of those engines. |
| 6 | Additive runs with `prior_status` taxonomy | **Adopt (light)** — carry rules in skill reusing `--baseline` + stable fingerprints | `Finding.fingerprint` (`models.py:48`, sha1 of rule+file+snippet) already gives stable re-find keys; what's missing is the *state machine* (carried / revalidation / suppressed-claim). No new infra needed. |
| 7 | Dedup: deterministic shortlist then agent adjudication, stable cross-run keys | **Adopt direction** — shortlist procedure in skill; root-cause clustering is future work | Our fingerprint dedups identical re-finds only; two rules firing on one root cause (e.g. SEC001 + TRUFFLEHOG_VERIFIED_SECRET) stay separate. Inverted-index shortlisting is implementable over `to_dict()` output today. |
| 8 | Budget gate + profiles (quick/standard/deep) + shallow-run detection | **Adopt (light)** — profiles + reserve-critics-first rule in skill | Directly prevents the failure mode "one big agent reads everything, compacts context, reports vibes". Shallow-hunter requeue is cheap to add to any multi-agent run. |
| 9 | Report derived from records; `incomplete` runs declare themselves | **Adopt** — Phase-6 rule in skill | Our `--markdown`/SARIF serialize whatever was found with no run-status concept. A `run_status: complete\|incomplete + reason` header is a one-field fix with real honesty value. |
| 10 | VVS contextual judgment (prod-reachability on a different model) | **Adapt** — KEV/EPSS already answer "exploited in the wild" for *deps*; skill adds a reachability check for *first-party* findings via deploy/config context | Don't build a second pipeline; fold the question ("is this path reachable in prod?") into Phase-5 verification using `search_documents`/`get_document` + repo config. |
| 11 | Static analysis as agent-reachable tooling | **Deliberately skip** — keep machines and agents separated | Their own data: hunters invoked Semgrep zero times in a month. Our design already does the right thing: `run_audit` MCP tool + Phase-0 deterministic sweep feed *candidates in*, agents don't invoke scanners mid-hunt. |
| 12 | Fleet cross-repo Trace + Feedback prompt-rewriting | **Skip** — no fleet, no 128-repo corpus | Revisit if AuditForge ever scans more than one repo per run. The Trace idea's single-repo cousin (dependency-graph walk for OSV findings) already exists via OSV + SBOM. |

## 5. What AuditForge keeps (their skill has none of this)

- **48,061 controls / 336 families with semantic + exact search** (`search_controls`
  hybrid R-106, `crosswalk_rule` exact hand-mappings vs `crosswalk_control`
  semantic hints) — every `confirmed` finding in the new skill gets a compliance
  citation (SOC 2 + NIST + mapping row), which their schema can't express.
- **Zero-dependency native scanner as CI gate** (`--fail-on HIGH`, SARIF,
  `--history`, `.soc2rc.yml`, git-aware remediation) — their pipeline has no
  deterministic pre-pass and no CI story.
- **12-engine orchestrator + KEV/EPSS/NVD prioritization** — answers "should I
  fix this *now*", which severity anchors alone don't.
- **License-gated document catalog** (`public_domain`/`free_to_access` only) —
  their agents read target source only; compliance provenance needs the catalog.
- **MCP server + CLI-fallback skill** — works with or without tool wiring;
  their skill assumes sub-agent orchestration exists.

## 6. Landscape notes (Oct-Nov 2026)

- **Trail of Bits `trailofbits/skills`** (39 plugins, CodeQL + Semgrep + SARIF
  parsing, `semgrep-rule-creator`): the deterministic-tooling complement. If we
  ever want agent-driven custom Semgrep rules per CWE, that's the upstream to
  vendor — but per section 4 row 11, keep it as a machine stage, not hunter
  tooling.
- **`solanabr/auditor-skill` pattern**: vendor upstream skill at a pinned commit
  + reconcile a delegation map on each bump. That's exactly what `resources/`
  + this doc do for Cloudflare's skill; adopt the same pin-and-reconcile habit
  for Trail of Bits if we vendor it later.
- **Comparison coverage** (7-tool roundups: Claude/Codex Security, CodeQL+
  Autofix, `/security-review`, Cloudflare skill) consistently ranks the
  Cloudflare skill as the start-from-your-own-agent option — i.e. the same
  niche our integrated skill targets, now with compliance citations attached.
- **Microsoft MDASH** (multi-model agentic scanning): independent confirmation
  that discovery-model is not validation-model (section 3) is becoming industry
  standard practice, not Cloudflare idiosyncrasy — another vote for section 4
  row 1.

## 7. Integration built from this review

- `.claude/skills/security-audit/SKILL.md` — AuditForge-hardened port: same two
  modes and six phases, plus a **Phase 0 deterministic sweep** (`audit_repo.py`
  + OSV/cargo-audit + KEV/EPSS enrich + `crosswalk_rule`) that seeds the ledger
  and candidate set, compliance citation per `confirmed` finding, `reports/`
  output convention, Python validators (no Node), single-agent fallback.
- `scripts/report-schema.json` — vendored from the MIT upstream (attribution in
  `SKILL.md` + validator docstrings); do not hand-edit, re-vendor on bump.
- `scripts/validate_findings.py`, `scripts/validate_coverage_ledger.py` —
  stdlib-only ports of `validate-findings.cjs` (711 lines) /
  `validate-coverage-ledger.cjs` (800 lines): same CLI
  (`<script> <file.json>`), same core contracts (size/count/depth caps,
  verdict branches, `additionalProperties` rejection, fingerprint shape,
  severity `overall <= impact`, coverage_id canonical encoding + uniqueness).
- `scripts/test_validate_audit_skill.py` — pytest coverage for both ports.
- Deferred (not built): SQLite run ledger (`run_id`, `repo`, `stage`) a la VDH
  persistence; deterministic dedup shortlister over `to_dict()` output;
  `run_status` header in `reporting.py` output. Candidates for ROADMAP entries.
