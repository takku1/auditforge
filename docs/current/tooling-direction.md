# Tooling direction: single tool vs multi-tool pipeline vs plugin

Verdict: **hybrid — all three, each doing what it's good at.** Keep the
single MCP server, expose the multi-tool pipeline *through* it, harden the
orchestrator, and wrap the whole thing as a distributable plugin. Details and
evidence below.

## 1. Current tooling set (observed, this repo)

- **Native scanner** (`scripts/audit_repo.py` + `auditor/`): 24 rule IDs,
  zero-dependency, `--fail-on` CI gate, SARIF/JSON/markdown, `--baseline`,
  `--history`, `.soc2rc.yml`, git-aware remediation. Fast, deterministic. Keep
  as-is; it is the Phase-0 pre-pass.
- **Orchestrator** (`scripts/universal_audit.py` + `auditor/orchestrator.py`
  + `auditor/scanners.py`): 12 engines (Checkov, Semgrep `p/security-audit` +
  `p/secrets` + `p/default`, Trivy `fs`, OSV ×6 ecosystems, cargo-audit/RUSTSEC,
  Nuclei, Scorecard, TruffleHog verified-only, SBOM/license, bounded GET-only
  DAST, SPF/DKIM/DMARC, read-only cloud posture). Gaps found by reading the
  code:
  - **Sequential**: `universal_audit.py:15-44` calls each `run_*` in order.
    No `concurrent`/`ThreadPool` anywhere in `scanners.py`.
  - **No timeouts on binary invocations**: `subprocess.run` without `timeout=`
    at `scanners.py:279` (checkov), `:339` (semgrep), `:379` (trivy),
    `:1682` (nuclei), `:1818` (scorecard), `:1996` (trufflehog). Only network
    paths and git history (`:147`, `timeout=300`) are bounded. A hung binary
    hangs the entire pipeline — graceful missing-binary skips
    (`engine_availability()`) cover absence, not hangs.
  - **No result caching**: identical re-runs re-execute everything (matters
    for agentic Phase-0 loops).
  - **No unified SARIF**: `reporting.py` has `to_sarif` (native-only) plus
    `to_universal_json/markdown` — the 12-engine output has no SARIF export.
- **Vuln intel** (`scripts/vuln_intel.py`): KEV 12h / EPSS 20h / NVD 7d TTLs +
  new `kev_catalog_ids()` for the freshness KEV-diff. Best-designed layer; keep.
- **MCP server** (`scripts/mcp_server.py`, registered in `.mcp.json`): single
  server, 11 tools. **`run_audit` is native-only** (spawns `audit_repo.py`
  with `timeout=120`); the 12-engine universal pipeline is **not tool-exposed**
  — agents can only reach it via shell. This is the single biggest access gap.
- **Skill** (`.claude/skills/auditforge/SKILL.md`): MCP-first with CLI
  fallbacks. Portable. Keep.
- **Freshness pipeline** (2026-11-02): `check_freshness.py` + manifest +
  weekly workflow. Keep; extend engine-update step per R-107.

## 2. What the landscape does (online research, Nov 2026)

- **Official plugin rule** ([code.claude.com/docs/en/plugins](https://code.claude.com/docs/en/plugins)):
  skills/MCP/commands work standalone; *"use a plugin when you want several
  skills, subagents, hooks, or MCP servers packaged as one unit... to give your
  setup to teammates, install it in many projects, or publish versioned
  releases."* Shape: `.claude-plugin/plugin.json` + `skills/` + `agents/` +
  `hooks/hooks.json` + `.mcp.json`, distributed via marketplaces
  (`/plugin install name@marketplace`).
- **Trail of Bits `static-analysis` plugin**: skills (codeql, semgrep,
  sarif-parsing) + slash-command workflows + scripts. Two design rules worth
  stealing: (a) *commands are generated in code* (`run-scans.sh`), so flags
  like `--metrics=off` and output-dir excludes are "properties of the code
  rather than instructions a model can drop"; (b) *no subagent runs any part
  of the scan* — the workflow calls the script, exit codes come from the
  processes. Hermetic tests.
- **`sast-mcp-server`** (MCP-registry-listed, FastMCP, 11 scanners incl.
  Semgrep/Trivy/OSV-Scanner/Checkov/Gitleaks/Grype/CodeQL/ZAP): single server,
  normalized `Finding` model, cross-scanner dedup, SARIF 2.1.0 export,
  closed-loop remediation (patch → re-scan → verify, auto-rollback). This is
  the existence proof that single-server multi-tool MCP works at our scale.
- **Mantis pattern** (per-scanner MCP servers, `available:false` degradation):
  works but multiplies install/config surface per tool. Our
  `engine_availability()` already achieves the degradation half without the
  multiplication.
- **Semgrep MCP folded into the `semgrep` binary** (standalone repo
  deprecated); third-party security MCPs are moving artifacts. Independent
  corroboration: ravenclaude `security-engineering` recommends
  *not bundling* third-party MCP servers. Our engines-as-local-binaries is
  the more stable integration shape — do not chase per-tool MCP servers.
- **IBM consulting MCP**: deterministic full-coverage wrapping of
  Semgrep/gitleaks/osv-scanner/Checkov/Trivy behind Streamable HTTP — same
  conclusion: orchestrate binaries behind *our* server, don't adopt theirs.

## 3. Recommendation

**Do not choose. Layer them:**

1. **Keep the single MCP server** — reject the per-tool split (Mantis). One
   server, engine-gated tools, `engine_availability` as the degradation
   story. No third-party MCP bundles (moving artifacts).
2. **Expose the pipeline through the server** — add `run_universal_audit`
   (engine allowlist, per-call timeout, target) and `engine_status` tools.
   Closes the agent-access gap; shell/CLI stays as fallback per the skill's
   existing philosophy.
3. **Ship a plugin wrapper for distribution** — `.claude-plugin/plugin.json`
   + skills (auditforge, security-audit) + commands (`/audit`, `/freshness`)
   + the MCP server as one installable unit, published via a marketplace.
   Additive: local `.mcp.json` flow keeps working. (OPEN: marketplace lives
   in a separate lightweight repo — KB clones must not ship as plugin weight.)
4. **Harden the orchestrator** (fault-containment + performance lenses):
   ThreadPoolExecutor across engines with per-engine timeouts (fixes the hang
   gap), mtime/lockfile-keyed result cache for agentic re-runs, unified SARIF
   across all engines (ToB `merge_sarif.py` precedent). Commands generated in
   code where models currently retype flags (ToB rule).
5. **Add engines selectively, not by bulk**: TLS/cipher audit (protocol-pillar
   gap) next; CodeQL by skill-reference only (build-system weight — ToB
   already packages it, link don't bundle); no Gitleaks (TruffleHog
   verified-only is the better default); Semgrep/Trivy/Nuclei refresh via
   R-107.
6. **Remediation stays out of the pipeline**: closed-loop patch→re-scan lives
   in the skill/R-108 layer with human merge (harness-blog gate), never as an
   engine side effect.

## 4. Tradeoffs sacrificed

- Per-tool MCP granularity (rejected: install friction, no new capability).
- Bulk scanner adoption à la sast-mcp's 11 (rejected: Bearer/njsscan/Bandit
  overlap Semgrep/Trivy coverage we already have; each new binary is update
  surface per R-107).
- Plugin-mandated distribution (rejected: local flow stays first-class; the
  plugin is for *other* repos/teammates, per the official rule).

## 5. Migration (behavior-preserving, in order)

1. Orchestrator: parallel + timeouts + cache (same CLI, same JSON shapes;
   new timeout tests + a hung-binary regression test).
2. MCP: two additive tools; no changes to existing 11.
3. Unified SARIF for universal output.
4. Plugin wrapper + marketplace repo; `/audit` + `/freshness` commands.
5. TLS/cipher engine; R-107 engine updates.

Validation for each: existing pytest suite, `audit_repo.py --fail-on HIGH`
self-scan, freshness gate, workspace-hygiene checks.

**Next step**: approve and I build it in that order (1–2 first: hung-engine
fix + `run_universal_audit` tool — the two highest-value, lowest-risk
changes). OPEN items needing your call: marketplace repo location/name, and
the `/audit` command's default engine set.
