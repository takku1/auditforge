# Field Test Report — AuditForge against RoninAI

**Date:** 2026-08-25
**Target:** `Z:\roninai` (pnpm monorepo: NestJS API, Next.js web, Go agent, FastAPI ai-engine, infra/compose)
**Scanner:** `scripts/audit_repo.py` static rules only (Checkov/Semgrep/Trivy/OSV/DAST not enabled)
**Outcome:** 2628 findings → **0** in project-owned code; vendored clones out of scope by design

---

## 1. Executive Summary

A real-world pass over an active monorepo validated the core engine (regex rules,
suppression token, test-context downgrade, SARIF/markdown output, baselines) and
surfaced **11 gaps**, three of which let genuine risk-shaped content through the
cracks during the test itself. Every gap below has a concrete observed failure
from this run — none are speculative. Section 5 proposes the backlog; register
in `ROADMAP.md`.

## 2. Run Statistics

| Metric | Value |
| --- | --- |
| Initial full-repo findings | 2628 (C:23 / H:224 / M:2369 / L:12) |
| Findings in vendored `resources/` clones | ~2610 (upstream code, correctly excluded from fixing) |
| Actionable project-code findings | 18 (C:2 / H:9 / M:6 / L:1) |
| Fixed properly (eliminated/env-var/refactor) | 14 |
| Suppressed with documented `soc2-ignore` | 4 |
| Residuals requiring structural change | 1 (local PEM → relocated out of tree) |
| Final scan | **0 findings** across ~718 files |

Noise ratio was healthy: the top-of-report signal (own-code CRITICALs) was
immediately actionable; the bulk was vendored third-party code.

## 3. What Worked Well

- Same-line `soc2-ignore` suppression with mandatory justification — clean triage story.
- Test/example-context downgrade kept fixture noise out of the critical path.
- Placeholder filtering (PLACEHOLDER_RE) correctly cleared most benign literals.
- Multi-format output + baseline/fail-on flags make CI gating straightforward.
- Rule-to-SOC2-control tagging made remediation reporting trivial to write up.

## 4. Gaps Observed (evidence-driven)

### G1. Credentialed connection strings are invisible  *(highest value)*
**Observed:** `postgresql://ronin:ronin_dev_password@localhost:5432/…` in
`.env.example` and compose files passed every rule. SEC001 matches keyword
assignments (`password=`, `api_key=`) but not `scheme://user:pass@host` shapes,
and `DATABASE_URL`/`REDIS_URL`/`CONN_STR` aren't in its keyword list.
**Risk class:** live-shaped credentials in tracked config.

### G2. No git-tracked vs untracked distinction
**Observed:** a local-only, never-committed LAN key (`ronin-lan.key`) reported as
CRITICAL with "remove from repository and rotate" — remediation text that doesn't
apply to an untracked artifact, while a *tracked* key would deserve identical
severity. The scanner can't tell the two apart, so triage guidance is wrong in
both directions.

### G3. No history scanning
**Observed:** nothing scans `git log -p`. A secret deleted from HEAD but alive
in past commits is fully invisible. (RoninAI's cert was verified manually via
`git log` — the tool should do this.)

### G4. OSV dependency scan is root-manifest-only
**Observed:** monorepo `services/*/package.json`, workspace locks, and
per-service Python requirements went unscanned; only root-level manifests are read.

### G5. PII001 forces obfuscation workarounds
**Observed:** any email anywhere = HIGH. Fixers resorted to `dev@localhost`,
`s3cret!@cache.example` string-shaping, and suppressions where RFC 2606
reserved TLDs (`.test`, `.example`, `.localhost`, `.invalid`) deserve built-in
exemption. The rule trains users to game it.

### G6. SDLC001 flags language stdlib patterns
**Observed:** `RegExp.prototype.exec(...)` in TSX flagged HIGH. Regex-only
matching cannot distinguish `eval/exec` from receiver calls; either add
receiver-shape filtering or delegate JS/TS to Semgrep AST mode.

### G7. NET004 doesn't know non-routable pseudo-hosts
**Observed:** `http://unigetui.ipc` (named-pipe IPC) needed manual suppression;
same reserved-suffix logic as G5 applies (`.ipc`, `.internal`, `.local`, `.test`).

### G8. Missing modern secret formats
**Observed:** no coverage for OpenAI `sk-proj-…`/`sk-svcacct-…`, Anthropic
`sk-ant-…`, raw JWT literals (`eyJ…` with two dots), or entropy scoring for
high-randomness strings outside assignment shape.

### G9. No Docker/compose-native checks
**Observed:** nothing catches privileged containers, `/var/run/docker.sock`
mounts, `image: :latest` pinning, or root-user containers without Checkov installed.

### G10. No per-repo configuration file
**Observed:** every invocation needs rediscovered CLI incantations
(`--exclude "resources/*"`); no `.soc2rc.yml` for excludes/severity/rule toggles.

### G11. Silent skips
**Observed:** >1.5 MB files and binary-detection skips happen with zero
reporting — a blind spot nobody can see in the output.

## 5. Proposed Backlog (register in ROADMAP.md)

| ID | Item | Fixes | Effort | Priority |
| --- | --- | --- | --- | --- |
| R-008 | New rule SEC008 "Credentialed Connection String": `\w+://[^/\s:@]+:([^/\s@]{4,})@` with placeholder filtering; exempt localhost creds to LOW | G1 | S | P1 |
| R-009 | Git integration: detect repo via `git rev-parse`; annotate findings tracked/untracked; vary remediation text; `--untracked-as-info` flag | G2 | M | P1 |
| R-010 | Workspace-aware OSV: walk `**/package.json`, `**/requirements.txt` honoring SKIP_DIRS/excludes | G4 | S | P1 |
| R-011 | PII001/NET004 reserved-suffix exemptions: `.test .example .localhost .invalid .local .ipc .internal` | G5, G7 | S | P1 |
| R-012 | New rules SEC009 (OpenAI/Anthropic/JWT token shapes) + optional `--entropy` heuristic | G8 | S | P2 |
| R-013 | History scan module (`--history`): regex pass over `git log -p --all`, reuse existing rules | G3 | M | P2 |
| R-014 | `.soc2rc.yml` discovery (excludes, min-severity, rule toggles) + docs | G10 | M | P2 |
| R-015 | SDLC001 receiver-shape filter (skip `x.exec(`/`y.eval(` when receiver is a compiled-regex variable in JS/TS) or document Semgrep delegation | G6 | S | P2 |
| R-016 | Lightweight compose/Dockerfile checks (docker.sock mount, privileged, :latest → LOW/MEDIUM) | G9 | M | P3 |
| R-017 | Skip-transparency summary line ("skipped N binary, M oversized") + `--list-skips` | G11 | S | P3 |
| R-018 | Ship pre-commit hook + GitHub Actions workflow template (`--fail-on HIGH --baseline`) | ops | S | P3 |

### Process lesson (not a tool change)
During remediation, one occurrence of a flagged URL was fixed while a sibling in
the same file survived and surfaced on re-audit. The scanner behaved correctly
(each occurrence reports independently); fix discipline must be
"resolve every occurrence per file", and re-running the audit before declaring
done is what caught it.

## 6. Recommended CI Gate (works today)

```
python scripts/audit_repo.py <repo> \
  --exclude "resources/*" --exclude "node_modules/*" \
  --min-severity LOW --fail-on HIGH --sarif audit.sarif
```

## 7. Non-Goals

- Rewriting the regex engine as AST-first: Semgrep integration already provides
  the escape hatch; built-in rules should stay dependency-free.
- Scanning vendored clones: ownership stays upstream; exclusions belong in the
  consuming repo's config (R-014).
