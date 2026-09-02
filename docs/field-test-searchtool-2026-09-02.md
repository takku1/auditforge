# Field Test Report — AuditForge against searchtool (Kumo)

**Date:** 2026-09-02
**Target:** `Z:\searchtool` (Rust workspace: resolver crates, egui/eframe GUI, tantivy
fulltext index, candle-based local LLM, OS-level action registry)
**Scanner:** `scripts/audit_repo.py` static rules only (Checkov/Semgrep/Trivy not
installed on this host); `cargo audit` run manually, outside AuditForge
**Outcome:** 879 findings → **0** in project-owned code; vendored `resources/*`
clones (gitignored reference material) correctly out of scope by design

This is AuditForge's first field test against a Rust-primary target (roninai,
2026-08-25, was TS/JS/Go/Python + compose). Every gap below was directly
observed or directly verified in `rules.py` during this run — none are
speculative, per the standard set in the roninai report.

---

## 1. Executive Summary

The core engine held up: excludes, extension filtering, and the vendored-clone
boundary all worked correctly, and the 0-finding result on project code is a
true negative, not a false negative from a config error (spot-checked with
`--json` and by confirming `.rs` is in `CODE_EXTENSIONS`). But this run surfaced
that **every rule in the ruleset is keyword-shaped for Python/JS/IaC idioms**;
none has a Rust-shaped (or Go-shaped, for that matter) counterpart pattern.
It also surfaced a gap class the roninai run didn't hit: **cross-file
authorization consistency**, which no regex engine can ever check, found by
manually reading a real inconsistency in searchtool's own code.

## 2. Run Statistics

| Metric | Value |
| --- | --- |
| Initial full-repo findings (incl. `resources/`, `external/`) | 879 (C:19 / H:272 / M:572 / L:16) |
| Findings in vendored `resources/*` clones | 879 — all of them (gitignored reference material, not shipped code) |
| Actionable project-code findings | **0** (across 120 files: `resolver/`, `docs/`, root config) |
| `cargo audit` (RustSec, 745 crates, run outside AuditForge) | 0 vulnerabilities; 3 unmaintained/unsound advisory warnings, all upstream-blocked |

## 3. What Worked Well

- `resources/*` vendored-clone exclusion behaved identically to roninai's
  `node_modules`-shaped noise: 100% of unfiltered findings were third-party.
- `.rs` is already in `CODE_EXTENSIONS` — Rust files were genuinely scanned,
  not silently skipped (verified by reading `rules.py` directly, not assumed).
- JSON/markdown output made it easy to hand a clean scoped result to the user
  without re-deriving anything.

## 4. Gaps Observed (evidence-driven)

### G12. No rule class for compiled-language danger idioms
**Observed:** SDLC001 only matches the literal tokens `eval(` / `exec(`, which
don't exist in Rust. The actual Rust-shaped risk surface — `unsafe` blocks,
raw pointer deref, `std::mem::transmute` — has no corresponding rule and isn't
even summarized as a count in the report.
**Evidence:** searchtool has 9 `unsafe` blocks (`resolver/gui/src/main.rs`,
`resolver/native-capabilities/src/lib.rs`, `resolver/object-index/semantic/src/lib.rs`).
Zero findings, zero mention, anywhere in the output.

### G13. No rule class for dynamic process/command construction
**Observed:** SDLC002 (SQL-via-concatenation) has no sibling for the
equally classic injection class — building a shell/process invocation from
dynamic input (`subprocess.call(x, shell=True)`, Go `exec.Command(userInput)`,
Rust `Command::new(x).arg(dynamic)`). No rule fires on any of these shapes in
any language.
**Evidence:** searchtool has 5 files invoking `Command::new`/`.arg`/`.args`
(`action-registry`, `agent-escalation-seam`, `cli`, `gui`, `skills`), including
OS-level abilities — lock, sleep, restart, shutdown, empty recycle bin. Every
argument had to be read by hand to confirm none were built from untrusted
input; the scanner produced no signal either way.

### G14. No native Rust dependency-vulnerability scanning
**Observed:** AuditForge's own CLAUDE.md "Dependency Vetting" mandate names
`npm audit`/`pip-audit` only. `universal_audit.py`'s `run_dependency_audit()`
has no cargo path, and `audit_repo.py` doesn't touch `Cargo.lock` at all (it's
in `SKIP_FILES` by design, same as other lockfiles).
**Evidence:** getting RustSec advisory coverage for searchtool's 745-crate
graph required installing `cargo audit` and running it entirely outside
AuditForge's workflow this session.

### G15. No cross-file / call-graph authorization checks
**Observed:** rules operate per-line, per-file. They cannot verify that a
confirmation/authorization gate declared in one module is actually enforced
at every call site of the function it's meant to protect. This is expected
of a regex engine — flagging it because the miss was concrete, not because
it's a defect in the current design.
**Evidence:** searchtool's `resolver/skills` layer hard-enforces "a
destructive skill step must set `requires_confirmation`" (`skills/src/lib.rs:291`,
`anyhow::bail!` if not). But `resolver/gui/src/main.rs:616-621` calls the same
underlying `execute_system_ability()` (covers `shutdown`/`restart`/
`empty_recycle_bin`) directly, with no confirmation check, bypassing that gate
entirely. A regex/pattern scanner has no way to ever catch this class of bug.

### G16. NET002 has no Rust or Go cert-bypass patterns
**Observed (verified directly in `rules.py`, not run against a live hit):**
NET002's patterns are `verify=False`, `rejectUnauthorized:false`,
`disable_ssl_certificate_validation=True` — Python/JS only. There is no
pattern for Rust's `danger_accept_invalid_certs(true)` (reqwest) /
`SslVerifyMode::NONE` (native-tls, openssl-rs), or Go's
`InsecureSkipVerify: true` (relevant again given roninai's Go agent).
searchtool does not currently trip this rule either way — recorded as a
verified latent gap in the ruleset itself, not an observed false negative.

### G17. Self-referential scan corruption when output is written inside the scanned tree
**Observed:** running `--markdown out.md` with `out.md` located inside the
directory being scanned, then re-running the scan, causes the tool to pick up
its own previous report's findings (e.g. vendored PII hits quoted in the
report body) as new findings on the next pass — a feedback loop. Nothing in
`--help` or CLAUDE.md warns against this.
**Evidence:** hit this directly this session; recovered by deleting the
in-tree report and re-running with output redirected outside the target.

## 5. Proposed Backlog (registered in ROADMAP.md)

See ROADMAP.md R-019 through R-024.

## 6. Non-Goals

- **G15 (cross-file authorization consistency)** is not a rule-engine gap to
  close by regex — it needs call-graph/dataflow analysis, which is exactly
  what the existing Semgrep-delegation escape hatch is for (same position the
  roninai report took on SDLC001's receiver-shape problem). The actionable
  fix is process, not code: add a manual call-site check to the CLAUDE.md
  Review Loop for any function gated by a `requires_confirmation`-shaped
  parameter (R-024).
- Scanning vendored clones remains out of scope — ownership stays upstream.

## 7. Recommended CI Gate (works today, same as roninai's)

```
python scripts/audit_repo.py <repo> \
  --exclude "resources/*" --exclude "external/*" --exclude "target/*" \
  --min-severity LOW --fail-on HIGH --sarif audit.sarif
```

Plus, for Rust targets specifically, until R-021 lands: `cargo audit` as a
separate manual/CI step — AuditForge does not cover it yet.
