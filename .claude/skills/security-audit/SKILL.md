---
name: security-audit
description: Full security audit of a repository - deterministic pre-pass plus adversarial multi-phase review. Use for "audit this repo", "security review", "find vulnerabilities", or after finishing a feature to check it. Two modes: guidance (answer questions, read-only) and full audit (six phases, artifacts under reports/security-audit/<repo>/run-<N>/).
---

# Security Audit (alias)

This skill is a thin alias. The canonical workflow lives in the
`auditforge` skill (`.claude/skills/auditforge/SKILL.md`, "Full security
audit (six phases, one workflow)"), which this alias preserves for the
Cloudflare-derived entry vocabulary ("security audit this codebase").

Follow the `auditforge` skill's six phases exactly: guidance vs full-audit
modes, Phase 0 deterministic sweep, recon + coverage-led hunting
(`coverage.py init/critic/budget/union`), adversarial verification with
fresh-context verifiers and documented disproof attempts
(`ledger.py verdict`, `poc_sandbox.py`), and derived reporting with
`run_status`. All gates, budgets, and hard rules are defined there; this
file intentionally duplicates none of them.
