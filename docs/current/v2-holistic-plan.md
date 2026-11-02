# AuditForge v2: the holistic assurance tool

Goal: one skill that takes a target and returns a verified, compliance-cited,
coverage-honest security verdict — deterministic engines for breadth,
adversarial agents for depth, sandboxed execution for proof. Cloudflare's
methodology ported onto AuditForge's intelligence base (see
`security-audit-skill-review.md` §4 for the per-idea adopt/adapt/skip log).

## What "holistic" covers (one workflow, modes select depth)

1. **Compliance audit** — control citations per finding (SOC 2 + NIST +
   OWASP/ASVS + MITRE via `crosswalk_rule`), evidence docs, gap actions.
2. **Hygiene sweep** — secrets, IAM, TLS, SDLC, PII (Phase 0, always first).
3. **Coverage-led hunting** — ledger units, critics, budget profiles.
4. **Adversarial verification** — finder ≠ checker, verdict discipline.
5. **Sandboxed proof** — PoC in Docker `--network none`, or honest
   `needs_validation`.
6. **Intel prioritization** — KEV/EPSS for deps, reachability check for
   first-party paths.
7. **Honest reporting** — records-first derived reports, declared
   run_status.
8. **Remediation advice** — PoC test + proposed diff; human merges.
9. **Freshness** — KB + engine update pipeline keeps results current.
10. **Must-build gaps** — domain profiles say what's missing, not just
    what's broken.

Non-goals (stay out): auto-applied patches, live probing without owner
approval, fleet/cross-repo trace, recall claims without ground truth.

## Architecture map (v2 additions in the engine tree)

| Module | Owns | Status |
| --- | --- | --- |
| auditor-core | detection engines, findings, reports | built, field-tested |
| framework-sync | control/document derivation | built |
| agentic-layer | MCP, vector index, vuln intel | built |
| verification-lifecycle | verdicts, adversarial review, PoC sandbox | planned |
| coverage-hunting | ledger, critics, budget, additive runs | planned |
| holistic-skill | the one skill + run convention + plugin commands | partially built |

Full contracts: `docs/architecture-engine/modules/*/SYSTEM.md` (L0:
`docs/architecture-engine/SYSTEM.md`, ADR-201/202).

## Migration (behavior-preserving, in order, each with its gate)

1. **Verdict wiring** — ledger statuses learn confirmed/needs_validation/
   rejected; validators gate run artifacts. Gate: validator exit 0 +
   pytest.
2. **Ledger-driven hunting** — per-run coverage ledger + critic wave +
   budget profiles in the skill (prose first, SQLite later). Gate:
   juice-shop trial run, ledger fully terminal, validator-clean.
3. **Sandbox boundary** — Docker `--network none` PoC runner;
   no-backend → needs_validation. Gate: refusal test + one sandboxed PoC
   end-to-end.
4. **Skill merge** — attack packs + phases fold into `auditforge`;
   `security-audit` becomes an alias; plugin resync + revalidate. Gate:
   `muse skills validate` + `muse plugins validate`.
5. **Benchmark scorecard** — OWASP Benchmark Youden's J for the SAST
   lane (static ceiling ≈ 0.39 is calibration, not a bar); juice-shop
   head-to-head protocol (precision/recall/FP/runtime, ground-truth
   honesty). Gate: published scorecard in `reports/`, warts included.
6. **Union reporting** — exploit-path × control-coverage union view;
   `run_status` header in markdown/SARIF output. Gate: self-audit HIGH 0
   + full suite green, as always.

## Open decisions (carried, not new)

- Marketplace repo location/name (from tooling-direction §5).
- `/audit` default engine set (same source).
- SQLite run persistence now vs after the first crashed long run
  (coverage-hunting contract).
- Linux sandbox ladder order (verification-lifecycle contract).
- Single-agent fallback `complete` bar (holistic-skill contract).
