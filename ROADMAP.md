# ROADMAP

Sole incomplete-work registry for AuditForge.

## Ready

| ID | Item | Notes |
| --- | --- | --- |
| R-007 | Contract the audit-engine surface (`universal_audit.py`, `auditor/` package, its test seams) via `recurspec reconcile plan` into a sibling subtree | closes the 4 `structure.public.uncontracted` findings; engine was declared out of scope for the current tree |
| R-008 | SEC008 credentialed-connection-string rule (`scheme://user:pass@host`) | evidence: roninai `.env.example` postgres creds passed clean; see docs/field-test-roninai-2026-08-25.md §G1 |
| R-009 | Git awareness: annotate findings tracked vs untracked, vary remediation | roninai local PEM got rotate-now advice despite never being committed; §G2 |
| R-010 | Workspace-aware OSV scan (`**/package.json`, `**/requirements.txt`) | monorepo services unscanned today; §G4 |
| R-011 | PII001/NET004 reserved-suffix exemptions (`.test .example .localhost .invalid .local .ipc .internal`) | forced obfuscation workarounds during roninai fixes; §G5/G7 |
| R-012 | Modern secret shapes (OpenAI/Anthropic/JWT) + optional `--entropy` heuristic | §G8 |
| R-013 | History scan via `git log -p --all` behind `--history` flag | deleted-from-HEAD secrets invisible today; §G3 |
| R-014 | `.soc2rc.yml` per-repo config discovery (excludes, min-severity, rule toggles) | every consumer rediscovers CLI incantations; §G10 |
| R-015 | SDLC001 receiver-shape filter or documented Semgrep delegation for JS/TS | flagged `RegExp.exec()` stdlib call; §G6 |
| R-016 | Lightweight compose/Dockerfile checks (docker.sock, privileged, :latest) | §G9 |
| R-017 | Skip transparency: report binary/oversized skip counts in output | silent >1.5MB skips today; §G11 |
| R-018 | Ship pre-commit hook + GitHub Actions gate template | operationalizes CC8.1 mandate; §5 |
| R-019 | Compiled-language danger-idiom rule family (Rust `unsafe`/`transmute`, raw pointer casts) or explicit non-goal note in CLAUDE.md | searchtool has 9 `unsafe` blocks, zero signal from the scanner; see docs/field-test-searchtool-2026-09-02.md §G12 |
| R-020 | New rule class for dynamic process/command construction (SDLC003), parallel to SDLC002's SQL-concat coverage, across Python/Go/Rust/Node `exec`/`Command`/`subprocess` shapes | searchtool has 5 files invoking `Command::new` incl. OS-level abilities (shutdown/restart/recycle-bin), no signal either way; §G13 |
| R-021 | `cargo audit` integration into `universal_audit.py` (`run_cargo_audit()`) + CLAUDE.md Dependency Vetting mandate updated to mention Rust alongside npm/pip-audit | had to run cargo audit entirely outside AuditForge this session; §G14 |
| R-022 | NET002 Rust/Go cert-bypass patterns (`danger_accept_invalid_certs`, `SslVerifyMode::NONE`, `InsecureSkipVerify`) | verified missing directly in rules.py; §G16 |
| R-023 | Warn/error when `--markdown`/`--sarif`/`--json` output path resolves inside the directory being scanned | caused a self-referential finding feedback loop this session; §G17 |
| R-024 | CLAUDE.md Review Loop: add a manual call-site check for any function gated by a `requires_confirmation`-shaped parameter, since no rule engine can verify cross-file authorization enforcement | searchtool's GUI bypasses its own skills-layer confirmation gate for `execute_system_ability`; §G15 (non-goal for the rule engine itself) |
| R-027 | Add HITRUST CSF, FFIEC (CAT), and SOC 1/SSAE 18 as tracked frameworks — no local KB references any of the three today; would need a new external source (none of the 15 cloned KBs, including the now-fully-parsed SCF crosswalk, contain them) | real blind spots vs. Drata/Vanta framework lists; docs/framework-coverage-audit-2026-09-02.md §4 |
| R-030 | (low priority) Wire `attack-stix-data/ics-attack` and `/mobile-attack` into `sync_frameworks.py::_parse_attack` (Enterprise is now fully parsed - R-026) | minor given project's web/cloud/SDLC focus; §5 |

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
| R-029 | Removed `Anthropic-Cybersecurity-Skills` (unofficial third-party repo, not in CLAUDE.md's workspace layout) from `update_sources.ps1`, `.gitignore`, `checks.ps1`; ran full source sync (15 KBs cloned, `framework_metadata.json` regenerated to 2075 controls / 11 families) | docs/framework-coverage-audit-2026-09-02.md §0 |
| R-025 | Wired CIS / STIG / Essential Eight / BSI / ANSSI / CCN / ISM / SRG / NIST product overlays into `sync_frameworks.py` via `_parse_cac_controls_dir()` - auto-discovers all `compliance-as-code/controls/*.yml` (single-file and split-directory layouts), 47 framework families | sync run: "47 framework families parsed"; docs/framework-coverage-audit-2026-09-02.md §2 |
| R-026 | Wired the SCF crosswalk workbook into `sync_frameworks.py` via `_parse_scf_crosswalk()` (openpyxl; added to requirements.txt) - 248 focal-document frameworks now queryable (ISO 27001/27002/27017/27018/27701/42001, GDPR, DORA, NIS2, EU AI Act, CMMC 2.0, FedRAMP R5, TISAX, UK Cyber Essentials, SOX, GLBA, NYDFS 500, LGPD, PIPEDA, CJIS, FERPA, COBIT, CSA CCM, Australia Essential Eight, +230 more), each keyed by SCF control ID → that framework's mapped clause(s) | sync run: "248 focal-document frameworks parsed... 30577 SCF-control-to-clause mappings"; §3 |
| R-031 | Wired MITRE ATT&CK Enterprise from a presence-flag into a real per-technique parse (`_parse_attack()`, STIX 2.1 bundle) - 697 techniques indexed by ATT&CK ID | sync run: "697 techniques indexed" |
| R-032 | Fixed `_parse_asvs()`: OWASP ASVS 5.0.0's JSON export changed schema (`Requirements` root + `Description` on leaf nodes, not the old `chapters`/`Name` shape the parser expected) - was silently indexing 0 ASVS controls despite the family showing as "found" | 0 → 442 ASVS controls after fix |
| R-033 | Added `openpyxl` and `pytest` to `requirements.txt` (real undeclared deps: xlsx crosswalk parsing, `test_build_rulepack.py`) | workspace-hygiene `checks.ps1` PASS (was failing on 3 MISS-requirement lines) |
