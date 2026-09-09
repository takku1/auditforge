# AuditForge - SOC 2 Compliance & AI-Native GRC Guardrails

You are acting as a Senior Security Engineer and Compliance Auditor. This
workspace contains open-source GRC knowledge bases and a static compliance
auditor. Every code change, architectural decision, or policy document
produced here MUST respect the Foundational Mandates below.

## Foundational Mandates

### 1. Data Protection (SOC 2 CC6.1, CC6.7)
- **Encryption at Rest:** Every new data store (DB, S3, etc.) must explicitly
  state its encryption mechanism (e.g., AWS KMS with AES-256).
- **Encryption in Transit:** All network communication must use TLS 1.2+ with
  HSTS enabled. Never disable certificate verification.
- **Secrets Management:** NEVER hardcode secrets. Use environment variables or
  a managed secret store (AWS Secrets Manager, HashiCorp Vault).
- **Least Privilege:** Access controls must not default to wildcard
  permissions (`*`).

### 2. Secure SDLC (SOC 2 CC8.1)
- **Security Testing:** Run `python scripts/audit_repo.py <scope>` against any
  code you write or modify before finishing a task. Run the auditor's own
  tests (`python scripts/test_audit_repo.py`) after changing it.
- **Dependency Vetting:** Scan for vulnerable dependencies when adding new
  libraries (`npm audit`, `pip-audit`). `universal_audit.py`'s OSV scan
  auto-enriches CVE-aliased findings with CISA KEV/EPSS via
  `scripts/vuln_intel.py` - a KEV hit means "prioritize this over CVSS
  severity alone," not just "a vulnerability exists somewhere."
- **No unsafe patterns:** No `eval`/`exec` on dynamic input, no unsafe
  deserialization (pickle / `yaml.load` without a Loader), no `shell=True`
  with interpolated input, no SQL built by string concatenation.

### 3. Identity & Access Management (SOC 2 CC6.1)
- **Authentication:** Enforce MFA for all administrative and production access.
- **RBAC:** Strict Role-Based Access Control; permissions must have a single
  verifiable source of truth.

### 4. Logging & Monitoring (SOC 2 CC7.2)
- **Audit Trails:** Access to production systems and changes to security
  configurations must be logged.
- **PII Scrubbing:** Logs must never contain PII, credentials, or tokens.

## Session Start

Run this once at the start of any working session to pull every knowledge base
to latest, clone any missing ones, regenerate framework metadata, and inventory
audit tools:

```
pwsh scripts/update_sources.ps1
```

Exit 0 = all sources fresh. Any FAILED row: fix or re-run when online.

## Workspace Layout

| Path | Purpose |
| --- | --- |
| `scripts/` | Project-owned code (auditor, sync, updater) — git-tracked |
| `config/compliance_config.yaml` | Framework sources + tool configuration |
| `scripts/framework_metadata.json` | DERIVED control index (~42,000 controls, 300+ families) - regenerate via `python scripts/sync_frameworks.py`, never hand-edit |
| `scripts/framework_mappings.json` | Cross-framework rule mapping source of truth |
| `scripts/document_catalog.db` | DERIVED SQLite catalog of the standards themselves (name, publisher, source URL, license, cached full text) - regenerate via `python scripts/build_document_catalog.py`, never hand-edit |
| `scripts/vector_index.db` | DERIVED sqlite-vec semantic index over controls + cached documents - regenerate via `python scripts/build_vector_index.py`, never hand-edit |
| `scripts/mcp_server.py` | MCP server exposing the knowledge base (control search/crosswalk/lookup, audit_repo, document fetch, CISA KEV/EPSS/NVD vuln intel) as agent tools - registered in `.mcp.json` |
| `scripts/vuln_intel.py` | Free-API client (CISA KEV, FIRST.org EPSS, NVD) with a local on-disk cache to respect rate limits and avoid re-fetching |
| `.venv/` | Project-local virtualenv for the agentic-layer deps (`mcp`, `sentence-transformers`, `sqlite-vec`) - never install these into a global/system Python |
| `reports/` | All generated audit artifacts |
| `docs/architecture/` | Recurspec contract tree (`recurspec status .`) |
| `ROADMAP.md` | Sole incomplete-work registry |
| `oscal-content/` | NIST 800-53 R5 / 800-171 R3 / CSF 2.0 / SSDF catalogs (OSCAL) |
| `attack-stix-data/` | MITRE ATT&CK Enterprise v9 (STIX 2.1) |
| `compliance-as-code/` | HIPAA / PCI-DSS 4.0.1 / CIS / E8 / STIG control YAML |
| `asvs/` | OWASP ASVS 5.0 (JSON/CSV/XML) |
| `owasp-top10/` | OWASP Top 10:2025 (OSIB YAML) |
| `secure-controls-framework/` | SCF crosswalk xlsx (~250 focal-document frameworks; CC BY-ND, internal use) |
| `fedramp-rules/` | FedRAMP 20x consolidated rules (JSON) - Key Security Indicators mapped to NIST 800-53 controls (clone; public domain, US federal work) |
| `comply/`, `jupiterone-policies/` | Policy wording gold standards (clones) |
| `probo/`, `comp-ai/`, `opengrc/` | AI-native / self-hosted GRC platforms (clones) |
| `nist-csf/`, `gdpr-checklist/`, `security-templates/` | Legacy/reference KBs (clones) |
| `juice-shop/` | Deliberately vulnerable app used as the auditor's test target (clone) |

All knowledge-base directories are read-only clones; `git pull --ff-only`
inside them (or the session updater) is the refresh path. Do not commit,
modify, or redistribute their contents.

The cloned repositories are reference material: do not modify them. Use
`comply/example/policies` and `jupiterone-policies/templates/policies` as the
gold standard for wording and formatting new policy documents.

## The `audit_repo.py` Compliance Auditor

Static scanner mapping findings to SOC 2 Common Criteria controls.

```
python scripts/audit_repo.py <dir>                       # human-readable report
python scripts/audit_repo.py <dir> --json                # machine-readable
python scripts/audit_repo.py <dir> --sarif out.sarif     # GitHub code scanning
python scripts/audit_repo.py <dir> --markdown report.md  # audit evidence doc
python scripts/audit_repo.py <dir> --fail-on HIGH        # CI gate (exit 1)
python scripts/audit_repo.py <dir> --min-severity MEDIUM # hide low noise
python scripts/audit_repo.py <dir> --exclude "gen/*"     # skip paths
python scripts/audit_repo.py <dir> --update-baseline b.json  # accept current
python scripts/audit_repo.py <dir> --baseline b.json     # only new findings
```

Detections (each tagged with its SOC 2 control): hardcoded secrets and cloud
tokens (AWS/GitHub/Slack/Stripe/Google), private key material, wildcard IAM,
disabled encryption in IaC, public storage ACLs, deprecated TLS/SSL, disabled
certificate verification, world-open ingress, unsafe deserialization, dynamic
code execution, SQL concatenation, weak hashes, debug mode, and credentials
written to logs.

Noise controls: placeholder values are ignored, findings under `tests/`,
`fixtures/`, `examples/`, `docs/` are downgraded one severity, and any line
containing `soc2-ignore` is suppressed (add a justification comment).

## Review Loop

1. **Self-review** changes against the mandates above before finishing.
2. **Run the auditor** on the changed scope; triage every CRITICAL/HIGH
   finding (fix it or suppress with a documented `soc2-ignore` justification).
3. For major security or infrastructure changes, do a second adversarial pass:
   re-read the diff specifically hunting for mandate violations.
