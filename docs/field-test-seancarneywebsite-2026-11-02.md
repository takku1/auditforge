# Field Test Report: AuditForge against seancarneywebsite

**Date:** 2026-11-01 → 2026-11-02 (two passes; the second ran after the WEB001–005 / `pii_allow` / RFC 2606 updates)
**Target:** `Z:\seancarneywebsite` (npm monorepo: `apps/web` = Astro 7 static site with Cloudflare Worker API routes, an LLM concierge (Anthropic SDK, TypeScript), GoHighLevel/Resend/Google Calendar integrations, first-party analytics)
**Engines run:** `audit_repo.py` (static rules); `universal_audit.py --engines network,email,sbom` (DAST against the local production build via `astro preview`, email-auth DNS, SBOM). Not run, **not installed on this host:** semgrep, trivy, osv-scanner, checkov, nuclei, scorecard, trufflehog.
**Method:** scan, then harden, then a manual gap analysis against the catalog's 442 OWASP ASVS 5.0 requirements (`framework_metadata.json`), then rescan.
**Outcome:** pass 1: 10 findings (all PII001). Pass 2 (new rules): 9 findings (7 WEB003, 2 WEB002), all now fixed. Final: **0 findings at `--fail-on LOW` with no baseline**. **About 25 real gaps were found and fixed by hand that no AuditForge rule detected.** They are listed in §4 as rule candidates.

Every item below was observed during the run or verified directly in `scripts/auditor/*.py`. None is speculative.

---

## 1. Executive summary

The new web lane is a real improvement:
- WEB003 found 2 genuine `innerHTML` sinks (LLM output rendered through HTML strings).
- WEB002 caught a report-only CSP.
- `pii_allow` and the RFC 2606 handling removed every false positive from pass 1.
- CICD001 caught unpinned GitHub Actions in CI that I wrote myself.

But four structural problems limit the lane:
1. **WEB004/WEB005 never evaluated a single file in this repo.** API-route detection only looks at the first three path segments, so `apps/web/src/pages/api/*` is invisible (§3.1). Any monorepo is a silent false negative.
2. **Header checks test presence, not quality.** Neither WEB001 (static) nor the DAST header check would flag a CSP with `'unsafe-inline'`, a missing `frame-ancestors`, or an empty `_headers` file.
3. **The LLM rules are Python-idiom only.** LLM001–003 can't match TypeScript SDK usage, and there is no rule for OWASP LLM05 (improper output handling), which was the most serious real bug in this target. WEB003 caught it only incidentally.
4. **Most ASVS application-logic requirements have no detection at all** (§4). The catalog knows the controls, but the scanner can't evidence them.

## 2. Run statistics

| Pass | Findings | Notes |
|---|---|---|
| 1 (2026-11-01, pre-update) | 10 HIGH PII001 | All emails: 1 real (hardcoded in a client script), 2 real (`.env.example`), the rest public business contact or `example.com` |
| 1b | 2 MEDIUM CICD001 | Unpinned `actions/checkout@v4`, `actions/setup-node@v4`: true positives, fixed (SHA-pinned) |
| 2 (2026-11-02, new rules) | 7 MEDIUM WEB003, 2 LOW WEB002 | 2 WEB003 were real (`Scout.astro` `innerHTML` with model text, `Hero.astro` iframe via template). 5 were build-time-only `set:html`. 1 WEB002 was real (`_headers`); 1 was a markdown checklist line |
| Final | **0** at `--fail-on LOW`, no baseline | |
| DAST (`network`) vs `localhost:4400` | 0 | HSTS + CSP present, no `Server` leak |
| email-auth for `seancarneymusic.com` (run directly) | 1 HIGH | **DMARC missing**: a true positive, valuable |
| email-auth via `universal_audit` | 3 (SPF/DKIM/DMARC) | **False positives against `localhost`** (§3.4) |

## 3. Bugs observed in AuditForge

### 3.1 WEB004/WEB005: API routes in monorepos are never scanned (HIGH impact)
`scan_web_posture()` → `parts = set(low.split("/")[:3])`. For `apps/web/src/pages/api/inquire.ts` the first three segments are `apps, web, src`, so the file never enters `api_files`.
- Verified: `{"apps","web","src"} & _WEB_ROUTE_DIRS` is empty, while `src/pages/api/...` is detected.
- **Fix:** test every segment (`set(low.split("/")) & _WEB_ROUTE_DIRS`), or match known framework route roots anywhere in the path: `pages/api`, `app/**/route.*`, `src/routes/**/+server.*`, `server/api`.

### 3.2 WEB004/WEB005: a per-file signal can't see centralized middleware
Once 3.1 is fixed, every route here would be flagged, because rate limiting, origin checks, method allowlists and content-type checks live in **one** file: `src/middleware.ts` (Astro), the equivalent of `middleware.ts` in Next.js or `hooks.server.ts` in SvelteKit.
- **Fix:** if a framework middleware file exists and matches `_WEB_RATE_RE` / `_WEB_ORIGIN_RE`, treat routes under it as covered. Report "covered by middleware" as evidence rather than staying silent.

### 3.3 WEB001: `Caddyfile` can never match
`base = os.path.basename(low)` is lowercased, but `_WEB_HEADERS_FILES` contains `"Caddyfile"` (capital C).
- **Fix:** lowercase the set entries.

### 3.4 Email-auth: bare `localhost` isn't treated as reserved
`_RESERVED_HOST_SUFFIX_RE = r"\.(test|example|invalid|localhost|...)$"` requires a leading dot, so `localhost` itself passes. `universal_audit --network-targets http://localhost:4400` then emits SPF/DKIM/DMARC findings for `localhost`.
- **Fix:** `r"(^|\.)(test|example|invalid|localhost|local|internal)$"`, and skip IP literals.
- **Also:** domains are derived from DAST targets. Add an explicit `--email-domains` option so a local DAST run can still check the production domain.

### 3.5 SBOM engine: direct manifest only, wrong versions
`_parse_package_json` reads `dependencies` and `devDependencies` and strips range characters (`^6.0.0` becomes `6.0.0`). The result was 13 components; `npm sbom` gives **195** production components.
- Because ranges become fake exact versions, any downstream vuln lookup (osv/epss) is run against the wrong versions.
- `package-lock.json` (v3 `packages` map) is never parsed. `Cargo.lock` and `Gemfile.lock` are.
- devDependencies are mixed into what is presented as the shipped SBOM.
- **Fix:** parse `package-lock.json`, `pnpm-lock.yaml` and `yarn.lock` when present; mark dev scope; fall back to the manifest only with a "ranges, not resolved" warning.

### 3.6 SBOM is written relative to the current directory
"SBOM written to reports/sbom.cyclonedx.json" lands in `Z:\auditforge\reports\`, not under the audited repo or an `--out` dir. It's gitignored, so this is harmless, but it surprises users and collides across targets.
- **Fix:** write under `<target>/reports/` or honor an `--out-dir`.

### 3.7 WEB002 counts documentation
`docs/current/02-launch-checklist.md` ("switch `Content-Security-Policy-Report-Only` to ...") was reported. It was labeled "(test/example context)" but still counted toward the gate.
- **Fix:** give WEB002 (and other config-shaped rules) an extension allowlist (`_headers`, `*.toml`, `*.json`, `*.conf`, `*.js/ts/mjs`, `*.yaml`), or exclude `*.md` by default.

### 3.8 WEB003 can't distinguish safe `set:html` uses from unsafe ones
All 5 false positives were `set:html` with build-time data:
- `JSON.stringify(...)` into `<script type="application/json">` and JSON-LD.
- Generated experiment CSS.
- `?raw` SVG imports.
- Generated inline boot script.

The only way to suppress them is an inline `soc2-ignore`. Suggested heuristics:
- **Downgrade to LOW** when the expression is `JSON.stringify(...).replace(/</g, ...)`, or the value comes from an `import ... ?raw`.
- **Raise to HIGH** when the file also references model/LLM output or `fetch` responses.
- **Add a rule** for `JSON.stringify` into `<script>` *without* `<` escaping. That is a real breakout risk, and it existed in this repo until the manual fix.

### 3.9 WEB003 misses common sinks
Verified against the patterns:

| Sink | Detected |
|---|---|
| `el.innerHTML = x` | yes |
| `el.insertAdjacentHTML('beforeend', x)` | **no** (`Scout.astro` had one) |
| `el.outerHTML = x` | **no** |
| `document.write(x)` | **no** |

Also worth covering: `DOMParser().parseFromString` followed by an append, React `dangerouslySetInnerHTML`, Vue `v-html`, and Svelte `{@html}`.

### 3.10 Inline suppression has no accountability
`SUPPRESS_TOKEN` ("soc2-ignore") anywhere on the line silences every rule, with no required reason. Suppressions aren't counted or listed in the report, and the token also works inside string literals.
- **Fix:** require `soc2-ignore[:RULE-ID]: <reason>`, scope it to the named rule, and list suppressions (file, line, rule, reason) in the markdown/SARIF report. SARIF has `suppressions[]` for exactly this.

### 3.11 DKIM selector probe list
The probe list is `["default","google","selector1","selector2","k1"]`. It misses `resend`, `s1`/`s2` (SendGrid), `mandrill`, `pm` (Postmark), `amazonses` and `mxvault`. Transactional senders are exactly where small sites send from.

### 3.12 Windows usability
- **No Windows venv.** `.venv` is Linux-only (`bin/`, `lib64`), so the scanner fails on Windows until PyYAML is available. I worked around it with a side `PYTHONPATH`. Ship a `requirements.txt` plus a PowerShell bootstrap, or make PyYAML optional (it is only used for `.soc2rc.yml`) with a clear message.
- **Help text is outdated.** `--help` still says "SOC 2 static compliance auditor", but findings now map to ASVS, OWASP, NIST and MITRE.

## 4. Gaps: real issues fixed by hand that no rule detected

Each row is something AuditForge's catalog has a control for (ASVS 5.0 ID given), was present in this codebase, and was found only by manual review. The detection idea is what a rule could match.

| # | Issue found | ASVS / OWASP | Detection idea (static unless noted) |
|---|---|---|---|
| 1 | Visitor text flowed into email `subject` / `reply_to` (CRLF header injection) | 1.3.11 | Taint-lite: request/body fields passed to `subject`, `replyTo`, `headers` of mail SDKs (resend, nodemailer, sendgrid) without a CR/LF strip |
| 2 | Admin token compared with `===` | 11.2.4 | `(token\|secret\|signature\|hmac\|key)\s*(===\|!==\|==)` in API handlers; suggest `timingSafeEqual` |
| 3 | Counter object keyed by visitor input (`obj[userKey]++`): prototype pollution | 15.3.6 | Bracket assignment on `{}` literals with request-derived keys; accept `Object.create(null)` / `Map` |
| 4 | Form draft (name, email, phone) persisted to `sessionStorage` | 14.3.3 | `(local\|session)Storage.setItem(` with values containing `email\|phone\|name` or a whole `FormData` |
| 5 | Lead score/tier passed in a URL query string | 14.2.1 | `location.href\|navigate\|href=` building `?…(tier\|score\|email\|token)=` |
| 6 | Session replay (Clarity) without masking on forms and the chat | 14.2.3 | Clarity / Hotjar / FullStory / LogRocket loaded while `<form>`/`<input>` lack `data-clarity-mask` / `data-hj-suppress` / `fs-exclude` |
| 7 | Marketing pixels loaded without consent gating | GDPR Art. 6/7, ePrivacy | `fbevents.js`, `gtag/js`, `clarity.ms/tag` loaders with no consent check (`consent`, `gtag('consent'`, `consentv2`) in the same script |
| 8 | LLM output rendered through HTML strings | OWASP LLM05 | Data flowing from `messages.create` / `.content[` / `completion` into `innerHTML` / `set:html` (rule LLM004) |
| 9 | LLM output linkified to arbitrary URLs | OWASP LLM05 | Regex-based linkify on model text without a host/path allowlist |
| 10 | LLM rules don't apply to TS SDK usage | OWASP LLM01/07 | Extend LLM001/002 to `system:` and `messages:` in `client.messages.create({...})` / `anthropic.messages` / `openai.chat.completions`, with template strings or `+` concatenation of request data |
| 11 | No method allowlist (any verb reached handlers; no 405 + `Allow`) | 4.1.4 | Astro/Next exporting `ALL` / default handlers, or no middleware method gate |
| 12 | No Content-Type enforcement on JSON POSTs (CSRF via `text/plain` simple requests) | 3.5.1 | POST handlers calling `request.json()` with no `content-type` check anywhere (file or middleware) |
| 13 | No last-resort error handler | 16.5.4 | No try/catch in middleware or global error handler; route handlers returning `String(err)` / `err.message` |
| 14 | No security-event logging (auth failures, rate limits, bad signatures) | 16.3.x | API repo with no structured log call on 401/403/429 paths |
| 15 | CSP had no `report-uri` / `report-to` | 3.4.7 | Parse the CSP value: flag a missing reporting directive |
| 16 | CSP `script-src 'unsafe-inline'` with no hashes or nonces | 3.4.3 | Parse the CSP: `'unsafe-inline'` in `script-src` without `'sha256-` / `'nonce-` / `'strict-dynamic'` |
| 17 | Honeypot returned a field-specific validation error (revealed the trap) | 2.4.1 (business logic) | Hard statically; heuristic: a schema field named `website\|url\|hp_\|honeypot` with validation messages |
| 18 | `JSON.stringify` into `<script>` without `<` escaping | 1.2.x | Covered in §3.8 |
| 19 | No `security.txt` (RFC 9116) | 13.x / RFC 9116 | DAST: GET `/.well-known/security.txt`; static: file or route present; check `Expires` < 1 year |
| 20 | No `Permissions-Policy` / `Referrer-Policy` / `COOP` / `X-Content-Type-Options` checks in DAST | 3.4.4–3.4.8 | `_header_findings()` checks only HSTS, CSP presence and `Server`. Add the rest, plus `X-Frame-Options` or CSP `frame-ancestors` |
| 21 | HSTS without `includeSubDomains` / `preload` or with a short `max-age` | 3.4.1, 3.7.4 | Parse the HSTS value (static `_headers` and DAST) |
| 22 | Admin/insights endpoint protected only by a static bearer token | 8.4.2, 6.x | Route paths matching `admin\|insights\|metrics\|internal` with only a token compare: recommend an identity-aware proxy |
| 23 | API endpoints indexable by search engines | 13.4.x | `_headers` / robots: `/api/*` without `X-Robots-Tag: noindex` or `Disallow` |
| 24 | No CI dependency audit gate / no Dependabot / no SBOM step | 15.1.x, 15.2.1 | Workflow without `npm audit` / `osv-scanner` / `trivy fs`; repo without `dependabot.yml` / `renovate.json` |
| 25 | Mail domain without DMARC | CIS 9.2 | Already exists (email engine) and worked when run directly. Surface it in `audit_repo.py` when a site config contains a domain (`astro.config` `site:`, `next.config` `env`, `package.json` `homepage`) |

## 5. What worked well
- **The `pii_allow` + RFC 2606 changes** removed every pass-1 false positive with no baseline needed. That is the right design: allowlist the published contact domain, not individual fingerprints.
- **CICD001** caught a real supply-chain issue.
- **WEB003** found the most important bug class in the repo: model output into HTML.
- **DAST against `astro preview`** (workerd, which applies `_headers`) is a good local pattern. It verified the real delivered headers, not just the config file.
- **Excludes** (`.soc2rc.yml`) worked for `node_modules`, `dist`, `.astro`, the 546 MB `reference/` snapshot and vendored `.claude/skills/`. The file-skip accounting ("not scanned, not scanned clean") is honest.
- **The ASVS 5.0 catalog** (442 requirements) made a complete manual gap matrix possible in one pass. The target's `docs/security/SECURITY.md` is built from it.

## 6. Suggested priorities
1. **Fix the bugs:** §3.1 (monorepo route detection), §3.2 (middleware awareness) and §3.4 (`localhost`). These are small and remove silent false negatives and false positives.
2. **Parse CSP and HSTS values** in both the static and DAST lanes (§4 rows 15, 16, 20, 21). That gives high value from one parser.
3. **Add LLM004** (LLM output into an HTML sink) and **TS/JS support for LLM001/002** (§4 rows 8–10).
4. **Parse npm lockfiles in the SBOM engine** (§3.5).
5. **Add a privacy lane:** consent-gated pixels, session-replay masking, PII in browser storage or URLs (§4 rows 4–7).
6. **Make suppressions accountable** (§3.10).
7. **Add a security-baseline lane for API middleware:** methods, content type, error handler, security logging (§4 rows 11–14).

## 7. Reproduce
```bash
SP=<scratch pylib with PyYAML + requests>
cd Z:/auditforge
PYTHONPATH=$SP python scripts/audit_repo.py Z:/seancarneywebsite --fail-on LOW          # 0 findings
cd Z:/seancarneywebsite/apps/web && npx astro build && npx astro preview --port 4400 &
cd Z:/auditforge && PYTHONPATH=$SP python scripts/universal_audit.py Z:/seancarneywebsite \
  --engines network,email,sbom --network-targets http://localhost:4400 --format markdown
# §4 rows 1–24 were present in the target when pass 1 ran and none was reported (the target is not
# yet a git repo, so the pre-hardening state isn't checked out; the fixes are listed in its docs/security/SECURITY.md §8).
```
