# Field Test Report, run 3: AuditForge against seancarneywebsite

**Date:** 2026-11-02 (re-test after the AuditForge update; follows `field-test-seancarneywebsite-2026-11-02.md`)
**Target:** `Z:\seancarneywebsite` (npm monorepo; `apps/web` = Astro 7 + Cloudflare Workers, Anthropic-backed concierge, GoHighLevel/Resend/Google Calendar)
**AuditForge state:** working tree on top of `9921f46`, uncommitted. 53 static rules, including new WEB006–013, PRIV001–003, SEC010–012, LLM004, SUPPRESS001.
**Engines run:**
- `audit_repo.py --fail-on LOW`.
- `universal_audit.py --engines network,email,sbom --network-targets http://localhost:4400 --email-domains seancarneymusic.com`, with DAST against the production build served by `astro preview`/workerd.
- Not installed, so not run: semgrep, trivy, osv-scanner, checkov, nuclei, scorecard, trufflehog.

**Outcome:**

| | Static | DAST | Email |
|---|---|---|---|
| Before fixes | 15 findings (14 MEDIUM, 1 LOW) | 18 findings: CSP missing on every page, caused by a regression my own fix introduced | DMARC |
| After fixes | **0** at LOW, no baseline | **0** | DMARC (a DNS change only the owner can make) |

Every claim below was observed during the run or verified in `scripts/auditor/*.py`.

---

## 1. Executive summary

This update is a big step up. Of the 12 bugs and 25 detection gaps in the first report, **10 of the 12 bugs are fixed or mostly fixed, and about 15 of the 25 gaps now have rules.** The new rules found **5 real issues** that two earlier manual hardening passes had missed:
- No request size limits.
- The header CSP still contained `'unsafe-inline'`.
- GA4 and Clarity loaded before consent (in cookieless mode).
- No eviction path for browser storage.
- Admin auth duplicated per route instead of one gate.

**The most valuable result came from DAST, not the static rules.** While fixing WEB006 I generated a CSP line of 2,783 characters. Cloudflare and workerd **silently drop any `_headers` line over 2,000 characters**, so the site would have shipped with no header CSP. My own browser crawl reported "clean", because no policy means no violations. The `network` engine reported `NET_CSP_MISSING` on every URL and caught it. No static rule checks for this (§4.1).

The main remaining weaknesses:
- **Several new rules are lexical.** They pass or fail on function names, not behavior (§3).
- **The plugin is not installable in Claude Code as shipped** (§5).

## 2. Scorecard: first-report items

### Bugs (first report §3)

| # | Item | Status | Evidence |
|---|---|---|---|
| 3.1 | Monorepo API routes never scanned | **Fixed** | `scan_web_posture` no longer slices `[:3]` |
| 3.2 | Per-file signal can't see middleware | **Fixed** | `_mw_covers()`; middleware coverage recognized, no WEB004/005 false positives |
| 3.3 | `Caddyfile` casing | **Fixed** | Present lowercased in `_WEB_HEADERS_FILES` |
| 3.4 | Bare `localhost` email-checked | **Fixed** | Regex matches `localhost`; `--email-domains` added and works |
| 3.5 | SBOM from manifest ranges only | **Fixed** | Lockfile parsed: 414 components with resolved versions; dev deps marked `scope: optional` |
| 3.6 | SBOM written relative to the current directory | **Open** | Still lands in `Z:\auditforge\reports\sbom.cyclonedx.json` when run from the AuditForge checkout |
| 3.7 | WEB002 counts Markdown docs | **Open** | `RULES_BY_ID["WEB002"].extensions` is empty. Didn't fire this run only because the doc text changed |
| 3.8 | WEB003 can't recognize safe `set:html` | **Partly** | Suppression with a reason works; no heuristic downgrade for escaped JSON or `?raw` imports |
| 3.9 | WEB003 missed sinks | **Fixed** | `insertAdjacentHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `{@html}` all match |
| 3.10 | Suppression accountability | **Partly** | Bare `soc2-ignore` now raises SUPPRESS001. Still not scoped to a rule ID, and suppressions aren't listed in the markdown/SARIF report |
| 3.11 | DKIM selectors | **Fixed** | Adds `resend`, `s1`/`s2`, `mandrill`, `pm`, `amazonses`, `mxvault` |
| 3.12 | Windows usability / help text | **Open** | No Windows venv, no `pyproject.toml`; `--help` still says "SOC 2 static compliance auditor" |

### Detection gaps (first report §4)

| # | Gap | Status |
|---|---|---|
| 1 | Mail header injection | SEC010 added |
| 2 | Timing-unsafe compare | SEC011 added |
| 3 | Prototype pollution | SEC012 added; false-positive issue, §3.1 |
| 4 | PII in browser storage | PRIV003, partly: sessionStorage and cookies only; **`localStorage` is not covered** |
| 5 | Sensitive data in URLs | Not seen |
| 6 | Session-replay masking | Not seen |
| 7 | Consent-gated pixels | PRIV001, lexical, §3.2 |
| 8–9 | LLM output into HTML / linkify | LLM004 added |
| 10 | LLM001/002 for the TypeScript SDK | **Open**: no `messages.create` / `system:` patterns |
| 11–14 | Method allowlist, content type, error handler, security logging | WEB010 / WEB011 added; method and content-type checks not seen |
| 15–16 | CSP reporting and `unsafe-inline` | WEB007 / WEB006 added |
| 19 | `security.txt` | Not seen |
| 20–21 | DAST header depth, HSTS value | WEB008 added (static); DAST still checks only HSTS and CSP presence plus `Server` |
| 22 | Admin route behind a static token | WEB009, different semantics, §3.3 |
| 24 | CI audit gate / Dependabot | Not seen |
| 25 | DMARC from site config | Works via `--email-domains` |

## 3. New-rule triage (15 findings, run 3)

| Rule | Hits | Verdict | What was done on the target |
|---|---|---|---|
| WEB012 no request size/duration bound | 1 | **True positive** | Middleware: `Content-Length` required (411), per-route `maxBodySize` 4–64 KB (413) |
| WEB006 weak CSP | 1 | **True positive in isolation.** The browser also enforced Astro's per-page meta policy with hashes, but that policy didn't cover `is:inline` scripts, which ran before the meta tag | Replaced with one header policy whose hashes are computed from built HTML |
| PRIV001 tracker loaded | 3 | **Partly true.** Meta was consent-gated; GA4/Clarity loaded cookieless before consent | All three now load only after consent; loader lines carry `soc2-ignore: PRIV001 - <reason>` |
| PRIV003 storage write | 7 | **Fair.** Keys were namespaced but writes were scattered, with no eviction path | `lib/storage.ts` helper and a "Clear data saved in this browser" control |
| WEB009 no single auth gate | 1 | **Fair outcome, wrong trigger** (§3.3) | `requireAuth()` gate in middleware, driven by `admin: true` routes |
| SEC012 prototype-pollution sink | 1 | **False positive**: matched the guard `field === '__proto__'` | Rewrote as a key allowlist regex (stronger anyway) |
| WEB010 no global error handler | 1 | **False positive**: middleware already had try/catch around `next()` | Extracted into a named `handleError()` |

### 3.1 SEC012 flags its own mitigation
The pattern `__proto__` matches any occurrence, including the denylist comparison that is the fix.
- **Suggest:** flag `__proto__` only in assignment or merge contexts (`obj[k] =`, `Object.assign`, `merge(`, `JSON.parse` followed by recursive copy) with a dynamic key.
- **Suppress** when the same line is a comparison (`=== '__proto__'`, `.has('__proto__')`).

### 3.2 PRIV001 / WEB009 / WEB010 / WEB012 are lexical, so names decide the outcome
- **PRIV001** fires on the vendor URL string even when the loader is inside a consent-checked function. Every consent-correct site needs a suppression.
  - **Suggest:** suppress when the enclosing function body or the preceding ~15 lines contain a consent predicate (`consent`, `granted`, `gtag('consent'`, `consentv2`, `hasConsent`, `cookieyes`, `OneTrust`, `__tcfapi`).
- **WEB010 and WEB012** pass only for names like `handleError` / `onError` or `maxBodySize` / `bodyLimit`. A middleware `catch` around `next()` or a `content-length` comparison does the job but isn't recognized.
  - The flip side: a function named `handleError` that does nothing passes.
  - **Suggest:** structural signals. For WEB010, a `catch` in middleware wrapping `next()` / `await handler`. For WEB012, a `content-length` read compared to a number, or framework config (`bodySizeLimit`, Next `api.bodyParser.sizeLimit`).

### 3.3 WEB009 assumes every API needs authentication
This site's APIs are intentionally public: contact form, newsletter, AI concierge. Only one route is privileged. The rule fired because no gate name appeared anywhere.
- **Suggest:** fire only when (a) privileged-looking routes exist (`admin|insights|internal|metrics|dashboard`), or (b) auth checks appear ad hoc in two or more route files without a shared gate.
- Otherwise report "no authenticated routes detected" as INFO.

### 3.4 PRIV003 skips localStorage
Only `document.cookie=` and `sessionStorage.setItem(` are patterns. `localStorage` persists indefinitely, so it is the more GDPR-relevant store, and the target writes consent, attribution and experiment assignment there.
- **Suggest:** include `localStorage.setItem(`.
- Suppress when keys share a namespace prefix and a bulk-clear function exists, e.g. `Object.keys(localStorage)` filtered by the prefix followed by `removeItem`.

## 4. New gaps found this run

### 4.1 `_headers` line-length limit (HIGH, silent CSP loss)
Cloudflare Pages/Workers static assets ignore any `_headers` line over 2,000 characters. workerd logs `Ignoring line N as it exceeds the maximum allowed length of 2000` at startup and nothing else. Hash-based CSPs reach this length easily: the first attempt here carried 37 hashes in 2,783 characters.
- **Static rule (WEB014 candidate):** any line in `_headers` longer than 2,000 characters → HIGH.
- **Also scan build output.** The source file can hold placeholders that a build step expands. Scan `dist/**/_headers`, `.vercel/output/config.json` and `netlify.toml` outputs too, not only source.
- **DAST:** already catches the symptom (`NET_CSP_MISSING`). Consider an explicit hint: "header present in `_headers` source but not served; check line length or rule matching".

### 4.2 Meta CSP is invisible to both lanes
Frameworks (Astro `security.csp`, Next nonce setups) emit `<meta http-equiv="Content-Security-Policy">`. Two failure modes were observed:
- **Static:** WEB006 judged the header in isolation, though the browser enforces the intersection of both policies.
- **More important:** a meta policy only governs content **after** the meta tag. Inline scripts placed earlier in `<head>` (Astro `is:inline` here) are not covered and were not hashed by the framework. This was invisible until the header dropped `'unsafe-inline'`, at which point 3 scripts per page were blocked.
- **Suggest (DAST):** parse meta CSP from fetched HTML, flag inline `<script>` elements that appear before the meta tag, and evaluate header and meta together.
- **Suggest (DAST):** verify each inline script's SHA-256 against the effective `script-src`. This is cheap with stdlib `hashlib` and would have caught the regression directly.

### 4.3 A DAST-generated finding per static asset
`NET_CSP_MISSING` was emitted for `favicon.svg`, `.png`, `.css`, `site.webmanifest`, `sitemap-index.xml` and others: 18 rows for one root cause.
- **Suggest:** evaluate document-level headers (CSP, frame-ancestors) only on `text/html` responses, and group by root cause.

### 4.4 Suppression reason quality
`soc2-ignore: <anything>` satisfies SUPPRESS001, and it still silences every rule on the line.
- **Suggest:** `soc2-ignore: RULE-ID - reason`. Suppress only that rule, and list suppressions in reports. SARIF has `result.suppressions[]` with `justification`.

## 5. Installability as a skill / plugin / suite

**Verdict: not installable in Claude Code as shipped.** It works only as an in-repo skill when the AuditForge checkout is the working directory.

| Check | Finding |
|---|---|
| Plugin manifest | `plugin/auditforge/.muse-plugin/plugin.json` uses the **Muse** schema (`schemaVersion`, `capabilities.skills[]`, `compat.manifestDir`). Claude Code expects `.claude-plugin/plugin.json` (name, version, description, author) with `skills/`, `commands/` and `agents/` discovered by directory convention, and MCP servers in `.mcp.json` or the manifest's `mcpServers` object. |
| Marketplace | No `.claude-plugin/marketplace.json` in the repo, so neither `/plugin marketplace add Z:\auditforge` nor `/plugin install auditforge@…` is possible. (Vendored clones `probo/` and `security-templates/` have `.claude-plugin/` dirs; AuditForge itself doesn't.) |
| Installed on this machine | No: absent from `~/.claude/plugins/installed_plugins.json` and from `~/.claude/skills/`. The README explicitly says installation "is intentionally never run". |
| Self-contained | No. The skills, commands and MCP launcher all require `AUDITFORGE_HOME` pointing at a full checkout (hundreds of MB of vendored framework clones) plus a project `.venv`. |
| Windows | The MCP launcher looks for `.venv\Scripts\python.exe`. The checkout's venv is Linux-only (`bin/`, `lib64`), so **the MCP server can't start on this machine**. `command: ["python3", …]` may also resolve to the Windows Store alias. |
| Python packaging | No `pyproject.toml` / `setup.py`, so no `pip install auditforge`, no `auditforge` console script, no pinned wheel; `requirements.txt` only. |
| Skill copies | `plugin/.../SKILL.md` are hand-synced copies of `.claude/skills/*` ("reconcile on bump"). Currently they differ only by the header note, but nothing enforces it. |
| Skill frontmatter | `trigger: /auditforge` is not a Claude Code skill field (it's ignored). The description is ~700 characters of framework names, which hurts trigger matching; lead with the use cases. |

**To make it an installable suite:**
1. **Add a Claude Code manifest.** Create `plugin/auditforge/.claude-plugin/plugin.json` (`name`, `version`, `description`, `author`), and keep the Muse manifest beside it if Muse support matters.
2. **Add a marketplace.** Create a repo-root `.claude-plugin/marketplace.json` listing `./plugin/auditforge`, so `/plugin marketplace add <path-or-git-url>` then `/plugin install auditforge` works.
3. **Ship the engine with the plugin.** Package `scripts/auditor` as a Python package (`pyproject.toml`, console scripts `auditforge-scan` and `auditforge-universal`). The plugin can then run `uvx auditforge-scan` or `pipx run`, with no checkout or `AUDITFORGE_HOME` needed for the scanner.
4. **Separate the knowledge base from the engine.** Make the control catalog a versioned data artifact (the existing SQLite/FTS index) downloaded on first use or bundled compressed, instead of requiring the vendored clones.
5. **MCP server.** Declare it in `.mcp.json` using `uvx` / `python -m auditforge.mcp`. Drop the hard `.venv` path assumption and fall back to the current interpreter on Windows.
6. **Generate the skill copies at build time** (or symlink them), and add a CI check that they match.
7. **Fix the help text and docs.** Update `--help` and the README to say "multi-framework static + DAST auditor", and document Windows setup.

## 6. Suggested priorities (updated)
1. **`_headers` line-length rule and build-output scanning** (§4.1). This is a silent total loss of CSP and it is easy to detect.
2. **Inline-script hash verification and meta-CSP awareness in DAST** (§4.2).
3. **Installability** (§5, steps 1–3).
4. **Replace lexical checks with structural ones** for PRIV001, WEB009, WEB010 and WEB012 (§3.2–3.3), and fix SEC012 matching its own guard (§3.1).
5. **Remaining open items:** PRIV003 `localStorage`, LLM001/002 for TypeScript, WEB002 extension scope, SBOM output path, and rule-scoped and reported suppressions.

## 7. Reproduce
```bash
SP=<pylib with PyYAML + requests>
cd Z:/auditforge
PYTHONPATH=$SP python scripts/audit_repo.py Z:/seancarneywebsite --fail-on LOW            # 0 findings
cd Z:/seancarneywebsite/apps/web && npx astro build && npx astro preview --port 4400 &
cd Z:/auditforge && PYTHONPATH=$SP python scripts/universal_audit.py Z:/seancarneywebsite \
  --engines network,email,sbom --network-targets http://localhost:4400 \
  --email-domains seancarneymusic.com --format markdown                                  # 1: DMARC
# §4.1 repro: put a 2,001-char header line in public/_headers, build, start preview:
#   workerd logs "Ignoring line N ..." and the header is absent; audit_repo.py reports nothing.
```
