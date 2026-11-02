import os
import re
import bisect
import fnmatch
import shutil
import socket
import ssl
import subprocess
import json
import sys
from typing import List, Any, Optional
from .models import Finding, Rule, UnifiedFinding
from .rules import (
    RULES, SKIP_DIRS, SKIP_FILES, SKIP_EXTENSIONS, MAX_FILE_BYTES,
    PLACEHOLDER_RE, RESERVED_SUFFIX_RE, TEST_PATH_RE, SUPPRESS_TOKEN,
    RULES_BY_ID, _WEB_HEADERS_FILES,
    is_comment, downgrade
)

def is_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def should_skip_file(name: str) -> bool:
    lower = name.lower()
    if lower in SKIP_FILES:
        return True
    return any(lower.endswith(ext) for ext in SKIP_EXTENSIONS)


def iter_files(root: str, excludes: list):
    exclude_dirs = set()
    for excl in excludes:
        if excl.endswith("/*"):
            exclude_dirs.add(excl[:-2].lower())
        else:
            exclude_dirs.add(excl.lower())

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames 
            if d.lower() not in SKIP_DIRS and d.lower() not in exclude_dirs
        ]
        for name in filenames:
            if should_skip_file(name):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            rel_posix = rel.replace(os.sep, "/")
            if any(fnmatch.fnmatch(rel_posix, pat) for pat in excludes):
                continue
            yield path, rel_posix


def _pii_allowed(value: str, patterns) -> bool:
    """pii_allow (.soc2rc.yml): public contact addresses that are not
    findings, e.g. ["*@seancarneymusic.com"]. fnmatch, case-insensitive.
    Applies to working-tree AND history scans."""
    v = (value or "").strip().lower()
    return any(fnmatch.fnmatchcase(v, str(p).strip().lower())
               for p in (patterns or []))


_SAFE_STRINGIFY_RE = re.compile(
    r"JSON\.stringify\s*\([^;]*\)\.replace(All)?\s*\(",
)
_MODEL_OUTPUT_RE = re.compile(
    r"fetch\s*\(|messages\.create|chat\.completions|completions\.create"
    r"|\bmodel_output\b|\bllm_output\b|\bcompletion\b",
)
def _suppression_scope(line_text: str):
    """Rule IDs named by soc2-ignore[RULE,...], or None when unscoped
    (an unscoped token suppresses every rule on the line). Run-3 §3.10.
    A scoped token anywhere on the line wins: a bare token on the same
    line does NOT widen a scoped suppression (probe-verified)."""
    m = re.search(r"soc2-ignore\s*\[([A-Za-z0-9_,\s-]+)\]", line_text)
    if not m:
        return None
    return {p.strip().upper() for p in m.group(1).split(",") if p.strip()}


def _suppression_reason(line_text: str) -> str:
    """Justification after the token (and optional [scope]); "" when bare."""
    idx = line_text.find(SUPPRESS_TOKEN)
    rest = line_text[idx + len(SUPPRESS_TOKEN):].strip()
    if rest.startswith("["):
        end = rest.find("]")
        rest = rest[end + 1:].strip() if end != -1 else ""
    if not rest.startswith(":"):
        return ""
    return rest[1:].strip(" \t\"'#").strip()


def _is_bare_suppression(line_text: str) -> bool:
    """True when a soc2-ignore carries no justification (field report §3.10):
    a bare token, a dangling scope, or a colon with nothing actionable
    after it. A `[scope]: reason` / `: reason` suffix keeps the suppression
    silent. Only lines that also matched a rule reach this check, so prose
    mentions never warn."""
    return not _suppression_reason(line_text)


_RAW_IMPORT_RE = re.compile(
    r"import\s+(\w+)\s+from\s*[^\s;]+\?raw",
)


_CONSENT_RE = re.compile(
    r"consent|hasConsent|consentv2|cookieyes|onetrust|__tcfapi|"
    r"consentmanager|osano|gtag\(\s*['\"]consent['\"]|"
    r"['\"](granted|denied)['\"]|consent.{0,24}granted|granted.{0,24}consent",
    re.IGNORECASE,
)
_STORAGE_EVICTION_RES = (
    re.compile(r"Object\.keys\s*\(\s*localStorage\s*\)"),
    re.compile(r"\bremoveItem\s*\("),
)
_PRIVILEGED_ROUTE_RE = re.compile(
    r"admin|insights|internal|metrics|dashboard|settings|billing|payment|account",
    re.IGNORECASE,
)
_CATCHES_DISPATCH_RE = re.compile(
    r"\btry\b.{0,400}?\bnext\s*\(.{0,400}?\bcatch\b|"
    r"\bcatch\b.{0,400}?await\s+handler",
    re.IGNORECASE | re.DOTALL,
)


def _consent_nearby(content: str, line_starts: list, line_no: int,
                    window: int = 15) -> bool:
    """True when a consent predicate appears on the match line or in the
    preceding window of lines (run-3 section 3.2): a consent-gated loader
    is compliant, not a PRIV001 finding."""
    end = line_starts[line_no] - 1 if line_no < len(line_starts) else len(content)
    start = line_starts[max(0, line_no - 1 - window)]
    return bool(_CONSENT_RE.search(content[start:end]))


def _storage_eviction_present(content: str) -> bool:
    """True when the file both enumerates localStorage keys and removes
    them (namespace prefix plus bulk-clear helper): the documented eviction
    path GDPR/CCPA deletion requests can reach (run-3 section 3.4)."""
    return all(rx.search(content) for rx in _STORAGE_EVICTION_RES)


def _catches_next_dispatch(mw_text: str) -> bool:
    """A try/catch around the middleware dispatch (or a catch that awaits
    the handler) IS the global error handler, whatever it is named
    (run-3 section 3.2)."""
    return bool(_CATCHES_DISPATCH_RE.search(mw_text))


def _content_length_bounded(text: str) -> bool:
    """A content-length read compared against a number bounds the request,
    whatever the variable is named (run-3 section 3.2). The read and the
    comparison may sit in different statements, so each content-length
    mention gets a +-150 char window instead of a single-line regex."""
    for m in re.finditer(r"content-length", text, re.IGNORECASE):
        window = text[max(0, m.start() - 150):m.end() + 150]
        if re.search(r"(>=|<=|>|<)\s*\d|\d\s*(>=|<=|>|<)", window):
            return True
    return False


def _raw_import_sink(line_text: str, content: str) -> bool:
    """True when line_text uses a binding imported from a ?raw static asset
    (build-time data, not runtime input - field report §3.8)."""
    for name in _RAW_IMPORT_RE.findall(content):
        if re.search(r"\b" + re.escape(name) + r"\b", line_text):
            return True
    return False


def scan_file(path: str, rel: str, pii_allow: list = None,
              suppressions: list = None) -> "tuple[list, Optional[str]]":
    """Returns (findings, skip_reason). skip_reason is None for a normally
    scanned file, else "oversized" / "binary" / "unreadable" - see R-017:
    these were silent no-ops before, indistinguishable from "scanned, found
    nothing" in the report.
    """
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return [], "oversized"
        with open(path, "rb") as fh:
            raw = fh.read()
        if is_binary(raw[:8192]):
            return [], "binary"
        content = raw.decode("utf-8", errors="ignore")
    except OSError:
        return [], "unreadable"

    ext = os.path.splitext(path)[1].lower()
    basename = os.path.basename(path).lower()
    line_starts = [0]
    for m in re.finditer(r"\n", content):
        line_starts.append(m.end())
    in_test = bool(TEST_PATH_RE.search(rel))

    findings = []
    warned_lines: set = set()
    for rule in RULES:
        ext_match = not rule.extensions or ext in rule.extensions
        # Extension-less files (Dockerfile, Dockerfile.dev, ...) match on
        # basename instead - see models.py Rule.filenames.
        name_match = bool(rule.filenames) and any(
            basename == fn or basename.startswith(fn + ".") for fn in rule.filenames
        )
        if not (ext_match or name_match):
            continue
        for pattern in rule.patterns:
            for match in pattern.finditer(content):
                if rule.check_reserved_suffix and RESERVED_SUFFIX_RE.search(match.group(0)):
                    continue
                if rule.id == "PII001" and pii_allow and _pii_allowed(match.group(0), pii_allow):
                    continue
                if rule.value_group:
                    value = match.group(rule.value_group) or ""
                    if PLACEHOLDER_RE.search(value):
                        continue
                    # Case-sensitive checks for constant/enum placeholders (all-caps)
                    # and lowercase dot-notation metrics or files (avoiding false positives like hunter2secret)
                    if value.isupper() and re.match(r"^[A-Z0-9_]+$", value):
                        continue
                    if value.islower() and re.match(r"^[a-z0-9_]+\.[a-z0-9_]+$", value):
                        continue
                line_no = bisect.bisect_right(line_starts, match.start())
                line_end = content.find("\n", match.start())
                line_text = content[line_starts[line_no - 1]:
                                    line_end if line_end != -1 else len(content)]

                if is_comment(line_text, ext):
                    continue
                if SUPPRESS_TOKEN in line_text:
                    scope = _suppression_scope(line_text)
                    if scope is None or rule.id in scope:
                        reason = _suppression_reason(line_text)
                        if suppressions is not None:
                            suppressions.append({
                                "file": rel,
                                "line": line_no,
                                "rule_id": rule.id,
                                "reason": reason,
                                "justified": bool(reason),
                            })
                        if line_no not in warned_lines and _is_bare_suppression(line_text):
                            warned_lines.add(line_no)
                            findings.append(Finding(
                                rule=RULES_BY_ID["SUPPRESS001"], severity="LOW", file=rel,
                                line=line_no, snippet=line_text.strip()[:200],
                                in_test_context=in_test,
                            ))
                        continue
                    # Scoped to other rule(s): this finding stands.
                if rule.id == "PRIV001" and _consent_nearby(content, line_starts, line_no):
                    continue
                if (rule.id == "PRIV003" and "localStorage" in match.group(0)
                        and _storage_eviction_present(content)):
                    continue
                if rule.id == "WEB002" and rel.lower().endswith(".md"):
                    continue  # prose docs mentioning the header are not a deployment (§3.7)

                severity = downgrade(rule.severity) if in_test else rule.severity
                if rule.id == "WEB003":
                    # Field report §3.8: JSON.stringify(...).replace(/</g, ...)
                    # is the safe serialization idiom - LOW whatever else the
                    # file does. A ?raw static-asset binding is build-time
                    # data - also LOW. Otherwise a sink in a file that handles
                    # model output or fetch responses is HIGH, not MEDIUM.
                    if _SAFE_STRINGIFY_RE.search(line_text):
                        severity = "LOW"
                    elif _raw_import_sink(line_text, content):
                        severity = "LOW"
                    elif (severity == "MEDIUM" and _MODEL_OUTPUT_RE.search(content)
                          and not rel.lower().endswith(".md")):
                        # Prose .md naming sinks while discussing model output
                        # is documentation, not a data flow - detection stays,
                        # but it never escalates to HIGH (docs/ HIGH-gate
                        # self-triage; cf. the WEB002 .md exemption above).
                        severity = "HIGH"
                snippet = match.group(0).strip()
                if len(snippet) > 200:
                    snippet = snippet[:200] + "..."
                findings.append(Finding(
                    rule=rule, severity=severity, file=rel,
                    line=line_no, snippet=snippet, in_test_context=in_test,
                ))
    return findings, None


_COMMIT_RE = re.compile(r"^commit ([0-9a-f]{40})")
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


# _WEB_HEADERS_FILES lives in auditor.rules now (single source shared
# with WEB002 filenames) - imported above.
_WEB_ROUTE_DIRS = frozenset({
    "api", "routes", "endpoints", "server", "handlers", "controllers",
})
_WEB_POST_RE = re.compile(
    r"export\s+(?:async\s+function\s+POST|const\s+POST)"
    r"|app\.(post|put|patch|delete)\s*\("
    r"|methods\s*=\s*\[[^\]]*[\'\"]POST"
    r"|@app\.route\([^)]*POST"
    r"|def\s+post\s*\(",
    re.IGNORECASE,
)
_WEB_RATE_RE = re.compile(
    r"ratelimit|rate.limit|throttl|slowapi|arcjet|upstash|token.?bucket",
    re.IGNORECASE,
)
_WEB_ORIGIN_RE = re.compile(
    r"\borigin\b|\breferer\b|csrf|xsrf|same.?origin|allowed.?hosts"
    r"|trusted.?host|verify.*host",
    re.IGNORECASE,
)
_CSP_NAME_VALUE_RE = re.compile(
    r"(?im)^[ \t]*(content-security-policy(?:-report-only)?)\s*[:=]\s*(.+?)\s*$",
)
_HSTS_VALUE_RE = re.compile(
    r"(?im)^[ \t]*strict-transport-security\s*[:=]\s*(.+?)\s*$",
)
_VERCEL_CSP_RE = re.compile(
    r"\"key\"\s*:\s*\"Content-Security-Policy\"\s*,\s*\"value\"\s*:\s*\"([^\"]+)\"",
    re.IGNORECASE,
)
_VERCEL_HSTS_RE = re.compile(
    r"\"key\"\s*:\s*\"Strict-Transport-Security\"\s*,\s*\"value\"\s*:\s*\"([^\"]+)\"",
    re.IGNORECASE,
)
# Framework middleware files whose rate-limit / origin checks cover
# every route under the same directory subtree (Next/Astro
# middleware.*, SvelteKit hooks.server.*) - field report §3.2.
_MIDDLEWARE_BASENAMES = frozenset({
    "middleware.ts", "middleware.js", "middleware.mjs", "middleware.py",
    "hooks.server.ts", "hooks.server.js",
})


_BASELINE_AUTH_RE = re.compile(
    r"withAuth|requireAuth|authenticate|verifyToken|verifySession|checkAuth|"
    r"isAuthenticated|authorize",
    re.IGNORECASE,
)
_BASELINE_ERROR_RE = re.compile(
    r"onError|handleError|errorHandler|window\.onerror|uncaughtException|"
    r"unhandledRejection|addEventListener\([^)]*error",
)
_BASELINE_LOG_RE = re.compile(
    r"logger\.|\.log\.(info|warn|error|debug)|console\.(log|info|warn|error)|"
    r"Sentry\.|captureException|reportError",
)
_BASELINE_BOUNDS_RE = re.compile(
    r"bodyLimit|maxBodySize|maxRequestSize|BODY_LIMIT|maxDuration|max_duration|"
    r"timeout\s*:\s*\d|bodySizeLimit|sizeLimit|maxPayload|client_max_body_size|clientMaxBodySize",
)


_METHOD_RE = re.compile(
    r"405|method\.not\.allowed|methodNotAllowed|method_not_allowed|"
    r"\bAllow\s*:|req\.method\b|request\.method\b",
    re.IGNORECASE,
)
_CONTENT_TYPE_RE = re.compile(
    r"415|unsupported\.media|content-type.{0,80}?(===|!==|==|!=|includes|startsWith|match\()",
    re.IGNORECASE,
)
_HEADERS_LINE_LIMIT = 2000  # Cloudflare Pages/Workers silently drop
# longer _headers lines (workerd logs once at startup): a hash-heavy CSP
# over the limit ships NO policy. Run-3 report section 4.1.

# Build-output dirs are SKIP_DIRS for generic scanning (noise), but the CDN
# serves the BUILT headers file, not the source - so header-config discovery
# takes a second targeted pass through them (run-3 section 4.1).
_BUILD_OUTPUT_DIRS = frozenset({
    "dist", "build", "out", ".vercel", ".next", ".nuxt",
})


def _check_headers_lines(rel: str, htext: str, findings: list) -> None:
    """WEB014: any _headers line over the platform limit is a HIGH - the
    whole policy on that line never ships. Only _headers carries this
    platform limit (netlify.toml / vercel.json do not)."""
    if os.path.basename(rel.lower().replace("\\", "/")) != "_headers":
        return
    for idx, line in enumerate(htext.splitlines(), 1):
        if len(line) > _HEADERS_LINE_LIMIT:
            findings.append(_web_finding(
                "WEB014", rel,
                "Line %d is %d chars - Cloudflare Pages/Workers silently "
                "drop _headers lines over 2000 chars, so this policy "
                "never ships: %s" % (idx, len(line), line[:120]),
                line=idx))


def _process_headers_text(rel: str, htext: str, csp_values: list,
                          hsts_values: list, findings: list) -> None:
    """Shared headers-file handling for source AND build-output files:
    CSP/HSTS value extraction for WEB006-008 plus WEB014 line length."""
    csp_values.extend((rel, v) for v in _csp_values_in(htext))
    hsts_values.extend((rel, v) for v in _hsts_values_in(htext))
    _check_headers_lines(rel, htext, findings)


def _build_output_headers(root: str, excludes: list):
    """Yield (path, rel) for headers-config files inside build-output dirs.
    iter_files() prunes these dirs entirely, so this targeted walk is the
    only way the served (built) config is seen."""
    excludes = excludes or []
    for bdir in _BUILD_OUTPUT_DIRS:
        broot = os.path.join(root, bdir)
        if not os.path.isdir(broot):
            continue
        for dirpath, _dirnames, filenames in os.walk(broot):
            for name in filenames:
                if should_skip_file(name):
                    continue
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                low = rel.lower()
                if (os.path.basename(low) in _WEB_HEADERS_FILES
                        or low.endswith(".vercel/output/config.json")):
                    if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                        continue
                    yield path, rel


def _middleware_coverage(middleware_files: list) -> "tuple[dict, dict, str]":
    """Map each middleware file to whether its text carries a
    rate-limiting signal / an origin-check signal (field report §3.2).
    Returns (rate_by_dir, origin_by_dir, combined_text): the two coverage
    maps keyed by the middleware file\'s directory ("" for repo root),
    plus all middleware texts joined for baseline-lane checks (§4 rows 11-14). Unreadable/oversized files are
    treated as carrying no signal - absence of evidence, not evidence."""
    rate_by_dir: dict = {}
    origin_by_dir: dict = {}
    texts: list = []
    for path, rel in middleware_files:
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
        rate_by_dir[parent] = (rate_by_dir.get(parent, False)
                               or bool(_WEB_RATE_RE.search(text)))
        origin_by_dir[parent] = (origin_by_dir.get(parent, False)
                                 or bool(_WEB_ORIGIN_RE.search(text)))
        texts.append(text)
    return rate_by_dir, origin_by_dir, "\n".join(texts)


def _mw_covers(coverage: dict, rel: str) -> bool:
    """True when a middleware file in the route\'s own directory or any
    ancestor directory carries the signal. A repo-root middleware.ts
    (dir "") covers every route; sibling-app middleware does not."""
    directory = rel.rsplit("/", 1)[0] if "/" in rel else ""
    while True:
        if coverage.get(directory):
            return True
        if not directory:
            return False
        directory = directory.rsplit("/", 1)[0] if "/" in directory else ""


def _unquote(value: str) -> str:
    """Strip one layer of matching surrounding quotes (chr() avoids quote
    literals in source). Used for netlify.toml double-quoted values."""
    if len(value) >= 2 and value[0] == value[-1] and ord(value[0]) in (34, 39):
        return value[1:-1].strip()
    return value


def _csp_values_in(text: str) -> list:
    """Content-Security-Policy values (enforced AND report-only) from
    _headers / netlify.toml ("CSP: ..." / "CSP = ...", quotes stripped)
    and vercel.json ("key": "Content-Security-Policy", "value": "...").
    Report-only still gets WEB002, but its value is graded too - an
    unsafe-inline report-only policy will be an unsafe enforced one the
    day it ships. Field report §4 rows 15-17."""
    out = []
    for m in _CSP_NAME_VALUE_RE.finditer(text):
        value = _unquote(m.group(2).strip())
        if value:
            out.append(value)
    for m in _VERCEL_CSP_RE.finditer(text):
        if m.group(1).strip():
            out.append(m.group(1).strip())
    return out


def _hsts_values_in(text: str) -> list:
    """Strict-Transport-Security values from the same config shapes."""
    out = []
    for m in _HSTS_VALUE_RE.finditer(text):
        value = _unquote(m.group(1).strip())
        if value:
            out.append(value)
    for m in _VERCEL_HSTS_RE.finditer(text):
        if m.group(1).strip():
            out.append(m.group(1).strip())
    return out


def _csp_directive(csp: str, name: str) -> str:
    """Value of one CSP directive ("" when absent)."""
    m = re.search(r"(?i)(?:^|;)\s*" + name + r"\s+([^;]+)", csp)
    return m.group(1).strip() if m else ""


def _csp_is_weak(csp: str) -> bool:
    """True when script-src (or its default-src fallback) allows
    unsafe-inline with no hash, nonce, or strict-dynamic mitigation."""
    script = _csp_directive(csp, "script-src") or _csp_directive(csp, "default-src")
    if not script or "unsafe-inline" not in script.lower():
        return False
    low = csp.lower()
    return not ("sha256-" in low or "sha384-" in low or "sha512-" in low
                or "nonce-" in low or "strict-dynamic" in low)


def _csp_has_reporting(csp: str) -> bool:
    low = csp.lower()
    return "report-uri" in low or "report-to" in low


def _hsts_problems(hsts: str) -> list:
    """Weak-HSTS reasons ([] when the value is strong). A missing max-age
    is the worst case - reported, not silently passed."""
    low = hsts.lower()
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    if not m:
        return ["no max-age directive"]
    problems = []
    if int(m.group(1)) < 31536000:
        problems.append("max-age=%s (< 31536000, one year)" % m.group(1))
    if "includesubdomains" not in low:
        problems.append("missing includeSubDomains")
    if "preload" not in low:
        problems.append("missing preload")
    return problems


def _web_finding(rule_id: str, rel: str, snippet: str,
                   line: int = 1, severity: str = None) -> "Finding":
    rule = RULES_BY_ID[rule_id]
    in_test = bool(TEST_PATH_RE.search(rel))
    return Finding(rule=rule, severity=severity or rule.severity, file=rel, line=line,
                   snippet=snippet, in_test_context=in_test)


def scan_web_posture(root: str, excludes: list) -> list:
    """File-presence lane the regex rules cannot express (field request):
    missing security-headers config, and state-changing route files without
    rate limiting or origin checks. Only runs when the target looks like a
    web app; absence findings point at line 1 by convention."""
    api_files: list = []
    middleware_files: list = []
    csp_values: list = []
    hsts_values: list = []
    turnstile_refs: list = []
    siteverify_found = False
    web = False
    headers_ok = False
    security_txt_found = False
    findings: list = []
    for path, rel in iter_files(root, excludes or []):
        low = rel.lower().replace("\\", "/")
        base = os.path.basename(low)
        if base == "security.txt":
            security_txt_found = True
        if base in _WEB_HEADERS_FILES:
            web = True
            try:
                if base in ("next.config.js", "next.config.mjs", "next.config.ts"):
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        htext = fh.read(200000)
                    if "headers" not in htext:
                        continue
                else:
                    if os.path.getsize(path) > MAX_FILE_BYTES:
                        headers_ok = True
                        continue
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        htext = fh.read()
                headers_ok = True
                _process_headers_text(rel, htext, csp_values,
                                      hsts_values, findings)
            except OSError:
                headers_ok = True
            continue
        if low.endswith((".astro", ".tsx", ".jsx", ".vue", ".svelte")) \
                or base == "package.json" or os.path.basename(os.path.dirname(low)) in _WEB_ROUTE_DIRS:
            web = True
        parts = set(low.split("/"))
        if parts & _WEB_ROUTE_DIRS or base.startswith(("route.", "+server.")):
            api_files.append((path, rel))
        if base in _MIDDLEWARE_BASENAMES:
            middleware_files.append((path, rel))
        if low.endswith((".html", ".js", ".jsx", ".ts", ".tsx", ".astro",
                         ".vue", ".svelte", ".php", ".py", ".rb", ".go")):
            try:
                if os.path.getsize(path) <= MAX_FILE_BYTES:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        ftext = fh.read().lower()
                    if ("turnstile" in ftext or "cf-challenge" in ftext
                            or "__cf_chl" in ftext):
                        turnstile_refs.append(rel)
                    if "siteverify" in ftext:
                        siteverify_found = True
            except OSError:
                pass
    for bpath, brel in _build_output_headers(root, excludes):
        web = True
        try:
            if os.path.getsize(bpath) > MAX_FILE_BYTES:
                headers_ok = True
                continue
            with open(bpath, "r", encoding="utf-8", errors="ignore") as fh:
                bhtext = fh.read()
        except OSError:
            headers_ok = True
            continue
        headers_ok = True
        _process_headers_text(brel, bhtext, csp_values,
                              hsts_values, findings)
    if not web:
        return findings
    mw_rate, mw_origin, mw_text = _middleware_coverage(middleware_files)
    route_texts: list = []
    for rel, value in csp_values:
        if _csp_is_weak(value):
            findings.append(_web_finding(
                "WEB006", rel,
                "Content-Security-Policy allows script-src unsafe-inline with "
                "no hash, nonce, or strict-dynamic mitigation: " + value[:160]))
        if not _csp_has_reporting(value):
            findings.append(_web_finding(
                "WEB007", rel,
                "Content-Security-Policy has no report-uri / report-to directive: "
                + value[:160]))
    for rel, value in hsts_values:
        problems = _hsts_problems(value)
        if problems:
            findings.append(_web_finding(
                "WEB008", rel,
                "Strict-Transport-Security value is weak (" + "; ".join(problems)
                + "): " + value[:160]))
    if not headers_ok:
        findings.append(_web_finding(
            "WEB001", ".",
            "No security-headers config found (_headers, vercel.json, "
            "netlify.toml, or next.config headers) - HSTS, CSP, nosniff "
            "and frame-ancestors are unenforced."))
    for path, rel in api_files:
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        if not _WEB_POST_RE.search(text):
            continue
        route_texts.append(text)
        covered_rate = bool(_WEB_RATE_RE.search(text)) or _mw_covers(mw_rate, rel)
        covered_origin = bool(_WEB_ORIGIN_RE.search(text)) or _mw_covers(mw_origin, rel)
        if not covered_rate:
            findings.append(_web_finding(
                "WEB004", rel,
                "State-changing route handler with no rate-limiting signal "
                "(ratelimit/throttle/quota) in the file or in covering middleware."))
        if not covered_origin:
            findings.append(_web_finding(
                "WEB005", rel,
                "State-changing route handler with no Origin/Referer/CSRF "
                "check signal in the file or in covering middleware."))
    if api_files:
        corpus = "\n".join([mw_text] + route_texts)
        gate_in_mw = bool(_BASELINE_AUTH_RE.search(mw_text))
        ad_hoc = sum(1 for t in route_texts if _BASELINE_AUTH_RE.search(t))
        auth_anywhere = bool(_BASELINE_AUTH_RE.search(corpus))
        if gate_in_mw:
            pass  # one shared gate in the middleware chain
        elif ad_hoc >= 2:
            findings.append(_web_finding(
                "WEB009", ".",
                "Auth checks appear ad-hoc in %d route files with no shared " % ad_hoc +
                "middleware gate - per-route checks drift; put one gate in "
                "the middleware chain (OWASP A01:2021, ASVS V3.2.2)."))
        elif not auth_anywhere:
            if any(_PRIVILEGED_ROUTE_RE.search(rel) for _, rel in api_files):
                findings.append(_web_finding(
                    "WEB009", ".",
                    "API routes exist but no single authentication gate (withAuth, "
                    "requireAuth, authenticate, verifyToken, ...) was found in "
                    "middleware or route files (OWASP A01:2021, ASVS V3.2.2)."))
            else:
                findings.append(_web_finding(
                    "WEB009", ".",
                    "No authentication gate was found, but no route looks "
                    "privileged (no admin/internal/dashboard-style paths) and "
                    "no scattered per-route checks - treat as informational "
                    "for an intentionally-public API; add a shared gate "
                    "before shipping a privileged route.",
                    severity="LOW"))
        if (not _BASELINE_ERROR_RE.search(corpus)
                and not _catches_next_dispatch(mw_text)):
            findings.append(_web_finding(
                "WEB010", ".",
                "API routes exist but no global error handler (onError, "
                "handleError, window.onerror, uncaughtException, ...)."))
        if not _BASELINE_LOG_RE.search(corpus):
            findings.append(_web_finding(
                "WEB011", ".",
                "API routes exist but no structured logging signal (logger.*, "
                "console.*, Sentry/captureException) was found."))
        if (not _BASELINE_BOUNDS_RE.search(corpus)
                and not _content_length_bounded(corpus)):
            findings.append(_web_finding(
                "WEB012", ".",
                "API routes exist but no request size/duration bound (bodyLimit, "
                "maxBodySize, maxDuration, timeout) was found."))
        if not _METHOD_RE.search(corpus):
            findings.append(_web_finding(
                "WEB015", ".",
                "State-changing routes exist but no method allowlist was "
                "found (405 handling, req.method/request.method check, "
                "Allow response header) - scope each route to its verbs "
                "(OWASP A01:2021, ASVS V3.2.2)."))
        if not _CONTENT_TYPE_RE.search(corpus):
            findings.append(_web_finding(
                "WEB016", ".",
                "State-changing routes exist but no content-type validation "
                "was found (415 handling, content-type header comparison) - "
                "reject unexpected media types explicitly (OWASP A05:2021).",
                severity="LOW"))
    if web and not security_txt_found:
        findings.append(_web_finding(
            "WEB017", ".",
            "No security.txt was found at the repo root or under "
            ".well-known/ - publish researcher contact details per "
            "RFC 9116 (Contact + Expires).",
            severity="LOW"))
    if turnstile_refs and not siteverify_found:
        findings.append(_web_finding(
            "WEB013", turnstile_refs[0],
            "Bot-challenge widget (Turnstile/Cloudflare challenge) is embedded "
            "but no server-side siteverify call was found - client-side-only "
            "checks are theater; verify the token server-side."))
    return findings


def scan_git_history(root: str, excludes: "Optional[list]" = None, timeout: int = 300, pii_allow: list = None) -> list:
    """Scans every commit reachable from any ref (`git log -p --all`) for
    secret-shaped findings, catching what a working-tree scan can't: a
    secret added and later removed from HEAD is still fully recoverable from
    history unless it's purged. See R-013 / docs/field-test... §G3.

    Returns [] (not an error) when `root` isn't a git repo or git isn't on
    PATH - same "unavailable" contract as `auditor.__init__._git_tracked_files`.
    Opt-in via CLI --history: a full-history diff scan is meaningfully
    slower than a working-tree scan, so it's never run by default.

    Line-based, not whole-file regex like scan_file(): only "+"-added lines
    are checked against each rule's patterns (a "-"-removed line was never
    actually present as of that commit; a context line gets seen again in
    every commit that touches the file otherwise, which would be pure noise).
    Hunk headers (`@@ -a,b +c,d @@`) are tracked to report each finding's
    real line number in that commit's version of the file, not just the
    commit hash.
    """
    excludes = excludes or []
    try:
        result = subprocess.run(
            ["git", "-C", root, "log", "-p", "--all", "--no-color", "--full-history"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore",
            timeout=timeout,
        )
    except (OSError, FileNotFoundError):
        return []
    if result.returncode != 0:
        return []

    findings = []
    commit = None
    current_file = None
    current_line = None
    for line in result.stdout.splitlines():
        m = _COMMIT_RE.match(line)
        if m:
            commit = m.group(1)[:8]
            current_file = None
            current_line = None
            continue
        m = _DIFF_FILE_RE.match(line)
        if m:
            current_file = m.group(1)
            current_line = None
            continue
        m = _HUNK_RE.match(line)
        if m:
            current_line = int(m.group(1))
            continue
        if current_file is None or current_line is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added_text = line[1:]
            _scan_history_line(findings, current_file, current_line, added_text,
                                commit, excludes)
            current_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            continue  # removed line - doesn't exist in this commit's version, no line advance
        else:
            current_line += 1  # context line
    return findings


def _scan_history_line(findings: list, file_path: str, line_no: int, text: str,
                        commit: "Optional[str]", excludes: list) -> None:
    rel_posix = file_path.replace("\\", "/")
    if any(fnmatch.fnmatch(rel_posix, pat) for pat in excludes):
        return
    if should_skip_file(os.path.basename(file_path)):
        return
    ext = os.path.splitext(file_path)[1].lower()
    basename = os.path.basename(file_path).lower()
    in_test = bool(TEST_PATH_RE.search(rel_posix))

    for rule in RULES:
        ext_match = not rule.extensions or ext in rule.extensions
        name_match = bool(rule.filenames) and any(
            basename == fn or basename.startswith(fn + ".") for fn in rule.filenames
        )
        if not (ext_match or name_match):
            continue
        for pattern in rule.patterns:
            for match in pattern.finditer(text):
                if rule.check_reserved_suffix and RESERVED_SUFFIX_RE.search(match.group(0)):
                    continue
                if rule.id == "PII001" and pii_allow and _pii_allowed(match.group(0), pii_allow):
                    continue
                if rule.value_group:
                    value = match.group(rule.value_group) or ""
                    if PLACEHOLDER_RE.search(value):
                        continue
                    if value.isupper() and re.match(r"^[A-Z0-9_]+$", value):
                        continue
                    if value.islower() and re.match(r"^[a-z0-9_]+\.[a-z0-9_]+$", value):
                        continue
                if is_comment(text, ext):
                    continue
                if SUPPRESS_TOKEN in text:
                    continue
                severity = downgrade(rule.severity) if in_test else rule.severity
                snippet = match.group(0).strip()
                if len(snippet) > 200:
                    snippet = snippet[:200] + "..."
                findings.append(Finding(
                    rule=rule, severity=severity, file=rel_posix,
                    line=line_no, snippet=snippet, in_test_context=in_test,
                    historical=True, commit=commit,
                ))


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def engine_availability() -> dict:
    """Which external scanner binaries are actually on PATH right now.

    subprocess.run() doesn't raise on a missing executable when the command
    is invoked without shell=True and produces no stdout either way, so a
    missing tool is otherwise indistinguishable from "0 findings" in the
    report - this makes that distinction explicit (R-035).
    """
    return {
        "checkov": _tool_available("checkov"),
        "semgrep": _tool_available("semgrep"),
        "trivy": _tool_available("trivy"),
        "cargo-audit": _tool_available("cargo-audit"),
        "nuclei": _tool_available("nuclei"),
        "scorecard": _tool_available("scorecard"),
        "trufflehog": _tool_available("trufflehog"),
    }


def _engine_timeout(conf) -> int:
    """Per-engine subprocess bound (seconds). Hung binaries must not hang the whole pipeline run - TimeoutExpired is an Exception subclass, so each runner\'s existing `except Exception` already converts it into a logged skip. Override per tool via `<tool>: {timeout: N}` in compliance_config.yaml."""
    try:
        return int((conf or {}).get("timeout", 600))
    except (ValueError, TypeError):
        return 600


# --- Checkov Scanner ---
def run_checkov(target_dir: str, conf: dict, mapping_data: dict) -> List[UnifiedFinding]:
    if not conf.get("enabled"): return []
    if not _tool_available("checkov"):
        print("Checkov not installed - skipping (external engine unavailable)", file=sys.stderr)
        return []
    print("Running Checkov (Local OSS Mode)...", file=sys.stderr)
    findings = []
    try:
        cmd = ["checkov", "-d", target_dir, "--output", "json", "--quiet"]
        if conf.get("soft_fail"): cmd.append("--soft-fail")

        env = os.environ.copy()
        env.pop("PRISMA_API_KEY", None)
        env.pop("BC_API_KEY", None)

        # No shell=True: cmd is already a list, and shell=True with a list
        # argument only executes cmd[0] via the shell on POSIX (the rest
        # become the shell's own $1, $2... rather than checkov's argv) -
        # silently broken on POSIX regardless of whether checkov is present.
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore', env=env, timeout=_engine_timeout(conf))
        if not result.stdout.strip():
            return []

        json_str = result.stdout
        if "[" in json_str:
            json_str = json_str[json_str.find("["):]
        
        data = json.loads(json_str)
        if isinstance(data, dict): data = [data]

        for report in data:
            results = report.get("results", {})
            for check in results.get("failed_checks", []):
                rule_id = check.get("check_id")
                severity = check.get("severity") or "MEDIUM"
                
                # Fetch snippet code
                code_block = check.get("code_block")
                snippet = ""
                if code_block:
                    lines = [line[1] for line in code_block if isinstance(line, list) and len(line) > 1]
                    snippet = "".join(lines).strip()
                
                finding = UnifiedFinding(
                    tool="Checkov",
                    rule_id=rule_id,
                    name=check.get("check_name"),
                    severity=str(severity),
                    file=check.get("file_path"),
                    line=check.get("file_line_range", [0, 0])[0],
                    snippet=snippet,
                    remediation=check.get("guideline", "")
                )
                finding.frameworks = mapping_data.get("mappings", {}).get(rule_id, [])
                if check.get("benchmarks"):
                    for b_name, b_vers in check["benchmarks"].items():
                        finding.frameworks.append(f"{b_name}:{','.join(b_vers)}")
                findings.append(finding)
    except Exception as e:
        print(f"Checkov failed: {e}", file=sys.stderr)
    return findings


# --- Semgrep Scanner ---
def run_semgrep(target_dir: str, conf: dict, mapping_data: dict) -> List[UnifiedFinding]:
    if not conf.get("enabled"): return []
    if not _tool_available("semgrep"):
        print("Semgrep not installed - skipping (external engine unavailable)", file=sys.stderr)
        return []
    print("Running Semgrep (Local OSS Mode)...", file=sys.stderr)
    findings = []
    try:
        cmd = ["semgrep", "--json", target_dir]
        for cfg in conf.get("config", []):
            cmd.extend(["--config", cfg])

        env = os.environ.copy()
        env.pop("SEMGREP_APP_TOKEN", None)

        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore', env=env, timeout=_engine_timeout(conf))
        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        for res in data.get("results", []):
            rule_id = res.get("check_id")
            extra = res.get("extra", {})
            severity = extra.get("severity") or "MEDIUM"
            finding = UnifiedFinding(
                tool="Semgrep",
                rule_id=rule_id,
                name=rule_id.split(".")[-1],
                severity=str(severity),
                file=res.get("path"),
                line=res.get("start", {}).get("line", 0),
                snippet=extra.get("lines", "").strip(),
                remediation=extra.get("message", "")
            )
            finding.frameworks = mapping_data.get("mappings", {}).get(rule_id, [])
            metadata = extra.get("metadata", {})
            if "compliance" in metadata:
                for framework, controls in metadata["compliance"].items():
                    finding.frameworks.append(f"{framework}:{controls}")
            findings.append(finding)
    except Exception as e:
        print(f"Semgrep failed: {e}", file=sys.stderr)
    return findings


# --- Trivy Scanner ---
def _trivy_vuln_to_finding(vuln: dict, ref: str, mapping_data: dict) -> "UnifiedFinding":
    """One Trivy JSON vuln entry -> normalized finding. Shared by the
    fs and image scans so both report identical shapes."""
    rule_id = vuln.get("VulnerabilityID", "DEP_VULN")
    severity = vuln.get("Severity", "MEDIUM")
    if severity == "UNKNOWN":
        severity = "LOW"
    finding = UnifiedFinding(
        tool="Trivy",
        rule_id=rule_id,
        name=f"Vulnerability in {vuln.get('PkgName')}",
        severity=severity,
        file=ref,
        line=0,
        snippet=f"Installed version: {vuln.get('InstalledVersion')}, Fixed version: {vuln.get('FixedVersion')}",
        remediation=vuln.get("PrimaryURL", "")
    )
    finding.frameworks = mapping_data.get("mappings", {}).get(rule_id, [])
    if not finding.frameworks:
        finding.frameworks = mapping_data.get("mappings", {}).get("DEP_VULN", ["SOC2:CC8.1", "NIST:CM-3"])
    return finding


def run_trivy(target_dir: str, conf: dict, mapping_data: dict) -> List[UnifiedFinding]:
    if not conf.get("enabled"): return []
    if not _tool_available("trivy"):
        print("Trivy not installed - skipping (external engine unavailable)", file=sys.stderr)
        return []
    print("Running Trivy (Local OSS Mode)...", file=sys.stderr)
    findings = []
    try:
        cmd = ["trivy", "fs", "--format", "json", target_dir]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=_engine_timeout(conf))
        if not result.stdout.strip():
            data = {"Results": []}
        else:
            data = json.loads(result.stdout)
        results = data.get("Results", [])
        for res in results:
            target = res.get("Target", "")
            vulns = res.get("Vulnerabilities", [])
            for vuln in vulns:
                findings.append(_trivy_vuln_to_finding(
                    vuln, os.path.join(target_dir, target), mapping_data))
    except Exception as e:
        print(f"Trivy failed: {e}", file=sys.stderr)
    for image in conf.get("images", []) or []:
        try:
            cmd = ["trivy", "image", "--format", "json", image]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=_engine_timeout(conf))
            if not result.stdout.strip():
                continue
            data = json.loads(result.stdout)
            for res in data.get("Results", []):
                target = res.get("Target", "")
                for vuln in res.get("Vulnerabilities", []) or []:
                    findings.append(_trivy_vuln_to_finding(
                        vuln, f"{image} ({target})", mapping_data))
        except Exception as e:
            print(f"Trivy image {image} failed: {e}", file=sys.stderr)
    return findings


def _parse_requirements_txt(path: str) -> List[tuple]:
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                parts = line.split("==", 1)
                pkg = parts[0].strip()
                ver = parts[1].split("#")[0].strip()
                out.append((pkg, ver))
    return out


def _parse_package_json(path: str) -> List[tuple]:
    out = []
    with open(path, "r", encoding="utf-8") as f:
        pkg_data = json.load(f)
    for section, scope in (("dependencies", "prod"),
                           ("peerDependencies", "prod"),
                           ("optionalDependencies", "prod"),
                           ("devDependencies", "dev")):
        for pkg, ver in (pkg_data.get(section, {}) or {}).items():
            clean_ver = "".join(c for c in str(ver)
                                if c.isdigit() or c == "." or c == "-")
            if len(clean_ver) < 1:
                continue
            known = [i for i, (p, _v, _s) in enumerate(out) if p == pkg]
            if known:
                out[known[0]] = (pkg, clean_ver, scope)
            else:
                out.append((pkg, clean_ver, scope))
    return out


def _parse_cargo_lock(path: str) -> List[tuple]:
    """Cargo.lock is valid TOML - a series of [[package]] tables, each with
    name/version. Uses stdlib tomllib (Python 3.11+); on an older
    interpreter this degrades to "Cargo.lock not parsed" rather than a hard
    failure - no new dependency added just for this."""
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            raise RuntimeError("tomllib/tomli unavailable - Cargo.lock not parsed")
    with open(path, "rb") as f:
        data = tomllib.load(f)
    out = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            out.append((name, version))
    return out


def _parse_go_sum(path: str) -> List[tuple]:
    """go.sum lines: `module version hash` and `module version/go.mod hash`.
    Emitted twice per module (content hash + go.mod hash) - dedup by
    (module, version), and strip the `/go.mod` version suffix variant.
    """
    seen = set()
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            module, version = parts[0], parts[1]
            version = version.split("/")[0].lstrip("v")
            key = (module, version)
            if key in seen:
                continue
            seen.add(key)
            out.append((module, version))
    return out


def _parse_gemfile_lock(path: str) -> List[tuple]:
    """Gemfile.lock's GEM section:
        GEM
          remote: https://rubygems.org/
          specs:
            rack (2.2.3)
            rails (7.0.4)
              actioncable (= 7.0.4)
    Top-level specs are indented exactly 4 spaces; their own dependency
    lines (indented 6) are skipped - those aren't independently pinned here.
    """
    out = []
    in_specs = False
    spec_re = re.compile(r"^ {4}(\S+) \(([^)]+)\)")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs:
                if line.strip() == "" or (not line.startswith(" ")):
                    in_specs = False
                    continue
                m = spec_re.match(line.rstrip("\n"))
                if m:
                    name, version = m.group(1), m.group(2)
                    if version and version[0].isdigit():
                        out.append((name, version))
    return out


def _parse_composer_lock(path: str) -> List[tuple]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for pkg in data.get("packages", []) + data.get("packages-dev", []):
        name = pkg.get("name")
        version = str(pkg.get("version", "")).lstrip("v")
        if name and version:
            out.append((name, version))
    return out


# filename -> (parser, OSV ecosystem name)
_NPM_LOCKFILES = frozenset({"package-lock.json", "pnpm-lock.yaml", "yarn.lock"})


def _split_pkg(item):
    """(pkg, ver, scope) for 2- or 3-tuples. Lockfile parsers know the
    scope (prod/dev/transitive); manifest parsers mostly do not, so they
    stay 2-tuples and land here as "unknown" (field report §3.5)."""
    if len(item) > 2:
        return item[0], item[1], item[2]
    return item[0], item[1], "unknown"


_SBOM_SCOPE = {"prod": "required", "transitive": "required",
               "dev": "optional", "unknown": "required"}


def _parse_package_lock(path: str) -> List[tuple]:
    """npm package-lock.json: exact RESOLVED versions, not manifest ranges.
    v2/v3 `packages` map (keys node_modules/<name>) carries per-entry dev
    flags; the v1 `dependencies` map does too. Root devDependencies names
    are always dev. Nested node_modules copies are transitive. Returns
    (pkg, ver, scope) triples (field report §3.5)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    root = (data.get("packages") or {}).get("", {})
    dev_names = set((root.get("devDependencies") or {}))
    out = []
    packages = data.get("packages") or {}
    if packages:
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict):
                continue
            if not key.startswith("node_modules/"):
                continue  # workspace root / link entry, not a dependency
            if key.count("node_modules/") > 1:
                name = key.rsplit("node_modules/", 1)[-1]
                scope = "transitive"
            else:
                name = key[len("node_modules/"):]
                scope = ("dev" if (entry.get("dev") or name in dev_names)
                         else "prod")
            ver = entry.get("version")
            if name and ver:
                out.append((name, str(ver), scope))
    else:
        for name, entry in (data.get("dependencies") or {}).items():
            if not isinstance(entry, dict):
                continue
            ver = entry.get("version")
            if not ver:
                continue
            scope = ("dev" if (entry.get("dev") or name in dev_names)
                     else "prod")
            out.append((name, str(ver), scope))
    return out


def _parse_yarn_lock(path: str) -> List[tuple]:
    """Yarn classic (v1) lockfile: `"name@range[, ...]":` headers followed
    by `  version "x.y.z"` lines. Quote-aware so berry (unquoted) headers
    and `version:` lines are skipped, not misread. Scope is not recorded
    in yarn v1 lockfiles - "unknown" (dev is resolved from a sibling
    package.json by the collector). No quote literals needed: QM covers
    both quote styles without embedding them."""
    out = []
    name = None
    QM = chr(34) + chr(39)
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\r\n")
            if not line or line[0] in " \t":
                if name:
                    stripped = line.strip()
                    if stripped.startswith("version"):
                        rest = stripped[len("version"):].strip()
                        if rest[:1] in QM:
                            out.append((name, rest.strip(QM), "unknown"))
                    name = None
                continue
            stripped = line.strip()
            if stripped[:1] in QM and stripped.endswith(":"):
                header = stripped[:-1]
                first = header.split(",", 1)[0].strip().strip(QM)
                if "@" in first:
                    parts = first.split("@")
                    if first.startswith("@"):
                        name = "@" + parts[1] if len(parts) > 2 else None
                    else:
                        name = parts[0] or None
                else:
                    name = None
            else:
                name = None
    return out


def _parse_pnpm_lock(path: str) -> List[tuple]:
    """pnpm-lock.yaml via PyYAML (already a project dependency): the
    `packages:` map keys look like `/pkg@1.2.3:` (peer suffixes in
    parens are stripped); dev scope comes from the `importers`
    devDependencies (field report §3.5)."""
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    dev_names = set()
    for importer in (data.get("importers") or {}).values():
        if isinstance(importer, dict):
            dev_names.update((importer.get("devDependencies") or {}))
    out = []
    for key, entry in (data.get("packages") or {}).items():
        if not isinstance(key, str) or "@" not in key:
            continue
        base = key.lstrip("/").split("(", 1)[0]
        name, _, ver = base.rpartition("@")
        if not name or not ver:
            continue
        out.append((name, ver, "dev" if name in dev_names else "prod"))
    return out


_LOCKFILE_PARSERS = {
    "requirements.txt": (_parse_requirements_txt, "PyPI"),
    "package.json": (_parse_package_json, "npm"),
    "package-lock.json": (_parse_package_lock, "npm"),
    "pnpm-lock.yaml": (_parse_pnpm_lock, "npm"),
    "yarn.lock": (_parse_yarn_lock, "npm"),
    "Cargo.lock": (_parse_cargo_lock, "crates.io"),
    "go.sum": (_parse_go_sum, "Go"),
    "Gemfile.lock": (_parse_gemfile_lock, "RubyGems"),
    "composer.lock": (_parse_composer_lock, "Packagist"),
}


# --- cargo audit (Rust/RUSTSEC) ---
def run_cargo_audit(target_dir: str, conf: dict, mapping_data: dict) -> List[UnifiedFinding]:
    """Runs `cargo audit --json` against every Cargo.lock found in target_dir
    (RUSTSEC advisory database, OSS, no API key). See ROADMAP R-021 - this
    had to be run entirely outside AuditForge before. Requires the
    `cargo-audit` binary (`cargo install cargo-audit`); skips (not fails)
    when it isn't installed, same contract as run_trivy.
    """
    if not conf.get("enabled"): return []
    if not _tool_available("cargo-audit"):
        print("cargo-audit not installed - skipping (external engine unavailable)", file=sys.stderr)
        return []

    findings = []
    for dirpath, dirnames, filenames in os.walk(target_dir):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        if "Cargo.lock" not in filenames:
            continue
        lockfile = os.path.join(dirpath, "Cargo.lock")
        print(f"Running cargo audit on {lockfile}...", file=sys.stderr)
        try:
            cmd = ["cargo", "audit", "--json", "--file", lockfile]
            result = subprocess.run(cmd, capture_output=True, text=True,
                                     encoding="utf-8", errors="ignore", timeout=_engine_timeout(conf))
            if not result.stdout.strip():
                continue
            data = json.loads(result.stdout)
            vulns = data.get("vulnerabilities", {}).get("list", [])
            for vuln in vulns:
                advisory = vuln.get("advisory", {})
                package = vuln.get("package", {})
                rule_id = advisory.get("id", "RUSTSEC-UNKNOWN")
                severity = str(advisory.get("severity") or "HIGH").upper()
                if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    severity = "HIGH"
                finding = UnifiedFinding(
                    tool="cargo-audit",
                    rule_id=rule_id,
                    name=advisory.get("title", f"Vulnerability in {package.get('name')}"),
                    severity=severity,
                    file=lockfile,
                    line=0,
                    snippet=f"{package.get('name')} {package.get('version')} - {advisory.get('description', '')[:200]}",
                    remediation=advisory.get("url", "") or "Upgrade the affected crate to a patched version.",
                )
                finding.frameworks = mapping_data.get("mappings", {}).get(rule_id, [])
                if not finding.frameworks:
                    finding.frameworks = mapping_data.get("mappings", {}).get("DEP_VULN", ["SOC2:CC8.1", "NIST:CM-3"])
                findings.append(finding)
        except Exception as e:
            print(f"cargo audit failed on {lockfile}: {e}", file=sys.stderr)
    return findings


# --- OSV API Scanner ---
def run_dependency_audit(target_dir: str, conf: dict, mapping_data: dict) -> List[UnifiedFinding]:
    """Workspace-aware: walks target_dir for every recognized lockfile/manifest
    (not just root-level requirements.txt/package.json - R-010), across 6
    ecosystems (PyPI, npm, crates.io, Go, RubyGems, Packagist - OSV's API
    already supports all of these). Skips the same noise dirs as the main
    scanner (node_modules, vendor, .git, ...) so a monorepo's dependency
    trees don't get re-walked as if they were first-party manifests.
    """
    if not conf.get("enabled"): return []
    print("Running OSV API Real-Time Dependency Scan...", file=sys.stderr)

    findings = []
    for dirpath, dirnames, filenames in os.walk(target_dir):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        npm_lock = bool(set(filenames) & _NPM_LOCKFILES)
        for fname in filenames:
            parser_info = _LOCKFILE_PARSERS.get(fname)
            if not parser_info:
                continue
            if fname == "package.json" and npm_lock:
                continue  # lockfile pins resolved versions; manifest ranges would double-count (§3.5)
            parser, ecosystem = parser_info
            file_path = os.path.join(dirpath, fname)
            if fname == "package.json" and not npm_lock:
                print(f"OSV: {file_path} has no lockfile sibling - versions are manifest ranges, not resolved", file=sys.stderr)
            try:
                packages = parser(file_path)
            except Exception as e:
                print(f"Error parsing {file_path}: {e}", file=sys.stderr)
                continue
            for pkg, ver, _scope in (_split_pkg(p) for p in packages):
                findings.extend(_query_osv(pkg, ver, ecosystem, file_path, target_dir, mapping_data))
    return findings


def _enrich_with_vuln_intel(vuln: dict, severity: str, remediation: str) -> tuple:
    """Best-effort CISA KEV / FIRST.org EPSS enrichment for one OSV vuln entry.
    OSV IDs (GHSA-*, PYSEC-*, ...) aren't CVE IDs, so this looks for a CVE
    alias first. Non-fatal on any failure (offline, rate-limited, no CVE
    alias) - the base OSV finding still reports either way, this only adds
    "is this one actually being exploited" context, per CLAUDE.md's
    risk-based remediation-prioritization mandate (CC7.1/CC7.2).
    """
    cve_id = next((a for a in vuln.get("aliases", []) if a.upper().startswith("CVE-")), None)
    if not cve_id:
        return severity, remediation
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import vuln_intel
        kev_hit = vuln_intel.check_kev(cve_id)
        if kev_hit is not None:
            severity = "CRITICAL"
            remediation += (f" | CISA KEV: actively exploited in the wild "
                             f"(added {kev_hit.get('dateAdded', 'unknown date')}, "
                             f"ransomware use: {kev_hit.get('knownRansomwareCampaignUse', 'Unknown')}) - "
                             f"treat as urgent regardless of CVSS.")
    except Exception:  # noqa: BLE001 - enrichment is best-effort, never fail the base scan for it
        pass
    return severity, remediation


def _query_osv(package_name: str, version: str, ecosystem: str, file_path: str, target_dir: str, mapping_data: dict) -> List[UnifiedFinding]:
    import requests
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    findings = []
    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulns", [])
            for vuln in vulns:
                rule_id = vuln.get("id", "DEP_VULN")
                severity = "HIGH"
                database_specific = vuln.get("database_specific", {})
                if database_specific and isinstance(database_specific, dict):
                    sev_field = database_specific.get("severity") or database_specific.get("cvss", {}).get("severity")
                    if sev_field:
                        severity = str(sev_field).upper()
                
                remediation = f"Upgrade package or check advisory: {vuln.get('id')} ({ecosystem}/{package_name})"
                severity, remediation = _enrich_with_vuln_intel(vuln, severity, remediation)
                finding = UnifiedFinding(
                    tool="OSV-API",
                    rule_id=rule_id,
                    name=f"Vulnerability in {package_name}",
                    severity=severity,
                    file=os.path.relpath(file_path, target_dir),
                    line=0,
                    snippet=f"Ecosystem: {ecosystem}, Package: {package_name}, Version: {version} - {vuln.get('summary', 'No summary')}",
                    remediation=remediation
                )
                finding.frameworks = mapping_data.get("mappings", {}).get(rule_id, [])
                if not finding.frameworks:
                    finding.frameworks = mapping_data.get("mappings", {}).get("DEP_VULN", ["SOC2:CC8.1", "NIST:CM-3"])
                findings.append(finding)
    except Exception as e:
        print(f"OSV query failed for {package_name}: {e}", file=sys.stderr)
    return findings


# --- Network DAST Scanner ---
# config/compliance_config.yaml ships with these as illustrative defaults, not
# real targets - scanning them silently (indistinguishable from "user
# configured example.com on purpose") was R-036. Treat an unmodified default
# list as "not configured" rather than a real audit target.
PLACEHOLDER_NETWORK_TARGETS = frozenset({
    "https://example.com",
    "https://api.example.com/health",
})


def _int_conf(conf: dict, key: str, env_var: str, default: int) -> int:
    """conf key wins, then env var, then default - never raises."""
    try:
        if key in conf and conf[key] is not None:
            return int(conf[key])
        return int(os.getenv(env_var, str(default)))
    except (ValueError, TypeError):
        return default


def _dast_auth_headers() -> dict:
    """Optional authenticated DAST mode. Credentials come from the
    environment ONLY (never config files, never CLI args that land in shell
    history): DAST_AUTH_HEADER ("Name: value", a single session header) and/or
    DAST_AUTH_COOKIE (raw Cookie header value). Returns {} (unauthenticated,
    default unchanged) when neither is set. Callers must never log the values
    - only whether auth mode is on (SOC 2 CC6.1/CC7.2: no credentials in logs).
    """
    headers = {}
    raw = (os.getenv("DAST_AUTH_HEADER", "") or "").strip()
    if raw and ":" in raw:
        name, _, value = raw.partition(":")
        if name.strip() and value.strip():
            headers[name.strip()] = value.strip()
    cookie = (os.getenv("DAST_AUTH_COOKIE", "") or "").strip()
    if cookie:
        headers["Cookie"] = cookie
    return headers


def _is_html_response(get_header) -> bool:
    """Document-level header checks (CSP, frame-ancestors) only apply to
    documents. A response declaring a non-HTML content type (images, css,
    fonts, manifests) is not governed by them - flagging every asset
    produced 18 rows for one root cause (run-3 section 4.3). A missing
    content-type still runs the checks (fail-closed)."""
    try:
        ctype = get_header("Content-Type")
    except Exception:
        return True
    if ctype is None:
        return True
    return "text/html" in str(ctype).lower()


def _page_scripts_and_meta(body: str) -> list:
    """Split an HTML body into meta-CSP and inline-script events:
    [("meta", offset, policy_text)] and [("script", offset, (attrs, text))]
    for inline (no src) non-blank scripts, in document order. Offsets are
    absolute char offsets for before/after-meta comparison (run-3 4.2).
    Stdlib html.parser only; best-effort (malformed markup skips)."""
    from html.parser import HTMLParser
    line_starts = [0]
    for m in re.finditer(r"\n", body):
        line_starts.append(m.end())

    class _P(HTMLParser):
        def __init__(self):
            super().__init__()
            self.events = []
            self._open = []

        def _abs(self):
            lineno, col = self.getpos()
            if 1 <= lineno <= len(line_starts):
                return line_starts[lineno - 1] + col
            return 0

        def handle_starttag(self, tag, attrs):
            ad = dict(attrs)
            if tag == "meta":
                if (ad.get("http-equiv", "").lower()
                        == "content-security-policy" and ad.get("content")):
                    self.events.append(("meta", self._abs(), ad["content"]))
            elif tag == "script" and not (ad.get("src") or "").strip():
                self._open.append([self._abs(), ad, []])

        def handle_data(self, data):
            if self._open:
                self._open[-1][2].append(data)

        def handle_endtag(self, tag):
            if tag == "script" and self._open:
                pos, ad, chunks = self._open.pop()
                text = "".join(chunks)
                if text.strip():
                    self.events.append(("script", pos, (ad, text)))

    parser = _P()
    parser.feed(body)
    return parser.events


def _csp_script_src_tokens(policy_text: str) -> set:
    """Tokens of script-src, falling back to default-src per the CSP
    fallback chain. Commas treated as whitespace (some servers emit them)."""
    directives = {}
    for part in str(policy_text).split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, rest = part.partition(" ")
        directives.setdefault(name.strip().lower(), rest.strip())
    src = directives.get("script-src", directives.get("default-src", ""))
    return set(src.replace(",", " ").split())


def _uncovered_inline_scripts(scripts: list, tokens: set) -> list:
    """Inline scripts neither nonce-covered nor hash-covered by the
    effective policy. Callers skip this entirely when 'unsafe-inline' is
    present (everything runs - WEAK already fires)."""
    import hashlib
    import base64
    uncovered = []
    for _pos, (attrs, text) in scripts:
        nonce = (attrs.get("nonce") or "").strip().strip("\'\"")
        if nonce and ("'nonce-%s'" % nonce in tokens
                      or "nonce-%s" % nonce in tokens):
            continue
        digest = base64.b64encode(
            hashlib.sha256(text.encode("utf-8")).digest()).decode()
        if ("'sha256-%s'" % digest in tokens
                or "sha256-%s" % digest in tokens):
            continue
        uncovered.append(text)
    return uncovered


def _header_findings(url: str, headers, mapping_data: dict,
                         body: str = "") -> List[UnifiedFinding]:
    """HSTS/CSP/server-leak header checks for one fetched URL, plus value
    grading (weak HSTS, weak CSP, missing CSP reporting) and the remaining
    expected security headers (field report §4 rows 15, 16, 20, 21).
    Lookup is case-insensitive: live responses are case-insensitive but
    test doubles are plain dicts."""
    out = []
    try:
        names = list(headers.keys())
    except Exception:
        return out
    try:
        lowered = {str(k).lower(): headers[k] for k in names}
    except Exception:
        lowered = {}

    def _get(name: str):
        try:
            value = headers.get(name)
        except Exception:
            value = None
        if value is None:
            value = lowered.get(name.lower())
        return value

    try:
        _ctype = _get("Content-Type")
    except Exception:
        _ctype = None
    is_html = _ctype is None or "text/html" in str(_ctype).lower()
    hsts = _get("Strict-Transport-Security")
    if not hsts:
        out.append(_create_network_finding("NET_HSTS_MISSING", "Missing HSTS Header", "HIGH", url, f"Found Headers: {names[:5]}...", "Ensure Strict-Transport-Security is set to enforce TLS.", mapping_data))
    else:
        problems = _hsts_problems(str(hsts))
        if problems:
            out.append(_create_network_finding("NET_HSTS_WEAK", "Weak HSTS Value", "LOW", url, "Strict-Transport-Security: " + str(hsts)[:200], "Use max-age=31536000 (one year) or longer plus includeSubDomains and preload (then submit to hstspreload.org); see ASVS V3.4.1.", mapping_data))
    csp = _get("Content-Security-Policy")
    if not csp and is_html:
        out.append(_create_network_finding("NET_CSP_MISSING", "Missing CSP Header", "MEDIUM", url, "", "Add Content-Security-Policy header to prevent XSS.", mapping_data))
    elif csp and is_html:
        csp_text = str(csp)
        if _csp_is_weak(csp_text):
            out.append(_create_network_finding("NET_CSP_WEAK", "Weak CSP Value", "MEDIUM", url, "Content-Security-Policy: " + csp_text[:200], "Remove unsafe-inline from script-src (hash or nonce every script) or add strict-dynamic with nonces; see ASVS V3.4.3.", mapping_data))
        if not _csp_has_reporting(csp_text):
            out.append(_create_network_finding("NET_CSP_NO_REPORT", "CSP Without Violation Reporting", "LOW", url, "Content-Security-Policy: " + csp_text[:200], "Add a report-uri / report-to directive and monitor the endpoint; see ASVS V3.4.7.", mapping_data))
    for header, rule_id, title, fix in (
        ("Permissions-Policy", "NET_PERMISSIONS_POLICY_MISSING", "Missing Permissions-Policy Header", "Set a Permissions-Policy header to disable unneeded powerful features (camera, geolocation, etc.); see ASVS V3.4.4."),
        ("Referrer-Policy", "NET_REFERRER_POLICY_MISSING", "Missing Referrer-Policy Header", "Set a Referrer-Policy (e.g. no-referrer or strict-origin-when-cross-origin); see ASVS V3.4.5."),
        ("Cross-Origin-Opener-Policy", "NET_COOP_MISSING", "Missing Cross-Origin-Opener-Policy Header", "Set Cross-Origin-Opener-Policy: same-origin to isolate the browsing context; see ASVS V3.4.6."),
        ("X-Content-Type-Options", "NET_XCTO_MISSING", "Missing X-Content-Type-Options Header", "Set X-Content-Type-Options: nosniff to block MIME sniffing; see ASVS V3.4.8."),
    ):
        if not _get(header):
            out.append(_create_network_finding(rule_id, title, "LOW", url, "", fix, mapping_data))
    report_only = _get("Content-Security-Policy-Report-Only")
    csp_all = " ".join(s for s in (str(csp) if csp else "",
                                    str(report_only) if report_only else "")
                        if s).lower()
    if is_html and not _get("X-Frame-Options") and "frame-ancestors" not in csp_all:
        out.append(_create_network_finding("NET_FRAME_ANCESTORS_MISSING", "Clickjacking Protection Missing", "LOW", url, "", "Set X-Frame-Options: DENY/SAMEORIGIN or a CSP frame-ancestors directive; see ASVS V3.4.2.", mapping_data))
    try:
        server_leak = _get("Server") or _get("X-Powered-By")
    except Exception:
        server_leak = None
    if server_leak:
        out.append(_create_network_finding("NET_INFO_LEAK", "Server Info Leak", "LOW", url, f"Leaked identity: {server_leak}", "Remove Server and X-Powered-By headers from the response.", mapping_data))
    body_text = body if isinstance(body, str) else ""
    if body_text.strip():
        try:
            _events = _page_scripts_and_meta(body_text)
        except Exception:
            _events = []
        _metas = [(pos, pol) for kind, pos, pol in _events if kind == "meta"]
        _scripts = [(pos, rest) for kind, pos, rest in _events if kind == "script"]
        if _metas and not csp:
            _first_meta = min(pos for pos, _ in _metas)
            _early = [t for pos, (_ad, t) in _scripts if pos < _first_meta]
            if _early:
                out.append(_create_network_finding(
                    "NET_META_CSP_ORDER", "Inline Script Before Meta CSP", "MEDIUM", url,
                    "%d inline script(s) appear before the meta CSP tag and run unconstrained (no header policy present); the meta tag governs only content after it." % len(_early),
                    "Place the meta CSP as the first element in <head> so it governs every script, or preferably enforce the policy as an HTTP header which covers the whole document; see ASVS V3.4.3.",
                    mapping_data))
        _policy_text = str(csp) if csp else (_metas[0][1] if _metas else "")
        if _policy_text and _scripts:
            _tokens = _csp_script_src_tokens(_policy_text)
            if "'unsafe-inline'" not in _tokens and "unsafe-inline" not in _tokens:
                _uncovered = _uncovered_inline_scripts(_scripts, _tokens)
                if _uncovered:
                    out.append(_create_network_finding(
                        "NET_CSP_UNHASHED_INLINE", "Inline Script Not Covered by CSP", "MEDIUM", url,
                        "%d uncovered inline script(s); first: %s" % (len(_uncovered), _uncovered[0][:120]),
                        "Hash every inline script (SHA-256) into script-src, use nonces, or move code to external files; verify with hashlib against the served bytes; see ASVS V3.4.3.",
                        mapping_data))
    return out


def _extract_same_origin_links(body: str, base_url: str) -> List[str]:
    """Same-origin http(s) links from one HTML page, stdlib only."""
    from html.parser import HTMLParser
    from urllib.parse import urljoin, urlparse

    class _Links(HTMLParser):
        def __init__(self):
            super().__init__()
            self.hrefs: List[str] = []

        def handle_starttag(self, tag, attrs):
            if tag in ("a", "link"):
                for k, v in attrs:
                    if k == "href" and v and v.strip():
                        self.hrefs.append(v.strip())

    parser = _Links()
    try:
        parser.feed(body)
    except Exception:
        return []
    origin = urlparse(base_url).netloc.lower()
    out = []
    for href in parser.hrefs:
        if href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute = urljoin(base_url, href).split("#")[0]
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.netloc.lower() != origin:
            continue
        if absolute not in out:
            out.append(absolute)
    return out


def _crawl_site(start_url: str, get, max_depth: int, max_pages: int,
                headers: dict, timeout_val: int) -> dict:
    """Breadth-first, same-origin, GET-only crawl from start_url. Returns
    {url: response} including the start page. Bounded by max_depth and
    max_pages - never follows off-origin links (R-052)."""
    pages = {}
    seen = set()
    queue = [(start_url, 0)]
    while queue and len(seen) < max_pages:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = get(url, timeout=timeout_val, headers=headers)
        except Exception as e:
            print(f"DAST crawl fetch failed for {url}: {e}", file=sys.stderr)
            continue
        pages[url] = resp
        if depth >= max_depth:
            continue
        body = getattr(resp, "text", "")
        if not isinstance(body, str) or not body:
            continue
        for link in _extract_same_origin_links(body, url):
            if link not in seen and len(queue) + len(seen) < max_pages:
                queue.append((link, depth + 1))
    return pages


# Light, non-destructive GET-only probes (R-052): one query param is replaced
# per request, nothing is written server-side, responses are only inspected
# for reflection/error signatures - ZAP-class depth is out of scope.
_DAST_FUZZ_PAYLOADS = {
    "XSS": "\"'><script>alert(1)</script>",
    "SQLI": "' OR '1'='1' -- ",
    "PATH": "../../etc/passwd",
}
_SQL_ERROR_RE = re.compile(
    r"you have an error in your sql syntax|mysql_fetch|ORA-[0-9]+|"
    r"PostgreSQL.*ERROR|sqlite3?::|ODBC.*SQL|JDBC.*SQLException",
    re.IGNORECASE,
)
_DAST_FUZZ_META = {
    "XSS": ("DAST_REFLECTED_XSS", "Possible Reflected XSS", "MEDIUM",
            "Encode all user-controlled output with context-aware output encoding, "
            "validate input allowlist-style, and enforce a Content-Security-Policy "
            "(SOC 2 CC8.1)."),
    "SQLI": ("DAST_SQL_ERROR", "Possible SQL Injection Error Disclosure", "MEDIUM",
             "Use parameterized queries / ORM bindings everywhere, never build SQL "
             "by string concatenation, and suppress verbose DB errors (SOC 2 CC8.1)."),
    "PATH": ("DAST_PATH_TRAVERSAL", "Possible Path Traversal Disclosure", "HIGH",
             "Canonicalize and allowlist file paths, jail file access to the intended "
             "directory, and reject '..' sequences (SOC 2 CC8.1)."),
}


def _fuzz_url(url: str, get, headers: dict, timeout_val: int, budget: int,
              findings: List[UnifiedFinding], mapping_data: dict) -> int:
    """Fuzz one URL's query params with light probes. Returns requests spent.
    Snippets name the param and probe class only - probe strings and response
    bodies are never echoed into findings (CC7.2/PII scrubbing)."""
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

    spent = 0
    try:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
    except Exception:
        return 0
    if not params:
        return 0
    for idx, (name, _value) in enumerate(params):
        for probe_class, payload in _DAST_FUZZ_PAYLOADS.items():
            if spent >= budget:
                return spent
            mutated = list(params)
            mutated[idx] = (name, payload)
            fuzzed = urlunparse(parsed._replace(
                query=urlencode(mutated, doseq=True)))
            spent += 1
            try:
                resp = get(fuzzed, timeout=timeout_val, headers=headers)
                body = getattr(resp, "text", "")
            except Exception:
                continue
            if not isinstance(body, str) or not body:
                continue
            hit = False
            if probe_class == "XSS" and payload in body:
                hit = True
            elif probe_class == "SQLI" and _SQL_ERROR_RE.search(body):
                hit = True
            elif probe_class == "PATH" and "root:x:" in body:
                hit = True
            if hit:
                rule_id, title, severity, remediation = _DAST_FUZZ_META[probe_class]
                findings.append(_create_network_finding(
                    rule_id, title, severity, url.split("?")[0],
                    f"Query param '{name}' reflected probe class {probe_class} "
                    f"(probe and response redacted).",
                    remediation, mapping_data))
                break  # one finding per param is enough signal
    return spent


def _domain_of(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def run_network_audit(targets: list, mapping_data: dict, dast_conf: "Optional[dict]" = None,
                      email_conf: "Optional[dict]" = None) -> List[UnifiedFinding]:
    if not targets: return []
    if set(targets) <= PLACEHOLDER_NETWORK_TARGETS:
        print(
            "Network audit skipped: config/compliance_config.yaml's "
            "network_targets is still the placeholder example.com default - "
            "set real targets (or pass --network-targets) to run DAST checks.",
            file=sys.stderr,
        )
        return []
    print("Running Network/API DAST Checks...", file=sys.stderr)
    import requests

    dast_conf = dict(dast_conf or {})
    email_conf = dict(email_conf or {})
    timeout_val = _int_conf(dast_conf, "timeout", "DAST_REQUEST_TIMEOUT", 10)
    user_agent = os.getenv("DAST_USER_AGENT", "AuditForge/1.0")
    headers_payload = {"User-Agent": user_agent}
    auth_headers = _dast_auth_headers()
    if auth_headers:
        # Credential VALUES never touch stdout/stderr/findings - CC6.1/CC7.2.
        print("DAST authenticated mode enabled via environment (credential value not logged)",
              file=sys.stderr)
        headers_payload.update(auth_headers)
    findings: List[UnifiedFinding] = []

    crawl_enabled = bool(dast_conf.get("crawl", True))
    max_depth = _int_conf(dast_conf, "max_depth", "DAST_MAX_DEPTH", 2)
    max_pages = _int_conf(dast_conf, "max_pages", "DAST_MAX_PAGES", 20)
    fuzz_enabled = bool(dast_conf.get("fuzz", True))
    fuzz_budget = _int_conf(dast_conf, "max_fuzz_requests", "DAST_MAX_FUZZ", 20)
    fuzz_spent = 0

    for target in targets:
        try:
            resp = requests.get(target, timeout=timeout_val, headers=headers_payload)
            findings.extend(_header_findings(target, resp.headers, mapping_data,
                                             getattr(resp, "text", "") or ""))
        except Exception as e:
            findings.append(_create_network_finding("NET_REACHABILITY", "Endpoint Unreachable or SSL Error", "HIGH", target, str(e), "Ensure endpoint is online, resolvable, and has a valid TLS certificate.", mapping_data))
            continue

        pages = {target: resp}
        if crawl_enabled:
            try:
                pages = _crawl_site(target, requests.get, max_depth, max_pages,
                                    headers_payload, timeout_val)
                pages.setdefault(target, resp)
            except Exception as e:
                print(f"DAST crawl failed for {target}: {e}", file=sys.stderr)
            for crawled_url, page_resp in pages.items():
                if crawled_url == target:
                    continue
                try:
                    findings.extend(_header_findings(
                        crawled_url, page_resp.headers, mapping_data,
                        getattr(page_resp, "text", "") or ""))
                except Exception:
                    continue
        if fuzz_enabled:
            for page_url in list(pages):
                if fuzz_spent >= fuzz_budget:
                    break
                try:
                    fuzz_spent += _fuzz_url(page_url, requests.get, headers_payload,
                                            timeout_val, fuzz_budget - fuzz_spent,
                                            findings, mapping_data)
                except Exception as e:
                    print(f"DAST fuzz failed for {page_url}: {e}", file=sys.stderr)

    if email_conf.get("enabled"):
        try:
            domains = sorted({_domain_of(t) for t in targets} - {""})
            findings.extend(run_email_auth_audit(
                domains, mapping_data,
                selectors=email_conf.get("selectors"),
                timeout=_int_conf(email_conf, "timeout", "EMAIL_DNS_TIMEOUT", 10)))
        except Exception as e:
            print(f"Email auth audit failed: {e}", file=sys.stderr)

    return findings


def _create_network_finding(rule_id: str, name: str, severity: str, file_path: str, snippet: str, remediation: str, mapping_data: dict) -> UnifiedFinding:
    finding = UnifiedFinding(
        tool="NetworkScanner",
        rule_id=rule_id,
        name=name,
        severity=severity,
        file=file_path,
        line=0,
        snippet=snippet,
        remediation=remediation
    )
    finding.frameworks = mapping_data.get("mappings", {}).get(rule_id, [])
    return finding


# --- Email authentication (SPF/DKIM/DMARC, R-055) ---
_PLACEHOLDER_EMAIL_DOMAINS = frozenset({"example.com", "example.org", "example.net"})
_RESERVED_HOST_SUFFIX_RE = re.compile(
    r"(^|\.)(test|example|invalid|localhost|local|internal|ipc)$", re.IGNORECASE)


def _is_ip_literal(host: str) -> bool:
    """True for IPv4/IPv6 literals (field report §3.4): DAST targets
    like http://127.0.0.1:4400 derive a "domain" that must never be
    DNS-probed for SPF/DKIM/DMARC. stdlib ipaddress, no new dep."""
    try:
        import ipaddress
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _dns_txt_records(name: str, timeout: int = 10) -> List[str]:
    """Stdlib-only DNS TXT lookup via DNS-over-HTTPS (RFC 8484, Cloudflare's
    dns-json endpoint) with urllib - no new dependency. Returns [] on any
    failure (offline, NXDOMAIN, rate-limited): a missing record and a failed
    lookup both degrade to "no record seen", and findings word it that way.
    """
    import json as _json
    import urllib.parse as _urlparse
    import urllib.request as _urlrequest

    url = ("https://cloudflare-dns.com/dns-query?name="
           + _urlparse.quote(name) + "&type=TXT")
    req = _urlrequest.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with _urlrequest.urlopen(req, timeout=timeout) as resp:
            data = _json.load(resp)
    except Exception as e:
        print(f"DNS TXT lookup failed for {name}: {e}", file=sys.stderr)
        return []
    out = []
    for ans in data.get("Answer", []) or []:
        if ans.get("type") == 16 and ans.get("data"):
            out.append(str(ans["data"]).strip().strip('"'))
    return out


def run_email_auth_audit(domains: list, mapping_data: dict,
                         selectors: "Optional[list]" = None,
                         timeout: int = 10) -> List[UnifiedFinding]:
    """SPF/DKIM/DMARC presence checks per domain (R-055). Missing records are
    findings with remediation (SOC 2 CC6.1); DKIM is probed under common
    provider selectors because the signing selector is provider-assigned and
    undiscoverable otherwise - a miss is LOW with manual-verify wording, not a
    hard fail. Placeholder/reserved hosts are skipped, never scanned.
    """
    if not domains:
        return []
    selectors = selectors or ["default", "google", "selector1", "selector2", "k1",
                            "resend", "s1", "s2", "mandrill", "pm",
                            "amazonses", "mxvault"]
    findings = []
    for raw in domains:
        domain = (raw or "").strip().lower().rstrip(".")
        if not domain:
            continue
        if domain in _PLACEHOLDER_EMAIL_DOMAINS or domain.endswith(".example.com"):
            continue
        if _RESERVED_HOST_SUFFIX_RE.search(domain):
            continue
        if _is_ip_literal(domain):
            continue
        print(f"Checking email auth records for {domain}...", file=sys.stderr)
        txts = _dns_txt_records(domain, timeout)
        if not any(t.lower().startswith("v=spf1") for t in txts):
            findings.append(_create_network_finding(
                "EMAIL_SPF_MISSING", "Missing SPF Record", "MEDIUM", domain,
                "No TXT record starting with 'v=spf1' observed.",
                "Publish an SPF TXT record listing authorized senders and ending "
                "in '-all' (e.g. 'v=spf1 include:_spf.provider.example -all'), or "
                "confirm mail is intentionally not sent from this domain "
                "(SOC 2 CC6.1).", mapping_data))
        dmarc = _dns_txt_records("_dmarc." + domain, timeout)
        if not any(t.lower().startswith("v=dmarc1") for t in dmarc):
            findings.append(_create_network_finding(
                "EMAIL_DMARC_MISSING", "Missing DMARC Record", "HIGH", domain,
                "No TXT record starting with 'v=DMARC1' observed at _dmarc.",
                "Publish a _dmarc TXT record starting at 'p=none' for visibility, "
                "then enforce 'p=quarantine'/'p=reject' with aggregate reports "
                "(rua=) so spoofed mail is quarantined, not delivered "
                "(SOC 2 CC6.1).", mapping_data))
        dkim_found = False
        for selector in selectors:
            if _dns_txt_records(f"{selector}._domainkey.{domain}", timeout):
                dkim_found = True
                break
        if not dkim_found:
            findings.append(_create_network_finding(
                "EMAIL_DKIM_MISSING", "No DKIM Record Under Common Selectors", "LOW",
                domain,
                f"No TXT observed under {len(selectors)} common "
                "<selector>._domainkey selectors.",
                "Enable DKIM signing with the mail provider and publish the "
                "provider-assigned selector TXT record; this check only probes "
                "common selector names, so confirm the real selector in the "
                "provider console (SOC 2 CC6.1).", mapping_data))
    return findings


# --- Live cloud posture + drift detection (R-051) ---
def _poll_aws() -> "tuple[list, str]":
    """Read-only AWS polling via boto3. Returns (items, skip_reason) where
    skip_reason is "" when a poll was attempted. Absent creds or absent boto3
    skip gracefully (never fail) - same contract as run_trivy/cargo-audit."""
    if not (os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE")
            or os.getenv("AWS_ROLE_ARN")
            or os.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")):
        return [], ("AWS credentials absent "
                    "(AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set) - skipping live AWS checks")
    try:
        import boto3
    except ImportError:
        return [], "boto3 not installed - skipping live AWS checks"
    items: list = []
    try:
        s3 = boto3.client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket.get("Name", "")
            public = False
            details: List[str] = []
            try:
                pab = s3.get_public_access_block(Bucket=name).get(
                    "PublicAccessBlockConfiguration", {})
                if not all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                                "BlockPublicPolicy", "RestrictPublicBuckets")):
                    public = True
                    details.append(f"public-access-block incomplete: {pab}")
            except Exception:
                public = True  # no block config is fail-open
                details.append("no public-access-block configuration")
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    # soc2-ignore: AWS canonical S3 grantee URIs - the http scheme is AWS-defined
                    # and must match ACL responses exactly; not a cleartext-protocol choice.
                    if uri in ("http://acs.amazonaws.com/groups/global/AllUsers",  # soc2-ignore: AWS canonical grantee URI, must match ACL responses exactly
                               "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"):  # soc2-ignore: AWS canonical grantee URI, must match ACL responses exactly
                        public = True
                        details.append(f"public ACL grant: {grant.get('Permission')}")
            except Exception as e:
                details.append(f"ACL unreadable: {e}")
            items.append({"provider": "aws", "service": "s3", "resource": name,
                          "public": public, "detail": "; ".join(details) or "private"})
    except Exception as e:
        return items, f"AWS S3 poll failed: {e}"
    try:
        iam = boto3.client("iam")
        try:
            iam.get_account_password_policy()
            items.append({"provider": "aws", "service": "iam",
                          "resource": "password-policy", "public": False,
                          "detail": "account password policy present"})
        except Exception:
            items.append({"provider": "aws", "service": "iam",
                          "resource": "password-policy", "public": True,
                          "detail": "no account password policy"})
    except Exception as e:
        return items, f"AWS IAM poll failed: {e}"
    return items, ""


def _poll_gcp() -> "tuple[list, str]":
    """Read-only GCP storage polling. Same skip-gracefully contract."""
    project = os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT")
    if not (os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or project):
        return [], ("GCP credentials absent "
                    "(GOOGLE_APPLICATION_CREDENTIALS/GCP_PROJECT not set) - skipping live GCP checks")
    try:
        from google.cloud import storage as gcs
    except ImportError:
        return [], "google-cloud-storage not installed - skipping live GCP checks"
    items: list = []
    try:
        for bucket in gcs.Client(project=project).list_buckets():
            public = False
            try:
                policy = bucket.get_iam_policy()
                public = any(
                    b.get("role", "").startswith("roles/storage.")
                    and {"allUsers", "allAuthenticatedUsers"} & set(b.get("members", []))
                    for b in getattr(policy, "bindings", []) or [])
            except Exception as e:
                items.append({"provider": "gcp", "service": "gcs", "resource": bucket.name,
                              "public": False,
                              "detail": f"IAM policy unreadable, exposure unknown: {e}"})
                continue
            items.append({"provider": "gcp", "service": "gcs", "resource": bucket.name,
                          "public": public,
                          "detail": "public IAM binding present" if public else "private"})
    except Exception as e:
        return items, f"GCP storage poll failed: {e}"
    return items, ""


def _poll_azure() -> "tuple[list, str]":
    """Read-only Azure storage polling. Same skip-gracefully contract."""
    subscription = os.getenv("AZURE_SUBSCRIPTION_ID")
    if not subscription:
        return [], ("Azure credentials absent "
                    "(AZURE_SUBSCRIPTION_ID not set) - skipping live Azure checks")
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.storage import StorageManagementClient
    except ImportError:
        return [], "azure-identity/azure-mgmt-storage not installed - skipping live Azure checks"
    items: list = []
    try:
        client = StorageManagementClient(DefaultAzureCredential(), subscription)
        for acct in client.storage_accounts.list():
            public = bool(getattr(acct, "allow_blob_public_access", False))
            items.append({"provider": "azure", "service": "storage",
                          "resource": getattr(acct, "name", "unknown"),
                          "public": public,
                          "detail": "allow_blob_public_access=true" if public else "no blob public access"})
    except Exception as e:
        return items, f"Azure storage poll failed: {e}"
    return items, ""


def _cloud_posture_to_findings(items: list, mapping_data: dict) -> List[UnifiedFinding]:
    findings = []
    for item in items:
        if item.get("service") == "s3" and item.get("public"):
            findings.append(_create_network_finding(
                "CLOUD_S3_PUBLIC", "Publicly Exposed S3 Bucket", "HIGH",
                f"aws:s3:{item.get('resource')}", str(item.get("detail", ""))[:200],
                "Enable S3 Block Public Access (all four settings), remove public ACL "
                "grants/policy statements, and require least-privilege bucket policies "
                "(SOC 2 CC6.1).", mapping_data))
        elif item.get("service") == "gcs" and item.get("public"):
            findings.append(_create_network_finding(
                "CLOUD_STORAGE_PUBLIC", "Publicly Exposed GCP Bucket", "HIGH",
                f"gcp:gcs:{item.get('resource')}", str(item.get("detail", ""))[:200],
                "Remove allUsers/allAuthenticatedUsers IAM bindings and enforce uniform "
                "bucket-level access (SOC 2 CC6.1).", mapping_data))
        elif item.get("service") == "storage" and item.get("public"):
            findings.append(_create_network_finding(
                "CLOUD_STORAGE_PUBLIC", "Publicly Exposed Azure Storage Account", "HIGH",
                f"azure:storage:{item.get('resource')}", str(item.get("detail", ""))[:200],
                "Set allow_blob_public_access=false and gate access with private "
                "endpoints / RBAC (SOC 2 CC6.1).", mapping_data))
        elif item.get("service") == "iam" and item.get("public"):
            findings.append(_create_network_finding(
                "CLOUD_IAM_POLICY", "No IAM Password Policy", "MEDIUM",
                f"{item.get('provider')}:iam:{item.get('resource')}",
                str(item.get("detail", ""))[:200],
                "Enforce an account password policy (length, complexity, rotation, "
                "MFA) per SOC 2 CC6.1.", mapping_data))
    for f in findings:
        f.tool = "CloudPosture"
    return findings


def _posture_key(item: dict) -> str:
    return f"{item.get('provider')}:{item.get('service')}:{item.get('resource')}"


def _diff_cloud_posture(old: dict, new_items: list) -> List[str]:
    """Human-readable drift lines between a baseline snapshot ({key: item})
    and a fresh poll. Pure function for testability."""
    new = {_posture_key(i): i for i in new_items}
    drift = []
    for key in sorted(set(new) - set(old)):
        drift.append(f"new resource: {key} ({new[key].get('detail', '')})")
    for key in sorted(set(old) - set(new)):
        drift.append(f"resource disappeared: {key} (was: {old[key].get('detail', '')})")
    for key in sorted(set(old) & set(new)):
        if old[key] != new[key]:
            drift.append(f"resource changed: {key} "
                         f"({old[key].get('detail', '')} -> {new[key].get('detail', '')})")
    return drift


def run_cloud_posture(conf: dict, mapping_data: dict) -> List[UnifiedFinding]:
    """Live read-only cloud polling (AWS/GCP/Azure, env creds only) with a
    JSON snapshot baseline and diff-on-rerun drift findings (R-051). Missing
    creds/SDKs skip with a stderr message and NEVER fail the run; when nothing
    was polled the baseline is left untouched so a creds outage can't read as
    mass resource deletion on the next run.
    """
    conf = conf or {}
    if not conf.get("enabled"):
        return []
    print("Running live cloud posture checks...", file=sys.stderr)
    providers = [p.lower() for p in conf.get("providers", ["aws", "gcp", "azure"])]
    pollers = {"aws": _poll_aws, "gcp": _poll_gcp, "azure": _poll_azure}
    items: list = []
    for provider in providers:
        poller = pollers.get(provider)
        if poller is None:
            print(f"Unknown cloud provider '{provider}' - skipping", file=sys.stderr)
            continue
        try:
            polled, skip_reason = poller()
        except Exception as e:
            print(f"Cloud poll for {provider} failed: {e}", file=sys.stderr)
            continue
        if skip_reason:
            print(f"{provider}: {skip_reason}", file=sys.stderr)
        items.extend(polled)

    findings = _cloud_posture_to_findings(items, mapping_data)

    baseline_path = conf.get("baseline_file", "reports/cloud_posture_baseline.json")
    if not items:
        return findings  # nothing polled - leave any existing baseline alone
    old_snapshot = None
    if os.path.exists(baseline_path):
        try:
            with open(baseline_path, "r", encoding="utf-8") as f:
                old_snapshot = json.load(f).get("posture", {})
        except Exception as e:
            print(f"Cloud baseline unreadable, re-baselining: {e}", file=sys.stderr)
    new_snapshot = {_posture_key(i): i for i in items}
    if isinstance(old_snapshot, dict):
        for line in _diff_cloud_posture(old_snapshot, items):
            drift_finding = _create_network_finding(
                "CLOUD_DRIFT", "Cloud Posture Drift", "HIGH", "cloud-baseline",
                line[:200],
                "Posture differs from the last snapshot: verify the change was an "
                "approved change (CC8.1) and update the baseline only after review "
                "(SOC 2 CC7.2/CC8.1).", mapping_data)
            drift_finding.tool = "CloudPosture"
            findings.append(drift_finding)
    try:
        parent = os.path.dirname(os.path.abspath(baseline_path))
        os.makedirs(parent, exist_ok=True)
        with open(baseline_path, "w", encoding="utf-8") as f:
            json.dump({"posture": new_snapshot}, f, indent=2)
    except Exception as e:
        print(f"Cloud baseline write failed: {e}", file=sys.stderr)
    return findings


# --- SBOM + license compliance (R-054) ---
_PERMISSIVE_LICENSE_DEFAULTS = [
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    "Python-2.0", "CC0-1.0", "Unlicense",
]
_COPYLEFT_LICENSE_RE = re.compile(
    r"GPL|AGPL|Affero|LGPL|Lesser General Public|CDDL|EPL|MPL|SSPL|"
    r"Commons Clause|General Public License", re.IGNORECASE)
_EU_CRA_NOTE = ("EU Cyber Resilience Act timing: in force since Sept 2024 with "
                "SBOM/product-security duties phasing in through 2027 - machine-readable "
                "SBOMs and license provenance are becoming a market-access requirement, "
                "not just hygiene.")


def _licenses_for_manifest(path: str, fname: str) -> dict:
    """Best-effort per-package licenses from the manifest itself. package.json
    declares the PROJECT's own license (recorded as SBOM metadata, never
    flagged); per-dependency licenses live in registries, not manifests, so
    deps resolve to 'unknown' unless the licenses.overrides config names them.
    """
    if fname != "package.json":
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    declared = {}
    for section in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"):
        deps = data.get(section, {}) or {}
        for name, spec in deps.items():
            if isinstance(spec, dict) and spec.get("license"):
                declared[name] = str(spec["license"])
    return declared


def _collect_sbom_components(target_dir: str) -> "tuple[list, str]":
    """Workspace-aware manifest walk reusing _LOCKFILE_PARSERS (same SKIP_DIRS
    noise exclusions as the OSV dependency audit). Returns (components,
    project_license)."""
    components = []
    seen = set()
    project_license = ""
    for dirpath, dirnames, filenames in os.walk(target_dir):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        npm_lock = bool(set(filenames) & _NPM_LOCKFILES)
        for fname in filenames:
            parser_info = _LOCKFILE_PARSERS.get(fname)
            if not parser_info:
                continue
            if fname == "package.json" and npm_lock:
                continue  # lockfile pins resolved versions; manifest ranges would double-count (§3.5)
            parser, ecosystem = parser_info
            file_path = os.path.join(dirpath, fname)
            if fname == "package.json" and not npm_lock:
                print(f"SBOM: {file_path} has no lockfile sibling - versions are manifest ranges, not resolved", file=sys.stderr)
            try:
                packages = parser(file_path)
            except Exception as e:
                print(f"SBOM: skipping unparsable {file_path}: {e}", file=sys.stderr)
                continue
            declared = _licenses_for_manifest(file_path, fname)
            if fname == "package.json":
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        top = json.load(f).get("license", "")
                    if top and not project_license:
                        project_license = str(top) if isinstance(top, str) else top.get("type", "")
                except Exception:
                    pass
            for pkg, ver, scope in (_split_pkg(p) for p in packages):
                key = (ecosystem, pkg, ver)
                if key in seen:
                    continue
                seen.add(key)
                components.append({
                    "name": pkg, "version": ver, "ecosystem": ecosystem,
                    "license": declared.get(pkg, "unknown"),
                    "scope": _SBOM_SCOPE.get(scope, "required"),
                    "file": os.path.relpath(file_path, target_dir),
                })
    components.sort(key=lambda c: (c["ecosystem"], c["name"], c["version"]))
    return components, project_license


def _write_sbom(components: list, project_license: str, sbom_conf: dict,
                target_dir: str) -> str:
    """Writes CycloneDX (default) or minimal SPDX JSON. Returns the path."""
    fmt = str(sbom_conf.get("format", "cyclonedx")).lower()
    default_name = ("sbom.spdx.json" if fmt == "spdx" else "sbom.cyclonedx.json")
    out_path = (sbom_conf.get("output")
                or os.path.join(target_dir, "reports", default_name))
    if not os.path.isabs(out_path):
        # A relative sbom.output belongs to the target, not the process
        # CWD - otherwise scanning another repo writes into the checkout
        # you happened to run from (run-3 section 3.6).
        out_path = os.path.join(target_dir, out_path)
    if fmt == "spdx":
        doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"auditforge-sbom-{os.path.basename(os.path.abspath(target_dir))}",
            "packages": [
                {"SPDXID": f"SPDXRef-Package-{i}",
                 "name": c["name"], "versionInfo": c["version"],
                 "supplier": f"ecosystem:{c['ecosystem']}",
                 "licenseDeclared": c["license"]}
                for i, c in enumerate(components, 1)
            ],
        }
    else:
        doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {"project_license": project_license or "unknown",
                         "note": _EU_CRA_NOTE},
            "components": [
                {"type": "library", "name": c["name"], "version": c["version"],
                 "scope": c["scope"], "ecosystem": c["ecosystem"],
                 "licenses": ([] if c["license"] == "unknown"
                              else [{"license": {"id": c["license"]}}])}
                for c in components
            ],
        }
    parent = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(parent, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    return out_path


def run_sbom_audit(target_dir: str, sbom_conf: dict, licenses_conf: dict,
                   mapping_data: dict) -> List[UnifiedFinding]:
    """SBOM generation + license compliance (R-054). Always writes the SBOM
    file when manifests are found; flags copyleft licenses HIGH and (only when
    licenses.flag_unknown_licenses is set) unknown licenses LOW against the
    licenses.allowlist. Never fails when no manifests exist.
    """
    sbom_conf = sbom_conf or {}
    licenses_conf = licenses_conf or {}
    if not sbom_conf.get("enabled"):
        return []
    print("Generating SBOM and checking license compliance...", file=sys.stderr)
    components, project_license = _collect_sbom_components(target_dir)
    if not components:
        print("SBOM: no manifests found - skipping", file=sys.stderr)
        return []
    try:
        out_path = _write_sbom(components, project_license, sbom_conf, target_dir)
        print(f"SBOM written to {out_path} ({len(components)} components)", file=sys.stderr)
    except Exception as e:
        print(f"SBOM write failed: {e}", file=sys.stderr)
        out_path = sbom_conf.get("output", "reports/sbom.cyclonedx.json")

    allowlist = set(licenses_conf.get("allowlist", _PERMISSIVE_LICENSE_DEFAULTS))
    overrides = licenses_conf.get("overrides", {}) or {}
    flag_unknown = bool(licenses_conf.get("flag_unknown_licenses", False))
    findings = []
    for comp in components:
        lic = overrides.get(comp["name"], comp["license"])
        where = f"{comp['file']} ({comp['ecosystem']}/{comp['name']}@{comp['version']})"
        if lic != "unknown" and _COPYLEFT_LICENSE_RE.search(lic):
            findings.append(_create_network_finding(
                "SBOM_COPYLEFT_LICENSE", "Copyleft-Licensed Dependency", "HIGH", where,
                f"Declared license '{lic}' is copyleft and not in the allowlist.",
                f"Replace with a permissively-licensed alternative, isolate behind a "
                f"service boundary with legal review, or add an explicit exception. "
                f"{_EU_CRA_NOTE} (SOC 2 CC8.1).", mapping_data))
        elif lic != "unknown" and lic not in allowlist:
            findings.append(_create_network_finding(
                "SBOM_LICENSE_UNKNOWN", "Non-Allowlisted License", "LOW", where,
                f"Declared license '{lic}' is not in licenses.allowlist.",
                f"Confirm the license is acceptable and add it to "
                f"licenses.allowlist, or replace the dependency. {_EU_CRA_NOTE} "
                f"(SOC 2 CC8.1).", mapping_data))
        elif lic == "unknown" and flag_unknown:
            findings.append(_create_network_finding(
                "SBOM_LICENSE_UNKNOWN", "Unknown Dependency License", "LOW", where,
                "No license declared in the manifest and none in licenses.overrides.",
                f"Resolve the upstream license (PyPI/npm registry metadata) and record "
                f"it in licenses.overrides, or add an exception. {_EU_CRA_NOTE} "
                f"(SOC 2 CC8.1).", mapping_data))
    for f in findings:
        f.tool = "SBOM"
        f.file = f"{out_path}: {f.file}"
    return findings


# --- Nuclei scanner (live-target template scan) ---
_NUCLEI_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _nuclei_severity(raw: object) -> str:
    sev = str(raw or "").upper()
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        return sev
    return "LOW"


def _nuclei_event_to_findings(event: dict, mapping_data: dict) -> List[UnifiedFinding]:
    info = event.get("info", {})
    if not isinstance(info, dict):
        info = {}
    template_id = str(event.get("template-id") or event.get("templateID")
                      or "NUCLEI_UNKNOWN")
    severity = _nuclei_severity(info.get("severity"))
    name = str(info.get("name") or template_id)
    host = str(event.get("matched-at") or event.get("host") or "")
    refs = info.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    remediation = str(info.get("remediation") or "")
    if not remediation and refs:
        remediation = "See: " + ", ".join(str(r) for r in refs[:3])
    snippet = str(info.get("description", "") or "")[:200]
    if not snippet:
        tags = info.get("tags") or []
        snippet = ("tags: " + ",".join(str(t) for t in tags[:5])) if tags else template_id
    finding = UnifiedFinding(
        tool="Nuclei",
        rule_id=template_id,
        name=name,
        severity=severity,
        file=host,
        line=0,
        snippet=snippet,
        remediation=remediation,
    )
    finding.frameworks = mapping_data.get("mappings", {}).get(template_id, [])
    if not finding.frameworks:
        finding.frameworks = mapping_data.get("mappings", {}).get(
            "NUCLEI_TEMPLATE", ["SOC2:CC7.1", "NIST:SI-10"])
    return [finding]


def run_nuclei(targets: list, mapping_data: dict,
               conf: "Optional[dict]" = None) -> List[UnifiedFinding]:
    """Runs `nuclei -u <target>` (ProjectDiscovery template scanner, OSS, no
    API key) against each live target. Same skip contract as run_trivy:
    disabled config, missing binary, or still-placeholder network_targets all
    skip with a stderr message instead of failing. Findings are per matched
    template; rule_id is the template-id with a NUCLEI_TEMPLATE framework
    fallback, same shape as run_trivy's CVE rule_ids.
    """
    conf = conf or {}
    if not conf.get("enabled"):
        return []
    if not targets:
        return []
    if set(targets) <= PLACEHOLDER_NETWORK_TARGETS:
        print(
            "Nuclei skipped: network_targets is still the placeholder example.com "
            "default - set real targets (or pass --network-targets) to run template scans.",
            file=sys.stderr,
        )
        return []
    if not _tool_available("nuclei"):
        print("Nuclei not installed - skipping (external engine unavailable)", file=sys.stderr)
        return []
    sev_filter = str(conf.get("severity", "") or "").lower().strip()
    if sev_filter:
        wanted = {part.strip() for part in sev_filter.split(",") if part.strip()}
        if not wanted or not wanted <= set(_NUCLEI_SEVERITIES):
            print(f"Nuclei: ignoring invalid severity filter {sev_filter!r} "
                  f"(use a subset of {','.join(_NUCLEI_SEVERITIES)})", file=sys.stderr)
            sev_filter = ""
    findings: List[UnifiedFinding] = []
    for target in targets:
        print(f"Running Nuclei on {target}...", file=sys.stderr)
        try:
            cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-nc"]
            if sev_filter:
                cmd.extend(["-severity", sev_filter])
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    encoding="utf-8", errors="ignore", timeout=_engine_timeout(conf))
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except Exception:
                    continue
                if isinstance(event, dict):
                    findings.extend(_nuclei_event_to_findings(event, mapping_data))
        except Exception as e:
            print(f"Nuclei failed on {target}: {e}", file=sys.stderr)
    return findings


# --- TLS / cipher posture (protocol pillar; stdlib ssl, no new binary) ---
_TLS_WEAK_CIPHER_RE = re.compile(
    r"RC4|DES-CBC|_DES_|3DES|MD5|NULL|anon|ADH|AECDH|EXPORT|aNULL|eNULL",
    re.IGNORECASE,
)
_TLS_WEAK_VERSIONS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})
_TLS_PLACEHOLDER_HOSTS = frozenset({"example.com", "api.example.com"})
_TLS_EXPIRY_SOON_DAYS = 30


def _tls_hostport(target: str):
    """(host, port) for a network_targets entry, or None for placeholders
    and unparseable values - mirrors run_network_audit's placeholder skip."""
    t = (target or "").strip()
    if not t or t in PLACEHOLDER_NETWORK_TARGETS:
        return None
    t = re.sub(r"^https?://", "", t, flags=re.IGNORECASE).split("/")[0]
    if "@" in t:
        return None
    if ":" in t:
        host, _, port = t.rpartition(":")
        try:
            port_n = int(port)
        except ValueError:
            return None
    else:
        host, port_n = t, 443
    host = host.strip().lower().strip("[]")
    if not host or host in _TLS_PLACEHOLDER_HOSTS:
        return None
    return host, port_n


def _tls_finding(rule_id: str, name: str, severity: str, target: str,
                 snippet: str, mapping_data: dict, remediation: str) -> UnifiedFinding:
    finding = UnifiedFinding(tool="TLS", rule_id=rule_id, name=name,
                             severity=severity, file=target, line=0,
                             snippet=snippet, remediation=remediation)
    finding.frameworks = mapping_data.get("mappings", {}).get(rule_id, [])
    return finding


def _cert_matches_host(cert: dict, host: str) -> bool:
    """Explicit hostname check (ssl.match_hostname was removed in 3.12).
    SAN dNSName entries first, CN fallback; leading wildcard matches one
    label; IP literals match iPAddress SANs. No names at all means the
    endpoint cannot be authenticated - report mismatch."""
    import ipaddress as _ip
    host = (host or "").lower().rstrip(".")
    try:
        host_ip = _ip.ip_address(host)
    except ValueError:
        host_ip = None
    names = []
    for typ, val in cert.get("subjectAltName", ()) or []:
        t = str(typ).lower()
        if t == "dns":
            names.append(("dns", str(val).lower().rstrip(".")))
        elif t == "ipaddress":
            names.append(("ip", str(val)))
    if not names:
        for rdn in cert.get("subject", ()) or []:
            for key, val in rdn:
                if str(key).lower() == "commonname":
                    names.append(("dns", str(val).lower().rstrip(".")))
    if not names:
        return False
    for kind, pattern in names:
        if kind == "ip":
            try:
                if host_ip is not None and _ip.ip_address(pattern) == host_ip:
                    return True
            except ValueError:
                continue
        elif pattern.startswith("*."):
            if host.count(".") == pattern.count(".") and host.endswith(pattern[1:]):
                return True
        elif host == pattern:
            return True
    return False


def run_tls_audit(targets: list, mapping_data: dict,
                  tls_conf: "Optional[dict]" = None) -> List[UnifiedFinding]:
    """TLS posture per host: negotiated version, cipher strength, certificate
    expiry and hostname match - stdlib ssl only, so there is no new binary
    to install. Placeholder example.com defaults are never dialed (R-036).
    Unreachable hosts skip with a stderr note; only established handshakes
    can produce findings."""
    conf = tls_conf or {}
    if not conf.get("enabled", True):
        return []
    try:
        timeout = int(conf.get("timeout", 10))
    except (ValueError, TypeError):
        timeout = 10
    findings = []
    for target in targets or []:
        hp = _tls_hostport(target)
        if hp is None:
            continue
        host, port = hp
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            with socket.create_connection((host, port), timeout=timeout) as raw:
                try:
                    raw_sock = ctx.wrap_socket(raw, server_hostname=host)
                except ssl.CertificateError:
                    findings.append(_tls_finding(
                        "TLS_CERT_HOSTNAME_MISMATCH", "Certificate hostname mismatch",
                        "HIGH", target, f"{label} certificate does not match the host.",
                        mapping_data, f"Serve a certificate valid for {host} "
                        "(SAN entry); clients cannot authenticate this endpoint."))
                    continue
                with raw_sock as sock:
                    version = sock.version() or ""
                    cipher = (sock.cipher() or [None])[0] or ""
                    cert = sock.getpeercert() or {}
        except (OSError, ssl.SSLError) as exc:
            print(f"TLS audit skipped for {host}:{port}: {exc}", file=sys.stderr)
            continue
        label = f"{host}:{port}"
        if version in _TLS_WEAK_VERSIONS:
            findings.append(_tls_finding(
                "TLS_WEAK_VERSION", f"Legacy {version} negotiated", "HIGH",
                target, f"{label} negotiated {version}; require TLS 1.2+.",
                mapping_data, f"Disable {version} on {label}; enforce TLS 1.2 "
                "or higher on every listener."))
        if _TLS_WEAK_CIPHER_RE.search(cipher):
            findings.append(_tls_finding(
                "TLS_WEAK_CIPHER", f"Weak cipher {cipher}", "HIGH",
                target, f"{label} negotiated cipher {cipher}.",
                mapping_data, f"Remove {cipher} from {label}'s cipher list; "
                "prefer AEAD suites (AES-GCM/ChaCha20-Poly1305)."))
        not_after = (cert.get("notAfter", "") or "").strip()
        if not_after:
            try:
                import datetime as _dt
                remaining = (_dt.datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(not_after),
                    tz=_dt.timezone.utc) - _dt.datetime.now(_dt.timezone.utc))
                if remaining.total_seconds() <= 0:
                    findings.append(_tls_finding(
                        "TLS_CERT_EXPIRED", "Certificate expired", "CRITICAL",
                        target, f"{label} certificate expired {not_after}.",
                        mapping_data, f"Replace the expired certificate on "
                        f"{label} immediately and automate renewal."))
                elif remaining.days < _TLS_EXPIRY_SOON_DAYS:
                    findings.append(_tls_finding(
                        "TLS_CERT_EXPIRING_SOON", "Certificate expiring soon",
                        "MEDIUM", target, f"{label} certificate expires "
                        f"{not_after} ({remaining.days}d).",
                        mapping_data, f"Renew the {label} certificate before "
                        "expiry; automate renewal with monitoring."))
            except (ValueError, OSError):
                pass
        if not _cert_matches_host(cert, host):
            findings.append(_tls_finding(
                "TLS_CERT_HOSTNAME_MISMATCH", "Certificate hostname mismatch",
                "HIGH", target, f"{label} certificate does not match the host.",
                mapping_data, f"Serve a certificate valid for {host} "
                "(SAN entry); clients cannot authenticate this endpoint."))
    return findings


# --- OpenSSF Scorecard \(supply-chain posture, incl\. SLSA-relevant checks\) ---
_GITHUB_REMOTE_RE = re.compile(
    r"github\.com[:/](?P<slug>[^/]+/[^/]+?)(?:\.git)?\s*$", re.IGNORECASE)
_SLSA_CHECKS = frozenset({"Signed-Releases", "Binary-Artifacts",
                           "Pinned-Dependencies", "Dangerous-Workflow"})
_SLSA_NOTE = ("SLSA relevance: this check gates SLSA-level supply-chain integrity "
               "(hermetic, attested builds) - consider SLSA provenance generation "
               "(https://slsa.dev) for release artifacts.")


def _github_slug(target_dir: str) -> "Optional[str]":
    """owner/repo slug from the target checkout's git origin, or None when the
    target is not a GitHub checkout (scorecard --repo needs a GitHub slug; a
    missing git binary or a non-GitHub remote is a skip, not a failure)."""
    try:
        result = subprocess.run(
            ["git", "-C", target_dir, "remote", "get-url", "origin"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore")
    except (OSError, FileNotFoundError):
        return None
    if result.returncode != 0:
        return None
    match = _GITHUB_REMOTE_RE.search((result.stdout or "").strip())
    return match.group("slug") if match else None


def run_scorecard(target_dir: str, conf: dict, mapping_data: dict) -> List[UnifiedFinding]:
    """Runs `scorecard --repo=<slug> --format=json` (OpenSSF, OSS). Auth, if
    needed, comes from the GITHUB_AUTH_TOKEN env var inherited by the
    subprocess - never from config, never logged. Checks scoring below
    conf min_score (default 7 on the 0-10 scale) become findings; inconclusive
    checks (score -1) are skipped, not flagged.
    """
    if not conf.get("enabled"):
        return []
    if not _tool_available("scorecard"):
        print("Scorecard not installed - skipping (external engine unavailable)", file=sys.stderr)
        return []
    slug = _github_slug(target_dir)
    if not slug:
        print("Scorecard skipped: target is not a GitHub checkout "
              "(no github.com git origin to score) - skipping", file=sys.stderr)
        return []
    try:
        min_score = int(conf.get("min_score", 7))
    except (ValueError, TypeError):
        min_score = 7
    print(f"Running OpenSSF Scorecard on {slug}...", file=sys.stderr)
    findings = []
    try:
        cmd = ["scorecard", f"--repo={slug}", "--format=json"]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding="utf-8", errors="ignore", timeout=_engine_timeout(conf))
        if not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
    except Exception as e:
        print(f"Scorecard failed on {slug}: {e}", file=sys.stderr)
        return []
    checks = data.get("checks", []) if isinstance(data, dict) else []
    for check in checks:
        if not isinstance(check, dict):
            continue
        name = str(check.get("name") or check.get("checkName") or "UNKNOWN")
        try:
            score = int(check.get("score", -1))
        except (ValueError, TypeError):
            continue
        if score < 0 or score >= min_score:
            continue
        severity = "HIGH" if score <= 3 else ("MEDIUM" if score <= 6 else "LOW")
        rule_id = "SCORECARD_" + re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")
        reason = str(check.get("reason", "") or "")[:200]
        remediation = (f"Raise OpenSSF Scorecard check '{name}' "
                       f"(score {score}/10, threshold {min_score}): "
                       f"https://github.com/ossf/scorecard")
        if name in _SLSA_CHECKS:
            remediation += f" | {_SLSA_NOTE}"
        finding = UnifiedFinding(
            tool="Scorecard",
            rule_id=rule_id,
            name=f"Scorecard: {name} ({score}/10)",
            severity=severity,
            file=slug,
            line=0,
            snippet=reason or f"Score {score}/10 on {name}",
            remediation=remediation,
        )
        finding.frameworks = mapping_data.get("mappings", {}).get(rule_id, [])
        if not finding.frameworks:
            finding.frameworks = mapping_data.get("mappings", {}).get(
                "SCORECARD_LOW_SCORE", ["SOC2:CC8.1", "NIST:CM-14"])
        findings.append(finding)
    return findings


# --- TruffleHog verified-secret scan ---
def _trufflehog_events(stdout: str) -> list:
    """TruffleHog emits newline-delimited JSON (one object per detection)."""
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        whole = json.loads(text)
        if isinstance(whole, list):
            return [e for e in whole if isinstance(e, dict)]
        if isinstance(whole, dict):
            return [whole]
    except Exception:
        pass
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except Exception:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def run_trufflehog(target_dir: str, conf: dict, mapping_data: dict) -> List[UnifiedFinding]:
    """Runs `trufflehog filesystem --json --only-verified` (OSS, no API key).
    Only verifier-confirmed credentials are reported - unverified candidates
    are dropped even if the binary ever ignores the flag. Raw secret values
    NEVER enter findings or logs (snippet names detector + location only);
    every finding is HIGH (a live credential must be rotated, SOC 2 CC6.1).
    """
    if not conf.get("enabled"):
        return []
    if not _tool_available("trufflehog"):
        print("TruffleHog not installed - skipping (external engine unavailable)", file=sys.stderr)
        return []
    print("Running TruffleHog (verified-only scan)...", file=sys.stderr)
    findings = []
    try:
        cmd = ["trufflehog", "filesystem", target_dir, "--json", "--only-verified"]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding="utf-8", errors="ignore", timeout=_engine_timeout(conf))
        events = _trufflehog_events(result.stdout)
    except Exception as e:
        print(f"TruffleHog failed: {e}", file=sys.stderr)
        return []
    for event in events:
        if not event.get("Verified"):
            continue
        detector = str(event.get("DetectorName") or event.get("Detector") or "unknown")
        meta = event.get("SourceMetadata", {}) or {}
        data_meta = (meta.get("Data") or {}) if isinstance(meta, dict) else {}
        fs_meta = (data_meta.get("Filesystem") or {}) if isinstance(data_meta, dict) else {}
        raw_file = str(fs_meta.get("file", "") or "")
        try:
            shown_file = os.path.relpath(raw_file, target_dir) if raw_file else ""
        except Exception:
            shown_file = raw_file
        try:
            line_no = int(fs_meta.get("line", 0) or 0)
        except (ValueError, TypeError):
            line_no = 0
        finding = UnifiedFinding(
            tool="TruffleHog",
            rule_id="TRUFFLEHOG_VERIFIED_SECRET",
            name=f"Verified {detector} credential",
            severity="HIGH",
            file=shown_file or target_dir,
            line=line_no,
            snippet=(f"Verified live {detector} credential at "
                     f"{shown_file or '?'}:{line_no} "
                     f"(secret value withheld - rotate immediately)"),
            remediation=(f"Revoke/rotate this {detector} credential now, purge it "
                         f"from history (it is verifier-confirmed live), and move "
                         f"callers to env-stored secrets or a manager (SOC 2 CC6.1)."),
        )
        finding.frameworks = mapping_data.get("mappings", {}).get(
            "TRUFFLEHOG_VERIFIED_SECRET", [])
        if not finding.frameworks:
            finding.frameworks = ["SOC2:CC6.1", "NIST:SC-28"]
        findings.append(finding)
    return findings
