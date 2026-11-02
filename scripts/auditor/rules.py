import re
from .models import Rule

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt",
    ".rb", ".php", ".cs", ".c", ".cpp", ".h", ".hpp", ".swift", ".scala",
    ".sh", ".ps1", ".sql",
}
IAC_EXTENSIONS = {".tf", ".tfvars", ".yaml", ".yml", ".json", ".hcl", ".toml"}
CONFIG_EXTENSIONS = IAC_EXTENSIONS | {".env", ".ini", ".cfg", ".conf", ".properties", ".xml"}
# Basenames that carry security-headers config (server _headers file,
# platform configs, server configs). Shared by WEB002 filenames and the
# posture lane's header discovery - run-3 section 3.7 / 4.1.
_WEB_HEADERS_FILES = frozenset({
    "_headers", "vercel.json", "netlify.toml", "next.config.js",
    "next.config.mjs", "next.config.ts", "nginx.conf", "caddyfile",
    "web.config",
})

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", "vendor",
    "dist", "build", "out", "target", ".next", ".nuxt", ".venv", "venv",
    "env", ".tox", ".mypy_cache", ".pytest_cache", "coverage", ".idea",
    ".vscode", "bin", "obj", ".terraform", "graphify-out",
    # Derived local cache of third-party regulatory HTML (see .gitignore):
    # not project-owned code, so the self-audit gate must not scan it.
    "document_cache",
}
SKIP_FILES = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock",
    "cargo.lock", "composer.lock", "gemfile.lock", "go.sum",
}
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip",
    ".gz", ".tar", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
    ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".pyc", ".min.js",
    ".map", ".lock", ".sum",
    # Derived SQLite stores (document_catalog.db, vector_index.db - see
    # .gitignore): chunked third-party text, not project-owned code.
    ".db", ".sqlite", ".sqlite3",
}
MAX_FILE_BYTES = 1_500_000
SUPPRESS_TOKEN = "soc2-ignore"

# Paths that indicate test/demo/documentation context
TEST_PATH_RE = re.compile(
    r"(?i)(^|[\\/])(tests?|specs?|__tests__|__mocks__|fixtures?|examples?|"
    r"samples?|mocks?|docs?|demo)([\\/]|$)|\.(test|spec)\.[a-z]+$"
    r"|(^|[\\/])(test_[^\\/]+|[^\\/]+_test|conftest)\.py$"
)

# Values that are clearly placeholders, not real secrets.
PLACEHOLDER_RE = re.compile(
    r"(?i)(\$\{|\{\{|%\(|<[^>]*>|\bexample\b|\bsample\b|change[_-]?me|"
    r"placeholder|your[_-]|dummy|\bfake\b|\bxxx+\b|\*\*\*|\btodo\b|\bfixme\b|"
    r"redacted|insert[_-]|^\.{3,}$|^x+$|^\*+$|"
    r"^(?:resource|chrome|about|file|https?|wss?|jar|data):|"  # URIs
    r"\bsecret\b|\bpassword\b|\bzippity\b|\bmock\b|\bapi[_-]?key\b)"  # Literal common placeholders
)

# RFC 2606 / RFC 6761 reserved-purpose suffixes plus common non-routable
# pseudo-host suffixes: matches here are never a live external target, so
# PII001/NET001/NET004 skip them instead of forcing users to obfuscate real
# test fixtures. See docs/field-test-roninai-2026-08-25.md §G5/G7.
RESERVED_SUFFIX_RE = re.compile(
    # Dotted suffixes: api.example, svc.test, thing.internal, ...
    r"(?i)\.(test|example|localhost|invalid|local|ipc|internal)\b"
    # Bare RFC 2606 documentation domains: user@example.com has no dot
    # before "example", so the suffix arm above never fires on it.
    r"|@example\.(com|net|org)\b"
)


def is_comment(line: str, ext: str) -> bool:
    """Check if a line looks like a comment in the given file type."""
    s = line.lstrip()
    if not s:
        return False
    if ext in {".py", ".sh", ".rb", ".yml", ".yaml", ".tf", ".tfvars", ".toml", ".ini", ".cfg", ".conf", ".properties"}:
        return s.startswith("#")
    if ext in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt", ".cs", ".c", ".cpp", ".h", ".hpp", ".scala"}:
        return s.startswith("//") or s.startswith("/*") or s.startswith("*")
    if ext == ".sql":
        return s.startswith("--") or s.startswith("/*")
    if ext in {".xml", ".html", ".xhtml"}:
        return s.startswith("<!--")
    return False


def downgrade(severity: str) -> str:
    idx = min(SEVERITY_RANK[severity] + 1, len(SEVERITIES) - 1)
    return SEVERITIES[idx]


def _r(*patterns):
    return tuple(re.compile(p) for p in patterns)


RULES = [
    # ---------------- Secrets management (CC6.1) ----------------
    Rule(
        id="SEC001", name="Hardcoded Secret Assignment", severity="CRITICAL",
        controls=("CC6.1",),
        patterns=_r(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|"
            r"auth[_-]?token|client[_-]?secret|private[_-]?key|credential)s?\b"
            r"\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]"
        ),
        value_group=2,
        extensions=frozenset(CODE_EXTENSIONS | CONFIG_EXTENSIONS) - frozenset({".webidl", ".properties", ".json", ".yaml", ".yml", ".lock"}),
        remediation="Move the value to an environment variable or a managed "
                    "secret store (AWS Secrets Manager, Vault).",
    ),
    Rule(
        id="SEC002", name="AWS Access Key ID", severity="CRITICAL",
        controls=("CC6.1",),
        patterns=_r(r"\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        remediation="Revoke the key immediately and rotate credentials; use "
                    "IAM roles or AWS Secrets Manager instead.",
    ),
    Rule(
        id="SEC003", name="Private Key Material", severity="CRITICAL",
        controls=("CC6.1",),
        patterns=_r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----[\s\w+/=]{16,}"),
        extensions=frozenset(CODE_EXTENSIONS | CONFIG_EXTENSIONS | {".txt", ".key", ".pem"}) - frozenset({".webidl", ".properties"}),
        remediation="Remove the private key from the repository, rotate it, "
                    "and store key material in a secret manager or HSM.",
    ),
    Rule(
        id="SEC004", name="GitHub Token", severity="CRITICAL",
        controls=("CC6.1",),
        patterns=_r(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b",
                    r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        remediation="Revoke the token in GitHub settings and use fine-grained "
                    "tokens injected at runtime.",
    ),
    Rule(
        id="SEC005", name="Slack Token", severity="CRITICAL",
        controls=("CC6.1",),
        patterns=_r(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        remediation="Revoke the token in the Slack admin console and rotate.",
    ),
    Rule(
        id="SEC006", name="Stripe Live Secret Key", severity="CRITICAL",
        controls=("CC6.1",),
        patterns=_r(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
        remediation="Roll the key in the Stripe dashboard immediately.",
    ),
    Rule(
        id="SEC007", name="Google API Key", severity="HIGH",
        controls=("CC6.1",),
        patterns=_r(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        remediation="Restrict or regenerate the key in Google Cloud Console.",
    ),
    Rule(
        id="SEC008", name="Credentialed Connection String", severity="CRITICAL",
        controls=("CC6.1",),
        patterns=_r(
            r"\b\w{2,15}://[^/\s:@'\"]+:([^/\s@'\"]{4,})@[^/\s'\"]+"
        ),
        value_group=1,
        extensions=frozenset(CODE_EXTENSIONS | CONFIG_EXTENSIONS) - frozenset({".lock"}),
        remediation="Never embed credentials in a connection string; inject the "
                    "password via environment variable or secret store and build "
                    "the URI at runtime. Evidence: docs/field-test-roninai-2026-08-25.md §G1.",
    ),
    Rule(
        id="SEC009", name="Modern Secret Token Shape", severity="CRITICAL",
        controls=("CC6.1",),
        patterns=_r(
            r"\bsk-(?:proj|svcacct|ant)-[A-Za-z0-9_-]{20,}\b",  # OpenAI project/service, Anthropic
            r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{20,}\b",  # Anthropic (explicit prefix families)
            r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\b",  # raw JWT
        ),
        remediation="Revoke the token at its issuing provider and load it from a "
                    "secret store at runtime. Evidence: docs/field-test-roninai-2026-08-25.md §G8.",
    ),
    Rule(
        id="SEC010", name="User Input Into Mail Header",
        severity="HIGH",
        controls=("CC8.1",),
        patterns=_r(
            r"Mail\s*::\s*(to|cc|bcc|from)\s*\(\s*\$(request|_(GET|POST|REQUEST|COOKIE))",
            r"\.setHeader\s*\([^,]+,\s*req\.(query|body|params)",
            r"\.sendMail\s*\([^)]*req\.(query|body|params)",
        ),
        remediation="Request data is flowing into an email header or envelope - "
                    "an attacker can inject BCC/Subject lines. Validate against "
                    "an allowlist and strip CR/LF before handing to the mailer "
                    "(CWE-113). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="SEC011", name="Timing-Unsafe Secret Comparison",
        severity="MEDIUM",
        controls=("CC6.1",),
        patterns=_r(
            r"\b\w*(?i:token|secret|signature|hmac)\w*\s*(==|===|!=|!==)\s*\w*(?i:token|secret|signature|hmac)\w*",
        ),
        remediation="Two secret-shaped values are compared with ==/=== - use a "
                    "constant-time compare (crypto.timingSafeEqual, hmac.compare_digest, "
                    "hash_equals) so response time does not leak the secret. "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="SEC012", name="Prototype Pollution Sink",
        severity="MEDIUM",
        controls=("CC8.1",),
        patterns=_r(
            r"\[\s*[\"']__proto__[\"']\s*\]\s*=(?!=)",  # soc2-ignore: rule pattern text matches itself
            r"\{\s*[\"']?__proto__[\"']?\s*:",  # soc2-ignore: rule pattern text matches itself
            r"\.constructor\s*\[",
            r"\.prototype\s*\[",
        ),
        remediation="A __proto__/constructor/prototype write with a dynamic key "
                    "lets an attacker pollute every object - freeze the prototype, "
                    "validate keys against an allowlist (deny __proto__/constructor/prototype), "
                    "or use keyless maps. "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="SUPPRESS001", name="Unjustified Suppression",
        severity="LOW",
        controls=("CC8.1",),
        patterns=(),
        remediation="This soc2-ignore carries no justification - append a `: reason` "
                    "suffix naming why the finding is accepted (false positive, "
                    "accepted risk with expiry, compensating control). Bare "
                    "suppressions rot into blind spots. "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    # ---------------- Least privilege / IAM (CC6.1, CC6.3) ----------------
    Rule(
        id="IAM001", name="Wildcard IAM Permissions", severity="CRITICAL",
        controls=("CC6.1", "CC6.3"),
        patterns=_r(r"['\"]Action['\"]\s*:\s*['\"]\*['\"]",
                    r"['\"]Resource['\"]\s*:\s*['\"]\*['\"]",
                    r"(?i)\bactions?\s*=\s*\[\s*['\"]\*['\"]"),
        remediation="Scope IAM actions/resources to the minimum required; "
                    "wildcards violate least privilege.",
    ),
    # ---------------- Encryption at rest (CC6.1, CC6.7) ----------------
    Rule(
        id="ENC001", name="Encryption Disabled (IaC)", severity="HIGH",
        controls=("CC6.1", "CC6.7"),
        patterns=_r(r"(?i)\bencrypted\s*[:=]\s*false\b",
                    r"(?i)\bstorage_encrypted\s*[:=]\s*false\b",
                    r"(?i)\bkms_key_id\s*[:=]\s*null\b",
                    r"(?i)\bsse_algorithm\s*[:=]\s*['\"]?none\b"),
        extensions=frozenset(IAC_EXTENSIONS | CODE_EXTENSIONS),
        remediation="Enable encryption at rest (e.g. AES-256 via KMS / CMK).",
    ),
    Rule(
        id="ENC002", name="Publicly Readable Storage ACL", severity="HIGH",
        controls=("CC6.1", "CC6.6"),
        patterns=_r(r"(?i)\bacl\s*[:=]\s*['\"]public-read(-write)?['\"]"),
        remediation="Block public access on object storage; serve public "
                    "assets through a CDN with scoped origin access.",
    ),
    # ---------------- Encryption in transit (CC6.7) ----------------
    Rule(
        id="NET001", name="Cleartext Protocol Usage (IaC)", severity="MEDIUM",
        controls=("CC6.7",),
        patterns=_r(r"\bhttp://(?!localhost|127\.0\.0\.1)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
        extensions=frozenset(IAC_EXTENSIONS),
        check_reserved_suffix=True,
        remediation="Enforce HTTPS or secure protocol equivalents in IaC templates.",
    ),
    Rule(
        id="NET002", name="Disabled Certificate Verification", severity="CRITICAL",
        controls=("CC6.7",),
        patterns=_r(r"verify\s*=\s*False\b",
                    r"rejectUnauthorized\s*:\s*false\b",
                    r"InsecureRequestWarning",  # soc2-ignore: detection pattern text, not a call
                    r"disable_ssl_certificate_validation\s*=\s*True",
                    r"danger_accept_invalid_certs\s*\(\s*true\s*\)",  # Rust: reqwest
                    r"SslVerifyMode::NONE\b",  # Rust: native-tls / openssl-rs  # soc2-ignore: detection pattern text, not a call
                    r"InsecureSkipVerify\s*:\s*true\b"),  # Go: crypto/tls
        extensions=frozenset(CODE_EXTENSIONS),
        remediation="Enforce SSL/TLS certificate verification; disabling it allows MitM attacks. "
                    "Evidence for the Rust/Go patterns: docs/field-test-searchtool-2026-09-02.md §G16.",
    ),
    Rule(
        id="NET003", name="World-Open Ingress (Security Group)", severity="HIGH",
        controls=("CC6.6",),
        patterns=_r(r"(?i)\bcidr_blocks\s*=\s*\[\s*['\"]0\.0\.0\.0/0['\"]\s*\]"),
        extensions=frozenset(IAC_EXTENSIONS),
        remediation="Scope security groups to specific trusted source IPs/CIDRs; avoid 0.0.0.0/0.",
    ),
    Rule(
        id="NET004", name="Cleartext Protocol Usage (Code)", severity="MEDIUM",
        controls=("CC6.7",),
        patterns=_r(r"\bhttp://(?!localhost|127\.0\.0\.1)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
        extensions=frozenset(CODE_EXTENSIONS),
        check_reserved_suffix=True,
        remediation="Enforce HTTPS or secure protocol equivalents in application source code.",
    ),
    # ---------------- Secure SDLC (CC8.1) ----------------
    Rule(
        id="SDLC001", name="Dangerous Function Use (eval/exec)", severity="HIGH",
        controls=("CC8.1",),
        # (?<!\.) excludes receiver-shaped calls (`compiledRegex.exec(...)`,
        # a JS/TS RegExp stdlib method, not the dangerous global eval/exec) —
        # see docs/field-test-roninai-2026-08-25.md §G6.
        patterns=_r(r"(?<!\.)\beval\([^)]*\)", r"(?<!\.)\bexec\([^)]*\)"),
        extensions=frozenset(CODE_EXTENSIONS),
        remediation="Avoid eval/exec on dynamic inputs; use parser libraries or structured data formats.",
    ),
    Rule(
        id="SDLC002", name="SQL Query Construction via Concatenation", severity="CRITICAL",
        controls=("CC8.1",),
        patterns=_r(r"execute\s*\(\s*['\"].*%\s*\w+",
                    r"execute\s*\(\s*f['\"].*\{\s*\w+.*\}",
                    r"execute\s*\(\s*['\"].*\+\s*\w+"),
        extensions=frozenset(CODE_EXTENSIONS),
        remediation="Use parameterized queries / bind variables; never concatenate raw variables into SQL.",
    ),
    Rule(
        id="SDLC003", name="Dynamic Process/Command Construction", severity="HIGH",
        controls=("CC8.1",),
        patterns=_r(
            r"subprocess\.\w+\([^)]*shell\s*=\s*True",  # Python
            r"child_process\.exec\(\s*[^,'\")\s][^,)]*\+",  # Node: exec + concat  # soc2-ignore: detection pattern text, not a call
            r"child_process\.exec\(\s*(?:f|`)[^)]*\$\{",  # Node: exec template literal  # soc2-ignore: detection pattern text, not a call
            r"os/exec\.Command\([^)]*\+",  # Go: exec.Command(x + y)
            r"Command::new\([^)]*format!",  # Rust: Command::new + format!  # soc2-ignore: detection pattern text, not a call
        ),
        extensions=frozenset(CODE_EXTENSIONS),
        remediation="Never build a shell/process invocation by concatenating dynamic "
                    "input; pass arguments as a discrete array and avoid shell=True / "
                    "a shell intermediary. Evidence: docs/field-test-searchtool-2026-09-02.md §G13.",
    ),
    Rule(
        id="SDLC004", name="Unsafe/Low-Level Memory Operation", severity="LOW",
        controls=("CC8.1",),
        patterns=_r(r"\bunsafe\s*\{", r"\bunsafe\s+fn\b", r"\bmem::transmute\b",
                    r"\bstd::mem::transmute\b"),
        extensions=frozenset({".rs"}),
        remediation="`unsafe` disables Rust's borrow/type-safety guarantees for this "
                    "block — confirm the safety invariant is documented and reviewed, "
                    "not that it must be removed. Evidence: "
                    "docs/field-test-searchtool-2026-09-02.md §G12 (9 unverified unsafe "
                    "blocks found with zero prior signal from this scanner).",
    ),
    Rule(
        id="SDLC005", name="Privileged/Insecure Container Config", severity="HIGH",
        controls=("CC6.1", "CC8.1"),
        patterns=_r(
            r"(?i)\bprivileged\s*:\s*true\b",
            r"/var/run/docker\.sock",
            r"(?i)^\s*image\s*:\s*[^\s]+:latest\b",
            r"(?i)\buser\s*:\s*[\"']?0[\"']?\s*$",
        ),
        extensions=frozenset({".yml", ".yaml"}),
        filenames=frozenset({"dockerfile"}),
        remediation="Avoid privileged containers, host Docker-socket mounts, floating "
                    "`:latest` tags, and root-user containers. "
                    "Evidence: docs/field-test-roninai-2026-08-25.md §G9.",
    ),
    # ---------------- PII & privacy (CC6.1) ----------------
    Rule(
        id="PRIV001", name="Third-Party Tracker Loaded",
        severity="MEDIUM",
        controls=("CC6.1",),
        patterns=_r(
            r"googletagmanager\.com/gtag/js",
            r"clarity\.ms/tag/",
            r"connect\.facebook\.net/\S*fbevents\.js",
            r"hotjar\.com",
            r"cdn\.segment\.com/analytics",
            r"cdn\.mxpnl\.com",
            r"posthog\.(init|capture)",
        ),
        remediation="A third-party tracker (analytics, session replay, ad "
                    "pixel) loads on this page - each one needs prior user "
                    "consent (GDPR Art.6 / CCPA) and a data-processing record. "
                    "Gate it behind the consent banner or remove it. "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="PRIV002", name="IP Address Written to Log Sink",
        severity="MEDIUM",
        controls=("CC6.1",),
        patterns=_r(
            r"(console\.(log|info|debug|warn|error)|logger?\.(info|debug|warn|error)|winston\.\w+|pino\.\w+|bunyan\.\w+)\s*\([^()]{0,200}?\b(ip|clientIp|client_ip|remoteAddr|remote_addr|xForwardedFor|x_forwarded_for)\b",
            r"\bINSERT\s+INTO\s+\w*log\w*\b[^;]{0,200}?\b(ip|clientIp|client_ip|remoteAddr|remote_addr)\b",
            r"(appendFileSync|appendFile)\s*\([^;]{0,160}?\.log\b[^;]{0,160}?\b(ip|clientIp|client_ip)\b",
        ),
        remediation="An IP address flows into a log sink (console/logger call, "
                    "log table, *.log append). Scrub or hash IPs at write time, "
                    "state the retention window in the privacy policy, and honor "
                    "deletion requests (GDPR Art.17). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="PRIV003", name="Cookie or Web Storage Write",
        severity="MEDIUM",
        controls=("CC6.1",),
        patterns=_r(
            r"document\.cookie\s*=[^=]",
            r"sessionStorage\.setItem\s*\(",
            r"localStorage\.setItem\s*\(",
        ),
        remediation="A cookie or web-storage entry is written - namespace it "
                    "(__Secure- / __Host- where applicable) and document the "
                    "eviction path so GDPR/CCPA deletion requests can reach it. "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="PII001", name="PII in Logs or Code", severity="HIGH",
        controls=("CC7.2",),
        patterns=_r(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", # Email
                    r"\b\d{3}-\d{2}-\d{4}\b"), # SSN (US)
        check_reserved_suffix=True,
        remediation="Ensure PII is never hardcoded or logged; use unique identifiers and scrub sensitive data.",
    ),
    Rule(
        id="CFG001", name="Debug Mode Enabled", severity="MEDIUM",
        controls=("CC7.1", "CC8.1"),
        patterns=_r(r"(?i)\bdebug\s*[:=]\s*true\b", r"\bDEBUG\s*=\s*True\b",
                    r"app\.run\([^)]*debug\s*=\s*True"),
        extensions=frozenset(CODE_EXTENSIONS | {".env", ".ini", ".cfg", ".conf"}),
        remediation="Disable debug mode outside local development; gate it "
                    "behind an environment variable.",
    ),
    # ---------------- Logging & monitoring (CC7.2) ----------------
    Rule(
        id="LOG001", name="Credential Written to Logs", severity="HIGH",
        controls=("CC7.2",),
        patterns=_r(r"(?i)(console\.(log|error|warn)|print|logger?\.(info|debug|"
                    r"warn|error))\s*\([^)]*\b(password|passwd|secret|api[_-]?key|"
                    r"auth[_-]?token|credit[_-]?card|ssn)\b"),
        extensions=frozenset(CODE_EXTENSIONS),
        remediation="Scrub credentials and PII from log statements (CC7.2 / "
                    "PII scrubbing mandate).",
    ),
]

EXTRA_RULES = [
    Rule(
        id="CICD001", name="Unpinned Third-Party GitHub Action", severity="MEDIUM",
        controls=("CC8.1",),
        patterns=_r(
            r"uses\s*:\s*[A-Za-z0-9_.\-]+/[^\s'\"@]+@(?![0-9a-fA-F]{40}(?![0-9a-fA-F]))[^\s'\"]+",
        ),
        extensions=frozenset({".yml", ".yaml"}),
        remediation="Pin third-party actions to a full commit SHA "
                    "(e.g. uses: owner/action@<40-char-sha>) instead of a "
                    "mutable tag or branch; tags/branches can be moved to "
                    "ship malicious code (supply-chain / CC8.1).",
    ),
    Rule(
        id="CICD002", name="Overly Broad GITHUB_TOKEN Permissions", severity="HIGH",
        controls=("CC6.1",),
        patterns=_r(
            r"(?i)permissions\s*:\s*write-all\b",
            r"(?i)\bcontents\s*:\s*write\b",
        ),
        extensions=frozenset({".yml", ".yaml"}),
        remediation="Scope GITHUB_TOKEN to the minimum each job needs "
                    "(default to read-only permissions, escalating single "
                    "scopes to write only where required); write-all violates "
                    "least privilege (CC6.1).",
    ),
    Rule(
        id="CICD003", name="Secret Interpolated into CI Run Script", severity="HIGH",
        controls=("CC6.1",),
        patterns=_r(
            r"run\s*:[\s\S]{0,400}?\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}",
            r"script\s*:[\s\S]{0,400}?[$][A-Za-z_]*(SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Za-z_]*",
            r"sh\s+['\"][^'\"]{0,300}?\$[A-Za-z_]*(SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Za-z_]*",
        ),
        extensions=frozenset({".yml", ".yaml"}),
        filenames=frozenset({"jenkinsfile"}),
        remediation="Never interpolate secrets into run:/script:/sh step text "
                    "(it can leak via logs or a compromised action); map the "
                    "secret to an env: entry and read it from the environment "
                    "at runtime (CC6.1).",
    ),
    Rule(
        id="LLM001", name="Untrusted Input in System Prompt / LLM Message", severity="HIGH",
        controls=("CC8.1",),
        patterns=_r(
            r"(?i)(system_prompt|system_message|system_instruction)\s*=\s*f['\"]",
            r"(?i)(system_prompt|system_message|system_instruction)\s*=\s*[^#\n]*\+",
            r"messages\s*=\s*\[[^\]]{0,500}?(\+\s*\w+|f['\"])",
            r"\bsystem\s*:\s*`[^`]{0,800}?\$\{",
            r"(?i)messages\s*:\s*\[[^\]]{0,800}?\$\{",
            r"\bsystem\s*:\s*[^,}\n]{0,200}?\+\s*\w+",
            r"\bsystem\s*=\s*f['\"]",
            r"\bsystem\s*=\s*[^#\n]{0,200}?\+\s*\w+",
            r"\bsystem\s*[:=]\s*(?![A-Z][A-Z0-9_]*\s*[,)}\]])(?![\"'`])(?!(?:process\.env|os\.environ|os\.getenv)\b)([A-Za-z_$][\w$]*)",
        ),
        extensions=frozenset(CODE_EXTENSIONS),
        remediation="Treat this as a direct prompt-injection sink (OWASP LLM "
                    "Top 10 LLM01:2025 Prompt Injection): never concatenate or "
                    "interpolate untrusted input into system prompts or LLM "
                    "message lists - keep instructions constant and pass "
                    "untrusted data as clearly delimited user-role content "
                    "with output validation (also see LLM05:2025 Improper "
                    "Output Handling).",
    ),
    Rule(
        id="LLM002", name="System Prompt Exposure", severity="MEDIUM",
        controls=("CC6.1",),
        patterns=_r(
            r"(?i)\b(return|print|console\.(log|error|warn)|logger?\.(info|debug|warn|error)|jsonify)\b\s*\(?[^()\n]{0,150}?\bsystem_prompt\b",
            r"(?i)f['\"][^'\"\n]{0,150}?\{\s*system_prompt\s*\}",
            r"(console\.(log|error|warn)|\breturn\b)\s*[(`]?[^()\n]{0,150}?\$\{\s*system\s*\}",
        ),
        extensions=frozenset(CODE_EXTENSIONS),
        remediation="Do not return, log, or render system-prompt text to "
                    "callers (OWASP LLM Top 10 LLM07:2025 System Prompt "
                    "Leakage); system instructions are confidential (CC6.1).",
    ),
    Rule(
        id="LLM004", name="LLM Output Rendered to HTML Sink",
        severity="HIGH",
        controls=("CC8.1",),
        patterns=_r(
            r"\.innerHTML\s*=\s*(model|llm|completion|message|response|generated|assistant|chat|reply|answer|content|output|text)\w*\b",
            r"set:html=\{\s*(model|llm|completion|message|response|generated|assistant|chat|reply|answer|content|output|text)\w*",
            r"\{\s*__html\s*:\s*(model|llm|completion|message|response|generated|assistant|chat|reply|answer|content|output|text)\w*",
            r"dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:\s*(model|llm|completion|message|response|generated|assistant|chat|reply|answer|content|output|text)\w*",  # soc2-ignore: rule pattern text matches itself
            r"v-html\s*=\s*\"(model|llm|completion|message|response|generated|assistant|chat|reply|answer|content|output|text)\w*\"",
            r"\{@html\s+(model|llm|completion|message|response|generated|assistant|chat|reply|answer|content|output|text)\w*",
            r"\.innerHTML\s*=\s*\w+\.(content|text|output)\b",
            r"set:html=\{\s*\w+\.(content|text)\b[^}]*\}",
        ),
        remediation="Model-generated text is flowing into an HTML sink "
                    "(innerHTML, set:html, dangerouslySetInnerHTML, v-html, "  # soc2-ignore: remediation prose names the sinks; not a sink
                    "{@html}) - render it as text or through the framework "
                    "escaper, and never let model output form markup, URLs, "
                    "or scripts without an allowlist (OWASP LLM Top 10 "
                    "LLM05:2025 Improper Output Handling; ASVS V1.2.1). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="LLM003", name="Unvalidated LLM Tool Output Executed", severity="HIGH",
        controls=("CC8.1",),
        patterns=_r(
            r"(?i)\bos\.(system|popen)\s*\([^()]{0,200}?\b(tool_output|tool_result|function_response|llm_output|model_output|agent_output|generated_code)\b",
            r"(?i)\bsubprocess\.\w+\s*\([^()]{0,300}?\b(tool_output|tool_result|function_response|llm_output|model_output|agent_output|generated_code)\b",
            r"(?i)\b(eval|exec)\s*\([^()]{0,200}?\b(tool_output|tool_result|function_response|llm_output|model_output|agent_output|generated_code)\b",
        ),
        extensions=frozenset(CODE_EXTENSIONS),
        remediation="Validate and constrain LLM tool/function-call outputs "
                    "before acting on them (OWASP LLM Top 10 LLM06:2025 "
                    "Excessive Agency, LLM05:2025 Improper Output Handling): "
                    "never pass model-generated text to a shell, subprocess, "
                    "eval/exec, or privileged operation without allowlist "
                    "validation and least-privilege execution (CC8.1).",
    ),
    Rule(
        id="K8S001", name="Insecure Kubernetes Pod Security Context", severity="HIGH",
        controls=("CC6.1", "CC8.1"),
        patterns=_r(
            r"(?i)\bprivileged\s*:\s*true\b",
            r"(?i)\bhost(PID|Network|IPC)\s*:\s*true\b",
            r"(?i)\ballowPrivilegeEscalation\s*:\s*true\b",
            r"(?i)\brunAsNonRoot\s*:\s*false\b",
            r"(?i)\brunAsUser\s*:\s*0\b",
        ),
        extensions=frozenset({".yml", ".yaml", ".json"}),
        remediation="Harden the pod securityContext per the CIS Kubernetes "
                    "Benchmark: never run privileged or with hostPID/hostNetwork/"
                    "hostIPC, set allowPrivilegeEscalation to false, and run as "
                    "a non-root user (runAsNonRoot true, runAsUser above zero); "
                    "also enforce readOnlyRootFilesystem and a seccompProfile "
                    "(restricted pod-security-standard) - absence of those "
                    "fields is not flagged by this presence-based check, so "
                    "verify them in review (CC6.1/CC8.1).",
    ),
    Rule(
        id="K8S002", name="Wildcard RBAC Verbs/Resources", severity="HIGH",
        controls=("CC6.1", "CC6.3"),
        patterns=_r(
            r"(?i)\bverbs\s*:\s*\[\s*['\"]\*['\"]",
            r"(?i)\bresources\s*:\s*\[\s*['\"]\*['\"]",
        ),
        extensions=frozenset({".yml", ".yaml", ".json"}),
        remediation="Scope RBAC rules to the minimum verbs/resources required "
                    "(least privilege, CC6.1/CC6.3); wildcard verbs or resources "
                    "grant full API control wherever the binding applies.",
    ),
    Rule(
        id="WEB001", name="Missing Security-Headers Config", severity="MEDIUM",
        controls=("CC6.7",),
        patterns=(),
        remediation="Ship a headers config (_headers, vercel.json, "
                    "netlify.toml, or equivalent) enforcing HSTS, a "
                    "Content-Security-Policy, X-Content-Type-Options: "
                    "nosniff, and frame-ancestors; verify with the ASVS "
                    "V3.4 checks (CC6.7).",
    ),
    Rule(
        id="WEB002", name="Report-Only Content Security Policy", severity="LOW",
        controls=("CC6.1",),
        patterns=_r(
            r"Content-Security-Policy-Report-Only",  # soc2-ignore: rule pattern text matches itself
        ),
        extensions=frozenset({""}),
        filenames=_WEB_HEADERS_FILES,

        remediation="Report-only mode collects telemetry but blocks nothing; "
                    "promote to an enforced Content-Security-Policy (keep "
                    "report-uri/report-to for signal) once clean (ASVS V3.4.7).",
    ),
    Rule(
        id="WEB003", name="DOM XSS Sink (innerHTML / set:html)", severity="MEDIUM",
        controls=("CC8.1",),
        patterns=_r(
            r"\.innerHTML\s*=\s*(?![\"'`\s])",  # soc2-ignore: rule pattern text matches itself
            r"set:html=\{",
            r"\.outerHTML\s*=\s*(?![\"'`\s])",  # soc2-ignore: rule pattern text matches itself
            r"\.insertAdjacentHTML\s*\([^,)]+,\s*(?![\"'`\s])",  # soc2-ignore: rule pattern text matches itself
            r"\bdocument\.write(ln)?\s*\((?![\"'`\s])",  # soc2-ignore: rule pattern text matches itself
            r"dangerouslySetInnerHTML",  # soc2-ignore: rule pattern text matches itself
            r"v-html\s*=",  # soc2-ignore: rule pattern text matches itself
            r"\{@html\s+(?![\"'`\s}])",  # soc2-ignore: rule pattern text matches itself
        ),
        remediation="Assigning non-literal HTML to innerHTML (or Astro "
                    "set:html) is a DOM-XSS sink; use textContent or the "
                    "framework escaping, and encode untrusted data per "
                    "ASVS V1.2.1/V1.2.3 (CC8.1).",
    ),
    Rule(
        id="WEB004", name="State-Changing API Route Without Rate Limiting",
        severity="MEDIUM",
        controls=("CC6.1",),
        patterns=(),
        remediation="Bind every state-changing route to a rate limiter "
                    "(per-endpoint quotas, 429s) to blunt credential-stuffing "
                    "and enumeration; see ASVS V2.4.1/V6.1.1 (CC6.1).",
    ),
    Rule(
        id="WEB005", name="State-Changing Handler Without Origin Check",
        severity="LOW",
        controls=("CC6.1",),
        patterns=(),
        remediation="Verify Origin/Referer (or a CSRF token) on "
                    "state-changing handlers so another site cannot drive "
                    "them through visitors browsers; see ASVS V3.4.2/V3.3.2 "
                    "(CC6.1).",
    ),
    Rule(
        id="WEB006", name="Weak Content-Security-Policy Value",
        severity="MEDIUM",
        controls=("CC6.7",),
        patterns=(),
        remediation="A Content-Security-Policy is configured but script-src "
                    "allows unsafe-inline with no hash, nonce, or "
                    "strict-dynamic fallback - any injected markup runs. "
                    "Remove unsafe-inline (hash or nonce every script) "
                    "or add strict-dynamic with nonces; see ASVS V3.4.3 "
                    "(CC6.7). Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="WEB007", name="CSP Without Violation Reporting",
        severity="LOW",
        controls=("CC6.1",),
        patterns=(),
        remediation="The Content-Security-Policy has no report-uri or report-to "
                    "directive, so real-world violations are invisible to the "
                    "operator. Add a reporting endpoint (and monitor it); see "
                    "ASVS V3.4.7 (CC6.1). Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="WEB008", name="Weak HSTS Value",
        severity="LOW",
        controls=("CC6.7",),
        patterns=(),
        remediation="Strict-Transport-Security is present but weak: use "
                    "max-age=31536000 (one year) or longer plus includeSubDomains "
                    "and preload (then submit to hstspreload.org); see ASVS V3.4.1 "
                    "(CC6.7). Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="WEB009", name="No Single Authentication Gate",
        severity="MEDIUM",
        controls=("CC6.1",),
        patterns=(),
        remediation="No single authentication gate (withAuth, requireAuth, "
                    "authenticate, verifyToken, or equivalent) was found in "
                    "the API middleware or route files. Every route doing its "
                    "own ad-hoc auth check drifts; put one gate in the "
                    "middleware chain (OWASP A01:2021, ASVS V3.2.2). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="WEB010", name="No Global Error Handler",
        severity="MEDIUM",
        controls=("CC7.1",),
        patterns=(),
        remediation="No global error handler (onError, handleError, "
                    "window.onerror, uncaughtException/unhandledRejection) "
                    "was found - framework defaults leak stack traces and "
                    "skip alerting. Add one handler that logs and returns a "
                    "generic response (OWASP A05:2021). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="WEB011", name="No Structured Logging Signal",
        severity="MEDIUM",
        controls=("CC7.1",),
        patterns=(),
        remediation="No structured logging signal (logger.*, console.*, "
                    "Sentry/captureException) was found in the API middleware "
                    "or route files. Rejected requests, errors, and auth "
                    "failures must be logged in one queryable shape (CC7.2). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="WEB012", name="No Request Size or Duration Bound",
        severity="LOW",
        controls=("CC6.1",),
        patterns=(),
        remediation="No request size or duration bound (bodyLimit, "
                    "maxBodySize, maxDuration, timeout) was found. Unbounded "
                    "bodies and runtimes are a resource-exhaustion vector; "
                    "set both (OWASP API4:2023). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="WEB013", name="Bot Challenge Without Server-Side Verification",
        severity="MEDIUM",
        controls=("CC6.1",),
        patterns=(),
        remediation="A bot-challenge widget (Turnstile / Cloudflare challenge) is "
                    "embedded but no server-side verification call (e.g. Turnstile "
                    "siteverify) was found - client-side-only checks are theater. "
                    "Verify the token server-side on every protected action "
                    "(OWASP A07:2021). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02.md.",
    ),
    Rule(
        id="WEB014", name="Oversized _headers Line",
        severity="HIGH",
        controls=("CC6.7",),
        patterns=(),
        remediation="A line in a _headers file is over 2000 characters - "
                    "Cloudflare Pages/Workers static assets silently ignore "
                    "such lines (workerd logs once at startup), so a long "
                    "hash/nonce CSP ships NO policy at all. Split the policy "
                    "across multiple path rules or shorten it (fewer hashes). "
                    "Check the built output too: build steps can expand "
                    "placeholders past the limit (OWASP A05:2021, ASVS V3.4.3). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02-run3.md.",
    ),
    Rule(
        id="WEB015", name="State-Changing Route Without Method Allowlist",
        severity="MEDIUM",
        controls=("CC6.1",),
        patterns=(),
        remediation="State-changing routes exist but no method allowlist was "
                    "found (405 handling, req.method/request.method check, "
                    "Allow response header). An endpoint that accepts any verb "
                    "invites method-confusion and CSRF-adjacent bypasses - "
                    "scope each route to its verbs (OWASP A01:2021, ASVS V3.2.2). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02-run3.md.",
    ),
    Rule(
        id="WEB016", name="State-Changing Route Without Content-Type Check",
        severity="LOW",
        controls=("CC6.1",),
        patterns=(),
        remediation="State-changing routes exist but no content-type "
                    "validation was found (415 handling, content-type header "
                    "comparison). Unguarded parsing invites smuggling and "
                    "mismatched-parser bugs - reject unexpected media types "
                    "explicitly (OWASP A05:2021). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02-run3.md.",
    ),
    Rule(
        id="WEB017", name="Missing security.txt",
        severity="LOW",
        controls=("CC6.1",),
        patterns=(),
        remediation="No security.txt was found at the repo root or under "
                    ".well-known/. Without a published contact, researchers "
                    "cannot report vulnerabilities responsibly - add one per "
                    "RFC 9116 (Contact + Expires). "
                    "Evidence: docs/field-test-seancarneywebsite-2026-11-02-run3.md.",
    ),
]

RULES.extend(EXTRA_RULES)

RULES_BY_ID = {r.id: r for r in RULES}
