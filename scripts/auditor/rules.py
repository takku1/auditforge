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
    r"(?i)\.(test|example|localhost|invalid|local|ipc|internal)\b"
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

RULES_BY_ID = {r.id: r for r in RULES}
