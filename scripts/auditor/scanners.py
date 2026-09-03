import os
import re
import bisect
import fnmatch
import shutil
import subprocess
import json
import sys
from typing import List, Any
from .models import Finding, Rule, UnifiedFinding
from .rules import (
    RULES, SKIP_DIRS, SKIP_FILES, SKIP_EXTENSIONS, MAX_FILE_BYTES,
    PLACEHOLDER_RE, RESERVED_SUFFIX_RE, TEST_PATH_RE, SUPPRESS_TOKEN,
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


def scan_file(path: str, rel: str) -> list:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return []
        with open(path, "rb") as fh:
            raw = fh.read()
        if is_binary(raw[:8192]):
            return []
        content = raw.decode("utf-8", errors="ignore")
    except OSError:
        return []

    ext = os.path.splitext(path)[1].lower()
    basename = os.path.basename(path).lower()
    line_starts = [0]
    for m in re.finditer(r"\n", content):
        line_starts.append(m.end())
    in_test = bool(TEST_PATH_RE.search(rel))

    findings = []
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
                    continue

                severity = downgrade(rule.severity) if in_test else rule.severity
                snippet = match.group(0).strip()
                if len(snippet) > 200:
                    snippet = snippet[:200] + "..."
                findings.append(Finding(
                    rule=rule, severity=severity, file=rel,
                    line=line_no, snippet=snippet, in_test_context=in_test,
                ))
    return findings


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
    }


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
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore', env=env)
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

        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore', env=env)
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
def run_trivy(target_dir: str, conf: dict, mapping_data: dict) -> List[UnifiedFinding]:
    if not conf.get("enabled"): return []
    if not _tool_available("trivy"):
        print("Trivy not installed - skipping (external engine unavailable)", file=sys.stderr)
        return []
    print("Running Trivy (Local OSS Mode)...", file=sys.stderr)
    findings = []
    try:
        cmd = ["trivy", "fs", "--format", "json", target_dir]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        if not result.stdout.strip():
            return []
        
        data = json.loads(result.stdout)
        results = data.get("Results", [])
        for res in results:
            target = res.get("Target", "")
            vulns = res.get("Vulnerabilities", [])
            for vuln in vulns:
                rule_id = vuln.get("VulnerabilityID", "DEP_VULN")
                severity = vuln.get("Severity", "MEDIUM")
                if severity == "UNKNOWN":
                    severity = "LOW"
                finding = UnifiedFinding(
                    tool="Trivy",
                    rule_id=rule_id,
                    name=f"Vulnerability in {vuln.get('PkgName')}",
                    severity=severity,
                    file=os.path.join(target_dir, target),
                    line=0,
                    snippet=f"Installed version: {vuln.get('InstalledVersion')}, Fixed version: {vuln.get('FixedVersion')}",
                    remediation=vuln.get("PrimaryURL", "")
                )
                finding.frameworks = mapping_data.get("mappings", {}).get(rule_id, [])
                if not finding.frameworks:
                    finding.frameworks = mapping_data.get("mappings", {}).get("DEP_VULN", ["SOC2:CC8.1", "NIST:CM-3"])
                findings.append(finding)
    except Exception as e:
        print(f"Trivy failed: {e}", file=sys.stderr)
    return findings


# --- OSV API Scanner ---
def run_dependency_audit(target_dir: str, conf: dict, mapping_data: dict) -> List[UnifiedFinding]:
    if not conf.get("enabled"): return []
    print("Running OSV API Real-Time Dependency Scan...", file=sys.stderr)
    
    findings = []
    req_txt = os.path.join(target_dir, "requirements.txt")
    pkg_json = os.path.join(target_dir, "package.json")
    
    if os.path.exists(req_txt):
        try:
            with open(req_txt, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "==" in line:
                        parts = line.split("==", 1)
                        pkg = parts[0].strip()
                        ver = parts[1].split("#")[0].strip()
                        findings.extend(_query_osv(pkg, ver, "PyPI", req_txt, target_dir, mapping_data))
        except Exception as e:
            print(f"Error parsing requirements.txt: {e}", file=sys.stderr)
            
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                pkg_data = json.load(f)
                dependencies = pkg_data.get("dependencies", {})
                devDependencies = pkg_data.get("devDependencies", {})
                all_deps = {**dependencies, **devDependencies}
                for pkg, ver in all_deps.items():
                    clean_ver = "".join(c for c in ver if c.isdigit() or c == "." or c == "-")
                    if len(clean_ver) >= 1:
                        findings.extend(_query_osv(pkg, clean_ver, "npm", pkg_json, target_dir, mapping_data))
        except Exception as e:
            print(f"Error parsing package.json: {e}", file=sys.stderr)
            
    return findings


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
                
                finding = UnifiedFinding(
                    tool="OSV-API",
                    rule_id=rule_id,
                    name=f"Vulnerability in {package_name}",
                    severity=severity,
                    file=os.path.relpath(file_path, target_dir),
                    line=0,
                    snippet=f"Ecosystem: {ecosystem}, Package: {package_name}, Version: {version} - {vuln.get('summary', 'No summary')}",
                    remediation=f"Upgrade package or check advisory: {vuln.get('id')} ({ecosystem}/{package_name})"
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


def run_network_audit(targets: list, mapping_data: dict) -> List[UnifiedFinding]:
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
    
    timeout_val = int(os.getenv("DAST_REQUEST_TIMEOUT", "10"))
    user_agent = os.getenv("DAST_USER_AGENT", "AuditForge/1.0")
    headers_payload = {"User-Agent": user_agent}
    findings = []

    for target in targets:
        try:
            resp = requests.get(target, timeout=timeout_val, headers=headers_payload)
            headers = resp.headers
            
            # Check HSTS
            if "Strict-Transport-Security" not in headers:
                findings.append(_create_network_finding("NET_HSTS_MISSING", "Missing HSTS Header", "HIGH", target, f"Found Headers: {list(headers.keys())[:5]}...", "Ensure Strict-Transport-Security is set to enforce TLS.", mapping_data))
            
            # Check CSP
            if "Content-Security-Policy" not in headers:
                findings.append(_create_network_finding("NET_CSP_MISSING", "Missing CSP Header", "MEDIUM", target, "", "Add Content-Security-Policy header to prevent XSS.", mapping_data))
                
            # Check Server Info Leak
            server_leak = headers.get("Server") or headers.get("X-Powered-By")
            if server_leak:
                findings.append(_create_network_finding("NET_INFO_LEAK", "Server Info Leak", "LOW", target, f"Leaked identity: {server_leak}", "Remove Server and X-Powered-By headers from the response.", mapping_data))
        except Exception as e:
            findings.append(_create_network_finding("NET_REACHABILITY", "Endpoint Unreachable or SSL Error", "HIGH", target, str(e), "Ensure endpoint is online, resolvable, and has a valid TLS certificate.", mapping_data))
            
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
