import os
import re
import bisect
import fnmatch
import shutil
import subprocess
import json
import sys
from typing import List, Any, Optional
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


def scan_file(path: str, rel: str) -> "tuple[list, Optional[str]]":
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
    return findings, None


_COMMIT_RE = re.compile(r"^commit ([0-9a-f]{40})")
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def scan_git_history(root: str, excludes: "Optional[list]" = None, timeout: int = 300) -> list:
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
    dependencies = pkg_data.get("dependencies", {})
    devDependencies = pkg_data.get("devDependencies", {})
    for pkg, ver in {**dependencies, **devDependencies}.items():
        clean_ver = "".join(c for c in ver if c.isdigit() or c == "." or c == "-")
        if len(clean_ver) >= 1:
            out.append((pkg, clean_ver))
    return out


def _parse_cargo_lock(path: str) -> List[tuple]:
    """Cargo.lock is valid TOML - a series of [[package]] tables, each with
    name/version. Uses stdlib tomllib (Python 3.11+); on an older
    interpreter this degrades to "Cargo.lock not parsed" rather than a hard
    failure - no new dependency added just for this."""
    try:
        import tomllib
    except ModuleNotFoundError:
        raise RuntimeError("tomllib unavailable (Python <3.11) - Cargo.lock not parsed")
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
_LOCKFILE_PARSERS = {
    "requirements.txt": (_parse_requirements_txt, "PyPI"),
    "package.json": (_parse_package_json, "npm"),
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
                                     encoding="utf-8", errors="ignore")
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
        for fname in filenames:
            parser_info = _LOCKFILE_PARSERS.get(fname)
            if not parser_info:
                continue
            parser, ecosystem = parser_info
            file_path = os.path.join(dirpath, fname)
            try:
                packages = parser(file_path)
            except Exception as e:
                print(f"Error parsing {file_path}: {e}", file=sys.stderr)
                continue
            for pkg, ver in packages:
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
