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
        "nuclei": _tool_available("nuclei"),
        "scorecard": _tool_available("scorecard"),
        "trufflehog": _tool_available("trufflehog"),
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


def _header_findings(url: str, headers, mapping_data: dict) -> List[UnifiedFinding]:
    """HSTS/CSP/server-leak header checks for one fetched URL."""
    out = []
    try:
        names = list(headers.keys())
    except Exception:
        return out
    if "Strict-Transport-Security" not in headers:
        out.append(_create_network_finding("NET_HSTS_MISSING", "Missing HSTS Header", "HIGH", url, f"Found Headers: {names[:5]}...", "Ensure Strict-Transport-Security is set to enforce TLS.", mapping_data))
    if "Content-Security-Policy" not in headers:
        out.append(_create_network_finding("NET_CSP_MISSING", "Missing CSP Header", "MEDIUM", url, "", "Add Content-Security-Policy header to prevent XSS.", mapping_data))
    try:
        server_leak = headers.get("Server") or headers.get("X-Powered-By")
    except Exception:
        server_leak = None
    if server_leak:
        out.append(_create_network_finding("NET_INFO_LEAK", "Server Info Leak", "LOW", url, f"Leaked identity: {server_leak}", "Remove Server and X-Powered-By headers from the response.", mapping_data))
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
            findings.extend(_header_findings(target, resp.headers, mapping_data))
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
                        crawled_url, page_resp.headers, mapping_data))
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
    r"\.(test|example|invalid|localhost|local|internal|ipc)$", re.IGNORECASE)


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
    selectors = selectors or ["default", "google", "selector1", "selector2", "k1"]
    findings = []
    for raw in domains:
        domain = (raw or "").strip().lower().rstrip(".")
        if not domain:
            continue
        if domain in _PLACEHOLDER_EMAIL_DOMAINS or domain.endswith(".example.com"):
            continue
        if _RESERVED_HOST_SUFFIX_RE.search(domain):
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
                    if uri in ("http://acs.amazonaws.com/groups/global/AllUsers",  # soc2-ignore
                               "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"):  # soc2-ignore
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
        for fname in filenames:
            parser_info = _LOCKFILE_PARSERS.get(fname)
            if not parser_info:
                continue
            parser, ecosystem = parser_info
            file_path = os.path.join(dirpath, fname)
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
            for pkg, ver in packages:
                key = (ecosystem, pkg, ver)
                if key in seen:
                    continue
                seen.add(key)
                components.append({
                    "name": pkg, "version": ver, "ecosystem": ecosystem,
                    "license": declared.get(pkg, "unknown"),
                    "file": os.path.relpath(file_path, target_dir),
                })
    components.sort(key=lambda c: (c["ecosystem"], c["name"], c["version"]))
    return components, project_license


def _write_sbom(components: list, project_license: str, sbom_conf: dict,
                target_dir: str) -> str:
    """Writes CycloneDX (default) or minimal SPDX JSON. Returns the path."""
    fmt = str(sbom_conf.get("format", "cyclonedx")).lower()
    default_name = ("sbom.spdx.json" if fmt == "spdx" else "sbom.cyclonedx.json")
    out_path = sbom_conf.get("output", os.path.join("reports", default_name))
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
                 "scope": "required", "ecosystem": c["ecosystem"],
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
                                    encoding="utf-8", errors="ignore")
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


# --- OpenSSF Scorecard (supply-chain posture, incl. SLSA-relevant checks) ---
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
                                encoding="utf-8", errors="ignore")
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
                                encoding="utf-8", errors="ignore")
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
