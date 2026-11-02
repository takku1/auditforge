import hashlib
import json
import os
import sys
try:
    import yaml
except ImportError:  # field-caught: scanner dies with a bare traceback otherwise
    print("error: PyYAML is required but not importable. Create the "
          "project-local venv first (a Linux-made .venv does not work on "
          "Windows and vice versa):\n"
          "  python -m venv .venv\n"
          "  .venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows\n"
          "  # .venv/bin/python -m pip install -r requirements.txt          # macOS/Linux",
          file=sys.stderr)
    raise SystemExit(2)
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from .models import UnifiedFinding
from .reporting import to_universal_markdown, to_universal_json
from . import scanners

# Engines whose output is a pure function of (target files + engine config):
# safe to cache. Live engines (network/nuclei/email/cloud) are never cached.
CACHEABLE_ENGINES = {"checkov", "semgrep", "trivy", "osv", "cargo_audit",
                     "sbom", "trufflehog", "scorecard"}

ENGINE_METHODS = ("checkov", "semgrep", "trivy", "osv", "cargo_audit",
                  "network", "email", "cloud", "sbom", "nuclei",
                  "scorecard", "trufflehog", "tls")

_AVAILABILITY_ALIASES = {"cargo_audit": "cargo-audit"}


class UniversalAuditor:
    def __init__(self, target_dir: str, config_path: str = "config/compliance_config.yaml",
                 use_cache: bool = True):
        self.target_dir = os.path.abspath(target_dir)
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        self.config_path = os.path.abspath(config_path)

        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.mapping_data = self._load_json(self.config["settings"]["mapping_file"])
        self.metadata_data = self._load_json(self.config["settings"]["metadata_file"])
        self.findings: List[UnifiedFinding] = []
        self.engine_errors: List[Dict[str, str]] = []
        self.use_cache = use_cache

    def _load_json(self, path: str) -> Dict[str, Any]:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def run_checkov(self):
        conf = self.config["tools"].get("checkov", {})
        self.findings.extend(scanners.run_checkov(self.target_dir, conf, self.mapping_data))

    def run_semgrep(self):
        conf = self.config["tools"].get("semgrep", {})
        self.findings.extend(scanners.run_semgrep(self.target_dir, conf, self.mapping_data))

    def run_trivy(self):
        conf = self.config["tools"].get("trivy", {})
        self.findings.extend(scanners.run_trivy(self.target_dir, conf, self.mapping_data))

    def run_dependency_audit(self):
        conf = self.config["tools"].get("osv", {"enabled": True})
        self.findings.extend(scanners.run_dependency_audit(self.target_dir, conf, self.mapping_data))

    def run_cargo_audit(self):
        conf = self.config["tools"].get("cargo_audit", {"enabled": True})
        self.findings.extend(scanners.run_cargo_audit(self.target_dir, conf, self.mapping_data))

    def run_network_audit(self, override_targets: Optional[List[str]] = None):
        targets = override_targets if override_targets is not None else self.config.get("network_targets", [])
        self.findings.extend(scanners.run_network_audit(
            targets, self.mapping_data,
            dast_conf=self.config.get("dast", {}),
            email_conf=self.config.get("email_auth", {})))

    def run_email_audit(self, override_domains=None):
        conf = self.config.get("email_auth", {})
        if not conf.get("enabled"):
            return
        domains = (list(override_domains) if override_domains is not None
                   else conf.get("domains", []) or [])
        if not domains:
            return
        try:
            timeout = int(conf.get("timeout", 10))
        except (ValueError, TypeError):
            timeout = 10
        self.findings.extend(scanners.run_email_auth_audit(
            domains, self.mapping_data,
            selectors=conf.get("selectors"), timeout=timeout))

    def run_cloud_posture(self):
        conf = self.config.get("cloud", {})
        self.findings.extend(scanners.run_cloud_posture(conf, self.mapping_data))

    def run_sbom_audit(self):
        sbom_conf = self.config.get("sbom", {"enabled": True})
        licenses_conf = self.config.get("licenses", {})
        self.findings.extend(scanners.run_sbom_audit(
            self.target_dir, sbom_conf, licenses_conf, self.mapping_data))

    def run_nuclei(self, override_targets: Optional[List[str]] = None):
        conf = self.config["tools"].get("nuclei", {})
        targets = override_targets if override_targets is not None else self.config.get("network_targets", [])
        self.findings.extend(scanners.run_nuclei(targets, self.mapping_data, conf))

    def run_scorecard(self):
        conf = self.config["tools"].get("scorecard", {"enabled": True})
        self.findings.extend(scanners.run_scorecard(self.target_dir, conf, self.mapping_data))

    def run_trufflehog(self):
        conf = self.config["tools"].get("trufflehog", {"enabled": True})
        self.findings.extend(scanners.run_trufflehog(self.target_dir, conf, self.mapping_data))

    def run_tls_audit(self, override_targets=None):
        conf = self.config.get("tls", {"enabled": True})
        if not conf.get("enabled", True):
            return
        targets = override_targets if override_targets is not None else self.config.get("network_targets", [])
        self.findings.extend(scanners.run_tls_audit(targets, self.mapping_data, conf))

    # ------------------------------------------------------------------
    # Parallel multi-engine runs + result cache
    # ------------------------------------------------------------------

    _RUN_METHODS = {
        "checkov": "run_checkov", "semgrep": "run_semgrep",
        "trivy": "run_trivy", "osv": "run_dependency_audit",
        "cargo_audit": "run_cargo_audit", "network": "run_network_audit",
        "email": "run_email_audit", "cloud": "run_cloud_posture",
        "sbom": "run_sbom_audit", "nuclei": "run_nuclei",
        "scorecard": "run_scorecard", "trufflehog": "run_trufflehog",
        "tls": "run_tls_audit",
    }

    def run_all(self, engines: Optional[List[str]] = None,
                network_targets: Optional[List[str]] = None,
                email_domains: Optional[List[str]] = None,
                parallel: bool = True, max_workers: int = 6):
        """Run every (or selected) engine. Engines are independent - running
        them concurrently on a thread pool is safe because each worker uses
        its own UniversalAuditor instance (no shared findings list); results
        merge here. Unexpected per-engine exceptions become engine_errors
        entries, never a dead run."""
        wanted = list(engines) if engines else list(self._RUN_METHODS)
        unknown = [e for e in wanted if e not in self._RUN_METHODS]
        if unknown:
            raise ValueError(f"unknown engines: {unknown} "
                             f"(choose from {sorted(self._RUN_METHODS)})")
        plan = [(name, self._RUN_METHODS[name]) for name in wanted]
        if parallel and len(plan) > 1:
            with ThreadPoolExecutor(
                    max_workers=min(max_workers, len(plan))) as pool:
                futures = {pool.submit(self._run_engine_isolated, name, method,
                                       network_targets, email_domains): name
                           for name, method in plan}
                for future in as_completed(futures):
                    findings, errors = future.result()
                    self.findings.extend(findings)
                    self.engine_errors.extend(errors)
        else:
            for name, method in plan:
                findings, errors = self._run_engine_isolated(
                    name, method, network_targets, email_domains)
                self.findings.extend(findings)
                self.engine_errors.extend(errors)

    def _run_engine_isolated(self, engine: str, method: str,
                             network_targets=None, email_domains=None):
        """Run one engine in a private auditor (thread-safe: no shared
        state), with cache lookup for deterministic engines. Returns
        (findings, errors); never raises."""
        sub = UniversalAuditor(self.target_dir, self.config_path,
                               use_cache=self.use_cache)
        cache_key = None
        if self.use_cache and engine in CACHEABLE_ENGINES:
            cache_key = self._cache_key(engine)
            cached = self._cache_load(cache_key)
            if cached is not None:
                return cached, []
        try:
            if engine in ("network", "nuclei"):
                getattr(sub, method)(network_targets)
            elif engine == "email":
                getattr(sub, method)(email_domains)
            else:
                getattr(sub, method)()
            findings = sub.findings
            errors = list(sub.engine_errors)
        except Exception as exc:  # noqa: BLE001 - one engine must not kill the run
            print(f"Engine {engine} failed: {exc}", file=sys.stderr)
            return [], [{"engine": engine, "error": str(exc)[:300]}]
        if cache_key is not None:
            self._cache_save(cache_key, findings)
        return findings, errors

    def _cache_file(self, key: str) -> str:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        d = os.path.join(root, "reports", ".audit-cache")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, f"{key}.json")

    def _cache_key(self, engine: str) -> str:
        h = hashlib.sha256()
        h.update(engine.encode())
        h.update(self.target_dir.encode())
        conf = self._engine_conf(engine)
        h.update(json.dumps(conf, sort_keys=True, default=str).encode())
        h.update(self._target_fingerprint().encode())
        return h.hexdigest()[:32]

    def _engine_conf(self, engine: str) -> dict:
        tools = self.config.get("tools", {})
        mapping = {"osv": tools.get("osv", {}), "cargo_audit": tools.get("cargo_audit", {}),
                   "sbom": {"sbom": self.config.get("sbom", {}),
                            "licenses": self.config.get("licenses", {})},
                   "scorecard": tools.get("scorecard", {}),
                   "trufflehog": tools.get("trufflehog", {})}
        return mapping.get(engine, tools.get(engine, {}))

    def _target_fingerprint(self) -> str:
        """mtime+size fingerprint of the target tree (skips noise dirs like
        the native scanner). Any content change invalidates the cache."""
        skip = {d.lower() for d in getattr(scanners, "SKIP_DIRS", [])}
        entries = []
        for dirpath, dirnames, filenames in os.walk(self.target_dir):
            dirnames[:] = [d for d in dirnames if d.lower() not in skip]
            for name in sorted(filenames):
                try:
                    st = os.stat(os.path.join(dirpath, name))
                except OSError:
                    continue
                rel = os.path.relpath(os.path.join(dirpath, name), self.target_dir)
                entries.append(f"{rel}|{st.st_size}|{st.st_mtime_ns}")
                if len(entries) >= 20000:
                    entries.append("TRUNCATED")
                    break
            if entries and entries[-1] == "TRUNCATED":
                break
        return hashlib.sha256("\n".join(entries).encode()).hexdigest()

    def _cache_load(self, key: str):
        path = self._cache_file(key)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [UnifiedFinding(**item) for item in data.get("findings", [])]
        except Exception:
            return None

    def _cache_save(self, key: str, findings: List[UnifiedFinding]):
        try:
            with open(self._cache_file(key), "w", encoding="utf-8") as f:
                json.dump({"generated_at": datetime.now(timezone.utc).isoformat(
                    timespec="seconds"),
                           "findings": [f.__dict__ for f in findings]}, f)
        except OSError:
            pass

    def run_status(self) -> Dict[str, str]:
        """Honest run state for Phase-6 style reporting: anything less than
        every enabled engine succeeding is 'partial', with the reason naming
        what didn't run. Mirrors the freshness gate's refuse-to-claim-clean
        posture."""
        availability = scanners.engine_availability()
        enabled = {k for k, v in self.config.get("tools", {}).items()
                   if isinstance(v, dict) and v.get("enabled")}
        missing = sorted(
            t for t in enabled
            if availability.get(_AVAILABILITY_ALIASES.get(t, t)) is False)
        reasons = []
        if missing:
            reasons.append("engines unavailable: " + ", ".join(missing))
        reasons.extend(f"{e['engine']}: {e['error']}"
                       for e in self.engine_errors)
        if reasons:
            return {"run_status": "partial", "reason": "; ".join(reasons)}
        return {"run_status": "complete", "reason": ""}

    def generate_report(self, output_format: str) -> str:
        summary = {
            "total": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity.upper() in ["CRITICAL", "ERROR"]),
            "high": sum(1 for f in self.findings if f.severity.upper() == "HIGH"),
            "medium": sum(1 for f in self.findings if f.severity.upper() in ["MEDIUM", "WARNING"]),
            "low": sum(1 for f in self.findings if f.severity.upper() in ["LOW", "INFO"]),
        }
        availability = scanners.engine_availability()
        status = self.run_status()

        if output_format == "markdown":
            return to_universal_markdown(self.findings, self.mapping_data, self.metadata_data, summary, availability)
        if output_format == "sarif":
            return to_universal_sarif(self.findings, summary)
        return to_universal_json(self.findings, summary, availability,
                                 engine_errors=self.engine_errors,
                                 run_status=status["run_status"],
                                 run_status_reason=status["reason"])
