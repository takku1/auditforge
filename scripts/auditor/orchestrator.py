import os
import yaml
import json
from typing import List, Dict, Any, Optional
from .models import UnifiedFinding
from .reporting import to_universal_markdown, to_universal_json
from . import scanners

class UniversalAuditor:
    def __init__(self, target_dir: str, config_path: str = "config/compliance_config.yaml"):
        self.target_dir = os.path.abspath(target_dir)
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)
        
        self.mapping_data = self._load_json(self.config["settings"]["mapping_file"])
        self.metadata_data = self._load_json(self.config["settings"]["metadata_file"])
        self.findings: List[UnifiedFinding] = []

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
        self.findings.extend(scanners.run_network_audit(targets, self.mapping_data))

    def generate_report(self, output_format: str) -> str:
        summary = {
            "total": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity.upper() in ["CRITICAL", "ERROR"]),
            "high": sum(1 for f in self.findings if f.severity.upper() == "HIGH"),
            "medium": sum(1 for f in self.findings if f.severity.upper() in ["MEDIUM", "WARNING"]),
            "low": sum(1 for f in self.findings if f.severity.upper() in ["LOW", "INFO"]),
        }
        availability = scanners.engine_availability()

        if output_format == "markdown":
            return to_universal_markdown(self.findings, self.mapping_data, self.metadata_data, summary, availability)
        return to_universal_json(self.findings, summary, availability)
