import json
import os
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import shutil
import sys

# Ensure scripts folder is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import universal_audit

class TestUniversalAudit(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="universal_audit_test_")
        
        # Write dummy config
        self.config_dir = os.path.join(self.root, "config")
        os.makedirs(self.config_dir, exist_ok=True)
        self.config_path = os.path.join(self.config_dir, "compliance_config.yaml")
        
        # Get path of mapping files from real workspace
        workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.mapping_file = os.path.join(workspace_dir, "scripts", "framework_mappings.json").replace("\\", "/")
        self.metadata_file = os.path.join(workspace_dir, "scripts", "framework_metadata.json").replace("\\", "/")

        config_content = f"""
settings:
  mapping_file: "{self.mapping_file}"
  metadata_file: "{self.metadata_file}"
tools:
  checkov:
    enabled: false
  semgrep:
    enabled: false
  trivy:
    enabled: true
  osv:
    enabled: true
network_targets: []
"""
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(config_content)
            
    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    @patch("subprocess.run")
    def test_run_trivy(self, mock_run):
        # Setup mock trivy output
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0001",
                            "PkgName": "requests",
                            "InstalledVersion": "2.28.0",
                            "FixedVersion": "2.28.1",
                            "Severity": "HIGH",
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-0001"
                        }
                    ]
                }
            ]
        })
        mock_run.return_value = mock_result
        
        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_trivy()
        
        self.assertEqual(len(auditor.findings), 1)
        finding = auditor.findings[0]
        self.assertEqual(finding.tool, "Trivy")
        self.assertEqual(finding.rule_id, "CVE-2023-0001")
        self.assertEqual(finding.severity, "HIGH")
        self.assertIn("requests", finding.name)

    @patch("requests.post")
    def test_run_dependency_audit_requirements(self, mock_post):
        # Create requirements.txt
        req_path = os.path.join(self.root, "requirements.txt")
        with open(req_path, "w", encoding="utf-8") as f:
            f.write("requests==2.28.0\n")
            
        # Mock OSV API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-c4g2-mg2v-rh48",
                    "summary": "Use of Outdated Package",
                    "database_specific": {
                        "severity": "HIGH"
                    }
                }
            ]
        }
        mock_post.return_value = mock_response
        
        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_dependency_audit()
        
        self.assertEqual(len(auditor.findings), 1)
        finding = auditor.findings[0]
        self.assertEqual(finding.tool, "OSV-API")
        self.assertEqual(finding.rule_id, "GHSA-c4g2-mg2v-rh48")
        self.assertEqual(finding.severity, "HIGH")

if __name__ == "__main__":
    unittest.main(verbosity=2)
