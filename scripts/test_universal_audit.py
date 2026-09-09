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

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_run_trivy(self, mock_run, mock_available):
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

        # R-034: cmd is already a list - shell=True must not be passed (on
        # POSIX it would only execute cmd[0] via the shell, silently dropping
        # the rest of the arguments).
        _, call_kwargs = mock_run.call_args
        self.assertNotIn("shell", call_kwargs)

    @patch("auditor.scanners._tool_available", return_value=False)
    @patch("subprocess.run")
    def test_run_trivy_skips_when_binary_missing(self, mock_run, mock_available):
        # R-035: a missing external engine must not be silently identical to
        # "ran and found nothing" - it should skip without invoking subprocess.
        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_trivy()

        self.assertEqual(auditor.findings, [])
        mock_run.assert_not_called()

    def test_engine_availability_reported(self):
        import auditor.scanners as scanners
        availability = scanners.engine_availability()
        self.assertEqual(set(availability.keys()), {"checkov", "semgrep", "trivy"})
        self.assertTrue(all(isinstance(v, bool) for v in availability.values()))

        report = universal_audit.UniversalAuditor(self.root, self.config_path).generate_report("json")
        payload = json.loads(report)
        self.assertIn("engine_availability", payload)

    def test_network_audit_skips_unmodified_placeholder_targets(self):
        # R-036: the shipped config default (example.com placeholders) must
        # not be silently scanned as if it were a real, user-chosen target.
        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_network_audit([
            "https://example.com", "https://api.example.com/health",
        ])
        self.assertEqual(auditor.findings, [])

    @patch("requests.get")
    def test_network_audit_scans_real_override_targets(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_get.return_value = mock_resp

        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_network_audit(["https://real-target.internal.example.org"])

        self.assertTrue(len(auditor.findings) > 0)

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

    @patch("requests.post")
    def test_run_dependency_audit_kev_enrichment_bumps_severity(self, mock_post):
        import vuln_intel  # noqa: E402 - same sys.path trick as scanners.py's lazy import

        req_path = os.path.join(self.root, "requirements.txt")
        with open(req_path, "w", encoding="utf-8") as f:
            f.write("pan-os-fake==1.0.0\n")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-fake-0000",
                    "aliases": ["CVE-2024-3400"],
                    "summary": "Command injection",
                    "database_specific": {"severity": "HIGH"},
                }
            ]
        }
        mock_post.return_value = mock_response

        with patch.object(vuln_intel, "check_kev", return_value={
            "dateAdded": "2024-04-12", "knownRansomwareCampaignUse": "Known",
        }):
            auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
            auditor.run_dependency_audit()

        finding = auditor.findings[0]
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertIn("CISA KEV", finding.remediation)
        self.assertIn("ransomware", finding.remediation.lower())

    @patch("requests.post")
    def test_run_dependency_audit_no_cve_alias_skips_enrichment(self, mock_post):
        req_path = os.path.join(self.root, "requirements.txt")
        with open(req_path, "w", encoding="utf-8") as f:
            f.write("somepkg==1.0.0\n")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [{"id": "GHSA-no-cve-0000", "summary": "x", "database_specific": {"severity": "HIGH"}}]
        }
        mock_post.return_value = mock_response

        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_dependency_audit()

        finding = auditor.findings[0]
        self.assertEqual(finding.severity, "HIGH")
        self.assertNotIn("CISA KEV", finding.remediation)


if __name__ == "__main__":
    unittest.main(verbosity=2)
