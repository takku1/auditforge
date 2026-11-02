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

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_run_trivy_scans_configured_images(self, mock_run, mock_available):
        # Trivy "images" config: one fs scan plus one image scan per entry.
        from auditor import scanners

        def _payload(target, cve, pkg):
            m = MagicMock()
            m.stdout = json.dumps({"Results": [{"Target": target,
                "Vulnerabilities": [{
                    "VulnerabilityID": cve, "PkgName": pkg,
                    "InstalledVersion": "1.0", "FixedVersion": "1.1",
                    "Severity": "HIGH", "PrimaryURL": "https://example.com"}]}]})
            return m

        mock_run.side_effect = [
            _payload("requirements.txt", "CVE-2023-0001", "requests"),
            _payload("myapp:1.0 (os-pkgs)", "CVE-2023-0002", "openssl"),
        ]
        findings = scanners.run_trivy(
            self.root, {"enabled": True, "images": ["myapp:1.0"]}, {"mappings": {}})

        self.assertEqual(len(findings), 2)
        by_id = {f.rule_id: f for f in findings}
        self.assertIn("myapp:1.0", by_id["CVE-2023-0002"].file)
        self.assertEqual(by_id["CVE-2023-0002"].tool, "Trivy")
        cmds = [c.args[0] for c in mock_run.call_args_list]
        self.assertIn(["trivy", "fs", "--format", "json", self.root], cmds)
        self.assertIn(["trivy", "image", "--format", "json", "myapp:1.0"], cmds)

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_run_trivy_no_images_by_default(self, mock_run, mock_available):
        # No "images" key: exactly one fs scan, no image subprocess calls.
        from auditor import scanners

        mock_result = MagicMock()
        mock_result.stdout = json.dumps({"Results": []})
        mock_run.return_value = mock_result
        findings = scanners.run_trivy(self.root, {"enabled": True}, {"mappings": {}})

        self.assertEqual(findings, [])
        self.assertEqual(mock_run.call_count, 1)

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_run_trivy_empty_fs_output_still_scans_images(self, mock_run, mock_available):
        # Empty fs stdout must not skip configured image scans.
        from auditor import scanners

        empty = MagicMock()
        empty.stdout = ""
        img = MagicMock()
        img.stdout = json.dumps({"Results": [{"Target": "img (os-pkgs)",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2023-0009", "PkgName": "zlib",
                "InstalledVersion": "1.2", "FixedVersion": "1.3",
                "Severity": "CRITICAL", "PrimaryURL": ""}]}]})
        mock_run.side_effect = [empty, img]
        findings = scanners.run_trivy(
            self.root, {"enabled": True, "images": ["img"]}, {"mappings": {}})

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CVE-2023-0009")
        self.assertIn("img", findings[0].file)

    def test_engine_availability_reported(self):
        import auditor.scanners as scanners
        availability = scanners.engine_availability()
        self.assertEqual(set(availability.keys()), {"checkov", "semgrep", "trivy", "cargo-audit", "nuclei", "scorecard", "trufflehog"})
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

    @patch("requests.post")
    def test_run_dependency_audit_is_workspace_aware(self, mock_post):
        # R-010: nested (not just root-level) manifests must be found.
        os.makedirs(os.path.join(self.root, "services", "api"), exist_ok=True)
        with open(os.path.join(self.root, "services", "api", "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("nestedpkg==1.0.0\n")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_dependency_audit()

        queried_files = {c.kwargs["json"]["package"]["name"] for c in mock_post.call_args_list}
        self.assertIn("nestedpkg", queried_files)

    @patch("requests.post")
    def test_run_dependency_audit_skips_noise_dirs(self, mock_post):
        os.makedirs(os.path.join(self.root, "node_modules", "some-dep"), exist_ok=True)
        with open(os.path.join(self.root, "node_modules", "some-dep", "package.json"), "w", encoding="utf-8") as f:
            f.write('{"dependencies": {"transitive-noise": "1.0.0"}}')

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_dependency_audit()

        mock_post.assert_not_called()

    @patch("requests.post")
    def test_run_dependency_audit_cargo_lock_ecosystem(self, mock_post):
        cargo_lock = """
[[package]]
name = "serde"
version = "1.0.150"

[[package]]
name = "libc"
version = "0.2.130"
"""
        with open(os.path.join(self.root, "Cargo.lock"), "w", encoding="utf-8") as f:
            f.write(cargo_lock)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_dependency_audit()

        calls = [(c.kwargs["json"]["package"]["name"], c.kwargs["json"]["package"]["ecosystem"])
                 for c in mock_post.call_args_list]
        self.assertIn(("serde", "crates.io"), calls)
        self.assertIn(("libc", "crates.io"), calls)

    @patch("requests.post")
    def test_run_dependency_audit_go_sum_ecosystem(self, mock_post):
        go_sum = (
            "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n"
            "github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n"
        )
        with open(os.path.join(self.root, "go.sum"), "w", encoding="utf-8") as f:
            f.write(go_sum)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_dependency_audit()

        calls = [(c.kwargs["json"]["package"]["name"], c.kwargs["json"]["package"]["ecosystem"], c.kwargs["json"]["version"])
                 for c in mock_post.call_args_list]
        self.assertEqual(calls, [("github.com/pkg/errors", "Go", "0.9.1")])  # deduped, not queried twice

    @patch("requests.post")
    def test_run_dependency_audit_gemfile_lock_ecosystem(self, mock_post):
        gemfile_lock = """GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.3)
    rails (7.0.4)
      actioncable (= 7.0.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails
"""
        with open(os.path.join(self.root, "Gemfile.lock"), "w", encoding="utf-8") as f:
            f.write(gemfile_lock)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_dependency_audit()

        calls = [(c.kwargs["json"]["package"]["name"], c.kwargs["json"]["package"]["ecosystem"])
                 for c in mock_post.call_args_list]
        self.assertIn(("rack", "RubyGems"), calls)
        self.assertIn(("rails", "RubyGems"), calls)
        # nested dependency line (indented 6) must not be queried as a top-level spec
        self.assertNotIn(("actioncable", "RubyGems"), calls)

    @patch("requests.post")
    def test_run_dependency_audit_composer_lock_ecosystem(self, mock_post):
        composer_lock = json.dumps({
            "packages": [{"name": "monolog/monolog", "version": "v2.8.0"}],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "v9.5.0"}],
        })
        with open(os.path.join(self.root, "composer.lock"), "w", encoding="utf-8") as f:
            f.write(composer_lock)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_post.return_value = mock_response

        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_dependency_audit()

        calls = [(c.kwargs["json"]["package"]["name"], c.kwargs["json"]["package"]["ecosystem"], c.kwargs["json"]["version"])
                 for c in mock_post.call_args_list]
        self.assertIn(("monolog/monolog", "Packagist", "2.8.0"), calls)
        self.assertIn(("phpunit/phpunit", "Packagist", "9.5.0"), calls)


class TestCargoAudit(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="cargo_audit_test_")
        os.makedirs(os.path.join(self.root, "config"), exist_ok=True)
        self.config_path = os.path.join(self.root, "config", "compliance_config.yaml")
        workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        mapping_file = os.path.join(workspace_dir, "scripts", "framework_mappings.json").replace("\\", "/")
        metadata_file = os.path.join(workspace_dir, "scripts", "framework_metadata.json").replace("\\", "/")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(f"""
settings:
  mapping_file: "{mapping_file}"
  metadata_file: "{metadata_file}"
tools:
  cargo_audit:
    enabled: true
network_targets: []
""")
        with open(os.path.join(self.root, "Cargo.lock"), "w", encoding="utf-8") as f:
            f.write('[[package]]\nname = "time"\nversion = "0.1.42"\n')

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_run_cargo_audit_parses_findings(self, mock_run, mock_available):
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({
            "vulnerabilities": {
                "found": True,
                "list": [{
                    "advisory": {
                        "id": "RUSTSEC-2020-0071",
                        "title": "Potential segfault in `time` 0.1.x",
                        "description": "chrono uses time 0.1 ...",
                        "url": "https://rustsec.org/advisories/RUSTSEC-2020-0071",
                        "severity": "HIGH",
                    },
                    "package": {"name": "time", "version": "0.1.42"},
                }],
            },
        })
        mock_run.return_value = mock_result

        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_cargo_audit()

        self.assertEqual(len(auditor.findings), 1)
        finding = auditor.findings[0]
        self.assertEqual(finding.tool, "cargo-audit")
        self.assertEqual(finding.rule_id, "RUSTSEC-2020-0071")
        self.assertEqual(finding.severity, "HIGH")
        self.assertIn("time", finding.snippet)

        _, call_kwargs = mock_run.call_args
        self.assertNotIn("shell", call_kwargs)

    @patch("auditor.scanners._tool_available", return_value=False)
    @patch("subprocess.run")
    def test_run_cargo_audit_skips_when_binary_missing(self, mock_run, mock_available):
        auditor = universal_audit.UniversalAuditor(self.root, self.config_path)
        auditor.run_cargo_audit()
        self.assertEqual(auditor.findings, [])
        mock_run.assert_not_called()


class _CloudPostureBase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="cloud_posture_test_")
        self.config_dir = os.path.join(self.root, "config")
        os.makedirs(self.config_dir, exist_ok=True)
        self.config_path = os.path.join(self.config_dir, "compliance_config.yaml")
        workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        mapping_file = os.path.join(workspace_dir, "scripts", "framework_mappings.json").replace("\\", "/")
        metadata_file = os.path.join(workspace_dir, "scripts", "framework_metadata.json").replace("\\", "/")
        self.baseline = os.path.join(self.root, "cloud_baseline.json")
        # Windows tmp paths carry backslashes, which are illegal in a
        # double-quoted YAML scalar - same normalization as above.
        self.baseline = self.baseline.replace("\\", "/")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(f"""
settings:
  mapping_file: "{mapping_file}"
  metadata_file: "{metadata_file}"
tools:
  checkov:
    enabled: false
  semgrep:
    enabled: false
network_targets: []
cloud:
  enabled: true
  providers: ["aws"]
  baseline_file: "{self.baseline}"
""")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _auditor(self):
        return universal_audit.UniversalAuditor(self.root, self.config_path)


_CLOUD_ENV_KEYS = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE",
                   "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                   "GOOGLE_APPLICATION_CREDENTIALS", "GCP_PROJECT",
                   "GOOGLE_CLOUD_PROJECT", "AZURE_SUBSCRIPTION_ID"]


def _clean_cloud_env():
    return {k: v for k, v in os.environ.items() if k not in _CLOUD_ENV_KEYS}


class TestCloudPosture(_CloudPostureBase):
    def test_skips_without_credentials(self):
        # R-051: absent creds = skip with message, never fail, no baseline.
        with patch.dict(os.environ, _clean_cloud_env(), clear=True):
            auditor = self._auditor()
            auditor.run_cloud_posture()
        self.assertEqual(auditor.findings, [])
        self.assertFalse(os.path.exists(self.baseline))

    def test_skips_when_sdk_missing(self):
        # R-051: creds present but boto3 absent = skip, never fail.
        env = _clean_cloud_env()
        env.update({"AWS_ACCESS_KEY_ID": "mock", "AWS_SECRET_ACCESS_KEY": "mock"})
        with patch.dict(os.environ, env, clear=True):
            with patch.dict(sys.modules, {"boto3": None}):
                auditor = self._auditor()
                auditor.run_cloud_posture()
        self.assertEqual(auditor.findings, [])
        self.assertFalse(os.path.exists(self.baseline))

    def test_flags_public_bucket_and_missing_password_policy(self):
        import auditor.scanners as scanners  # noqa: E402

        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "open-bucket"}]}
        mock_s3.get_public_access_block.side_effect = Exception(
            "NoSuchPublicAccessBlockConfiguration")
        mock_s3.get_bucket_acl.return_value = {"Grants": [
            {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},  # soc2-ignore: mock of AWS canonical grantee URI
             "Permission": "READ"}]}
        mock_iam = MagicMock()
        mock_iam.get_account_password_policy.side_effect = Exception("NoSuchEntity")
        mock_boto3 = MagicMock()
        mock_boto3.client.side_effect = lambda name, **kw: mock_s3 if name == "s3" else mock_iam

        env = _clean_cloud_env()
        env.update({"AWS_ACCESS_KEY_ID": "mock", "AWS_SECRET_ACCESS_KEY": "mock"})
        with patch.dict(os.environ, env, clear=True):
            with patch.dict(sys.modules, {"boto3": mock_boto3}):
                auditor = self._auditor()
                auditor.run_cloud_posture()

        by_rule = {f.rule_id for f in auditor.findings}
        self.assertIn("CLOUD_S3_PUBLIC", by_rule)
        self.assertIn("CLOUD_IAM_POLICY", by_rule)
        s3_finding = next(f for f in auditor.findings if f.rule_id == "CLOUD_S3_PUBLIC")
        self.assertEqual(s3_finding.severity, "HIGH")
        self.assertEqual(s3_finding.tool, "CloudPosture")
        self.assertIn("SOC2:CC6.1", s3_finding.frameworks)
        self.assertTrue(os.path.exists(self.baseline))

    def test_drift_detection_against_baseline(self):
        import auditor.scanners as scanners  # noqa: E402

        v1 = [{"provider": "aws", "service": "s3", "resource": "b1",
               "public": False, "detail": "private"}]
        v2 = [{"provider": "aws", "service": "s3", "resource": "b1",
               "public": True, "detail": "public ACL grant: READ"},
              {"provider": "aws", "service": "s3", "resource": "b2",
               "public": False, "detail": "private"}]
        with patch.dict(os.environ, _clean_cloud_env(), clear=True):
            auditor = self._auditor()
            with patch.object(scanners, "_poll_aws", return_value=(v1, "")):
                auditor.run_cloud_posture()
            self.assertFalse([f for f in auditor.findings if f.rule_id == "CLOUD_DRIFT"])
            n_before = len(auditor.findings)
            with patch.object(scanners, "_poll_aws", return_value=(v2, "")):
                auditor.run_cloud_posture()
        drift = [f for f in auditor.findings[n_before:] if f.rule_id == "CLOUD_DRIFT"]
        self.assertEqual(len(drift), 2)  # b1 changed + b2 new
        self.assertTrue(all(f.severity == "HIGH" for f in drift))
        self.assertTrue(all("SOC2:CC7.2" in f.frameworks for f in drift))

    def test_no_baseline_overwrite_when_nothing_polled(self):
        # A creds outage must not rewrite the baseline into "everything gone".
        sentinel = {"posture": {"aws:s3:keep": {"detail": "private"}}}
        with open(self.baseline, "w", encoding="utf-8") as f:
            json.dump(sentinel, f)
        with patch.dict(os.environ, _clean_cloud_env(), clear=True):
            auditor = self._auditor()
            auditor.run_cloud_posture()
        self.assertEqual(auditor.findings, [])
        with open(self.baseline, encoding="utf-8") as f:
            self.assertEqual(json.load(f), sentinel)


def _doh_urlopen_mock(routes):
    """routes: {dns_name: [txt, ...] or None for a lookup failure}."""
    def _fake_urlopen(req, timeout=None):
        from urllib.parse import urlparse, parse_qs
        name = parse_qs(urlparse(req.full_url).query).get("name", [""])[0]
        if name in routes and routes[name] is None:
            raise Exception("mock DNS failure")
        txts = routes.get(name, [])
        payload = {"Status": 0, "Answer": [
            {"name": name, "type": 16, "data": '"%s"' % t} for t in txts]}
        m = MagicMock()
        m.__enter__.return_value.read.return_value = json.dumps(payload)
        return m
    return _fake_urlopen


class TestEmailAuth(_CloudPostureBase):
    def test_missing_records_flagged(self):
        import auditor.scanners as scanners  # noqa: E402

        with patch("urllib.request.urlopen", side_effect=_doh_urlopen_mock({})):
            findings = scanners.run_email_auth_audit(
                ["mail.example.org"], {}, selectors=["default"])
        by_rule = {f.rule_id: f for f in findings}
        self.assertEqual(set(by_rule), {"EMAIL_SPF_MISSING", "EMAIL_DMARC_MISSING",
                                        "EMAIL_DKIM_MISSING"})
        self.assertEqual(by_rule["EMAIL_SPF_MISSING"].severity, "MEDIUM")
        self.assertEqual(by_rule["EMAIL_DMARC_MISSING"].severity, "HIGH")
        self.assertEqual(by_rule["EMAIL_DKIM_MISSING"].severity, "LOW")

    def test_present_records_pass(self):
        import auditor.scanners as scanners  # noqa: E402

        routes = {
            "mail.example.org": ["v=spf1 include:_spf.provider.example -all"],
            "_dmarc.mail.example.org": ["v=DMARC1; p=reject; rua=mailto:d@mail.example.org"],
            "default._domainkey.mail.example.org": ["v=DKIM1; k=rsa; p=mockkey"],
        }
        with patch("urllib.request.urlopen", side_effect=_doh_urlopen_mock(routes)):
            findings = scanners.run_email_auth_audit(
                ["mail.example.org"], {}, selectors=["default"])
        self.assertEqual(findings, [])

    def test_header_findings_full_good_headers_pass(self):
        # Field report §4 row 20: the complete set of expected headers
        # with strong values must stay silent.
        from auditor import scanners as _sc
        headers = {
            "Strict-Transport-Security":
                "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy":
                "default-src 'self'; script-src 'self' 'sha256-abc'; "
                "frame-ancestors 'none'; report-uri /csp",
            "Permissions-Policy": "camera=()",
            "Referrer-Policy": "no-referrer",
            "Cross-Origin-Opener-Policy": "same-origin",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        self.assertEqual(_sc._header_findings("https://shop.test/", headers, {}), [])

    def test_header_findings_missing_optional_headers(self):
        from auditor import scanners as _sc
        headers = {
            "Strict-Transport-Security":
                "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy":
                "default-src 'self'; report-uri /csp",
        }
        ids = {f.rule_id for f in _sc._header_findings(
            "https://shop.test/", headers, {})}
        self.assertEqual(ids, {"NET_PERMISSIONS_POLICY_MISSING",
                               "NET_REFERRER_POLICY_MISSING",
                               "NET_COOP_MISSING",
                               "NET_XCTO_MISSING",
                               "NET_FRAME_ANCESTORS_MISSING"})

    def test_header_findings_weak_hsts_value(self):
        # Field report §4 row 21, DAST side.
        from auditor import scanners as _sc
        headers = {"Strict-Transport-Security": "max-age=86400",
                   "Content-Security-Policy": "default-src 'self'"}
        ids = {f.rule_id for f in _sc._header_findings(
            "https://shop.test/", headers, {})}
        self.assertIn("NET_HSTS_WEAK", ids)
        self.assertNotIn("NET_HSTS_MISSING", ids)

    def test_header_findings_weak_csp_value(self):
        # Field report §4 rows 15-16, DAST side.
        from auditor import scanners as _sc
        headers = {
            "Strict-Transport-Security":
                "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy":
                "default-src 'self'; script-src 'self' 'unsafe-inline'",
        }
        ids = {f.rule_id for f in _sc._header_findings(
            "https://shop.test/", headers, {})}
        self.assertIn("NET_CSP_WEAK", ids)
        self.assertIn("NET_CSP_NO_REPORT", ids)
        self.assertNotIn("NET_CSP_MISSING", ids)

    def test_dkim_new_provider_selectors(self):
        # Field report §3.11: resend/s1/s2/mandrill/pm/amazonses/mxvault.
        from auditor import scanners as _sc
        routes = {"resend._domainkey.acmewidgets.io":
                  ["v=DKIM1; k=rsa; p=MOCKKEY"]}
        with patch("urllib.request.urlopen",
                   side_effect=_doh_urlopen_mock(routes)):
            findings = _sc.run_email_auth_audit(
                ["acmewidgets.io"], {"mappings": {}})
        ids = {f.rule_id for f in findings}
        self.assertNotIn("EMAIL_DKIM_MISSING", ids)
        self.assertIn("EMAIL_DMARC_MISSING", ids)

    def test_frame_ancestors_from_report_only_csp(self):
        # Field report §4 row 19, DAST side: a report-only CSP carrying
        # frame-ancestors still counts as clickjacking protection.
        from auditor import scanners as _sc
        headers = {
            "Strict-Transport-Security":
                "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; report-uri /csp",
            "Content-Security-Policy-Report-Only":
                "default-src 'self'; frame-ancestors 'none'",
            "Permissions-Policy": "camera=()",
            "Referrer-Policy": "no-referrer",
            "Cross-Origin-Opener-Policy": "same-origin",
            "X-Content-Type-Options": "nosniff",
        }
        ids = {f.rule_id for f in _sc._header_findings(
            "https://shop.test/", headers, {})}
        self.assertNotIn("NET_FRAME_ANCESTORS_MISSING", ids)

    def test_header_findings_skip_doc_checks_on_non_html(self):
        # Run-3 §4.3: one missing header CSP produced 18 rows (favicon,
        # css, webmanifest, sitemap...). Document-level headers are only
        # evaluated on text/html responses.
        from auditor import scanners as _sc
        headers = {"Content-Type": "image/png",
                   "Strict-Transport-Security":
                       "max-age=63072000; includeSubDomains; preload"}
        ids = {f.rule_id for f in _sc._header_findings(
            "https://shop.test/icon.png", headers, {}, body="PNGDATA")}
        self.assertNotIn("NET_CSP_MISSING", ids)
        self.assertNotIn("NET_CSP_WEAK", ids)
        self.assertNotIn("NET_FRAME_ANCESTORS_MISSING", ids)
        # Transport-level checks still run on non-HTML.
        self.assertNotIn("NET_HSTS_MISSING", ids)

    def test_meta_csp_pre_inline_script_flagged(self):
        # Run-3 §4.2: a meta CSP governs only content AFTER the meta tag.
        # With no header policy, earlier inline scripts run unconstrained.
        from auditor import scanners as _sc
        body = ("<html><head><script>early()</script>"
                "<meta http-equiv=\"Content-Security-Policy\" "
                "content=\"default-src 'self'\">"
                "<script>late()</script></head></html>")
        ids = {f.rule_id for f in _sc._header_findings(
            "https://shop.test/", {}, {}, body=body)}
        self.assertIn("NET_CSP_MISSING", ids)  # no header policy, still true
        self.assertIn("NET_META_CSP_ORDER", ids)

    def test_inline_script_hash_verified(self):
        # Run-3 §4.2: every inline script's SHA-256 is checked against the
        # effective script-src (header preferred, else meta, default-src
        # fallback, nonce-aware). One covered + one uncovered script.
        import hashlib
        import base64
        from auditor import scanners as _sc
        covered_js = "console.log('covered')"
        digest = base64.b64encode(
            hashlib.sha256(covered_js.encode()).digest()).decode()
        headers = {
            "Strict-Transport-Security":
                "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy":
                "default-src 'self'; script-src 'self' 'sha256-%s'; "
                "report-uri /csp" % digest,
        }
        body = ("<html><head><script>%s</script>"
                "<script>alert('nope')</script></head></html>" % covered_js)
        hits = [f for f in _sc._header_findings(
            "https://shop.test/", headers, {}, body=body)
            if f.rule_id == "NET_CSP_UNHASHED_INLINE"]
        self.assertEqual(len(hits), 1)
        self.assertIn("1 uncovered", hits[0].snippet)

    def test_unsafe_inline_skips_hash_check(self):
        # With 'unsafe-inline' everything runs: WEAK already fires, and a
        # hash audit would be meaningless noise.
        from auditor import scanners as _sc
        headers = {"Content-Security-Policy":
                   "default-src 'self'; script-src 'self' 'unsafe-inline'"}
        body = "<html><head><script>alert(1)</script></head></html>"
        ids = {f.rule_id for f in _sc._header_findings(
            "https://shop.test/", headers, {}, body=body)}
        self.assertIn("NET_CSP_WEAK", ids)
        self.assertNotIn("NET_CSP_UNHASHED_INLINE", ids)

    def test_nonce_covered_script_passes(self):
        # A script carrying a nonce listed in the policy is covered.
        from auditor import scanners as _sc
        headers = {"Content-Security-Policy":
                   "default-src 'self'; script-src 'nonce-abc123'"}
        body = ('<html><head><script nonce="abc123">alert(1)</script>'
                "</head></html>")
        ids = {f.rule_id for f in _sc._header_findings(
            "https://shop.test/", headers, {}, body=body)}
        self.assertNotIn("NET_CSP_UNHASHED_INLINE", ids)

    def test_placeholders_and_reserved_hosts_skipped(self):
        import auditor.scanners as scanners  # noqa: E402

        with patch("urllib.request.urlopen") as mock_open:
            findings = scanners.run_email_auth_audit(
                ["example.com", "app.internal", "host.test"], {})
        self.assertEqual(findings, [])
        mock_open.assert_not_called()

    def test_explicit_domains_via_orchestrator(self):
        auditor = self._auditor()
        auditor.config["email_auth"] = {
            "enabled": True, "domains": ["mail.example.org"],
            "selectors": ["default"], "timeout": 5}
        with patch("urllib.request.urlopen", side_effect=_doh_urlopen_mock({})):
            auditor.run_email_audit()
        self.assertTrue(any(f.rule_id == "EMAIL_DMARC_MISSING" for f in auditor.findings))

    def test_email_domains_override_config(self):
        # Field report §3.4: --email-domains lets a local DAST run check
        # the production domain even when DAST targets are localhost.
        auditor = self._auditor()
        auditor.config["email_auth"] = {"enabled": True, "domains": [],
                                        "selectors": ["default"], "timeout": 5}
        with patch("urllib.request.urlopen",
                   side_effect=_doh_urlopen_mock({})):
            auditor.run_email_audit(
                override_domains=["acmewidgets.io"])
        self.assertTrue(any(f.rule_id == "EMAIL_DMARC_MISSING"
                            for f in auditor.findings))

    def test_email_domains_threaded_through_run_all(self):
        # _run_engine_isolated re-reads config from disk, so the
        # email_auth block must be in the file, not just in memory.
        with open(self.config_path, "a", encoding="utf-8") as f:
            f.write("email_auth:\n  enabled: true\n  domains: []\n")
        from auditor import scanners as _sc
        auditor = self._auditor()
        seen = {}

        def spy(domains, mapping_data, selectors=None, timeout=10):
            seen["domains"] = list(domains)
            return []

        with patch.object(_sc, "run_email_auth_audit", side_effect=spy):
            auditor.run_all(engines=["email"], parallel=False,
                            email_domains=["acmewidgets.io"])
        self.assertEqual(seen.get("domains"), ["acmewidgets.io"])

    def test_email_checks_run_in_network_audit_path(self):
        # R-055: enabled email_auth extends run_network_audit for target domains.
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.text = "<html></html>"
        auditor = self._auditor()
        auditor.config["email_auth"] = {"enabled": True, "selectors": ["default"]}
        with patch("requests.get", return_value=mock_resp):
            with patch("urllib.request.urlopen", side_effect=_doh_urlopen_mock({})):
                auditor.run_network_audit(["https://mail.example.org"])
        self.assertTrue(any(f.rule_id == "EMAIL_DMARC_MISSING" for f in auditor.findings))


def _dast_router(captured):
    def _fake_get(url, timeout=None, headers=None):
        from urllib.parse import unquote
        captured.append((url, dict(headers or {})))
        m = MagicMock()
        m.status_code = 200
        if "/search" in url:
            m.headers = {}
            m.text = "results page echo: " + unquote(url)
        elif "/about" in url:
            m.headers = {"Server": "contains-example"}
            m.text = "<html><body>about</body></html>"
        else:
            m.headers = {}
            m.text = ('<html><a href="/about">a</a>'
                      '<a href="https://external.example.net/">x</a>'
                      '<a href="/search?q=hello">s</a></html>')
        return m
    return _fake_get


class TestDASTCrawlFuzz(_CloudPostureBase):
    def test_crawl_stays_same_origin(self):
        captured = []
        auditor = self._auditor()
        auditor.config["dast"] = {"crawl": True, "fuzz": False,
                                  "max_depth": 2, "max_pages": 20}
        with patch("requests.get", side_effect=_dast_router(captured)):
            auditor.run_network_audit(["https://app.example.org"])
        fetched = {u for u, _h in captured}
        self.assertIn("https://app.example.org/about", fetched)
        self.assertIn("https://app.example.org/search?q=hello", fetched)
        self.assertFalse(any("external.example.net" in u for u in fetched))
        # crawled info-leak page is header-checked too
        self.assertTrue(any(f.rule_id == "NET_INFO_LEAK" and "about" in f.file
                            for f in auditor.findings))

    def test_fuzz_reflection(self):
        captured = []
        auditor = self._auditor()
        auditor.config["dast"] = {"crawl": True, "fuzz": True,
                                  "max_depth": 1, "max_pages": 10,
                                  "max_fuzz_requests": 10}
        with patch("requests.get", side_effect=_dast_router(captured)):
            auditor.run_network_audit(["https://app.example.org"])
        xss = [f for f in auditor.findings if f.rule_id == "DAST_REFLECTED_XSS"]
        self.assertEqual(len(xss), 1)
        self.assertIn("SOC2:CC8.1", xss[0].frameworks)
        # probe string and response bodies never echoed into findings
        for f in auditor.findings:
            self.assertNotIn("<script>", f.snippet)
            self.assertNotIn("alert(1)", f.snippet)

    def test_auth_credential_sent_but_never_logged(self):
        import auditor.scanners as scanners  # noqa: E402

        captured = []
        self.assertEqual(scanners._dast_auth_headers(), {})
        env = _clean_cloud_env()
        env["DAST_AUTH_COOKIE"] = "session=mock-cookie-value"
        auditor = self._auditor()
        auditor.config["dast"] = {"crawl": False, "fuzz": False}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(scanners._dast_auth_headers(),
                             {"Cookie": "session=mock-cookie-value"})
            with patch("requests.get", side_effect=_dast_router(captured)):
                auditor.run_network_audit(["https://app.example.org"])
        self.assertTrue(captured)
        for _url, headers in captured:
            self.assertEqual(headers.get("Cookie"), "session=mock-cookie-value")
        haystack = " ".join(f.snippet + f.remediation + f.file + f.name
                            for f in auditor.findings)
        self.assertNotIn("mock-cookie-value", haystack)


class TestSBOM(_CloudPostureBase):
    def _write_manifests(self):
        with open(os.path.join(self.root, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("requests==2.28.0\n")
        with open(os.path.join(self.root, "package.json"), "w", encoding="utf-8") as f:
            json.dump({"name": "demo", "license": "MIT",
                       "dependencies": {"leftpad": "^1.3.0"}}, f)

    def test_sbom_cyclonedx_and_copyleft_flagged(self):
        self._write_manifests()
        sbom_path = os.path.join(self.root, "sbom.json")
        auditor = self._auditor()
        auditor.config["sbom"] = {"enabled": True, "format": "cyclonedx",
                                  "output": sbom_path}
        auditor.config["licenses"] = {"allowlist": ["MIT"],
                                      "overrides": {"requests": "GPL-3.0"}}
        auditor.run_sbom_audit()

        doc = json.load(open(sbom_path, encoding="utf-8"))
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        names = {c["name"] for c in doc["components"]}
        self.assertIn("requests", names)
        self.assertIn("leftpad", names)

        copyleft = [f for f in auditor.findings if f.rule_id == "SBOM_COPYLEFT_LICENSE"]
        self.assertEqual(len(copyleft), 1)
        self.assertEqual(copyleft[0].severity, "HIGH")
        self.assertEqual(copyleft[0].tool, "SBOM")
        self.assertIn("SOC2:CC8.1", copyleft[0].frameworks)
        self.assertIn("EU Cyber Resilience Act", copyleft[0].remediation)
        # allowlisted/declared-MIT project license itself is never flagged
        self.assertFalse(any("demo" in f.file and "package.json" not in f.file
                             for f in copyleft))

    def test_package_lock_wins_over_manifest_ranges(self):
        # Field report §3.5: a lockfile pins exact resolved versions; the
        # manifest only has ranges ("fake" versions). Lock wins.
        from auditor import scanners as _sc
        with open(os.path.join(self.root, "package.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"name": "demo", "dependencies": {"leftpad": "^9.9.9"},
                       "devDependencies": {"eslint": "~2.0.0"}}, f)
        lock = {"name": "demo", "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"leftpad": "1.3.0"},
                          "devDependencies": {"eslint": "2.0.0"}},
                    "node_modules/leftpad": {"version": "1.3.0"},
                    "node_modules/eslint": {"version": "2.0.0", "dev": True}}}
        with open(os.path.join(self.root, "package-lock.json"), "w",
                  encoding="utf-8") as f:
            json.dump(lock, f)
        pkgs = {p[0]: (p[1], p[2]) for p in _sc._parse_package_lock(
            os.path.join(self.root, "package-lock.json"))}
        self.assertEqual(pkgs["leftpad"], ("1.3.0", "prod"))
        self.assertEqual(pkgs["eslint"], ("2.0.0", "dev"))

        auditor = self._auditor()
        auditor.config["sbom"] = {"enabled": True, "format": "cyclonedx",
                                  "output": os.path.join(self.root, "sb.json")}
        auditor.config["licenses"] = {"allowlist": ["MIT"]}
        auditor.run_sbom_audit()
        doc = json.load(open(os.path.join(self.root, "sb.json"),
                             encoding="utf-8"))
        by_name = {c["name"]: c for c in doc["components"]}
        self.assertEqual(by_name["leftpad"]["version"], "1.3.0")
        self.assertNotIn("9.9.9", json.dumps(doc))

    def test_yarn_lock_classic_parsed(self):
        from auditor import scanners as _sc
        with open(os.path.join(self.root, "yarn.lock"), "w",
                  encoding="utf-8") as f:
            f.write('# yarn lockfile v1\n\n'
                    '"leftpad@^1.3.0":\n'
                    '  version "1.3.0"\n'
                    '  resolved "https://registry.yarnpkg.com/leftpad.tgz"\n')
        pkgs = _sc._parse_yarn_lock(os.path.join(self.root, "yarn.lock"))
        self.assertEqual(pkgs, [("leftpad", "1.3.0", "unknown")])

    def test_pnpm_lock_scopes(self):
        from auditor import scanners as _sc
        with open(os.path.join(self.root, "pnpm-lock.yaml"), "w",
                  encoding="utf-8") as f:
            f.write("lockfileVersion: '9.0'\n"
                    "importers:\n"
                    "  .:\n"
                    "    dependencies:\n"
                    "      leftpad:\n"
                    "        specifier: ^1.3.0\n"
                    "        version: 1.3.0\n"
                    "    devDependencies:\n"
                    "      eslint:\n"
                    "        specifier: ~2.0.0\n"
                    "        version: 2.0.0\n"
                    "packages:\n"
                    "  /leftpad@1.3.0:\n"
                    "    resolution: {integrity: sha512-x}\n"
                    "  /eslint@2.0.0:\n"
                    "    resolution: {integrity: sha512-y}\n")
        pkgs = {p[0]: (p[1], p[2]) for p in _sc._parse_pnpm_lock(
            os.path.join(self.root, "pnpm-lock.yaml"))}
        self.assertEqual(pkgs["leftpad"], ("1.3.0", "prod"))
        self.assertEqual(pkgs["eslint"], ("2.0.0", "dev"))

    def test_manifest_only_warns_ranges_not_resolved(self):
        import io
        from contextlib import redirect_stderr
        self._write_manifests()
        auditor = self._auditor()
        auditor.config["sbom"] = {"enabled": True, "format": "cyclonedx",
                                  "output": os.path.join(self.root, "sb.json")}
        buf = io.StringIO()
        with redirect_stderr(buf):
            auditor.run_sbom_audit()
        self.assertIn("ranges, not resolved", buf.getvalue())

    def test_sbom_default_output_under_target_reports(self):
        self._write_manifests()
        auditor = self._auditor()
        auditor.config["sbom"] = {"enabled": True, "format": "cyclonedx"}
        auditor.config["licenses"] = {"allowlist": ["MIT"]}
        auditor.run_sbom_audit()
        default = os.path.join(self.root, "reports", "sbom.cyclonedx.json")
        self.assertTrue(os.path.isfile(default), default)

    def test_sbom_relative_output_under_target(self):
        # Run-3 §3.6: a relative sbom.output resolved against the process
        # CWD, so scanning another repo wrote into the AuditForge checkout.
        # Relative outputs resolve against the target; absolute paths stay.
        self._write_manifests()
        auditor = self._auditor()
        auditor.config["sbom"] = {"enabled": True, "format": "cyclonedx",
                                  "output": "reports/sbom.cyclonedx.json"}
        auditor.run_sbom_audit()
        expect = os.path.join(self.root, "reports", "sbom.cyclonedx.json")
        self.assertTrue(os.path.isfile(expect), expect)

    def test_sbom_dev_dependency_marked_optional(self):
        with open(os.path.join(self.root, "package.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"name": "demo",
                       "devDependencies": {"mocha": "^10.0.0"}}, f)
        auditor = self._auditor()
        out = os.path.join(self.root, "sb.json")
        auditor.config["sbom"] = {"enabled": True, "format": "cyclonedx",
                                  "output": out}
        auditor.run_sbom_audit()
        doc = json.load(open(out, encoding="utf-8"))
        by_name = {c["name"]: c for c in doc["components"]}
        self.assertEqual(by_name["mocha"].get("scope"), "optional")

    def test_sbom_spdx_format(self):
        self._write_manifests()
        sbom_path = os.path.join(self.root, "sbom-spdx.json")
        auditor = self._auditor()
        auditor.config["sbom"] = {"enabled": True, "format": "spdx",
                                  "output": sbom_path}
        auditor.config["licenses"] = {"allowlist": ["MIT", "Apache-2.0"]}
        auditor.run_sbom_audit()
        doc = json.load(open(sbom_path, encoding="utf-8"))
        self.assertTrue(doc["spdxVersion"].startswith("SPDX-"))

    def test_unknown_licenses_opt_in_only(self):
        self._write_manifests()
        sbom_path = os.path.join(self.root, "sbom.json")
        auditor = self._auditor()
        auditor.config["sbom"] = {"enabled": True, "format": "cyclonedx",
                                  "output": sbom_path}
        auditor.config["licenses"] = {"allowlist": ["MIT"]}
        auditor.run_sbom_audit()
        self.assertFalse([f for f in auditor.findings
                          if f.rule_id == "SBOM_LICENSE_UNKNOWN"])

        auditor2 = self._auditor()
        auditor2.config["sbom"] = {"enabled": True, "format": "cyclonedx",
                                   "output": sbom_path}
        auditor2.config["licenses"] = {"allowlist": ["MIT"],
                                       "flag_unknown_licenses": True}
        auditor2.run_sbom_audit()
        unknown = [f for f in auditor2.findings if f.rule_id == "SBOM_LICENSE_UNKNOWN"]
        self.assertTrue(len(unknown) >= 2)  # requests + leftpad
        self.assertTrue(all(f.severity == "LOW" for f in unknown))

    def test_no_manifests_skips(self):
        empty = os.path.join(self.root, "empty")
        os.makedirs(empty)
        sbom_path = os.path.join(self.root, "sbom.json")
        auditor = universal_audit.UniversalAuditor(empty, self.config_path)
        auditor.config["sbom"] = {"enabled": True, "format": "cyclonedx",
                                  "output": sbom_path}
        auditor.run_sbom_audit()
        self.assertEqual(auditor.findings, [])
        self.assertFalse(os.path.exists(sbom_path))




class _ExtScannerBase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ext_scanner_test_")
        os.makedirs(os.path.join(self.root, "config"), exist_ok=True)
        self.config_path = os.path.join(self.root, "config", "compliance_config.yaml")
        workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        mapping_file = os.path.join(workspace_dir, "scripts", "framework_mappings.json").replace("\\", "/")
        metadata_file = os.path.join(workspace_dir, "scripts", "framework_metadata.json").replace("\\", "/")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(f"""
settings:
  mapping_file: "{mapping_file}"
  metadata_file: "{metadata_file}"
tools:
  checkov:
    enabled: false
  semgrep:
    enabled: false
  nuclei:
    enabled: true
    severity: "critical,high"
  scorecard:
    enabled: true
    min_score: 7
  trufflehog:
    enabled: true
network_targets: []
""")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _auditor(self):
        return universal_audit.UniversalAuditor(self.root, self.config_path)


class TestTruffleHog(_ExtScannerBase):
    _SECRET = "FAKE-TOKEN-FOR-TESTS-ONLY-0001"  # soc2-ignore: synthetic fixture, never a real credential

    def _event(self, verified=True):
        return json.dumps({
            "SourceMetadata": {"Data": {"Filesystem": {
                "file": os.path.join(self.root, "app.py"), "line": 12}}},
            "DetectorName": "Github",
            "Verified": verified,
            "Raw": self._SECRET,
        })

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_run_trufflehog_parses_verified(self, mock_run, mock_available):
        mock_result = MagicMock()
        mock_result.stdout = self._event(verified=True) + "\n"
        mock_run.return_value = mock_result

        auditor = self._auditor()
        auditor.run_trufflehog()

        self.assertEqual(len(auditor.findings), 1)
        finding = auditor.findings[0]
        self.assertEqual(finding.tool, "TruffleHog")
        self.assertEqual(finding.rule_id, "TRUFFLEHOG_VERIFIED_SECRET")
        self.assertEqual(finding.severity, "HIGH")
        self.assertIn("Github", finding.name)
        self.assertIn("SOC2:CC6.1", finding.frameworks)
        # Raw secret values must never enter findings.
        haystack = finding.snippet + finding.remediation + finding.file + finding.name
        self.assertNotIn(self._SECRET, haystack)

        _, call_kwargs = mock_run.call_args
        self.assertNotIn("shell", call_kwargs)
        argv = mock_run.call_args.args[0]
        self.assertIn("--only-verified", argv)
        self.assertIn("--json", argv)

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_run_trufflehog_drops_unverified(self, mock_run, mock_available):
        mock_result = MagicMock()
        mock_result.stdout = self._event(verified=False) + "\n"
        mock_run.return_value = mock_result

        auditor = self._auditor()
        auditor.run_trufflehog()

        self.assertEqual(auditor.findings, [])

    @patch("auditor.scanners._tool_available", return_value=False)
    @patch("subprocess.run")
    def test_run_trufflehog_skips_when_binary_missing(self, mock_run, mock_available):
        auditor = self._auditor()
        auditor.run_trufflehog()
        self.assertEqual(auditor.findings, [])
        mock_run.assert_not_called()


class TestNuclei(_ExtScannerBase):
    def _event(self):
        return json.dumps({
            "template-id": "CVE-2023-0001-template",
            "info": {
                "name": "Fake RCE Template",
                "severity": "critical",
                "description": "A fake remotely exploitable condition.",
                "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2023-0001"],
            },
            "matched-at": "https://real-target.internal.example.org/login",
        })

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_run_nuclei_parses_findings(self, mock_run, mock_available):
        mock_result = MagicMock()
        mock_result.stdout = self._event() + "\n"
        mock_run.return_value = mock_result

        auditor = self._auditor()
        auditor.run_nuclei(["https://real-target.internal.example.org"])

        self.assertEqual(len(auditor.findings), 1)
        finding = auditor.findings[0]
        self.assertEqual(finding.tool, "Nuclei")
        self.assertEqual(finding.rule_id, "CVE-2023-0001-template")
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertIn("real-target", finding.file)

        _, call_kwargs = mock_run.call_args
        self.assertNotIn("shell", call_kwargs)
        argv = mock_run.call_args.args[0]
        self.assertEqual(argv[:3], ["nuclei", "-u", "https://real-target.internal.example.org"])
        self.assertIn("-jsonl", argv)
        self.assertIn("critical,high", argv)  # severity filter from config

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_run_nuclei_invalid_severity_filter_ignored(self, mock_run, mock_available):
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        auditor = self._auditor()
        auditor.config["tools"]["nuclei"]["severity"] = "bogus"
        auditor.run_nuclei(["https://real-target.internal.example.org"])

        argv = mock_run.call_args.args[0]
        self.assertNotIn("-severity", argv)

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_run_nuclei_skips_placeholder_targets(self, mock_run, mock_available):
        auditor = self._auditor()
        auditor.run_nuclei([
            "https://example.com", "https://api.example.com/health",
        ])
        self.assertEqual(auditor.findings, [])
        mock_run.assert_not_called()

    @patch("auditor.scanners._tool_available", return_value=False)
    @patch("subprocess.run")
    def test_run_nuclei_skips_when_binary_missing(self, mock_run, mock_available):
        auditor = self._auditor()
        auditor.run_nuclei(["https://real-target.internal.example.org"])
        self.assertEqual(auditor.findings, [])
        mock_run.assert_not_called()


class TestScorecard(_ExtScannerBase):
    def _payload(self):
        return json.dumps({
            "repo": {"name": "github.com/fake-org/fake-repo"},
            "checks": [
                {"name": "Signed-Releases", "score": 3,
                 "reason": "no releases found with signed artifacts"},
                {"name": "Maintained", "score": 10,
                 "reason": "30 commit(s) and 5 issue activity in the last 90 days"},
                {"name": "Fuzzing", "score": -1,
                 "reason": "inconclusive - could not determine"},
            ],
        })

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("auditor.scanners._github_slug", return_value="fake-org/fake-repo")
    @patch("subprocess.run")
    def test_run_scorecard_flags_low_checks(self, mock_run, mock_slug, mock_available):
        mock_result = MagicMock()
        mock_result.stdout = self._payload()
        mock_run.return_value = mock_result

        auditor = self._auditor()
        auditor.run_scorecard()

        self.assertEqual(len(auditor.findings), 1)  # passing + inconclusive skipped
        finding = auditor.findings[0]
        self.assertEqual(finding.tool, "Scorecard")
        self.assertEqual(finding.rule_id, "SCORECARD_SIGNED_RELEASES")
        self.assertEqual(finding.severity, "HIGH")
        self.assertIn("SOC2:CC8.1", finding.frameworks)
        # SLSA-relevant checks carry SLSA provenance guidance.
        self.assertIn("slsa.dev", finding.remediation)

        _, call_kwargs = mock_run.call_args
        self.assertNotIn("shell", call_kwargs)
        argv = mock_run.call_args.args[0]
        self.assertEqual(argv[0], "scorecard")
        self.assertIn("--repo=fake-org/fake-repo", argv)

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("auditor.scanners._github_slug", return_value=None)
    @patch("subprocess.run")
    def test_run_scorecard_skips_non_github_checkout(self, mock_run, mock_slug, mock_available):
        auditor = self._auditor()
        auditor.run_scorecard()
        self.assertEqual(auditor.findings, [])
        mock_run.assert_not_called()

    @patch("auditor.scanners._tool_available", return_value=False)
    @patch("subprocess.run")
    def test_run_scorecard_skips_when_binary_missing(self, mock_run, mock_available):
        auditor = self._auditor()
        auditor.run_scorecard()
        self.assertEqual(auditor.findings, [])
        mock_run.assert_not_called()



    def test_engine_timeout_default_and_override(self):
        from auditor import scanners
        self.assertEqual(scanners._engine_timeout({}), 600)
        self.assertEqual(scanners._engine_timeout(None), 600)
        self.assertEqual(scanners._engine_timeout({"timeout": 30}), 30)
        self.assertEqual(scanners._engine_timeout({"timeout": "bad"}), 600)

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_hung_binary_becomes_skip_not_hang(self, mock_run, mock_available):
        import subprocess
        from auditor import scanners
        mock_run.side_effect = subprocess.TimeoutExpired("trivy", 600)
        findings = scanners.run_trivy(self.root, {"enabled": True}, {"mappings": {}})
        self.assertEqual(findings, [])
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs.get("timeout"), 600)

    @patch("auditor.scanners._tool_available", return_value=True)
    @patch("subprocess.run")
    def test_per_tool_timeout_override_reaches_binary(self, mock_run, mock_available):
        from auditor import scanners
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_run.return_value = mock_result
        scanners.run_trivy(self.root, {"enabled": True, "timeout": 42},
                           {"mappings": {}})
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs.get("timeout"), 42)


    def test_run_all_unknown_engine_rejected(self):
        auditor = self._auditor()
        with self.assertRaises(ValueError):
            auditor.run_all(engines=["nope"])

    def test_run_all_caches_deterministic_engine(self):
        from auditor.models import UnifiedFinding
        from auditor import scanners as _sc
        finding = UnifiedFinding(tool="Trivy", rule_id="CVE-2024-0001",
                                 name="Vuln", severity="HIGH",
                                 file="requirements.txt", line=0,
                                 snippet="pkg 1.0")
        with patch.object(_sc, "run_trivy", return_value=[finding]) as m, \
                patch("auditor.scanners._tool_available", return_value=True):
            first = self._auditor()
            first.run_all(engines=["trivy"], parallel=False)
            self.assertEqual(len(first.findings), 1)
            self.assertEqual(m.call_count, 1)
            second = self._auditor()
            second.run_all(engines=["trivy"], parallel=False)
            self.assertEqual(len(second.findings), 1)
            self.assertEqual(second.findings[0].rule_id, "CVE-2024-0001")
            self.assertEqual(m.call_count, 1)  # cache hit: no re-run

    def test_run_all_runs_engines_in_parallel(self):
        from auditor.models import UnifiedFinding
        from auditor import scanners as _sc
        f1 = UnifiedFinding(tool="A", rule_id="R1", name="n", severity="LOW",
                            file="f", line=1, snippet="s")
        f2 = UnifiedFinding(tool="B", rule_id="R2", name="n", severity="LOW",
                            file="f", line=1, snippet="s")
        with patch.object(_sc, "run_trivy", return_value=[f1]), \
                patch.object(_sc, "run_semgrep", return_value=[f2]), \
                patch("auditor.scanners._tool_available", return_value=True):
            auditor = self._auditor()
            auditor.run_all(engines=["trivy", "semgrep"], parallel=True)
            self.assertEqual({f.rule_id for f in auditor.findings}, {"R1", "R2"})

    def test_run_all_isolates_engine_failure(self):
        from auditor import scanners as _sc
        with patch.object(_sc, "run_trivy", side_effect=RuntimeError("boom")), \
                patch("auditor.scanners._tool_available", return_value=True):
            auditor = self._auditor()
            auditor.run_all(engines=["trivy"], parallel=False)
            self.assertEqual(auditor.findings, [])
            self.assertEqual(len(auditor.engine_errors), 1)
            self.assertEqual(auditor.engine_errors[0]["engine"], "trivy")
            self.assertEqual(auditor.run_status()["run_status"], "partial")

    def test_universal_sarif_and_run_status(self):
        from auditor import reporting
        from auditor.models import UnifiedFinding
        f1 = UnifiedFinding(tool="Semgrep", rule_id="R1", name="XSS",
                            severity="HIGH", file="a.js", line=3, snippet="s",
                            frameworks=["ASVS:V1.2.1"], remediation="fix it")
        f2 = UnifiedFinding(tool="Semgrep", rule_id="R1", name="XSS",
                            severity="LOW", file="b.js", line=0, snippet="s2")
        payload = json.loads(reporting.to_universal_sarif([f1, f2], {"total": 2}))
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(len(payload["runs"][0]["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(payload["runs"][0]["results"]), 2)
        levels = [r["level"] for r in payload["runs"][0]["results"]]
        self.assertEqual(levels, ["error", "note"])
        region = payload["runs"][0]["results"][1]["locations"][0] \
            ["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 1)
        out = json.loads(reporting.to_universal_json(
            [f1], {"total": 1}, {"semgrep": True},
            engine_errors=[{"engine": "x", "error": "y"}],
            run_status="partial", run_status_reason="x"))
        self.assertEqual(out["run_status"], "partial")
        self.assertEqual(len(out["engine_errors"]), 1)


    def _fake_tls_sock(self, version="TLSv1.3",
                         cipher="ECDHE-RSA-AES128-GCM-SHA256",
                         not_after="Jan  1 00:00:00 2030 GMT",
                         host="db.internal"):
        sock = MagicMock()
        sock.version.return_value = version
        sock.cipher.return_value = (cipher, "TLSv1.3", 128)
        sock.getpeercert.return_value = {
            "subject": ((("commonName", host),),), "notAfter": not_after}
        sock.__enter__.return_value = sock
        return sock

    def _run_tls(self, targets, sock):
        from auditor import scanners as _sc
        ctx = MagicMock()
        ctx.wrap_socket.return_value.__enter__.return_value = sock
        raw = MagicMock()
        raw.__enter__.return_value = raw
        with patch.object(_sc.socket, "create_connection",
                          return_value=raw) as conn, \
                patch.object(_sc.ssl, "create_default_context",
                             return_value=ctx):
            out = _sc.run_tls_audit(targets, {"mappings": {}}, {"enabled": True})
        return out, conn

    def test_tls_legacy_version_flagged(self):
        out, _ = self._run_tls(["https://db.internal:443"],
                               self._fake_tls_sock(version="TLSv1.1"))
        self.assertEqual([f.rule_id for f in out], ["TLS_WEAK_VERSION"])
        self.assertEqual(out[0].severity, "HIGH")

    def test_tls_weak_cipher_flagged(self):
        out, _ = self._run_tls(["db.internal"],
                               self._fake_tls_sock(cipher="RC4-SHA"))
        self.assertEqual([f.rule_id for f in out], ["TLS_WEAK_CIPHER"])

    def test_tls_expired_cert_critical(self):
        out, _ = self._run_tls(
            ["db.internal"],
            self._fake_tls_sock(not_after="Jan  1 00:00:00 2020 GMT"))
        self.assertEqual([f.rule_id for f in out], ["TLS_CERT_EXPIRED"])
        self.assertEqual(out[0].severity, "CRITICAL")

    def test_tls_hostname_mismatch(self):
        out, _ = self._run_tls(["other.internal"],
                               self._fake_tls_sock(host="db.internal"))
        self.assertEqual([f.rule_id for f in out],
                         ["TLS_CERT_HOSTNAME_MISMATCH"])

    def test_tls_healthy_host_clean(self):
        out, conn = self._run_tls(["https://db.internal"],
                                  self._fake_tls_sock())
        self.assertEqual(out, [])
        self.assertEqual(conn.call_count, 1)

    def test_tls_placeholders_never_dialed(self):
        from auditor import scanners as _sc
        with patch.object(_sc.socket, "create_connection") as conn:
            out = _sc.run_tls_audit(["https://example.com",
                                     "https://api.example.com/health"],
                                    {"mappings": {}}, {"enabled": True})
        self.assertEqual(out, [])
        conn.assert_not_called()

    def test_orchestrator_tls_uses_placeholders_safely(self):
        auditor = self._auditor()  # default config: placeholder targets
        auditor.run_tls_audit()
        self.assertEqual(auditor.findings, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
