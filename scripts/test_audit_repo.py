"""Tests for the SOC 2 static compliance auditor.

Run with:  python -m unittest scripts.test_audit_repo -v
      or:  python scripts/test_audit_repo.py
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import audit_repo  # noqa: E402


class AuditFixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="soc2_audit_test_")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, rel, content):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def audit(self, **kwargs):
        return audit_repo.audit_directory(self.root, **kwargs)

    def rule_ids(self, report):
        return {f.rule.id for f in report["findings"]}


class TestDetections(AuditFixture):
    def test_hardcoded_secret(self):
        self.write("app/config.py", 'password = "hunter2secret"\n')  # soc2-ignore: intentional detection-test fixture
        report = self.audit()
        self.assertIn("SEC001", self.rule_ids(report))
        finding = report["findings"][0]
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertIn("CC6.1", finding.rule.controls)

    def test_placeholder_secret_is_skipped(self):
        self.write("app/config.py",
                   'password = "${DB_PASSWORD}"\n'
                   'api_key = "your_api_key_here"\n'
                   'secret = "changeme"\n')
        report = self.audit()
        self.assertNotIn("SEC001", self.rule_ids(report))

    def test_aws_key_and_private_key(self):
        self.write("infra/creds.txt",
                   "AKIAIOSFODNN7EXAMPLE\n"  # soc2-ignore: intentional detection-test fixture
                   "-----BEGIN RSA PRIVATE KEY-----\n"
                   "MIIEowIBAAKCAQEA0y...\n")
        ids = self.rule_ids(self.audit())
        self.assertIn("SEC002", ids)
        self.assertIn("SEC003", ids)

    def test_wildcard_iam(self):
        self.write("infra/policy.json",
                   '{"Statement": [{"Action": "*", "Resource": "*"}]}\n')  # soc2-ignore: intentional detection-test fixture
        report = self.audit()
        self.assertIn("IAM001", self.rule_ids(report))
        self.assertEqual(report["summary"]["CRITICAL"], 2)

    def test_iac_encryption_and_ingress(self):
        self.write("infra/main.tf",
                   'resource "aws_ebs_volume" "v" {\n'
                   "  encrypted = false\n"
                   "}\n"
                   'resource "aws_security_group_rule" "r" {\n'
                   '  cidr_blocks = ["0.0.0.0/0"]\n'
                   "}\n")
        ids = self.rule_ids(self.audit())
        self.assertIn("ENC001", ids)
        self.assertIn("NET003", ids)

    def test_tls_verification_disabled(self):
        self.write("app/client.py",
                   "requests.get(url, verify=False)\n")  # soc2-ignore: intentional detection-test fixture
        self.write("app/client.js",
                   "https.request({rejectUnauthorized: false})\n")  # soc2-ignore: intentional detection-test fixture
        report = self.audit()
        net002 = [f for f in report["findings"] if f.rule.id == "NET002"]
        self.assertEqual(len(net002), 2)

    def test_credential_logging(self):
        self.write("app/login.js",
                   "console.log('user password: ' + password)\n")
        self.assertIn("LOG001", self.rule_ids(self.audit()))

    def test_http_url_in_code_but_not_localhost(self):
        self.write("app/api.ts",
                   'const a = "http://api.acmewidgets.io/v1";\n'
                   'const b = "http://localhost:3000";\n')
        report = self.audit()
        net004 = [f for f in report["findings"] if f.rule.id == "NET004"]
        self.assertEqual(len(net004), 1)

    def test_pii_email_flagged_but_reserved_suffix_exempt(self):
        self.write("app/users.py",
                   'real = "jane.doe@acmewidgets.io"\n'
                   'fixture_a = "dev@localhost"\n'
                   'fixture_b = "s3cret@cache.example"\n')
        report = self.audit()
        pii = [f for f in report["findings"] if f.rule.id == "PII001"]
        self.assertEqual(len(pii), 1)
        self.assertIn("jane.doe@acmewidgets.io", pii[0].snippet)

    def test_http_url_reserved_suffix_exempt(self):
        # RFC 2606/6761 reserved-purpose and non-routable pseudo-host
        # suffixes are never a live external target - see
        # docs/field-test-roninai-2026-08-25.md §G5/G7 (R-011).
        self.write("app/api.ts",
                   'const a = "http://api.example.com/v1";\n'
                   'const b = "http://svc.test/health";\n'
                   'const c = "http://thing.internal/ping";\n')
        report = self.audit()
        self.assertEqual([f for f in report["findings"] if f.rule.id == "NET004"], [])


class TestNoiseControls(AuditFixture):
    def test_inline_suppression(self):
        self.write("app/config.py",
                   'password = "legitsecret123"  # soc2-ignore: vetted\n')
        self.assertNotIn("SEC001", self.rule_ids(self.audit()))

    def test_test_context_downgrade(self):
        self.write("tests/fixtures/conf.py", 'password = "fixturesecret1"\n')  # soc2-ignore: intentional detection-test fixture
        report = self.audit()
        finding = report["findings"][0]
        self.assertTrue(finding.in_test_context)
        self.assertEqual(finding.severity, "HIGH")  # downgraded from CRITICAL

    def test_skip_dirs_and_lockfiles(self):
        self.write("node_modules/pkg/index.js", 'password = "nodesecret123"\n')  # soc2-ignore: intentional detection-test fixture
        self.write("package-lock.json", '{"password": "lockedsecret12"}\n')
        self.assertEqual(self.audit()["summary"]["total"], 0)

    def test_exclude_glob(self):
        self.write("generated/out.py", 'password = "gensecret1234"\n')  # soc2-ignore: intentional detection-test fixture
        report = self.audit(excludes=["generated/*"])
        self.assertEqual(report["summary"]["total"], 0)

    def test_min_severity_filter(self):
        self.write("app/api.ts", 'const a = "http://api.acmewidgets.io";\n')  # MEDIUM
        report = self.audit(min_severity="HIGH")
        self.assertEqual(report["summary"]["total"], 0)


class TestOutputsAndBaseline(AuditFixture):
    def seed(self):
        self.write("app/config.py", 'password = "hunter2secret"\n')  # soc2-ignore: intentional detection-test fixture

    def test_json_output_shape(self):
        self.seed()
        data = json.loads(audit_repo.to_json(self.audit()))
        finding = data["findings"][0]
        for key in ("rule_id", "severity", "soc2_controls", "file", "line",
                    "snippet", "remediation", "fingerprint"):
            self.assertIn(key, finding)

    def test_sarif_output_valid(self):
        self.seed()
        sarif = json.loads(audit_repo.to_sarif(self.audit()))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "auditforge")
        self.assertEqual(run["results"][0]["ruleId"], "SEC001")
        self.assertEqual(run["results"][0]["level"], "error")

    def test_markdown_output(self):
        self.seed()
        md = audit_repo.to_markdown(self.audit())
        self.assertIn("# AuditForge - SOC 2 Compliance Audit Report", md)
        self.assertIn("SEC001", md)

    def test_baseline_roundtrip(self):
        self.seed()
        report = self.audit()
        baseline_path = os.path.join(self.root, "..",
                                     os.path.basename(self.root) + ".baseline")
        try:
            audit_repo.write_baseline(baseline_path, report)
            known = audit_repo.load_baseline(baseline_path)
            self.assertEqual(known, {f.fingerprint for f in report["findings"]})
        finally:
            if os.path.exists(baseline_path):
                os.remove(baseline_path)

    def test_cli_fail_on_gate(self):
        self.seed()
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc_fail = audit_repo.main([self.root, "--fail-on", "CRITICAL"])
            rc_pass = audit_repo.main([self.root, "--fail-on", "NEVER"])
        self.assertEqual(rc_fail, 1)
        self.assertEqual(rc_pass, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
