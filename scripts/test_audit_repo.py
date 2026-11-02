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


    def test_rfc2606_documentation_domains_exempt(self):
        # Bare RFC 2606 domains (user@example.com) have no dot before
        # "example", so the dotted-suffix arm never fired on them -
        # field-caught on a real site audit.
        self.write("app/contact.py",
                   'owner = "bookings@acmewidgets.io"\n'
                   'a = "dev@example.com"\n'
                   'b = "qa@example.net"\n'
                   'c = "ops@example.org"\n')
        report = self.audit()
        pii = [f for f in report["findings"] if f.rule.id == "PII001"]
        self.assertEqual(len(pii), 1)
        self.assertIn("bookings@acmewidgets.io", pii[0].snippet)


    def test_web001_missing_headers_config(self):
        self.write("package.json", '{"name": "shop"}\n')
        self.write("index.html", "<html></html>\n")
        report = self.audit()
        self.assertIn("WEB001", self.rule_ids(report))
        self.write("_headers", "/*\n  X-Content-Type-Options: nosniff\n")
        report = self.audit()
        self.assertNotIn("WEB001", self.rule_ids(report))

    def test_web002_report_only_csp(self):
        self.write("site/_headers", "Content-Security-Policy-Report-Only: default-src 'self'\n")  # soc2-ignore: intentional detection-test fixture
        report = self.audit()
        self.assertIn("WEB002", self.rule_ids(report))

    def test_web003_innerhtml_sink_only_on_dynamic(self):
        self.write("app/ui.js",
                   "el.innerHTML = userInput;\n"  # soc2-ignore: intentional detection-test fixture
                   'box.innerHTML = "<b>static</b>";\n')
        report = self.audit()
        hits = [f for f in report["findings"] if f.rule.id == "WEB003"]
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0].file.replace("\\", "/").endswith("app/ui.js"))
        self.assertEqual(hits[0].line, 1)

    def test_web004_rate_limit_and_web005_origin(self):
        self.write("api/submit.ts",
                   "export async function POST(req: Request) {\n"
                   "  await save(await req.json());\n"
                   "}\n")
        report = self.audit()
        ids = self.rule_ids(report)
        self.assertIn("WEB004", ids)
        self.assertIn("WEB005", ids)
        self.write("api/guarded.ts",
                   "import { ratelimit } from './upstash';\n"
                   "export async function POST(req: Request) {\n"
                   "  if (req.headers.get('origin') !== 'https://shop.test') return new Response('no', {status: 403});\n"
                   "  await ratelimit.limit(req.ip);\n"
                   "}\n")
        report = self.audit()
        hits = [f for f in report["findings"]
                if f.rule.id in ("WEB004", "WEB005") and "guarded" in f.file]
        self.assertEqual(hits, [])

    def test_web004_monorepo_routes_detected(self):
        # Field report §3.1: apps/web/src/pages/api/* was invisible because
        # only the first three path segments were tested for route dirs.
        self.write("apps/web/src/pages/api/inquire.ts",
                   "export async function POST(req: Request) {\n"
                   "  await save(await req.json());\n"
                   "}\n")
        ids = self.rule_ids(self.audit())
        self.assertIn("WEB004", ids)
        self.assertIn("WEB005", ids)

    def test_web004_middleware_coverage_silences_routes(self):
        # Field report §3.2: rate limiting / origin checks that live in one
        # framework middleware file cover every route under it.
        self.write("apps/web/src/pages/api/inquire.ts",
                   "export async function POST(req: Request) {\n"
                   "  await save(await req.json());\n"
                   "}\n")
        self.write("apps/web/src/middleware.ts",
                   "import { ratelimit } from './upstash';\n"
                   "export async function onRequest(ctx, next) {\n"
                   "  if (ctx.request.headers.get('origin') !== 'https://shop.test') "
                   "return new Response('no', {status: 403});\n"
                   "  await ratelimit.limit(ctx.clientAddress);\n"
                   "  return next();\n"
                   "}\n")
        report = self.audit()
        hits = [f for f in report["findings"]
                if f.rule.id in ("WEB004", "WEB005")]
        self.assertEqual(hits, [])
        # Both directions: without the middleware the same route fires,
        # proving the test is not vacuous (routes really are detected).
        import os
        os.remove(os.path.join(self.root, "apps/web/src/middleware.ts"))
        ids = self.rule_ids(self.audit())
        self.assertIn("WEB004", ids)
        self.assertIn("WEB005", ids)

    def test_web001_caddyfile_matches(self):
        # Field report §3.3: _WEB_HEADERS_FILES holds "Caddyfile" but the
        # lookup key is lowercased, so it could never match.
        self.write("package.json", '{"name": "shop"}\n')
        self.write("Caddyfile", "example.com {\n  header Strict-Transport-Security max-age=31536000\n}\n")
        report = self.audit()
        self.assertNotIn("WEB001", self.rule_ids(report))

    def test_web006_weak_csp_unsafe_inline(self):
        # Field report §4 row 16: script-src 'unsafe-inline' with no
        # hash/nonce/strict-dynamic is a weak policy, not just a present one.
        self.write("package.json", '{"name": "shop"}\n')
        self.write("site/_headers",
                   "/*\n"
                   "  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; report-uri /csp\n"
                   "  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n")
        report = self.audit()
        self.assertIn("WEB006", self.rule_ids(report))
        self.assertNotIn("WEB007", self.rule_ids(report))

    def test_web007_csp_without_reporting(self):
        # Field report §4 row 15: a CSP with no report-uri/report-to
        # blinds the operator to real-world violations.
        self.write("package.json", '{"name": "shop"}\n')
        self.write("site/_headers",
                   "/*\n"
                   "  Content-Security-Policy: default-src 'self'; script-src 'self'\n"
                   "  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n")
        report = self.audit()
        self.assertIn("WEB007", self.rule_ids(report))
        self.assertNotIn("WEB006", self.rule_ids(report))

    def test_web008_weak_hsts_value(self):
        # Field report §4 row 21: short max-age, no subdomains, no preload.
        self.write("package.json", '{"name": "shop"}\n')
        self.write("site/_headers",
                   "/*\n"
                   "  Content-Security-Policy: default-src 'self'; report-uri /csp\n"
                   "  Strict-Transport-Security: max-age=86400\n")
        self.assertIn("WEB008", self.rule_ids(self.audit()))

    def test_web_strong_headers_pass_value_checks(self):
        self.write("package.json", '{"name": "shop"}\n')
        self.write("site/_headers",
                   "/*\n"
                   "  Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-abc'; report-to csp\n"
                   "  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n"
                   "  X-Content-Type-Options: nosniff\n"
                   "  Referrer-Policy: no-referrer\n"
                   "  Permissions-Policy: camera=()\n")
        ids = self.rule_ids(self.audit())
        self.assertNotIn("WEB006", ids)
        self.assertNotIn("WEB007", ids)
        self.assertNotIn("WEB008", ids)

    def test_web003_covers_more_sinks(self):
        # Field report §3.9: insertAdjacentHTML / outerHTML / document.write
        # were missed while innerHTML was caught.
        self.write("app/ui.js",
                   "el.insertAdjacentHTML('beforeend', userHtml);\n"  # soc2-ignore: intentional detection-test fixture
                   "el.outerHTML = data;\n"  # soc2-ignore: intentional detection-test fixture
                   "document.write(name);\n")  # soc2-ignore: intentional detection-test fixture
        hits = [f for f in self.audit()["findings"] if f.rule.id == "WEB003"]
        self.assertEqual(len(hits), 3)

    def test_web003_framework_raw_html_sinks(self):
        self.write("app/C.jsx",
                   "return <div dangerouslySetInnerHTML={{__html: reply}} />;\n")  # soc2-ignore: intentional detection-test fixture
        self.write("app/C.vue",
                   '<div v-html="chatReply"></div>\n')  # soc2-ignore: intentional detection-test fixture
        self.write("app/C.svelte",
                   "{@html assistantMsg}\n")  # soc2-ignore: intentional detection-test fixture
        hits = [f for f in self.audit()["findings"] if f.rule.id == "WEB003"]
        self.assertEqual(len(hits), 3)

    def test_web003_safe_stringify_downgraded(self):
        # Field report §3.8: JSON.stringify(...).replace(/</g, ...) is the
        # safe idiom - LOW, not MEDIUM.
        self.write("app/ui.js",
                   "el.innerHTML = JSON.stringify(state).replace(/</g, '\\u003c');\n")
        hits = [f for f in self.audit()["findings"] if f.rule.id == "WEB003"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "LOW")

    def test_web003_raw_import_downgraded(self):
        # Field report §3.8: a ?raw static-asset import is build-time data.
        self.write("app/ui.js",
                   "import iconSvg from './icon.svg?raw';\n"
                   "el.innerHTML = iconSvg;\n")
        hits = [f for f in self.audit()["findings"] if f.rule.id == "WEB003"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "LOW")

    def test_web003_model_or_fetch_context_raised(self):
        # Field report §3.8: a sink in a file that also handles model output
        # or fetch responses is HIGH, not MEDIUM.
        self.write("app/chat.js",
                   "const r = await fetch('/api/chat');\n"
                   "const data = await r.text();\n"
                   "el.innerHTML = data;\n")
        hits = [f for f in self.audit()["findings"] if f.rule.id == "WEB003"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "HIGH")

    def test_llm004_model_output_to_html_sink(self):
        # Field report §4 row 8 (OWASP LLM05): model text into an HTML sink.
        self.write("app/chat.ts",
                   "const reply = completion.choices[0].message.content;\n"
                   "el.innerHTML = reply;\n")  # soc2-ignore: intentional detection-test fixture
        self.write("app/Answer.astro",
                   "---\nconst answer = data.text;\n---\n<div set:html={answer} />\n")  # soc2-ignore: intentional detection-test fixture
        hits = [f for f in self.audit()["findings"] if f.rule.id == "LLM004"]
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(f.severity == "HIGH" for f in hits))

    def test_llm001_typescript_sdk_calls(self):
        # Field report §4 row 10: system:/messages: in TS SDK calls with
        # template-literal interpolation of request data.
        self.write("app/agent.ts",
                   "const res = await client.messages.create({\n"
                   '  model: "claude-x",\n'
                   "  system: `You are a ${role} helper`,\n"
                   '  messages: [{ role: "user", content: req.body.q }]\n'
                   "});\n")
        self.assertIn("LLM001", self.rule_ids(self.audit()))

    def test_llm002_typescript_system_exposure(self):
        # Field report §4 row 10: returning/logging the system prompt
        # variable in a TS SDK session leaks system instructions.
        self.write("app/agent.ts",
                   "const system = buildSystemPrompt(user);\n"
                   "console.log(`using system: ${system}`);\n"
                   "return { system };\n")
        self.assertIn("LLM002", self.rule_ids(self.audit()))

    def test_llm001_python_system_param(self):
        self.write("app/agent.py",
                   'resp = client.messages.create(model="x", system=f"role {r}")\n')
        self.assertIn("LLM001", self.rule_ids(self.audit()))

    def test_priv001_third_party_trackers(self):
        # Field report §4 row 4: GA4 / Clarity / Meta Pixel script includes
        # are consent-gated obligations - flag each one.
        self.write("site/index.html",
                   '<script src="https://www.googletagmanager.com/gtag/js?id=G-X"></script>\n'
                   '<script src="https://www.clarity.ms/tag/abc123"></script>\n'
                   '<script src="https://connect.facebook.net/en_US/fbevents.js"></script>\n')
        hits = [f for f in self.audit()["findings"] if f.rule.id == "PRIV001"]
        self.assertEqual(len(hits), 3)
        self.assertTrue(all(h.severity == "MEDIUM" for h in hits))

    def test_priv002_ip_written_to_log_sink(self):
        # Field report §4 row 6: IP addresses in log calls need a scrubbing
        # + retention story.
        self.write("app/server.ts",
                   'console.log("login from", clientIp);\n'  # soc2-ignore: intentional detection-test fixture
                   "logger.info({ ip: req.ip, path });\n")  # soc2-ignore: intentional detection-test fixture
        hits = [f for f in self.audit()["findings"] if f.rule.id == "PRIV002"]
        self.assertEqual(len(hits), 2)

    def test_priv003_cookie_and_session_storage_writes(self):
        # Field report §4 row 7: cookie/session writes need namespacing and
        # a documented eviction path (GDPR/CCPA deletion).
        self.write("app/state.ts",
                   'document.cookie = "sess=" + token;\n'  # soc2-ignore: intentional detection-test fixture
                   'sessionStorage.setItem("draft", body);\n')  # soc2-ignore: intentional detection-test fixture
        hits = [f for f in self.audit()["findings"] if f.rule.id == "PRIV003"]
        self.assertEqual(len(hits), 2)

    def test_web_baseline_lane_silent_when_covered(self):
        # Field report §4 rows 11-14: a middleware with a single auth gate,
        # a global error handler, structured logging, and size/duration
        # bounds silences the whole baseline lane.
        self.write("src/pages/api/notify.ts",
                   "export async function POST(req: Request) {\n"
                   "  return Response.json({ ok: true });\n"
                   "}\n")
        self.write("src/middleware.ts",
                   "import { withAuth } from './auth';\n"
                   "export async function onRequest(ctx, next) {\n"
                   "  try {\n"
                   "    const user = await withAuth(ctx.request);\n"
                   "    ctx.log.info({ user: user.id }, 'notify');\n"
                   "    return await next();\n"
                   "  } catch (err) {\n"
                   "    ctx.log.error({ err }, 'failed');\n"
                   "    return new Response('err', { status: 500 });\n"
                   "  }\n"
                   "}\n"
                   "export const config = { maxDuration: 10, bodyLimit: '1mb' };\n"
                   "export async function handleError({ error }: any) {\n"
                   "  console.error(error);\n"
                   '  return new Response("oops", { status: 500 });\n'
                   "}\n")
        ids = self.rule_ids(self.audit())
        for rid in ("WEB009", "WEB010", "WEB011", "WEB012"):
            self.assertNotIn(rid, ids)

    def test_web_baseline_lane_fires_when_bare(self):
        # Same route with a bare middleware: all four baseline gaps fire.
        self.write("src/pages/api/notify.ts",
                   "export async function POST(req: Request) {\n"
                   "  return Response.json({ ok: true });\n"
                   "}\n")
        self.write("src/middleware.ts",
                   "export async function onRequest(ctx, next) {\n"
                   "  return next();\n"
                   "}\n")
        ids = self.rule_ids(self.audit())
        for rid in ("WEB009", "WEB010", "WEB011", "WEB012"):
            self.assertIn(rid, ids)

    def test_suppress001_bare_warns_justified_silent(self):
        # Field report §3.10: a bare soc2-ignore still suppresses the finding
        # but must itself warn (LOW); a justified one stays silent.
        # The bare token is split so this test source stays SUPPRESS001-clean.
        bare = "soc2-" + "ignore"
        self.write("app/keys.py",
                   'KEY = "AKIAIOSFODNN7X4K9Q2X"  # ' + bare + "\n"  # soc2-ignore: intentional detection-test fixture
                   'OTHER = "AKIAIOSFODNN7X4K9Q3X"  # soc2-ignore: test vector\n')
        report = self.audit()
        ids = self.rule_ids(report)
        self.assertNotIn("SEC002", ids)
        bare = [f for f in report["findings"] if f.rule.id == "SUPPRESS001"]
        self.assertEqual(len(bare), 1)
        self.assertEqual(bare[0].severity, "LOW")
        self.assertEqual(bare[0].line, 1)

    def test_sec010_mail_header_injection(self):
        # Field report §4 row 1 (HIGH): request data into mail headers.
        self.write("app/invite.php",
                   'Mail::to($request->input("email"))->send($m);\n')  # soc2-ignore: intentional detection-test fixture
        self.write("app/go.js",
                   'res.setHeader("Location", req.query.next);\n')  # soc2-ignore: intentional detection-test fixture
        hits = [f for f in self.audit()["findings"] if f.rule.id == "SEC010"]
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(h.severity == "HIGH" for h in hits))

    def test_sec011_timing_unsafe_token_compare(self):
        # Field report §4 row 2 (MEDIUM): ==/=== between two token-shaped
        # values; a comparison against a non-secret literal is fine.
        self.write("app/auth.ts",
                   "if (userToken === storedToken) {\n"  # soc2-ignore: intentional detection-test fixture
                   "  ok();\n"
                   "}\n"
                   "if (token === undefined) {\n"
                   "  missing();\n"
                   "}\n")
        hits = [f for f in self.audit()["findings"] if f.rule.id == "SEC011"]
        self.assertEqual(len(hits), 1)

    def test_sec012_prototype_pollution(self):
        # Field report §4 row 3 (MEDIUM).
        self.write("app/merge.js",
                   'obj["__proto__"] = payload;\n'  # soc2-ignore: intentional detection-test fixture
                   "x.constructor[name] = val;\n")  # soc2-ignore: intentional detection-test fixture
        hits = [f for f in self.audit()["findings"] if f.rule.id == "SEC012"]
        self.assertEqual(len(hits), 2)

    def test_web002_ignores_md_prose(self):
        # Field report §3.7: prose documentation mentioning the header name
        # is not a deployment.
        self.write("package.json", '{"name": "shop"}\n')
        self.write("docs/SECURITY.md",
                   "# Security\n\nWe run Content-Security-Policy-Report-Only in staging.\n")
        self.assertNotIn("WEB002", self.rule_ids(self.audit()))

    def test_web003_no_high_in_md_prose(self):
        # Self-triage of the docs/ HIGH gate: prose .md that names sinks
        # while discussing model output is documentation, not a data flow -
        # detection stays, but it must never escalate to HIGH. The file sits
        # at the scan root so rel is basename-only (as in `audit_repo.py docs`).
        self.write("notes.md",  # soc2-ignore: intentional detection-test fixture
                   "# Notes\n\nLegacy pages render with document.write(x).\n"  # soc2-ignore: intentional detection-test fixture
                   "The completion API returns fetch responses with model output.\n")  # soc2-ignore: intentional detection-test fixture
        hits = [f for f in self.audit()["findings"] if f.rule.id == "WEB003"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "MEDIUM")

    def test_report_only_csp_value_graded(self):
        # Field report §4 row 17: a report-only policy is still audited for
        # unsafe-inline and missing reporting.
        self.write("package.json", '{"name": "shop"}\n')
        self.write("site/_headers",
                   "/*\n"
                   "  Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-inline'\n")
        ids = self.rule_ids(self.audit())
        self.assertIn("WEB002", ids)
        self.assertIn("WEB006", ids)
        self.assertIn("WEB007", ids)

    def test_turnstile_without_siteverify(self):
        # Field report §4 row 22: a Turnstile widget with no server-side
        # siteverify call is client-side theater.
        self.write("site/index.html",
                   '<div class="cf-turnstile" data-sitekey="x"></div>\n')
        self.write("src/pages/api/verify.ts",
                   "export async function POST(req: Request) {\n"
                   "  return Response.json({ ok: true });\n"
                   "}\n")
        self.assertIn("WEB013", self.rule_ids(self.audit()))
        self.write("src/pages/api/verify.ts",
                   "export async function POST(req: Request) {\n"
                   "  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: fd });\n"
                   "  return Response.json({ ok: (await r.json()).success });\n"
                   "}\n")
        self.assertNotIn("WEB013", self.rule_ids(self.audit()))

    def test_web_lane_silent_for_non_web_repo(self):
        self.write("main.py", 'print("hello")\n')
        report = self.audit()
        web = [f for f in report["findings"] if f.rule.id.startswith("WEB")]
        self.assertEqual(web, [])


class TestEmailReservedHosts(AuditFixture):
    def test_localhost_and_ip_literals_never_scanned(self):
        # Field report §3.4: bare "localhost" (no leading dot for the
        # suffix arm) and IP literals derived from DAST targets must be
        # skipped, never DNS-probed.
        from unittest.mock import patch
        from auditor import scanners
        with patch.object(scanners, "_dns_txt_records") as m:
            findings = scanners.run_email_auth_audit(
                ["localhost", "LOCALHOST", "127.0.0.1", "::1",
                 "example.com", "svc.test"],
                {"mappings": {}})
        self.assertEqual(findings, [])
        m.assert_not_called()

    def test_real_domain_still_scanned(self):
        from unittest.mock import patch
        from auditor import scanners
        with patch.object(scanners, "_dns_txt_records", return_value=[]) as m:
            findings = scanners.run_email_auth_audit(
                ["acmewidgets.io"], {"mappings": {}})
        self.assertTrue(m.called)
        ids = {f.rule_id for f in findings}
        self.assertIn("EMAIL_SPF_MISSING", ids)
        self.assertIn("EMAIL_DMARC_MISSING", ids)


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

    def test_derived_document_cache_excluded(self):
        # scripts/document_cache/ is derived, gitignored third-party HTML -
        # its PII-shaped content must not trip the self-audit gate.
        self.write("document_cache/nist-800-53.html",
                   "<html><body>Contact jane.doe@acmewidgets.io re 123-45-6789</body></html>\n")
        report = self.audit()
        self.assertEqual([f for f in report["findings"] if f.rule.id == "PII001"], [])

    def test_derived_sqlite_db_excluded(self):
        self.write("document_catalog.db", "contact jane.doe@acmewidgets.io\n")
        report = self.audit()
        self.assertEqual(report["summary"]["total"], 0)

    def test_derived_cache_does_not_fail_high_gate(self):
        self.write("document_cache/nist-800-53.html",
                   "<html><body>Contact jane.doe@acmewidgets.io re 123-45-6789</body></html>\n")
        self.write("document_catalog.db", "contact jane.doe@acmewidgets.io\n")
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = audit_repo.main([self.root, "--fail-on", "HIGH"])
        self.assertEqual(rc, 0)

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


class TestSkipTransparency(AuditFixture):
    def test_oversized_file_counted_not_silent(self):
        from auditor.rules import MAX_FILE_BYTES
        self.write("app/huge.py", "x = 1\n" * (MAX_FILE_BYTES // 6 + 1000))
        report = self.audit()
        self.assertEqual(report["skipped"]["oversized"], 1)

    def test_binary_file_counted_not_silent(self):
        path = os.path.join(self.root, "app", "blob.py")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(b"\x00\x01\x02binary garbage password = notreal\x00")
        report = self.audit()
        self.assertEqual(report["skipped"]["binary"], 1)

    def test_normal_scan_reports_zero_skips(self):
        self.write("app/config.py", 'x = 1\n')
        report = self.audit()
        self.assertEqual(sum(report["skipped"].values()), 0)

    def test_skip_counts_reach_text_output(self):
        from auditor.rules import MAX_FILE_BYTES
        self.write("app/huge.py", "x = 1\n" * (MAX_FILE_BYTES // 6 + 1000))
        report = self.audit()
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            audit_repo.print_text(report, use_color=False)
        self.assertIn("Files skipped: 1", buf.getvalue())
        self.assertIn("oversized", buf.getvalue())


class TestSoc2rcConfig(AuditFixture):
    def write_config(self, content):
        self.write(".soc2rc.yml", content)

    def test_pii_allow_config_suppresses_public_contact(self):
        # A published business contact is not a leak - pii_allow in
        # .soc2rc.yml suppresses it without resorting to the baseline.
        self.write("app/contact.py",
                   'owner = "bookings@acmewidgets.io"\n'
                   'leak = "jane.doe@other.io"\n')
        self.write_config('pii_allow:\n  - "*@acmewidgets.io"\n')
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = audit_repo.main([self.root, "--json"])
        data = json.loads(buf.getvalue())
        pii = [f for f in data["findings"] if f["rule_id"] == "PII001"]
        self.assertEqual(len(pii), 1)
        self.assertIn("jane.doe@other.io", pii[0]["snippet"])
        self.assertEqual(rc, 0)



    def test_exclude_from_config_applies(self):
        self.write("generated/out.py", 'password = "gensecret1234"\n')  # soc2-ignore: intentional detection-test fixture
        self.write_config("exclude:\n  - \"generated/*\"\n")
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = audit_repo.main([self.root, "--json"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data["summary"]["total"], 0)
        self.assertEqual(rc, 0)

    def test_min_severity_from_config_applies(self):
        self.write("app/api.ts", 'const a = "http://api.acmewidgets.io";\n')  # MEDIUM
        self.write_config("min_severity: HIGH\n")
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            audit_repo.main([self.root, "--json"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data["summary"]["total"], 0)

    def test_cli_min_severity_overrides_config(self):
        self.write("app/api.ts", 'const a = "http://api.acmewidgets.io";\n')  # MEDIUM
        self.write_config("min_severity: HIGH\n")
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            audit_repo.main([self.root, "--json", "--min-severity", "LOW"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data["summary"]["total"], 1)

    def test_disable_rules_from_config(self):
        self.write("app/config.py", 'password = "hunter2secret"\n')  # soc2-ignore: intentional detection-test fixture
        self.write_config("disable_rules:\n  - SEC001\n")
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            audit_repo.main([self.root, "--json"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data["summary"]["total"], 0)

    def test_malformed_config_does_not_crash(self):
        self.write_config("not: valid: yaml: [[[\n")
        self.write("app/config.py", 'password = "hunter2secret"\n')  # soc2-ignore: intentional detection-test fixture
        report = self.audit()  # goes through audit_directory directly - config only loaded by main()
        self.assertEqual(report["summary"]["total"], 1)
        # exercise main()'s own config-loading path too, just checking it doesn't raise
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = audit_repo.main([self.root, "--json"])
        self.assertEqual(rc, 0)


class TestOutputPathWarning(AuditFixture):
    def test_warns_when_markdown_output_inside_scan_dir(self):
        self.write("app/config.py", 'password = "hunter2secret"\n')  # soc2-ignore: intentional detection-test fixture
        out_path = os.path.join(self.root, "report.md")
        import contextlib, io
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            audit_repo.main([self.root, "--markdown", out_path])
        self.assertIn("inside the directory being scanned", err.getvalue())

    def test_no_warning_when_output_outside_scan_dir(self):
        self.write("app/config.py", 'password = "hunter2secret"\n')  # soc2-ignore: intentional detection-test fixture
        out_dir = tempfile.mkdtemp(prefix="soc2_report_")
        out_path = os.path.join(out_dir, "report.md")
        try:
            import contextlib, io
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                audit_repo.main([self.root, "--markdown", out_path])
            self.assertNotIn("inside the directory being scanned", err.getvalue())
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)


class TestHistoryScan(AuditFixture):
    def _git(self, *args):
        import subprocess
        subprocess.run(["git", "-C", self.root, *args], capture_output=True, text=True, check=True)

    def _init_repo_with_deleted_secret(self):
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.email", "test@example.com")
        self._git("config", "user.name", "Test")
        self.write("app/config.py", 'x = 1\n')
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "initial")
        # add a secret, commit it
        self.write("app/config.py", 'password = "hunter2secret"\n')  # soc2-ignore: intentional detection-test fixture
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "oops added a secret")
        # remove it from HEAD
        self.write("app/config.py", 'x = 1\n')
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "remove secret")

    def test_working_tree_scan_misses_deleted_secret(self):
        try:
            self._init_repo_with_deleted_secret()
        except Exception:
            self.skipTest("git not available")
        report = self.audit()
        self.assertEqual(report["summary"]["total"], 0)

    def test_history_scan_finds_deleted_secret(self):
        try:
            self._init_repo_with_deleted_secret()
        except Exception:
            self.skipTest("git not available")
        report = self.audit(history=True)
        self.assertGreaterEqual(report["summary"]["total"], 1)
        finding = report["findings"][0]
        self.assertTrue(finding.historical)
        self.assertIsNotNone(finding.commit)
        self.assertIn("history", finding.effective_remediation.lower())

    def test_history_flag_off_by_default(self):
        try:
            self._init_repo_with_deleted_secret()
        except Exception:
            self.skipTest("git not available")
        report = self.audit()  # history=False by default
        self.assertTrue(all(not f.historical for f in report["findings"]))

    def test_history_scan_non_repo_returns_empty(self):
        self.write("app/config.py", 'x = 1\n')
        report = self.audit(history=True)  # self.root is not a git repo
        self.assertEqual(report["summary"]["total"], 0)


class TestCICDRules(AuditFixture):
    def test_unpinned_action_flagged(self):
        self.write(".github/workflows/ci.yml",
                   "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
        self.assertIn("CICD001", self.rule_ids(self.audit()))

    def test_sha_pinned_action_passes(self):
        self.write(".github/workflows/ci.yml",
                   "jobs:\n  build:\n    steps:\n"
                   "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n")
        self.assertNotIn("CICD001", self.rule_ids(self.audit()))

    def test_broad_token_permissions_flagged(self):
        self.write(".github/workflows/deploy.yml",
                   "permissions: write-all\njobs:\n  d:\n    steps:\n      - run: make deploy\n")
        self.write(".github/workflows/other.yml", "jobs:\n  b:\n    permissions:\n      contents: write\n")
        report = self.audit()
        cicd002 = [f for f in report["findings"] if f.rule.id == "CICD002"]
        self.assertEqual(len(cicd002), 2)
        self.assertTrue(all(f.severity == "HIGH" for f in cicd002))

    def test_read_only_token_permissions_pass(self):
        self.write(".github/workflows/ci.yml",
                   "permissions: read-all\njobs:\n  b:\n    steps:\n      - run: make test\n")
        self.assertNotIn("CICD002", self.rule_ids(self.audit()))

    def test_secret_in_run_script_flagged(self):
        self.write(".github/workflows/deploy.yml",
                   "jobs:\n  d:\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n")
        report = self.audit()
        self.assertIn("CICD003", self.rule_ids(report))
        finding = [f for f in report["findings"] if f.rule.id == "CICD003"][0]
        self.assertIn("CC6.1", finding.rule.controls)

    def test_gitlab_script_secret_and_jenkins_sh_flagged(self):
        self.write(".gitlab-ci.yml",
                   "deploy:\n  script:\n    - echo $DEPLOY_TOKEN\n")
        self.write("Jenkinsfile", "pipeline {\n  steps {\n    sh 'curl -H $API_TOKEN $URL'\n  }\n}\n")
        report = self.audit()
        cicd003 = [f for f in report["findings"] if f.rule.id == "CICD003"]
        self.assertEqual(len(cicd003), 2)


class TestLLMRules(AuditFixture):
    def test_system_prompt_fstring_flagged(self):
        self.write("app/llm.py", 'system_prompt = f"You are {user_name}"\n')  # soc2-ignore: intentional detection-test fixture
        report = self.audit()
        self.assertIn("LLM001", self.rule_ids(report))
        finding = [f for f in report["findings"] if f.rule.id == "LLM001"][0]
        self.assertEqual(finding.severity, "HIGH")
        self.assertIn("CC8.1", finding.rule.controls)
        self.assertIn("LLM01", finding.rule.remediation)

    def test_system_prompt_concat_and_messages_sink_flagged(self):
        self.write("app/llm.py", 'system_prompt = BASE_PROMPT + user_input\n')  # soc2-ignore: intentional detection-test fixture
        self.write("app/chat.py", 'messages = [{"role": "system", "content": BASE + user_input}]\n')  # soc2-ignore: intentional detection-test fixture
        report = self.audit()
        llm001 = [f for f in report["findings"] if f.rule.id == "LLM001"]
        self.assertEqual(len(llm001), 2)

    def test_constant_system_prompt_passes(self):
        self.write("app/llm.py", 'system_prompt = "You are a helpful assistant."\n')
        self.assertNotIn("LLM001", self.rule_ids(self.audit()))

    def test_system_prompt_exposure_flagged(self):
        self.write("app/llm.py", 'return system_prompt\n')  # soc2-ignore: intentional detection-test fixture
        self.write("app/debug.js", 'console.log(system_prompt)\n')  # soc2-ignore: intentional detection-test fixture
        report = self.audit()
        llm002 = [f for f in report["findings"] if f.rule.id == "LLM002"]
        self.assertEqual(len(llm002), 2)
        self.assertIn("LLM07", llm002[0].rule.remediation)

    def test_tool_output_executed_flagged(self):
        self.write("app/agent.py", 'os.system(tool_output)\n')  # soc2-ignore: intentional detection-test fixture
        self.write("app/agent2.py", 'subprocess.run(["sh", "-c", llm_output])\n')  # soc2-ignore: intentional detection-test fixture
        self.write("app/agent3.py", 'eval(generated_code)\n')  # soc2-ignore: intentional detection-test fixture
        report = self.audit()
        llm003 = [f for f in report["findings"] if f.rule.id == "LLM003"]
        self.assertEqual(len(llm003), 3)
        self.assertIn("LLM06", llm003[0].rule.remediation)

    def test_tool_output_logged_not_executed(self):
        self.write("app/agent.py", 'print(tool_output)\n')
        self.assertNotIn("LLM003", self.rule_ids(self.audit()))


class TestK8sRules(AuditFixture):
    def test_insecure_pod_security_context_flagged(self):
        self.write("k8s/deploy.yaml",
                   "spec:\n  hostNetwork: true\n  containers:\n"
                   "  - securityContext:\n"
                   "      privileged: true\n"
                   "      allowPrivilegeEscalation: true\n"
                   "      runAsNonRoot: false\n"
                   "      runAsUser: 0\n"
                   "      hostPID: true\n")
        report = self.audit()
        k8s001 = [f for f in report["findings"] if f.rule.id == "K8S001"]
        self.assertEqual(len(k8s001), 6)
        self.assertTrue(all(f.severity == "HIGH" for f in k8s001))
        self.assertIn("CC6.1", k8s001[0].rule.controls)

    def test_hardened_pod_passes(self):
        self.write("k8s/deploy.yaml",
                   "spec:\n  containers:\n  - securityContext:\n"
                   "      allowPrivilegeEscalation: false\n"
                   "      runAsNonRoot: true\n"
                   "      runAsUser: 1000\n")
        self.assertNotIn("K8S001", self.rule_ids(self.audit()))

    def test_wildcard_rbac_flagged(self):
        self.write("k8s/rbac.yaml",
                   'rules:\n- apiGroups: [""]\n  resources: ["pods"]\n  verbs: ["*"]\n')
        self.write("k8s/rbac2.yaml",
                   'rules:\n- apiGroups: [""]\n  resources: ["*"]\n  verbs: ["get"]\n')
        report = self.audit()
        k8s002 = [f for f in report["findings"] if f.rule.id == "K8S002"]
        self.assertEqual(len(k8s002), 2)

    def test_scoped_rbac_passes(self):
        self.write("k8s/rbac.yaml",
                   'rules:\n- apiGroups: [""]\n  resources: ["pods"]\n  verbs: ["get", "list"]\n')
        self.assertNotIn("K8S002", self.rule_ids(self.audit()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
