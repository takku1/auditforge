import csv
import os
import re
import yaml
import json
from pathlib import Path

class FrameworkManager:
    """Regenerates scripts/framework_metadata.json from local knowledge bases.

    Sources are read-only clones kept fresh by scripts/update_sources.ps1.
    Derived file - never hand-edit framework_metadata.json.
    """

    # representative paths checked/seeded by sync_all
    SOURCES = {
        "nist_csf":      {"local_path": "nist-csf/README.md"},
        "jupiterone":    {"local_path": "jupiterone-policies/templates/policies"},
        "oscal_80053":   {"local_path": "oscal-content/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"},
        "oscal_800171":  {"local_path": "oscal-content/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json"},
        "csf2":          {"local_path": "oscal-content/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json"},
        "cac_controls":  {"local_path": "compliance-as-code/controls"},
        "asvs":          {"local_path": "asvs/5.0/docs_en"},
        "top10":         {"local_path": "owasp-top10/osib/export"},
        "attack":        {"local_path": "attack-stix-data/enterprise-attack"},
        "attack_ics":    {"local_path": "attack-stix-data/ics-attack"},
        "attack_mobile": {"local_path": "attack-stix-data/mobile-attack"},
        "scf":           {"local_path": "secure-controls-framework"},
        "fedramp_rules": {"local_path": "fedramp-rules/fedramp-consolidated-rules.json"},
        "saf_aws":         {"local_path": "mitre-saf-cis/aws-foundations-cis-baseline/controls"},
        "saf_azure":       {"local_path": "mitre-saf-cis/azure-foundations-cis-baseline/controls"},
        "saf_eks":         {"local_path": "mitre-saf-cis/eks-cis-cluster-baseline/controls"},
        "saf_gcp":         {"local_path": "mitre-saf-cis/gcp-cis-benchmark/controls"},
        "saf_gke":         {"local_path": "mitre-saf-cis/gke-cis-benchmark/controls"},
        # MITRE SAF DISA STIG InSpec baselines (Apache-2.0, same precedent as
        # the CIS baselines above): RHEL 8/9 STIG profiles, one SV-*.rb per
        # STIG, parsed by the same _parse_saf_inspec (SV- file names and
        # title/desc/impact/tag headers match the CIS shape).
        "saf_rhel8":       {"local_path": "mitre-saf-cis/rhel8-stig-baseline/controls"},
        "saf_rhel9":       {"local_path": "mitre-saf-cis/rhel9-stig-baseline/controls"},
        # DISA STIG XCCDF drop-ins (public.cyber.mil quarterly zips - no
        # "latest" URL, so manual drop-in like HITRUST precedent, not a
        # clone; parser activates only when the files are present).
        "stig_xccdf":      {"local_path": "references/disa-stig", "dropin": True},
        # DOE C2M2 v2.1 model PDF (US federal work, public domain -
        # refreshed by update_sources.ps1 $directDownloads, same wiring as
        # the AI RMF PDF).
        "c2m2":            {"local_path": "references/c2m2", "dropin": True},
        "ssdf":          {"local_path": "oscal-content/nist.gov/SP800-218/ver1/json/NIST_SP800-218_ver1_catalog.json"},
        "top10_2025":    {"local_path": "owasp-top10/2025/docs/en"},
        "samm":          {"local_path": "references/samm", "dropin": True},
        "nist80063":     {"local_path": "references/nist-800-63-4", "dropin": True},
        "cvss":          {"local_path": "references/cvss-v4", "dropin": True},
        "bsimm":         {"local_path": "references/bsimm", "dropin": True},
        "cisa_cpg":      {"local_path": "references/cisa-cpg", "dropin": True},
        "ref_cis":       {"local_path": "references/cis-controls", "dropin": True},
        "ref_ccm":       {"local_path": "references/ccm-bundle", "dropin": True},
        "ref_hitrust":   {"local_path": "references/hitrust-csf", "dropin": True},
        "ref_caiq":      {"local_path": "references/csa-caiq", "dropin": True},
        "ref_aicm":      {"local_path": "references/csa-aicm", "dropin": True},
        "genai":         {"local_path": "references/nist-ai-600-1/NIST.AI.600-1.pdf", "dropin": True},
        # OWASP Top-10 family (R-059..R-066): CC-licensed clones kept fresh
        # by scripts/update_sources.ps1, same precedent as owasp-top10/asvs.
        # agentic/ shares the llm clone (GenAI Security Project initiative).
        "api_security":  {"local_path": "owasp-api-security/editions/2023/en"},
        "mobile":        {"local_path": "owasp-mobile-top10/2023-risks"},
        "llm":           {"local_path": "owasp-llm-top10/2_0_vulns"},
        "agentic":       {"local_path": "owasp-llm-top10/initiatives/agent_security_initiative/agentic-top-10/Sprint 1-first-public-draft-expanded"},
        "mcp":           {"local_path": "owasp-mcp-top10/2025"},
        "k8s":           {"local_path": "owasp-k8s-top10/2025/en/src"},
        "cicd":          {"local_path": "owasp-cicd-top10"},
        "masvs":         {"local_path": "owasp-masvs/controls"},
        # MITRE/AI expansion (R-067/R-068 + CWE/CAPEC/D3FEND): ATLAS and
        # D3FEND are permissively licensed git clones (Apache-2.0 /
        # MIT - LICENSE files verified 2026-09-20) kept fresh by
        # scripts/update_sources.ps1, same precedent as attack-stix-data.
        # CWE/CAPEC/AI RMF are direct-download drop-ins under references/
        # (MITRE "latest" URLs / NIST PDF - refreshed by the
        # $directDownloads section of update_sources.ps1, no pinned
        # snapshots); parsers activate only when the files are present.
        "atlas":         {"local_path": "atlas-data/dist"},
        "d3fend":        {"local_path": "d3fend-ontology/src/ontology"},
        "cwe":           {"local_path": "references/cwe", "dropin": True},
        "capec":         {"local_path": "references/capec", "dropin": True},
        "ai_rmf":        {"local_path": "references/nist-ai-rmf", "dropin": True},
    }

    # One spec per OWASP Top-10-family list (R-059..R-066), consumed by
    # sync_all and reused by tests so parser args cannot drift from the
    # sync wiring. Keys: source_key (SOURCES), prefix (control/family key),
    # label, filename_re, title_id_re (named groups `id` + `title`), plus
    # optional year / with_lead (see _parse_owasp_categories).
    OWASP_CATEGORY_SPECS = (
        {"source_key": "api_security", "prefix": "API",
         "label": "OWASP API Security Top 10:2023",
         "filename_re": re.compile(r"^0xa[0-9a]-(.+)\.md$"),
         "title_id_re": re.compile(
             r"(?P<id>API\s*0*\d+\s*:\s*2023)\s+(?P<title>.+)", re.I)},
        {"source_key": "mobile", "prefix": "MOBILE",
         "label": "OWASP Mobile Top 10:2024",
         "filename_re": re.compile(r"^m(\d+)-(.+)\.md$"),
         "title_id_re": re.compile(r"(?P<id>M\s*0*\d+)\s*:\s*(?P<title>.+)"),
         "year": "2024"},
        {"source_key": "llm", "prefix": "LLM",
         "label": "OWASP LLM Top 10:2025",
         "filename_re": re.compile(r"^LLM(\d+)_([A-Za-z0-9]+)\.md$"),
         "title_id_re": re.compile(
             r"(?P<id>LLM\s*0*\d+\s*:\s*2025)\s+(?P<title>.+)")},
        {"source_key": "agentic", "prefix": "AGENTIC",
         "label": "OWASP Top 10 for Agentic Applications 2026",
         "filename_re": re.compile(r"^ASI(\d+)_.+\.md$"),
         "title_id_re": re.compile(
             r"(?P<id>ASI\s*0*\d+)\s*[-\u2013\u2014]\s*(?P<title>.+)"),
         "year": "2026", "with_lead": False},
        {"source_key": "mcp", "prefix": "MCP",
         "label": "OWASP MCP Top 10:2025",
         "filename_re": re.compile(r"^MCP(\d+)-2025[-\u2013\u2014](.+)\.md$"),
         "title_id_re": re.compile(
             r"(?P<id>MCP\s*0*\d+\s*:\s*2025)\s*[-\u2013\u2014]\s*(?P<title>.+)")},
        {"source_key": "k8s", "prefix": "K8S",
         "label": "OWASP Kubernetes Top 10:2025",
         "filename_re": re.compile(r"^(K\d+)-(.+)\.md$"),
         "title_id_re": re.compile(r"(?P<id>K\s*0*\d+)\s*:\s*(?P<title>.+)"),
         "year": "2025"},
        {"source_key": "cicd", "prefix": "CICD",
         "label": "OWASP Top 10 CI/CD Security Risks",
         "filename_re": re.compile(r"^(CICD-SEC-\d+)-(.+)\.md$"),
         "title_id_re": re.compile(
             r"(?P<id>CICD-SEC-0*\d+)\s*:\s*(?P<title>.+)")},
        {"source_key": "masvs", "prefix": "MASVS",
         "label": "OWASP Mobile Application Security Verification Standard (MASVS)",
         "filename_re": re.compile(r"^(MASVS-[A-Z]+-\d+)\.md$"),
         "title_id_re": re.compile(r"(?P<id>MASVS-[A-Z]+-\d+)\s*(?P<title>.*)")},
    )

    # Friendlier labels for the ComplianceAsCode control files that map to a
    # single, well-known named standard (rather than a per-product benchmark
    # variant, which gets an auto-derived label from its own policy/title).
    CAC_LABEL_OVERRIDES = {
        "hipaa": "HIPAA Security Rule",
        "pcidss_3": "PCI DSS v3.2.1",
        "pcidss_4": "PCI DSS v4.0",
        "e8": "Australian Cyber Security Centre Essential Eight",
        "srg_gpos": "DISA SRG - General Purpose Operating System",
        "srg_ctr": "DISA SRG - Container Platform",
        "ospp": "NIAP OS Protection Profile",
    }

    def __init__(self):
        self.metadata = {"frameworks": {}, "controls": {}}

    def sync_all(self):
        print("Starting AuditForge framework sync...")
        missing = []
        for name, src in self.SOURCES.items():
            if os.path.exists(src["local_path"]):
                print(f"[+] {name}: found")
            else:
                if not src.get("dropin"):
                    missing.append(name)
                if src.get("dropin"):
                    print(f"[i] {name}: empty drop-in ({src['local_path']}) - see references/README.md")
                else:
                    print(f"[!] {name}: MISSING ({src['local_path']})")
        if missing:
            print("[i] Run scripts/update_sources.ps1 to clone missing sources.")

        self._parse_legacy_nist()
        self._parse_jupiterone()
        self._parse_oscal("oscal_80053", "NIST53", "NIST SP 800-53 Rev5")
        self._parse_oscal("oscal_800171", "NIST171", "NIST SP 800-171 Rev3")
        self._parse_oscal("csf2", "CSF2", "NIST Cybersecurity Framework 2.0")
        self._parse_cac_controls_dir()
        self._parse_asvs()
        self._parse_attack("attack", "ATTACK", "MITRE ATT&CK Enterprise")
        self._parse_attack("attack_ics", "ATTACK_ICS", "MITRE ATT&CK ICS")
        self._parse_attack("attack_mobile", "ATTACK_MOBILE", "MITRE ATT&CK Mobile")
        self._parse_scf_crosswalk()
        self._parse_fedramp_ksi()
        self._parse_saf_inspec("saf_aws", "SAF_AWS", "MITRE SAF CIS AWS Foundations Benchmark (InSpec)")
        self._parse_saf_inspec("saf_azure", "SAF_AZURE", "MITRE SAF CIS Azure Foundations Benchmark (InSpec)")
        self._parse_saf_inspec("saf_eks", "SAF_EKS", "MITRE SAF CIS EKS Benchmark (InSpec)")
        self._parse_saf_inspec("saf_gcp", "SAF_GCP", "MITRE SAF CIS GCP Benchmark (InSpec)")
        self._parse_saf_inspec("saf_gke", "SAF_GKE", "MITRE SAF CIS GKE Benchmark (InSpec)")
        self._parse_saf_inspec("saf_rhel8", "SAF_RHEL8", "MITRE SAF RHEL 8 STIG Baseline (InSpec)")
        self._parse_saf_inspec("saf_rhel9", "SAF_RHEL9", "MITRE SAF RHEL 9 STIG Baseline (InSpec)")
        # DISA STIG XCCDF + DOE C2M2 - each a no-op when its drop-in is
        # absent (see _parse_stig_xccdf / _parse_c2m2).
        self._parse_stig_xccdf()
        self._parse_c2m2()
        # OWASP Top 10 OSIB export is a deeply nested CWE-linkage graph, not a
        # flat control list; the indexed Top 10:2025 categories come from the
        # 2025/docs/en markdown in the same clone (see _parse_top10_2025).
        # (old presence-flag comment retired; OSIB has no 2025 nodes, only
        # link targets to top10.2021.x - see docs/framework-coverage-audit-2026-09-02.md).
        self._parse_ssdf()
        self._parse_top10_2025()
        # Open-source drop-ins (parsed only when the user supplies the file
        # under references/ - never auto-fetched; see references/README.md).
        self._parse_samm()
        self._parse_section_markdown(
            "nist80063", "NIST80063", "NIST SP 800-63-4 Digital Identity Guidelines",
            re.compile(r"(?P<id>\d+(?:\.\d+)+)\s+(?P<title>.+)"))
        # The usnistgov/800-63-4 source ships section bodies as HTML, not
        # markdown (headings carry slug ids, no dotted numbers) - parsed below.
        self._parse_nist80063_html()
        self._parse_cvss()
        self._parse_section_markdown(
            "bsimm", "BSIMM", "BSIMM Software Security Framework",
            re.compile(r"(?P<title>.+?)\s+\((?P<id>[A-Za-z]{1,4})\)\s*$"))
        self._parse_reference_csv("cisa_cpg", "CPG", "CISA Cybersecurity Performance Goals 2.0")
        self._parse_genai()
        # OWASP Top-10 family (R-059..R-066) - one spec per list, each a
        # no-op when its clone is absent.
        for spec in self.OWASP_CATEGORY_SPECS:
            self._parse_owasp_categories(**spec)
        # MITRE/AI expansion (R-067/R-068 + CWE/CAPEC/D3FEND) - each a
        # no-op when its clone/drop-in is absent.
        self._parse_atlas()
        self._parse_d3fend()
        self._parse_cwe()
        self._parse_capec()
        self._parse_ai_rmf()
        # Gated frameworks (licenses forbid automated fetching - registration,
        # Fair-Use-only, or subscription gates; user-supplied files only).
        self._parse_reference_csv("ref_cis", "CIS", "CIS Critical Security Controls v8.1")
        self._parse_reference_json("ref_ccm", "CCM", "CSA Cloud Controls Matrix v4")
        self._parse_reference_csv("ref_hitrust", "HITRUST", "HITRUST CSF")
        self._parse_reference_csv("ref_caiq", "CAIQ", "CSA Consensus Assessments Initiative Questionnaire")
        self._parse_reference_csv("ref_aicm", "AICM", "CSA AI Controls Matrix")
        # (old top10 presence-flag _register_family call retired)

        out = Path(__file__).parent / "framework_metadata.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)
        print(f"Metadata updated: {out.name} "
              f"({len(self.metadata['controls'])} controls, "
              f"{len(self.metadata['frameworks'])} families)")

    def _register_family(self, key, label, check_path):
        if os.path.exists(check_path):
            self.metadata["frameworks"][key] = label

    def _parse_legacy_nist(self):
        path = self.SOURCES["nist_csf"]["local_path"]
        if not os.path.exists(path):
            return
        content = Path(path).read_text(encoding="utf-8")
        pattern = re.compile(r"\*\*([A-Z]{2}\.[A-Z]{2}-\d+)\*\*: (.*)")
        n = 0
        for match in pattern.finditer(content):
            control_id, description = match.groups()
            self.metadata["controls"][f"NIST:{control_id}"] = description
            n += 1
        if n:
            self.metadata["frameworks"]["NIST"] = "NIST Cybersecurity Framework v1.1 (legacy)"

    def _parse_jupiterone(self):
        path = self.SOURCES["jupiterone"]["local_path"]
        if not os.path.isdir(path):
            return
        for filename in os.listdir(path):
            if not filename.endswith(".md.tmpl"):
                continue
            pid = filename.replace(".md.tmpl", "").upper()
            lines = Path(os.path.join(path, filename)).read_text(
                encoding="utf-8").splitlines()
            title = next((l.strip("# \n") for l in lines if l.startswith("# ")), pid)
            self.metadata["controls"][f"J1:{pid}"] = title
        self.metadata["frameworks"]["J1"] = "JupiterOne Security Policies"

    def _parse_oscal(self, key, prefix, label):
        path = self.SOURCES[key]["local_path"]
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        catalog = data.get("catalog", {})

        def walk(controls):
            for c in controls or []:
                cid = c.get("id", "")
                title = (c.get("title") or "").strip()
                if cid and title:
                    self.metadata["controls"][f"{prefix}:{cid.upper()}"] = title
                walk(c.get("controls"))

        for group in catalog.get("groups", []):
            walk(group.get("controls"))
        walk(catalog.get("controls"))
        self.metadata["frameworks"][prefix] = label

    def _walk_cac_controls(self, controls, prefix):
        """Recursively index a ComplianceAsCode controls: list; returns count added."""
        n = 0

        def walk(items):
            nonlocal n
            for c in items or []:
                if not isinstance(c, dict):
                    continue
                cid = str(c.get("id", "")).strip()
                title = str(c.get("title", "")).strip()
                if cid and title:
                    self.metadata["controls"][f"{prefix}:{cid}"] = title
                    n += 1
                walk(c.get("controls"))

        walk(controls)
        return n

    def _parse_cac_controls_dir(self):
        """Auto-discovers every ComplianceAsCode controls/*.yml file (CIS, STIG,
        HIPAA, PCI DSS, Essential Eight, SRG, BSI, ANSSI, CCN, ISM, NIST
        product overlays, ...) and registers each as its own framework family.
        Handles both the single-file and split-directory (controls/<id>/section-*.yml)
        layouts documented in compliance-as-code/.claude/CLAUDE.md.
        """
        base = Path(self.SOURCES["cac_controls"]["local_path"])
        if not base.is_dir():
            return
        families = 0
        skipped_sections = 0
        for path in sorted(base.glob("*.yml")):
            stem = path.stem
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
            except yaml.YAMLError:
                continue
            if not isinstance(data, dict):
                continue

            controls = data.get("controls")
            if not controls:
                # split-directory format: controls/<stem>/section-*.yml (or,
                # for some products, one file per control - both contain a
                # top-level `controls:` list). A handful of these embed
                # unquoted Jinja2 macros (e.g. `{{{ full_name }}}`) in titles,
                # which aren't valid standalone YAML - skip just that file.
                subdir = base / stem
                if subdir.is_dir():
                    controls = []
                    for section in sorted(subdir.glob("*.yml")):
                        try:
                            with open(section, "r", encoding="utf-8") as sf:
                                sdata = yaml.safe_load(sf)
                        except yaml.YAMLError:
                            skipped_sections += 1
                            continue
                        if isinstance(sdata, dict):
                            controls.extend(sdata.get("controls") or [])
            if not controls:
                continue

            prefix = re.sub(r"[^A-Z0-9]+", "_", stem.upper()).strip("_")
            label = self.CAC_LABEL_OVERRIDES.get(stem) or str(
                data.get("policy") or data.get("title") or stem).strip()
            n = self._walk_cac_controls(controls, prefix)
            if n:
                self.metadata["frameworks"][prefix] = f"{label} (via ComplianceAsCode)"
                families += 1
        print(f"[i] cac_controls: {families} framework families parsed from "
              f"compliance-as-code/controls/*.yml"
              + (f" ({skipped_sections} section files skipped - unquoted Jinja2 macros)"
                 if skipped_sections else ""))

    def _parse_attack(self, source_key: str, prefix: str, label: str):
        """Parses MITRE ATT&CK techniques from a STIX 2.1 bundle. Generalized
        (R-030) to cover all three matrices - Enterprise (`attack`/`ATTACK`,
        unchanged prefix for backward compatibility with anything already
        querying it), ICS (`attack_ics`/`ATTACK_ICS`), and Mobile
        (`attack_mobile`/`ATTACK_MOBILE`) - each registered as its own
        framework family rather than merged into one, since technique IDs
        aren't guaranteed unique across matrices.
        """
        base = Path(self.SOURCES[source_key]["local_path"])
        stem = base.name  # "enterprise-attack" | "ics-attack" | "mobile-attack"
        path = base / f"{stem}.json"
        if not path.exists():
            candidates = sorted(base.glob(f"{stem}-*.json"))
            if not candidates:
                return
            path = candidates[-1]
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        n = 0
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            name = (obj.get("name") or "").strip()
            ext_id = next(
                (r.get("external_id") for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack" and r.get("external_id")),
                None,
            )
            if ext_id and name:
                self.metadata["controls"][f"{prefix}:{ext_id}"] = name
                n += 1
        if n:
            self.metadata["frameworks"][prefix] = label
        print(f"[i] {source_key}: {n} techniques indexed")

    def _parse_scf_crosswalk(self):
        """Parses the Secure Controls Framework crosswalk workbook: registers
        every focal document (ISO 27001/27017/27018/27701/42001, GDPR, DORA,
        NIS2, CMMC 2.0, FedRAMP R5, TISAX, UK Cyber Essentials, LGPD, PIPEDA,
        SOX, GLBA, NYDFS 500, CIS Controls, and ~240 more) as its own
        framework family, keyed by SCF control ID -> that framework's mapped
        clause(s). Requires openpyxl (see requirements.txt).
        """
        base = Path(self.SOURCES["scf"]["local_path"])
        if not base.is_dir():
            return
        candidates = sorted(base.glob("secure-controls-framework-scf-*.xlsx"))
        if not candidates:
            return
        xlsx_path = candidates[-1]

        try:
            import openpyxl
        except ImportError:
            print("[!] scf: openpyxl not installed (pip install -r requirements.txt) "
                  "- registering crosswalk as presence-only")
            self.metadata["frameworks"]["SCF"] = (
                "Secure Controls Framework crosswalk (unparsed - install openpyxl)")
            return

        wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
        if "Focal Documents" not in wb.sheetnames or "SCF 2026.2" not in wb.sheetnames:
            scf_sheet_name = next((s for s in wb.sheetnames if s.startswith("SCF 20")), None)
            if not scf_sheet_name or "Focal Documents" not in wb.sheetnames:
                print("[!] scf: expected sheets not found, skipping crosswalk parse")
                return
        else:
            scf_sheet_name = "SCF 2026.2"

        fd_rows = list(wb["Focal Documents"].iter_rows(values_only=True))
        fd_header = fd_rows[0]
        fd_idx = {name: i for i, name in enumerate(fd_header) if name}
        focal_docs = []
        for r in fd_rows[1:]:
            if not r:
                continue
            col_header = r[fd_idx["SCF Column Header"]] if "SCF Column Header" in fd_idx else None
            fdi = r[fd_idx["Focal Document Identifier (FDI)"]] if "Focal Document Identifier (FDI)" in fd_idx else None
            fdn = r[fd_idx["Focal Document Name (FDN)"]] if "Focal Document Name (FDN)" in fd_idx else None
            if col_header and fdi and fdn:
                focal_docs.append((str(col_header), str(fdi), str(fdn)))

        scf_ws = wb[scf_sheet_name]
        scf_rows = scf_ws.iter_rows(values_only=True)
        scf_header = next(scf_rows)
        header_to_col = {}
        for i, h in enumerate(scf_header):
            if h:
                header_to_col.setdefault(str(h), i)

        mapped = []
        seen_prefixes = set()
        for col_header, fdi, fdn in focal_docs:
            col_idx = header_to_col.get(col_header)
            if col_idx is None:
                continue
            prefix = "SCF_" + re.sub(r"[^A-Z0-9]+", "_", fdi.upper()).strip("_")
            if prefix in seen_prefixes:
                continue
            seen_prefixes.add(prefix)
            mapped.append((col_idx, prefix, fdn))

        idx_scf_num = 2  # "SCF #"
        counts = {prefix: 0 for _, prefix, _ in mapped}
        for row in scf_rows:
            scf_id = row[idx_scf_num] if len(row) > idx_scf_num else None
            if not scf_id:
                continue
            for col_idx, prefix, _ in mapped:
                cell = row[col_idx] if col_idx < len(row) else None
                if cell in (None, ""):
                    continue
                clauses = str(cell).replace("\n", " ").replace("\r", " ").strip()
                clauses = re.sub(r"\s+", " ", clauses)
                self.metadata["controls"][f"{prefix}:{scf_id}"] = clauses
                counts[prefix] += 1

        registered = 0
        for _, prefix, fdn in mapped:
            if counts[prefix]:
                self.metadata["frameworks"][prefix] = f"{fdn} (via SCF crosswalk)"
                registered += 1
        total_cells = sum(counts.values())
        print(f"[i] scf: {registered} focal-document frameworks parsed from crosswalk "
              f"({total_cells} SCF-control-to-clause mappings)")

    def _parse_asvs(self):
        docs_dir = self.SOURCES["asvs"]["local_path"]
        if not os.path.isdir(docs_dir):
            return
        json_file = next(
            (f for f in sorted(os.listdir(docs_dir))
             if f.endswith("_en.json") and ".flat." not in f and ".legacy." not in f),
            None,
        )
        if not json_file:
            return
        with open(os.path.join(docs_dir, json_file), "r", encoding="utf-8") as f:
            data = json.load(f)

        def walk(items):
            for it in items or []:
                code = it.get("Shortcode", "")
                # Section/chapter nodes carry Name; leaf requirements carry
                # Description instead (schema changed in the 5.0.0 export).
                name = (it.get("Name") or it.get("Description") or "").strip()
                if code and name:
                    self.metadata["controls"][f"ASVS:{code}"] = name
                walk(it.get("Items"))

        walk(data.get("Requirements") or data.get("chapters"))
        version = data.get("Version", "")
        self.metadata["frameworks"]["ASVS"] = f"OWASP ASVS v{version}"

    def _parse_fedramp_ksi(self):
        """Parses FedRAMP 20x's Key Security Indicators (the framework that
        replaced the old Rev5 baseline-profile model - see ROADMAP RF-003).
        Source: FedRAMP/rules (github.com/FedRAMP/rules), the machine-readable
        source of truth behind fedramp.gov/2026/ - public domain, US federal
        work. Each indicator (e.g. KSI-CED-RAT) becomes its own control entry,
        with its mapped NIST SP 800-53 control IDs appended so it crosswalks
        against the NIST53:* entries already indexed by _parse_oscal.
        """
        path = self.SOURCES["fedramp_rules"]["local_path"]
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        ksi_groups = data.get("KSI")
        if not isinstance(ksi_groups, dict):
            return

        n = 0
        for group in ksi_groups.values():
            if not isinstance(group, dict):
                continue
            indicators = group.get("indicators")
            if not isinstance(indicators, dict):
                continue
            for ind_id, ind in indicators.items():
                if not isinstance(ind, dict):
                    continue
                statement = str(ind.get("statement") or ind.get("name") or "").strip()
                if not statement:
                    continue
                controls = ind.get("controls") or []
                mapped = ", ".join(sorted({str(c).upper() for c in controls if c})) if controls else ""
                text = f"{statement} (maps to NIST 800-53: {mapped})" if mapped else statement
                self.metadata["controls"][f"FEDRAMP20X:{ind_id}"] = text
                n += 1
        if n:
            self.metadata["frameworks"]["FEDRAMP20X"] = (
                "FedRAMP 20x Key Security Indicators (via FedRAMP/rules)")
        print(f"[i] fedramp_rules: {n} Key Security Indicators indexed")

    @staticmethod
    def _ruby_quoted(text, pos):
        """Reads a Ruby single/double-quoted string starting at `pos`
        (which must hold the opening quote); returns (value, end_pos).
        Backslash escapes are collapsed. Unterminated strings run to EOF
        rather than raising, so one malformed control can't kill the sync.
        """
        quote = text[pos]
        out = []
        i = pos + 1
        while i < len(text):
            ch = text[i]
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                return "".join(out), i + 1
            out.append(ch)
            i += 1
        return "".join(out), len(text)

    def _iter_inspec_controls(self, text):
        """Yields (control_id, title, overview_desc, impact, tags) per
        `control '...' do` block in an InSpec .rb file. Only the header
        section is read: the first `title`, the first *unlabeled* `desc`
        (labeled `desc 'rationale',` / `'check',` / `'fix',` bodies are
        skipped), the first `impact` (numeric or word like `high`), and
        `tag name: value` lines. Test bodies (`describe`/`it`/`input()`)
        are never evaluated. File-level scalar assignments (`control_id`,
        `control_abbrev`, `sub_control_id`) preceding each block are tracked
        so interpolated ids (`control "cis-gcp-#{control_id}-#{...}"`) resolve
        to concrete values; literals pass through unchanged.
        """
        var_re = re.compile(
            r"^[ \t]*(?P<var>control_id|control_abbrev|sub_control_id)"
            r"[ \t]*=[ \t]*['\"](?P<val>[^'\"]*)['\"]", re.M)
        interp_re = re.compile(r"#\{(\w+)((?:\.\w+(?:\([^}]*\))?)*)\}")

        def resolve(value, variables):
            def sub(mm):
                var, mods = mm.group(1), mm.group(2)
                if var not in variables:
                    return mm.group(0)
                val = variables[var]
                if ".upcase" in mods:
                    val = val.upper()
                elif ".downcase" in mods:
                    val = val.lower()
                return val

            for _ in range(3):  # nested refs (sub id embeds control id)
                new_value = interp_re.sub(sub, value)
                if new_value == value:
                    break
                value = new_value
            return value

        blocks = list(re.finditer(
            r"^[ \t]*control[ \t]+(['\"])(?P<id>.+?)\1[ \t]+do\b",
            text, re.M))
        variables: dict = {}
        prev_end = 0
        for bi, m in enumerate(blocks):
            for vm in var_re.finditer(text, prev_end, m.start()):
                variables[vm.group("var")] = resolve(vm.group("val"), variables)
            prev_end = m.end()
            cid = resolve(m.group("id").strip(), variables)
            body = text[m.end():blocks[bi + 1].start() if bi + 1 < len(blocks)
                        else len(text)]
            title, desc, impact, tags = "", "", "", {}
            seen_title = seen_desc = seen_impact = False
            for lm in re.finditer(
                    r"^[ \t]*(?P<kw>title|desc|impact|tag)[ \t]+(?P<rest>.*)$",
                    body, re.M):
                kw, rest = lm.group("kw"), lm.group("rest")
                if kw == "title" and not seen_title and rest[:1] in ("'", '"'):
                    abs_pos = lm.start() + len(lm.group(0)) - len(rest)
                    title = re.sub(r"\s+", " ", resolve(
                        self._ruby_quoted(body, abs_pos)[0],
                        variables)).strip()
                    seen_title = True
                elif kw == "desc" and not seen_desc and rest[:1] in ("'", '"'):
                    abs_pos = lm.start() + len(lm.group(0)) - len(rest)
                    value, end = self._ruby_quoted(body, abs_pos)
                    # A comma right after the quoted string means a labeled
                    # desc ('rationale', 'check', 'fix', 'impact') - skip it.
                    if body[end:].lstrip()[:1] == ",":
                        continue
                    desc = re.sub(r"\s+", " ", value).strip()
                    seen_desc = True
                elif kw == "impact" and not seen_impact:
                    im = re.match(r"([0-9]+(?:\.[0-9]+)?|[A-Za-z]+)",
                                  rest.strip().strip("'\""))
                    if im:
                        impact = im.group(1)
                        seen_impact = True
                elif kw == "tag":
                    tm = re.match(r"(\w+):\s*(.*)$", rest, re.S)
                    if tm:
                        tags.setdefault(tm.group(1), tm.group(2).strip())
            if cid:
                yield cid, title, desc, impact, tags

    def _parse_saf_inspec(self, source_key, prefix, label):
        """Indexes a MITRE SAF CIS InSpec baseline (controls/*.rb, one
        `control` block per CIS recommendation - Apache-2.0, permits local
        internal use). Each control becomes one entry keyed by its InSpec
        control ID, carrying title + overview prose with mapped NIST 800-53
        IDs appended so it crosswalks against the NIST53:* entries.
        No-op when the baseline clone is absent.
        """
        base = Path(self.SOURCES[source_key]["local_path"])
        if not base.is_dir():
            return
        files = sorted(base.glob("*.rb"))
        if not files:
            return
        n = 0
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for cid, title, desc, impact, tags in self._iter_inspec_controls(text):
                if not title:
                    continue
                nist = [c.strip() for c in re.findall(r"'([^']+)'",
                        tags.get("nist", "")) if c.strip()]
                severity = re.sub(r"\s+", " ", tags.get(
                    "severity", "").strip().strip("'\"")).strip()
                cis_rid = tags.get("cis_rid", "").strip(" '\"")
                if not cis_rid:
                    # GCP/GKE baselines tag cis_gcp/cis_gke instead of cis_rid
                    # (value is often the raw `control_id.to_s` expression, in
                    # which case the resolved control id already carries it).
                    for ck in ("cis_gcp", "cis_gke"):
                        cv = tags.get(ck, "").strip(" '\"")
                        if cv and not cv.endswith(".to_s"):
                            cis_rid = cv
                            break
                    else:
                        rm = re.match(r"cis-gc?p?e?-(\d+(?:\.\d+)*)-",
                                      cid, re.I)
                        if rm:
                            cis_rid = rm.group(1)
                entry = title
                if desc and desc != title:
                    entry += f" - {desc[:600]}"
                meta = []
                if nist:
                    meta.append("maps to NIST 800-53: " + ", ".join(nist))
                if cis_rid:
                    meta.append(f"CIS recommendation {cis_rid}")
                if severity:
                    meta.append(f"severity {severity}")
                if impact:
                    meta.append(f"impact {impact}")
                if meta:
                    entry += " (" + "; ".join(meta) + ")"
                key = f"{prefix}:{cid.upper()}"
                if key not in self.metadata["controls"]:
                    self.metadata["controls"][key] = entry[:2000]
                    n += 1
        if n:
            self.metadata["frameworks"][prefix] = label
        print(f"[i] {source_key}: {n} InSpec controls indexed")

    def _iter_genai_actions(self, text):
        """Yields (action_id, title) per MS-/MG- action in NIST AI 600-1
        extracted text. The ID opens a line; the title is the same-line
        remainder plus following non-blank, non-ID lines (the PDF also
        emits risk-category tags on their own lines, which ride along as
        associated concepts).
        """
        id_re = re.compile(r"^(MS|MG)-\d+\.\d+-\d+\b")
        cur_id, buf = None, []

        def flush():
            if cur_id and buf:
                title = re.sub(r"\s+", " ", " ".join(buf)).strip()
                if title:
                    return cur_id, title[:2000]
            return None

        for line in text.splitlines():
            s = line.strip()
            m = id_re.match(s)
            if m:
                prev = flush()
                if prev:
                    yield prev
                cur_id = m.group(0)
                rest = s[m.end():].strip()
                buf = [rest] if rest else []
            elif s and cur_id is not None:
                buf.append(s)
        prev = flush()
        if prev:
            yield prev

    def _parse_genai_from_text(self, text):
        n = 0
        for cid, title in self._iter_genai_actions(text):
            key = f"GENAI:{cid.upper()}"
            if key not in self.metadata["controls"]:
                self.metadata["controls"][key] = title
                n += 1
        if n:
            self.metadata["frameworks"]["GENAI"] = (
                "NIST AI 600-1 Generative AI Profile")
        return n

    def _parse_genai(self):
        """Indexes NIST AI 600-1 GenAI Profile actions (MS-/MG- IDs) from
        the locally fetched public-domain PDF (US federal work). pypdf is
        imported lazily so a missing dependency degrades to a no-op, not
        a crash; likewise a missing/unreadable file. No-op when absent.
        """
        path = Path(self.SOURCES["genai"]["local_path"])
        if not path.is_file():
            return
        try:
            from pypdf import PdfReader
        except ImportError:
            print("[i] genai: pypdf unavailable - skipping")
            return
        try:
            reader = PdfReader(str(path))
            text = "\n".join((p.extract_text() or "") for p in reader.pages)
        except Exception as e:
            print(f"[i] genai: unreadable PDF ({e}) - skipping")
            return
        n = self._parse_genai_from_text(text)
        print(f"[i] genai: {n} actions indexed")

    # -- Coverage expansion: SSDF, OWASP Top 10:2025, references/ drop-ins ---

    def _parse_ssdf(self):
        """Indexes NIST SP 800-218 Secure Software Development Framework tasks
        from the locally vendored OSCAL catalog (public domain, US federal
        work). Unlike _parse_oscal, this reads each control's `statement`
        prose part: SSDF control titles are bare IDs ("PO.1.1"), so
        title-only indexing would store no usable text.
        """
        path = self.SOURCES["ssdf"]["local_path"]
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        catalog = data.get("catalog", {})

        def statement(control):
            for part in control.get("parts") or []:
                if isinstance(part, dict) and part.get("name") == "statement":
                    prose = (part.get("prose") or "").strip()
                    if prose:
                        return re.sub(r"\s+", " ", prose)
            return ""

        def walk(controls):
            for c in controls or []:
                cid = str(c.get("id", "")).strip().upper()
                text = statement(c) or (c.get("title") or "").strip()
                if cid and text and text != cid:
                    self.metadata["controls"][f"SSDF:{cid}"] = text[:2000]
                walk(c.get("controls"))

        n_before = len(self.metadata["controls"])
        for group in catalog.get("groups", []):
            walk(group.get("controls"))
        walk(catalog.get("controls"))
        n = len(self.metadata["controls"]) - n_before
        if n:
            self.metadata["frameworks"]["SSDF"] = (
                "NIST SP 800-218 Secure Software Development Framework (SSDF)")
        print(f"[i] ssdf: {n} tasks indexed")

    @staticmethod
    def _first_paragraph_after(lines, heading):
        """First plain-text paragraph under a `## <heading>` markdown line."""
        in_section = False
        for line in lines:
            s = line.strip()
            if s.startswith("##"):
                in_section = heading in s.lower()
                continue
            if not in_section or not s:
                continue
            if s.startswith(("<", "#", "|", "!", "[", "{:")):
                continue
            return re.sub(r"\s+", " ", s)[:600]
        return ""

    def _parse_top10_2025(self):
        """Indexes the OWASP Top 10:2025 categories (A01-A10) from the
        2025/docs/en markdown in the owasp-top10 clone (CC-licensed, free to
        access). Replaces the old presence-only flag: the OSIB YAML export
        carries no 2025 nodes (only link targets to top10.2021.x), so the
        markdown category files are the machine-readable source.
        """
        docs_dir = self.SOURCES["top10_2025"]["local_path"]
        if not os.path.isdir(docs_dir):
            return
        name_re = re.compile(r"^A(\d{2})_2025-(.+)\.md$")
        n = 0
        for filename in sorted(os.listdir(docs_dir)):
            m = name_re.match(filename)
            if not m:
                continue
            num, slug = m.groups()
            lines = Path(os.path.join(docs_dir, filename)).read_text(
                encoding="utf-8", errors="ignore").splitlines()
            title = next((l.lstrip("# ").strip() for l in lines
                          if l.startswith("#")), slug.replace("_", " "))
            title = re.sub(r"\s*!\s*\[icon\].*$", "", title).strip()
            background = self._first_paragraph_after(lines, "background")
            text = f"A{num}:2025 {title}"
            if background:
                text += f" - {background}"
            self.metadata["controls"][f"top10:A{num}"] = text[:2000]
            n += 1
        if n:
            self.metadata["frameworks"]["top10"] = "OWASP Top 10:2025"
        print(f"[i] top10_2025: {n} categories indexed")

    @staticmethod
    def _owasp_doc_title_and_lead(lines):
        """Split OWASP category markdown into (title, lead paragraph).

        Title prefers the `title:` frontmatter field (Mobile/MCP/K8s/CI-CD
        carry it; their first `#` heading is a section like `# Threat
        Agents`), else the first `#`/`##` heading. Lead is the first
        plain-text paragraph under any later heading, skipping tables,
        markup, and bold label-only lines (e.g. Agentic's `**Description:**`
        or Mobile's `**Application Specific**`).
        """
        title, title_idx = "", -1
        title_from_heading = False
        if lines and lines[0].strip() == "---":
            for i in range(1, min(len(lines), 30)):
                s = lines[i].strip()
                if s in ("---", "..."):
                    break
                m = re.match(r"title\s*:\s*[\"']?(?P<t>.+?)[\"']?\s*$", s)
                if m:
                    title, title_idx = m.group("t").strip(), i
                    break
        if not title:
            for i, line in enumerate(lines):
                s = line.strip()
                if s.startswith("#"):
                    title, title_idx = s.lstrip("#").strip(), i
                    title_from_heading = True
                    break
        title = re.sub(r"\*+", "", title).strip()
        lead = ""
        # Content following a title-heading belongs to that heading (LLM /
        # Agentic / MASVS / API titles are their own section); frontmatter
        # titles need the first later heading to open a section.
        in_section = title_from_heading
        for line in lines[title_idx + 1:]:
            s = line.strip()
            if not s:
                continue
            if s.startswith("#"):
                in_section = True
                continue
            if not in_section:
                continue
            if s.startswith(("<", "|", "!", "[", "{:", "```")):
                continue
            if re.fullmatch(r"\*{1,2}[^*]+\*{1,2}:?", s) and len(s) < 80:
                continue
            lead = re.sub(r"\s+", " ", s)[:600]
            break
        return title, lead

    def _parse_owasp_categories(self, source_key, prefix, label,
                                filename_re, title_id_re, year="",
                                with_lead=True):
        """Generic OWASP Top-10-family indexer (R-059..R-066), generalizing
        the _parse_top10_2025 markdown pattern: one markdown file per
        category, control ID + title from the doc title, first section
        paragraph as context. Files whose title carries no ID (prefaces,
        indexes, templates) are skipped. No-op when the clone is absent.
        `year` is appended to bare IDs (M1 -> M1:2024) only when the ID
        does not already carry it; pass "" when the list has no year.
        `with_lead` is False when the upstream bodies are still template
        placeholders (Agentic draft) - titles index, filler prose does not.
        """
        base = Path(self.SOURCES[source_key]["local_path"])
        if not base.is_dir():
            return
        n = 0
        for filename in sorted(os.listdir(base)):
            if not filename_re.match(filename):
                continue
            lines = Path(os.path.join(str(base), filename)).read_text(
                encoding="utf-8", errors="ignore").splitlines()
            title, lead = self._owasp_doc_title_and_lead(lines)
            if not with_lead:
                lead = ""
            if not title:
                continue
            m = title_id_re.search(title)
            if not m:
                continue
            cid = re.sub(r"\s+", "", m.group("id")).upper()
            try:
                t = m.group("title").strip()
            except IndexError:
                t = ""
            t = re.sub(r"\s+", " ", re.sub(r"\*+", "", t)).strip()
            if not cid:
                continue
            disp = cid if (not year or year in cid) else f"{cid}:{year}"
            if t:
                text = f"{disp} {t}"
            else:
                text = disp
            if lead and lead not in text:
                text += f" - {lead}"
            key = f"{prefix}:{disp}"
            if key not in self.metadata["controls"]:
                self.metadata["controls"][key] = text[:2000]
                n += 1
        if n:
            self.metadata["frameworks"][prefix] = label
        print(f"[i] {source_key}: {n} categories indexed")

    def _store_atlas(self, cid, name, desc):
        cid = re.sub(r"\s+", "", str(cid or "")).upper()
        name = re.sub(r"\s+", " ", str(name or "").strip())
        desc = re.sub(r"\s+", " ", str(desc or "").strip())
        if not cid or not name:
            return False
        text = f"{name} - {desc[:600]}" if desc and desc != name else name
        key = f"ATLAS:{cid}"
        if key not in self.metadata["controls"]:
            self.metadata["controls"][key] = text[:2000]
            return True
        return False

    def _parse_atlas(self):
        """Indexes MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
        techniques from the Apache-2.0 atlas-data clone
        (github.com/mitre-atlas/atlas-data - auto-cloned by
        scripts/update_sources.ps1, same precedent as attack-stix-data).
        Unlike ATT&CK's STIX JSON (see _parse_attack), ATLAS ships YAML:
        dist/v6/ATLAS-<date>.yaml (newest dated file wins; the unversioned
        ATLAS-latest.yaml is a one-line pointer, not data) with `techniques`
        / `tactics` mappings of AML.Txxxx[.xxx] / AML.TAxxxx entries, plus a
        fallback for the legacy dist/ATLAS.yaml v5 shape (`matrices` list).
        Technique IDs are ATLAS-namespaced (AML.*), so one ATLAS family
        covers tactics and techniques alike. No-op when the clone is absent.
        """
        base = Path(self.SOURCES["atlas"]["local_path"])
        if not base.is_dir():
            return
        path = None
        v6 = base / "v6"
        if v6.is_dir():
            dated = sorted(p for p in v6.glob("ATLAS-*.yaml")
                           if p.name != "ATLAS-latest.yaml")
            if dated:
                path = dated[-1]
        if path is None:
            legacy = base / "ATLAS.yaml"
            if not legacy.is_file():
                return
            path = legacy
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            return
        if not isinstance(data, dict):
            return
        n = 0
        techniques = data.get("techniques")
        tactics = data.get("tactics")
        if isinstance(techniques, dict):
            for cid, entry in techniques.items():
                if isinstance(entry, dict):
                    n += self._store_atlas(cid, entry.get("name"),
                                           entry.get("description"))
                elif entry:
                    n += self._store_atlas(cid, entry, "")
        if isinstance(tactics, dict):
            for cid, entry in tactics.items():
                if isinstance(entry, dict):
                    n += self._store_atlas(cid, entry.get("name"),
                                           entry.get("description"))
                elif entry:
                    n += self._store_atlas(cid, entry, "")
        for matrix in data.get("matrices", []) or []:
            if not isinstance(matrix, dict):
                continue
            for group_key in ("tactics", "techniques"):
                group = matrix.get(group_key)
                if isinstance(group, dict):
                    items = group.values()
                elif isinstance(group, list):
                    items = group
                else:
                    continue
                for entry in items:
                    if not isinstance(entry, dict):
                        continue
                    n += self._store_atlas(entry.get("id"), entry.get("name"),
                                           entry.get("description"))
        if n:
            self.metadata["frameworks"]["ATLAS"] = (
                "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)")
        print(f"[i] atlas: {n} techniques indexed")

    def _parse_d3fend(self):
        """Indexes MITRE D3FEND defensive techniques from the MIT-licensed
        d3fend-ontology clone (github.com/d3fend/d3fend-ontology -
        auto-cloned by scripts/update_sources.ps1). The distribution
        artifact is src/ontology/d3fend-protege.ttl (Turtle); it is parsed
        with a stdlib regex over subject blocks (`:d3fend-id "D3-XXX"` plus
        the block's rdfs:label and :definition) so no rdflib dependency is
        needed. Each D3-XXX becomes one D3FEND:* entry. No-op when absent.
        """
        base = Path(self.SOURCES["d3fend"]["local_path"])
        ttl = base / "d3fend-protege.ttl"
        if not ttl.is_file():
            candidates = sorted(base.glob("*.ttl"))
            if not candidates:
                return
            ttl = candidates[-1]
        try:
            text = ttl.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return
        n = 0
        for block in re.split(r"\n(?=:)", text):
            m_id = re.search(r':d3fend-id\s+"(D3-[A-Za-z]+)"', block)
            if not m_id:
                continue
            m_lab = re.search(r'rdfs:label\s+"((?:[^"\\]|\\.)*)"', block)
            if not m_lab:
                continue
            label = re.sub(r"\s+", " ",
                           m_lab.group(1).replace('\\"', '"')
                           .replace("\\\\", "\\")).strip()
            m_def = re.search(r':definition\s+"((?:[^"\\]|\\.)*)"', block)
            desc = ""
            if m_def:
                desc = re.sub(
                    r"\s+", " ",
                    m_def.group(1).replace('\\"', '"')
                    .replace("\\\\", "\\")).strip()
            if not label:
                continue
            entry = f"{label} - {desc[:600]}" if desc and desc != label else label
            key = f"D3FEND:{m_id.group(1).upper()}"
            if key not in self.metadata["controls"]:
                self.metadata["controls"][key] = entry[:2000]
                n += 1
        if n:
            self.metadata["frameworks"]["D3FEND"] = (
                "MITRE D3FEND Cyber Countermeasures")
        print(f"[i] d3fend: {n} techniques indexed")

    @staticmethod
    def _xml_local(tag):
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag.rsplit(":", 1)[-1]

    def _parse_cwe(self):
        """Indexes MITRE CWE weaknesses from references/cwe/ (a
        cwec_v*.xml drop-in, or the .zip that ships it, fetched from
        https://cwe.mitre.org/data/xml/cwec_latest.xml.zip - MITRE free
        download, no registration; refreshed by update_sources.ps1). Element
        names are matched namespace-tolerantly (local name only) so schema
        version drift (cwe-6/cwe-7/...) cannot break the parse. Each
        <Weakness ID Name> plus its <Description> becomes one CWE:CWE-<id>
        entry. No-op when the drop-in is absent.
        """
        import xml.etree.ElementTree as ET
        import zipfile
        base = Path(self.SOURCES["cwe"]["local_path"])
        if not base.is_dir():
            return
        xml_text = None
        for path in sorted(base.glob("*.xml")):
            try:
                xml_text = path.read_text(encoding="utf-8", errors="ignore")
                break
            except OSError:
                continue
        if xml_text is None:
            for path in sorted(base.glob("*.zip")):
                try:
                    with zipfile.ZipFile(str(path)) as zf:
                        inner = next((n for n in zf.namelist()
                                      if n.lower().endswith(".xml")), None)
                        if inner is None:
                            continue
                        xml_text = zf.read(inner).decode("utf-8", "ignore")
                        break
                except (zipfile.BadZipFile, OSError, KeyError):
                    continue
        if not xml_text:
            return
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return
        n = 0
        for el in root.iter():
            if self._xml_local(el.tag) != "Weakness":
                continue
            cid = str(el.get("ID") or "").strip()
            name = re.sub(r"\s+", " ", str(el.get("Name") or "").strip())
            if not cid or not name:
                continue
            desc = ""
            for child in el:
                if self._xml_local(child.tag) == "Description":
                    desc = re.sub(r"\s+", " ",
                                  "".join(child.itertext())).strip()
                    break
            entry = f"{name} - {desc[:600]}" if desc and desc != name else name
            key = f"CWE:CWE-{cid}"
            if key not in self.metadata["controls"]:
                self.metadata["controls"][key] = entry[:2000]
                n += 1
        if n:
            self.metadata["frameworks"]["CWE"] = "MITRE Common Weakness Enumeration"
        print(f"[i] cwe: {n} weaknesses indexed")

    def _parse_capec(self):
        """Indexes MITRE CAPEC attack patterns from references/capec/ (a
        capec_latest.xml drop-in, or a views/*.xml(.zip) export, fetched from
        https://capec.mitre.org/data/xml/capec_latest.xml - MITRE free
        download, no registration; refreshed by update_sources.ps1).
        Namespace-tolerant like _parse_cwe. Each <Attack_Pattern ID Name>
        plus its <Description> becomes one CAPEC:CAPEC-<id> entry. No-op
        when the drop-in is absent.
        """
        import xml.etree.ElementTree as ET
        import zipfile
        base = Path(self.SOURCES["capec"]["local_path"])
        if not base.is_dir():
            return
        candidates = sorted(base.glob("*.xml")) + sorted(base.glob("*.zip"))
        if not candidates:
            return
        n = 0
        seen_files = 0
        for path in candidates:
            try:
                if path.suffix.lower() == ".zip":
                    with zipfile.ZipFile(str(path)) as zf:
                        inner = next((n_ for n_ in zf.namelist()
                                      if n_.lower().endswith(".xml")), None)
                        if inner is None:
                            continue
                        xml_text = zf.read(inner).decode("utf-8", "ignore")
                else:
                    xml_text = path.read_text(encoding="utf-8", errors="ignore")
            except (zipfile.BadZipFile, OSError, KeyError):
                continue
            try:
                root = ET.fromstring(xml_text)
            except ET.ParseError:
                continue
            seen_files += 1
            for el in root.iter():
                if self._xml_local(el.tag) != "Attack_Pattern":
                    continue
                cid = str(el.get("ID") or "").strip()
                name = re.sub(r"\s+", " ", str(el.get("Name") or "").strip())
                if not cid or not name:
                    continue
                desc = ""
                for child in el:
                    if self._xml_local(child.tag) == "Description":
                        desc = re.sub(r"\s+", " ",
                                      "".join(child.itertext())).strip()
                        break
                entry = (f"{name} - {desc[:600]}"
                         if desc and desc != name else name)
                key = f"CAPEC:CAPEC-{cid}"
                if key not in self.metadata["controls"]:
                    self.metadata["controls"][key] = entry[:2000]
                    n += 1
        if n:
            self.metadata["frameworks"]["CAPEC"] = (
                "MITRE Common Attack Pattern Enumeration and Classification")
        if seen_files:
            print(f"[i] capec: {n} patterns indexed")

    def _iter_ai_rmf_subcategories(self, text):
        """Yields (subcategory_id, title) per GOVERN/MAP/MEASURE/MANAGE
        major.minor entry in NIST AI RMF 1.0 extracted text (same shape as
        _iter_genai_actions: the ID opens a line, the title is the same-line
        remainder plus following non-blank lines). PDF line-wrap hyphens
        ("inte- grated") are joined; category headers ("GOVERN 1:", no
        minor) and Table/Figure/Section lines end the current entry.
        """
        id_re = re.compile(r"^(GOVERN|MAP|MEASURE|MANAGE)\s+(\d+)\.(\d+)\s*:")
        stop_re = re.compile(
            r"^(GOVERN|MAP|MEASURE|MANAGE)\s+\d+\s*:|^(Table|Figure|Section)\b")
        cur_id, buf = None, []

        def flush():
            if cur_id and buf:
                title = re.sub(r"(\w)-\s+(\w)", r"\1\2", " ".join(buf))
                title = re.sub(r"\s+", " ", title).strip()
                if title:
                    return cur_id, title[:2000]
            return None

        for line in text.splitlines():
            s = line.strip()
            m = id_re.match(s)
            if m:
                prev = flush()
                if prev:
                    yield prev
                cur_id = f"{m.group(1)}-{m.group(2)}.{m.group(3)}"
                rest = s[m.end():].strip()
                buf = [rest] if rest else []
            elif s and cur_id is not None:
                if stop_re.match(s):
                    prev = flush()
                    if prev:
                        yield prev
                    cur_id, buf = None, []
                else:
                    buf.append(s)
        prev = flush()
        if prev:
            yield prev

    def _parse_ai_rmf_from_text(self, text):
        n = 0
        for cid, title in self._iter_ai_rmf_subcategories(text):
            key = f"AIRMF:{cid.upper()}"
            if key not in self.metadata["controls"]:
                self.metadata["controls"][key] = title
                n += 1
        if n:
            self.metadata["frameworks"]["AIRMF"] = (
                "NIST AI Risk Management Framework 1.0")
        return n

    def _parse_ai_rmf(self):
        """Indexes NIST AI RMF 1.0 Govern/Map/Measure/Manage subcategories
        from the locally fetched public-domain PDF
        (references/nist-ai-rmf/NIST.AI.100-1.pdf, US federal work -
        refreshed by update_sources.ps1). Same lazy-pypdf wiring as
        _parse_genai: a missing dependency or file degrades to a no-op.
        """
        path = Path(self.SOURCES["ai_rmf"]["local_path"]) / "NIST.AI.100-1.pdf"
        if not path.is_file():
            pdfs = sorted(Path(self.SOURCES["ai_rmf"]["local_path"]).glob("*.pdf")) \
                if Path(self.SOURCES["ai_rmf"]["local_path"]).is_dir() else []
            if not pdfs:
                return
            path = pdfs[0]
        try:
            from pypdf import PdfReader
        except ImportError:
            print("[i] ai_rmf: pypdf unavailable - skipping")
            return
        try:
            reader = PdfReader(str(path))
            text = "\n".join((p.extract_text() or "") for p in reader.pages)
        except Exception as e:
            print(f"[i] ai_rmf: unreadable PDF ({e}) - skipping")
            return
        n = self._parse_ai_rmf_from_text(text)
        print(f"[i] ai_rmf: {n} subcategories indexed")

    @staticmethod
    def _stig_bench_tag(root, filename):
        """Short benchmark tag for STIG entry keys (V-IDs repeat across
        STIGs, so the key is namespaced STIG:<BENCH>:<V-ID>). Prefers the
        XCCDF <Benchmark> title/id, else the file stem; drops the leading
        DISA "U_", quarterly version tokens (V2R1), and packaging words
        (Manual/XCCDF/STIG) so a new quarterly release keeps stable keys.
        """
        title = ""
        for el in root.iter():
            if FrameworkManager._xml_local(el.tag) == "Benchmark":
                for child in el:
                    if FrameworkManager._xml_local(child.tag) == "title" \
                            and (child.text or "").strip():
                        title = child.text.strip()
                        break
                if not title:
                    title = str(el.get("id") or "")
                break
        raw = title or re.sub(r"\.zip$", "", filename, flags=re.I)
        toks = [t for t in re.split(r"[^A-Za-z0-9]+", raw.upper()) if t]
        drop = {"U", "MANUAL", "XCCDF", "XML", "STIG"}
        toks = [t for t in toks
                if t not in drop and not re.fullmatch(r"V\d+R\d+", t)]
        return "-".join(toks[:4])[:24] or "STIG"

    def _parse_stig_xccdf_text(self, xml_text, filename):
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return 0
        bench = self._stig_bench_tag(root, filename)
        n = 0
        for group in root.iter():
            if self._xml_local(group.tag) != "Group":
                continue
            vid = str(group.get("id") or "").strip().upper()
            if not re.fullmatch(r"V-\d+", vid):
                continue
            title, rule_desc, rule_id, severity = "", "", "", ""
            for child in group:
                local = self._xml_local(child.tag)
                if local == "title" and not title:
                    title = re.sub(r"\s+", " ",
                                   "".join(child.itertext())).strip()
                elif local == "Rule" and not rule_desc:
                    rule_id = str(child.get("id") or "").strip().upper()
                    severity = str(child.get("severity") or "").strip()
                    for sub in child:
                        if self._xml_local(sub.tag) == "description":
                            rule_desc = re.sub(
                                r"\s+", " ",
                                "".join(sub.itertext())).strip()
                            break
            if not title:
                continue
            entry = title
            if rule_desc and rule_desc != title:
                entry += f" - {rule_desc[:600]}"
            meta = []
            if rule_id:
                meta.append(f"STIG ID {rule_id}")
            if severity:
                meta.append(f"severity {severity}")
            if meta:
                entry += " (" + "; ".join(meta) + ")"
            key = f"STIG:{bench}:{vid}"
            if key not in self.metadata["controls"]:
                self.metadata["controls"][key] = entry[:2000]
                n += 1
        return n

    def _parse_stig_xccdf(self):
        """Indexes DISA STIG requirements from references/disa-stig/ (the
        quarterly *-Manual-xccdf.xml files inside the public.cyber.mil
        STIG zips - free download, no registration, but versioned quarterly
        with no "latest" URL, so a manual drop-in rather than a
        $directDownloads fetch; see references/README.md). Namespace-
        tolerant like _parse_cwe (XCCDF 1.1/1.2). Each <Group id="V-...">
        plus its <Rule> description becomes one STIG:<BENCH>:<V-ID> entry
        (V-IDs repeat across STIGs, hence the benchmark namespace). The
        MITRE SAF STIG InSpec baselines (SAF_RHEL8/SAF_RHEL9) carry the
        same requirements as executable checks; this parser covers STIGs
        with no SAF profile. No-op when the drop-in is absent.
        """
        import zipfile
        base = Path(self.SOURCES["stig_xccdf"]["local_path"])
        if not base.is_dir():
            return
        candidates = sorted(base.glob("*.xml")) + sorted(base.glob("*.zip"))
        if not candidates:
            return
        n = seen = 0
        for path in candidates:
            try:
                if path.suffix.lower() == ".zip":
                    with zipfile.ZipFile(str(path)) as zf:
                        inners = [x for x in zf.namelist()
                                  if x.lower().endswith((".xml", "-xccdf"))]
                        if not inners:
                            continue
                        for inner in sorted(inners):
                            try:
                                xml_text = zf.read(inner).decode(
                                    "utf-8", "ignore")
                            except KeyError:
                                continue
                            seen += 1
                            n += self._parse_stig_xccdf_text(
                                xml_text, f"{path.name}/{inner}")
                else:
                    xml_text = path.read_text(encoding="utf-8",
                                              errors="ignore")
                    seen += 1
                    n += self._parse_stig_xccdf_text(xml_text, path.name)
            except (zipfile.BadZipFile, OSError):
                continue
        if n:
            self.metadata["frameworks"]["STIG"] = (
                "DISA Security Technical Implementation Guides (XCCDF)")
        if seen:
            print(f"[i] stig_xccdf: {n} requirements indexed")

    def _iter_c2m2_practices(self, text):
        """Yields (practice_id, objective_title, mil, practice_text) per
        DOE C2M2 v2.1 practice. IDs follow the model notation
        DOMAIN-objective+letter (e.g. ASSET-1a, Figure 5): the domain comes
        from the `6.N Name (SHORT)` heading (SHORT wraps onto the next
        line), the objective from `N. Title` lines, and each practice from
        `MIL1|2|3 <letter>.` lines with wrapped continuation lines. Page
        headers, page numbers, and Figure/Table lines terminate the current
        practice; TOC dotted-leader lines never open headings.
        """
        domain_re = re.compile(r"^6\.\d+\s+(?P<rest>.*)$")
        short_re = re.compile(r"\((?P<short>[A-Z][A-Z0-9-]*)\)\s*$")
        obj_re = re.compile(r"^(?P<num>\d{1,2})\.\s+(?P<title>[A-Z].+)$")
        mil_re = re.compile(r"^MIL(?P<mil>[123])\s+(?:(?P<letter>[a-z])\.\s*(?P<rest>.*)|(?P<none>No practice.*))$")
        cont_re = re.compile(r"^(?P<letter>[a-z])\.\s+(?P<rest>.*)$")
        skip_re = re.compile(
            r"^(Cybersecurity Capability Maturity Model|Figure|Table)\b|^\d+\s*$")
        domain, objnum, objtitle = None, None, ""
        pending_domain, cur_mil, cur_letter, buf = False, None, None, []

        def flush():
            if domain and objnum and cur_letter and buf:
                practice = re.sub(r"\s+", " ", " ".join(buf)).strip()
                if practice:
                    return (f"{domain}-{objnum}{cur_letter}", domain,
                            objtitle, cur_mil, practice[:2000])
            return None

        for line in text.splitlines():
            s = line.strip()
            if not s:
                continue
            if ".." not in s:
                m = domain_re.match(s)
                if m:
                    prev = flush()
                    if prev:
                        yield prev
                    cur_mil, cur_letter, buf = None, None, []
                    objnum, objtitle = None, ""
                    rest = m.group("rest")
                    sm = re.search(r"\(([A-Z][A-Z0-9-]*)\)\s*$", rest)
                    if sm:
                        domain, pending_domain = sm.group(1), False
                    else:
                        pending_domain = True
                    continue
            if pending_domain:
                sm = short_re.search(s)
                if sm:
                    domain = sm.group(1)
                    pending_domain = False
                    continue
            if skip_re.match(s) or (s.isupper() and len(s) < 80):
                prev = flush()
                if prev:
                    yield prev
                cur_mil, cur_letter, buf = None, None, []
                continue
            m = mil_re.match(s)
            if m and domain and objnum:
                prev = flush()
                if prev:
                    yield prev
                if m.group("none"):
                    cur_mil, cur_letter, buf = None, None, []
                else:
                    cur_mil, cur_letter = m.group("mil"), m.group("letter")
                    buf = [m.group("rest")] if m.group("rest") else []
                continue
            m = cont_re.match(s)
            if m and domain and objnum and cur_mil:
                prev = flush()
                if prev:
                    yield prev
                cur_letter = m.group("letter")
                buf = [m.group("rest")] if m.group("rest") else []
                continue
            m = obj_re.match(s)
            if m and domain and ".." not in s:
                prev = flush()
                if prev:
                    yield prev
                objnum, objtitle = m.group("num"), m.group("title").strip()
                cur_mil, cur_letter, buf = None, None, []
                continue
            if cur_letter is not None:
                buf.append(s)
        prev = flush()
        if prev:
            yield prev

    def _parse_c2m2_from_text(self, text):
        n = 0
        for pid, dom, objtitle, mil, practice in self._iter_c2m2_practices(
                text):
            key = f"C2M2:{pid.upper()}"
            if key not in self.metadata["controls"]:
                self.metadata["controls"][key] = (
                    f"{practice} ({dom} objective "
                    f"{objtitle}, MIL{mil})")[:2000]
                n += 1
        if n:
            self.metadata["frameworks"]["C2M2"] = (
                "DOE Cybersecurity Capability Maturity Model v2.1")
        return n

    def _parse_c2m2(self):
        """Indexes DOE C2M2 v2.1 domain practices (DOMAIN-objective+letter,
        e.g. ASSET-1a) from the public-domain model PDF
        (references/c2m2/, US federal work - refreshed by
        update_sources.ps1 $directDownloads). Same lazy-pypdf wiring as
        _parse_genai/_parse_ai_rmf: a missing dependency or file degrades
        to a no-op. SCF crosswalk rows already map C2M2 clauses; this adds
        the native practice text.
        """
        base = Path(self.SOURCES["c2m2"]["local_path"])
        if not base.is_dir():
            return
        cands = sorted(base.glob("C2M2*.pdf")) + sorted(base.glob("*.pdf"))
        if not cands:
            return
        path = cands[0]
        try:
            from pypdf import PdfReader
        except ImportError:
            print("[i] c2m2: pypdf unavailable - skipping")
            return
        try:
            reader = PdfReader(str(path))
            text = "\n".join((p.extract_text() or "") for p in reader.pages)
        except Exception as e:
            print(f"[i] c2m2: unreadable PDF ({e}) - skipping")
            return
        n = self._parse_c2m2_from_text(text)
        print(f"[i] c2m2: {n} practices indexed")

    def _walk_named_descriptions(self, node, prefix):
        """Recursive name+description indexer over a decoded YAML/JSON doc;
        returns the count added. Tolerates schema drift (name/title/activity
        x description/prose/text) so a new release layout degrades to fewer
        controls rather than zero."""
        added = 0

        def walk(item):
            nonlocal added
            if isinstance(item, dict):
                name = (item.get("name") or item.get("title")
                        or item.get("activity") or item.get("text")
                        or item.get("number") or "")
                desc = (item.get("description") or item.get("shortDescription")
                        or item.get("longDescription") or item.get("prose")
                        or item.get("text") or item.get("benefit") or "")
                if isinstance(name, str) and isinstance(desc, str):
                    name = name.strip()
                    desc = re.sub(r"\s+", " ", desc.strip())
                    if name and desc:
                        cid = re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")[:64]
                        key = f"{prefix}:{cid}"
                        if cid and key not in self.metadata["controls"]:
                            self.metadata["controls"][key] = desc[:2000]
                            added += 1
                for value in item.values():
                    walk(value)
            elif isinstance(item, list):
                for value in item:
                    walk(value)

        walk(node)
        return added

    def _parse_samm_file(self, path, data):
        """Indexes one SAMM v2 datamodel YAML by its `type` tag, keyed on the
        filename code (e.g. `Activity D-SA-1-A.yml` -> activity D-SA-1-A).
        Returns the count added. Unknown shapes fall back to the generic
        name+description walker. Answer sets carry no indexable prose and are
        skipped.
        """
        if not isinstance(data, dict) or not isinstance(data.get("type"), str):
            return self._walk_named_descriptions(data, "SAMM")
        dtype = data["type"]
        stem = path.stem
        code = stem.split(None, 1)[1] if len(stem.split(None, 1)) > 1 else stem
        key = "SAMM:" + re.sub(r"[^A-Z0-9]+", "_",
                               f"{dtype}_{code}".upper()).strip("_")[:72]
        if key in self.metadata["controls"]:
            return 0

        def clean(*values):
            for v in values:
                if isinstance(v, (int, float)):
                    v = str(v)
                if isinstance(v, str) and v.strip():
                    return re.sub(r"\s+", " ", v.strip())
            return ""

        title = desc = ""
        if dtype == "Activity":
            title = clean(data.get("title"))
            desc = clean(data.get("shortDescription"),
                         data.get("longDescription"))
        elif dtype == "Practice":
            title = clean(data.get("name"))
            desc = clean(data.get("shortDescription"),
                         data.get("longDescription"))
        elif dtype == "PracticeLevel":
            # Join record linking a practice to a maturity level; the only
            # indexable prose is the level objective.
            title = f"Practice level {code}"
            desc = clean(data.get("objective"))
        elif dtype in ("Function", "Stream"):
            title = clean(data.get("name"))
            desc = clean(data.get("description"))
        elif dtype == "Question":
            title = clean(data.get("text"))
            quality = data.get("quality") or []
            if isinstance(quality, list):
                desc = "; ".join(clean(q) for q in quality if clean(q))[:600]
        elif dtype == "MaturityLevel":
            number = clean(data.get("number"), data.get("id"))
            title = f"Maturity Level {number}" if number else ""
            desc = clean(data.get("description"))
        elif dtype == "AnswerSet":
            return 0
        else:
            return self._walk_named_descriptions(data, "SAMM")
        if not title:
            return 0
        text = f"{title} - {desc[:600]}" if desc and desc != title else title
        self.metadata["controls"][key] = text[:2000]
        return 1

    def _parse_samm(self):
        """Indexes OWASP SAMM v2 practices/activities from a user-supplied
        YAML drop-in (references/samm/*.yaml - the SAMM model from
        owaspsamm.org; CC BY-SA 4.0). No-op when the drop-in is absent.
        """
        base = Path(self.SOURCES["samm"]["local_path"])
        if not base.is_dir():
            return
        files = sorted(base.glob("*.yaml")) + sorted(base.glob("*.yml"))
        if not files:
            return
        n = 0
        for path in files:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
            except yaml.YAMLError:
                continue
            n += self._parse_samm_file(path, data)
        if n:
            self.metadata["frameworks"]["SAMM"] = (
                "OWASP Software Assurance Maturity Model v2 (user-supplied drop-in)")
        print(f"[i] samm: {n} activities indexed")

    def _parse_section_markdown(self, source_key, prefix, label, header_re):
        """Generic markdown-section indexer over references/<dir>/*.md
        drop-ins. Each header matching `header_re` (named groups `id` and
        `title`) becomes one control; the first plain paragraph under it is
        stored as context. Callers: NIST SP 800-63-4 section headers
        ("4.1.2 Title", public domain) and BSIMM practice headers
        ("Strategy & Metrics (SM)", CC BY-SA). No-op when absent.
        """
        base = Path(self.SOURCES[source_key]["local_path"])
        if not base.is_dir():
            return
        files = sorted(base.glob("*.md"))
        if not files:
            return
        state = {"n": 0, "pending": None, "leads": []}

        def flush():
            pending, leads = state["pending"], state["leads"]
            if pending:
                cid, title = pending
                key = f"{prefix}:{cid}"
                text = title + (f" - {leads[0]}" if leads else "")
                if key not in self.metadata["controls"]:
                    self.metadata["controls"][key] = text[:2000]
                    state["n"] += 1
            state["pending"], state["leads"] = None, []

        for path in files:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line in lines:
                s = line.strip()
                if s.startswith("#"):
                    m = header_re.search(s.lstrip("#").strip())
                    flush()
                    if m:
                        title = re.sub(r"\s+", " ", m.group("title").strip())
                        state["pending"] = (m.group("id").strip().upper(), title)
                elif (state["pending"] is not None and not state["leads"] and s
                        and not s.startswith(("<", "#", "|", "!", "[", "{:"))):
                    state["leads"].append(re.sub(r"\s+", " ", s)[:600])
            flush()
        if state["n"]:
            self.metadata["frameworks"][prefix] = f"{label} (user-supplied drop-in)"
        print(f"[i] {source_key}: {state['n']} sections indexed")

    def _parse_nist80063_html(self):
        """Indexes NIST SP 800-63-4 sections from the usnistgov/800-63-4 HTML
        volumes (references/nist-800-63-4/sp800-63{,a,b,c}.html - public
        domain, US federal work). Each <h2>/<h3 id="slug"> becomes one
        control carrying its heading text plus the first following paragraph;
        the volume stem prefixes the key (slugs repeat across volumes).
        No-op when the drop-in is absent.
        """
        base = Path(self.SOURCES["nist80063"]["local_path"])
        if not base.is_dir():
            return
        files = sorted(base.glob("*.html"))
        if not files:
            return
        head_re = re.compile(
            r"<h([23])\s+[^>]*\bid\s*=\s*\"(?P<id>[^\"]+)\"[^>]*>"
            r"(?P<title>.*?)</h\1>", re.S | re.I)
        para_re = re.compile(r"<p[^>]*>(?P<body>.*?)</p>", re.S | re.I)
        tag_re = re.compile(r"<[^>]+>")
        anchor_re = re.compile(
            r'<a\s+[^>]*class\s*=\s*"header-link"[^>]*>.*?</a>', re.S | re.I)

        def text_of(html):
            text = tag_re.sub("", anchor_re.sub("", html))
            text = re.sub(r"\s+", " ", text.replace("&nbsp;", " ")).strip()
            for entity, char in (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                                 ("&quot;", '"'), ("&#39;", "'")):
                text = text.replace(entity, char)
            return text

        n = 0
        for path in files:
            try:
                html = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            vol = re.sub(r"[^A-Z0-9]+", "",
                         path.stem.upper().replace("SP800", ""))
            if not vol:
                vol = path.stem.upper()[:8]
            for hm in head_re.finditer(html):
                slug = hm.group("id").strip()
                title = text_of(hm.group("title"))
                if not slug or not title:
                    continue
                cid = re.sub(r"[^A-Z0-9]+", "_", slug.upper()).strip("_")
                key = f"NIST80063:{vol}-{cid}"[:96]
                if not cid or key in self.metadata["controls"]:
                    continue
                lead = ""
                pm = para_re.search(html, hm.end())
                if pm:
                    # Only take the paragraph if it belongs to this section
                    # (no intervening heading).
                    gap = html[hm.end():pm.start()]
                    if "<h2" not in gap.lower() and "<h3" not in gap.lower():
                        lead = text_of(pm.group("body"))[:600]
                entry = f"{title} - {lead}" if lead else title
                self.metadata["controls"][key] = entry[:2000]
                n += 1
        if n:
            self.metadata["frameworks"]["NIST80063"] = (
                "NIST SP 800-63-4 Digital Identity Guidelines "
                "(user-supplied drop-in)")
        print(f"[i] nist80063-html: {n} sections indexed")

    def _parse_cvss(self):
        """Indexes FIRST CVSS v4.0 base metrics from a user-supplied JSON
        drop-in (references/cvss-v4/*.json - metric definitions from the
        BSD-2-Clause cvss-v4-calculator repo or first.org/cvss/v4-0/; code and
        schema only, never spec prose). Accepts {"metrics": [...]} or a bare
        [...] list of {id/name/description} mappings. Raw upstream
        `cvss_config.js` (`"Name (SHORT)": {"tooltip": ..., "short": ...}`)
        is parsed directly when present, so the JSON derivation step is a
        convenience rather than a requirement.
        """
        base = Path(self.SOURCES["cvss"]["local_path"])
        if not base.is_dir():
            return
        files = sorted(base.glob("*.json"))
        if not files and not sorted(base.glob("*.js")):
            return
        n = 0

        def store(mid, name, desc):
            nonlocal n
            mid = str(mid or "").strip().upper()
            name = re.sub(r"\s+", " ", str(name or "").strip())
            desc = re.sub(r"\s+", " ", str(desc or "").strip())
            if not mid or not desc:
                return
            text = f"{name}: {desc}" if name else desc
            key = f"CVSS:{mid}"
            if key not in self.metadata["controls"]:
                self.metadata["controls"][key] = text[:2000]
                n += 1

        for path in files:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            candidates = data.get("metrics") if isinstance(data, dict) else data
            if not isinstance(candidates, list):
                continue
            for m in candidates:
                if not isinstance(m, dict):
                    continue
                store(m.get("id") or m.get("acronym") or m.get("metric"),
                      m.get("name") or m.get("title"),
                      m.get("description"))
        js_metric_re = re.compile(
            r'"(?P<name>[^"]+?)\((?P<paren>[A-Z]{1,4})\)"\s*:\s*\{'
            r'\s*"tooltip"\s*:\s*"(?P<tip>(?:[^"\\]|\\.)*)"\s*,\s*'
            r'"short"\s*:\s*"(?P<short>[A-Z]{1,4})"',
            re.S)
        for path in sorted(base.glob("*.js")):
            try:
                js = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for mm in js_metric_re.finditer(js):
                tip = mm.group("tip").replace('\\"', '"').replace("\\\\", "\\")
                store(mm.group("short"), mm.group("name").strip(), tip)
        if n:
            self.metadata["frameworks"]["CVSS"] = (
                "FIRST CVSS v4.0 base metrics (user-supplied drop-in)")
        print(f"[i] cvss: {n} metrics indexed")

    def _parse_reference_csv(self, source_key, prefix, label):
        """Generic CSV/TSV drop-in indexer for user-supplied framework files
        (CISA CPG, CIS, HITRUST, CAIQ, AICM). Header-aware: prefers columns
        named like id/title/description, else falls back to columns 0/1.
        Files without a header row are skipped (first row is the header).
        """
        base = Path(self.SOURCES[source_key]["local_path"])
        if not base.is_dir():
            return
        files = sorted(base.glob("*.csv")) + sorted(base.glob("*.tsv"))
        if not files:
            return
        id_names = {"id", "control id", "control_id", "controlid",
                    "requirement id", "safeguard", "safeguard id", "practice",
                    "goal id", "csf id", "question id", "statement id",
                    "number", "ref", "reference", "control number"}
        title_names = {"title", "name", "control", "control title",
                       "requirement", "safeguard title", "practice", "goal",
                       "security practice", "question", "statement",
                       "description", "safeguard description"}
        desc_names = {"description", "details", "text", "requirement text",
                      "discussion", "explanation", "rationale"}
        n = 0
        for path in files:
            try:
                text = path.read_text(encoding="utf-8-sig", errors="ignore")
            except OSError:
                continue
            try:
                dialect = csv.Sniffer().sniff(text[:8192],
                                              delimiters=[",", ";", "\t", "|"])
            except csv.Error:
                dialect = csv.excel
            rows = csv.reader(text.splitlines(), dialect)
            try:
                header = next(rows)
            except StopIteration:
                continue
            cols = [str(h or "").strip().lower() for h in header]

            def colidx(names, fallback):
                for i, c in enumerate(cols):
                    if c in names:
                        return i
                if fallback is not None and fallback < len(cols):
                    return fallback
                return None

            id_i = colidx(id_names, 0)
            title_i = colidx(title_names, 1 if len(cols) > 1 else 0)
            desc_i = colidx(desc_names, None)
            if id_i is None or title_i is None:
                continue
            for row in rows:
                if len(row) <= max(id_i, title_i):
                    continue
                cid = row[id_i].strip().upper()
                title = re.sub(r"\s+", " ", row[title_i].strip())
                if not cid or not title:
                    continue
                if (desc_i is not None and desc_i not in (id_i, title_i)
                        and len(row) > desc_i):
                    desc = re.sub(r"\s+", " ", row[desc_i].strip())
                    if desc and desc != title:
                        title = f"{title} - {desc[:600]}"
                key = f"{prefix}:{cid}"
                if key not in self.metadata["controls"]:
                    self.metadata["controls"][key] = title[:2000]
                    n += 1
        if n:
            self.metadata["frameworks"][prefix] = f"{label} (user-supplied drop-in)"
        print(f"[i] {source_key}: {n} controls indexed")

    def _parse_reference_json(self, source_key, prefix, label):
        """Generic JSON drop-in indexer (e.g. a CSA CCM machine-readable
        bundle the user obtained for internal use under CSA's terms).
        Accepts a bare control list or an object with a controls /
        requirements / statements / domains list, descending recursively so
        CCM-style `domains[].controls[]` nests index too. Entries carry an
        id plus title/name, with description/specification/text as context.
        """
        base = Path(self.SOURCES[source_key]["local_path"])
        if not base.is_dir():
            return
        files = sorted(base.glob("*.json"))
        if not files:
            return
        nest_keys = ("controls", "requirements", "statements", "domains",
                     "items", "questions")
        n = 0
        for path in files:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            top: list = data if isinstance(data, list) else []
            if isinstance(data, dict):
                for list_key in nest_keys:
                    value = data.get(list_key)
                    if isinstance(value, list):
                        top.extend(value)
                    elif isinstance(value, dict):
                        for sub in value.values():
                            if isinstance(sub, list):
                                top.extend(sub)
            stack = list(top)
            while stack:
                entry = stack.pop()
                if not isinstance(entry, dict):
                    continue
                for list_key in nest_keys:
                    nested = entry.get(list_key)
                    if isinstance(nested, list):
                        stack.extend(nested)
                    elif isinstance(nested, dict):
                        for sub in nested.values():
                            if isinstance(sub, list):
                                stack.extend(sub)
                cid = str(entry.get("id") or entry.get("control_id")
                          or entry.get("code") or "").strip().upper()
                title = str(entry.get("title") or entry.get("name") or "").strip()
                desc = re.sub(r"\s+", " ", str(
                    entry.get("description") or entry.get("specification")
                    or entry.get("text") or "").strip())
                if not title:
                    title, desc = desc, ""
                if not cid or not title:
                    continue
                text = f"{title} - {desc[:600]}" if desc and desc != title else title
                key = f"{prefix}:{cid}"
                if key not in self.metadata["controls"]:
                    self.metadata["controls"][key] = text[:2000]
                    n += 1
        if n:
            self.metadata["frameworks"][prefix] = f"{label} (user-supplied drop-in)"
        print(f"[i] {source_key}: {n} controls indexed")


if __name__ == "__main__":
    FrameworkManager().sync_all()
