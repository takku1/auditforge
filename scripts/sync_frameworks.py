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
        "scf":           {"local_path": "secure-controls-framework"},
    }

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
                missing.append(name)
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
        self._parse_attack()
        self._parse_scf_crosswalk()
        # OWASP Top 10 OSIB export is a deeply nested CWE-linkage graph, not a
        # flat control list - deliberately left as a presence flag rather than
        # a fragile deep-parse; see docs/framework-coverage-audit-2026-09-02.md.
        self._register_family("top10", "OWASP Top 10:2025 (OSIB export - presence only)",
                               "owasp-top10/osib/export")

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

    def _parse_attack(self):
        """Parses MITRE ATT&CK Enterprise techniques from the STIX 2.1 bundle."""
        base = Path(self.SOURCES["attack"]["local_path"])
        path = base / "enterprise-attack.json"
        if not path.exists():
            candidates = sorted(base.glob("enterprise-attack-*.json"))
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
                self.metadata["controls"][f"ATTACK:{ext_id}"] = name
                n += 1
        if n:
            self.metadata["frameworks"]["ATTACK"] = "MITRE ATT&CK Enterprise"
        print(f"[i] attack: {n} techniques indexed")

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


if __name__ == "__main__":
    FrameworkManager().sync_all()
