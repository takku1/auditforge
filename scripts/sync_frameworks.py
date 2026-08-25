import os
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
        "hipaa_cac":     {"local_path": "compliance-as-code/controls/hipaa.yml"},
        "pcidss_cac":    {"local_path": "compliance-as-code/controls/pcidss_4.yml"},
        "asvs":          {"local_path": "asvs/5.0/docs_en"},
        "top10":         {"local_path": "owasp-top10/osib/export"},
        "attack":        {"local_path": "attack-stix-data/enterprise-attack"},
        "scf":           {"local_path": "secure-controls-framework"},
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
        self._parse_cac_yaml("hipaa_cac", "HIPAA", "HIPAA Security Rule (via ComplianceAsCode)")
        self._parse_cac_yaml("pcidss_cac", "PCI4", "PCI DSS v4.0 (via ComplianceAsCode)")
        self._parse_asvs()
        self._register_family("top10", "OWASP Top 10:2025", "owasp-top10/osib/export")
        self._register_family("attack", "MITRE ATT&CK Enterprise", "attack-stix-data/enterprise-attack")
        self._register_family("scf", "Secure Controls Framework crosswalk (~120 mappings)", "secure-controls-framework")

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
        import re
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

    def _parse_cac_yaml(self, key, prefix, label):
        path = self.SOURCES[key]["local_path"]
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        def walk(controls):
            for c in controls or []:
                cid = str(c.get("id", "")).strip()
                title = str(c.get("title", "")).strip()
                if cid and title:
                    self.metadata["controls"][f"{prefix}:{cid}"] = title
                walk(c.get("controls"))

        walk(data.get("controls"))
        self.metadata["frameworks"][prefix] = label

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
                name = (it.get("Name") or "").strip()
                if code and name:
                    self.metadata["controls"][f"ASVS:{code}"] = name
                walk(it.get("Items"))

        for chapter in data.get("chapters", []):
            walk(chapter.get("Items"))
        version = data.get("Version", "")
        self.metadata["frameworks"]["ASVS"] = f"OWASP ASVS v{version}"


if __name__ == "__main__":
    FrameworkManager().sync_all()
