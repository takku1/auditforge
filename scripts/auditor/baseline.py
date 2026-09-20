import json

def load_baseline(path: str) -> set:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return set(data.get("fingerprints", []))


def write_baseline(path: str, report: dict):
    data = {
        "generated_at": report["scanned_at"],
        "target": report["target"],
        "fingerprints": sorted({f.fingerprint for f in report["findings"]}),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
