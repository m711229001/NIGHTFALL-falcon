"""Falcon MAG Framework - Report Fusion

Merges multiple JSON reports (from Framework + external tools) into one.
Outputs a unified JSON + Markdown.
"""

import json
from datetime import datetime
from pathlib import Path


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print("Failed to load", path, ":", e)
        return None


def fuse(input_paths, output_base):
    """Fuse multiple scan JSON reports into one."""
    merged = {
        "fused_at": datetime.now().isoformat(),
        "sources": [],
        "findings": [],
        "module_results": {},
    }

    for p in input_paths:
        data = _load(p)
        if not data:
            continue
        merged["sources"].append(p)
        for f in data.get("findings", []) or []:
            merged["findings"].append(f)
        for name, r in (data.get("module_results") or {}).items():
            merged["module_results"][name] = r

    # Dedupe findings by (category, url, payload)
    seen = set()
    unique = []
    for f in merged["findings"]:
        key = (f.get("category", ""), f.get("url", ""), f.get("payload", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    merged["findings"] = unique

    out_json = output_base + ".json"
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=2, ensure_ascii=False, default=str)

    return {
        "json": out_json,
        "total_findings": len(unique),
        "sources": len(merged["sources"]),
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python -m core.report_fusion out_base in1.json in2.json ...")
        sys.exit(1)
    out = sys.argv[1]
    ins = sys.argv[2:]
    print(fuse(ins, out))