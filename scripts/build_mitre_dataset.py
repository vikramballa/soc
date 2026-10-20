#!/usr/bin/env python3
"""Build security/mitre-data/enterprise-attack-compact.json from the official MITRE ATT&CK STIX 2.1 bundle.

Source: https://github.com/mitre-attack/attack-stix-data (ATT&CK® is a registered trademark of
The MITRE Corporation; data used under the ATT&CK Terms of Use, see security/mitre-data/NOTICE.md).

Usage:  python3 scripts/build_mitre_dataset.py [path-or-url-to-enterprise-attack.json]
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUT = Path(__file__).resolve().parents[1] / "security" / "mitre-data" / "enterprise-attack-compact.json"


def _ext_id(obj: dict) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def _clean(text: str, limit: int) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "…"
    return text


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else URL
    if src.startswith("http"):
        if not src.startswith("https://raw.githubusercontent.com/mitre-attack/"):
            raise SystemExit("refusing to download from an unexpected host")
        with urllib.request.urlopen(src, timeout=120) as r:  # noqa: S310 (fixed https host)
            bundle = json.load(r)
    else:
        bundle = json.loads(Path(src).read_text())

    objs = bundle["objects"]
    version = None
    for o in objs:
        if o.get("type") == "x-mitre-collection":
            version = o.get("x_mitre_version")
    tactics = []
    order_names: list[str] = []
    for o in objs:
        if o.get("type") == "x-mitre-matrix" and not o.get("revoked"):
            refs = o.get("tactic_refs", [])
            by_id = {x["id"]: x for x in objs if x.get("type") == "x-mitre-tactic"}
            order_names = [by_id[r]["x_mitre_shortname"] for r in refs if r in by_id]
    for o in objs:
        if o.get("type") != "x-mitre-tactic" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid, url = _ext_id(o)
        short = o["x_mitre_shortname"]
        tactics.append({
            "id": tid, "shortname": short, "name": o["name"], "url": url,
            "description": _clean(o.get("description", ""), 400),
            "order": order_names.index(short) if short in order_names else 99,
        })
    tactics.sort(key=lambda t: t["order"])

    techniques = []
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid, url = _ext_id(o)
        if not tid:
            continue
        techniques.append({
            "id": tid,
            "name": o["name"],
            "tactics": sorted({p["phase_name"] for p in o.get("kill_chain_phases", [])
                               if p.get("kill_chain_name") == "mitre-attack"}),
            "platforms": o.get("x_mitre_platforms", []),
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
            "parent_id": tid.split(".")[0] if "." in tid else None,
            "url": url,
            "description": _clean(o.get("description", ""), 600),
            "detection": _clean(o.get("x_mitre_detection", ""), 400),
        })
    techniques.sort(key=lambda t: t["id"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"attack_version": version, "source": URL, "tactics": tactics,
                               "techniques": techniques}, ensure_ascii=False, separators=(",", ":")))
    print(f"ATT&CK {version}: {len(tactics)} tactics, {len(techniques)} techniques -> {OUT}")


if __name__ == "__main__":
    main()
