"""Build MITRE ATT&CK Navigator layers (layer format 4.5) for detection coverage and observed techniques.

A layer opens directly in the official ATT&CK Navigator, so teams can review gaps, compare with threat
reports, or combine it with other layers without SentinelX-specific tooling.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sentinelx import __version__
from sentinelx.mitre.catalog import MitreCatalog

LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"
# Colors are only a supplement: every scored technique also carries a comment and metadata in text.
_GRADIENT = {
    "coverage": ["#dbeafeff", "#1d4ed8ff"],
    "observed": ["#fef3c7ff", "#b91c1cff"],
}


def build_layer(
    catalog: MitreCatalog,
    mode: str,
    scores: Mapping[str, int],
    details: Mapping[str, list[str]],
    description: str,
) -> dict[str, Any]:
    """``scores`` maps technique id -> count (rules covering it, or incidents observing it); ``details``
    maps technique id -> human-readable lines (rule titles, incident numbers) shown as metadata."""
    techniques: list[dict[str, Any]] = []
    parents_to_expand: set[str] = set()
    for tid in sorted(scores):
        t = catalog.get(tid)
        if t is None or scores[tid] <= 0:
            continue  # never emit ids that are not in the current ATT&CK catalog
        lines = list(details.get(tid, []))
        techniques.append(
            {
                "techniqueID": t.id,
                "score": scores[tid],
                "enabled": True,
                "comment": f"{scores[tid]} {'rule(s)' if mode == 'coverage' else 'incident(s)'}",
                "metadata": [{"name": "SentinelX", "value": line} for line in lines[:25]],
            }
        )
        if t.parent_id:
            parents_to_expand.add(t.parent_id)
    present = {x["techniqueID"] for x in techniques}
    for pid in sorted(parents_to_expand):
        if pid in present:
            next(x for x in techniques if x["techniqueID"] == pid)["showSubtechniques"] = True
        elif catalog.get(pid) is not None:
            techniques.append({"techniqueID": pid, "showSubtechniques": True, "enabled": True})
    max_score = max((x.get("score", 0) for x in techniques), default=0)
    major = catalog.version.split(".", 1)[0]
    label = "Detection coverage" if mode == "coverage" else "Observed techniques"
    return {
        "name": f"SentinelX - {label}",
        "versions": {"attack": major, "navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": description,
        "sorting": 3,
        "hideDisabled": False,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "techniques": techniques,
        "gradient": {"colors": _GRADIENT[mode], "minValue": 0, "maxValue": max(1, max_score)},
        "legendItems": [],
        "metadata": [
            {"name": "generated_by", "value": f"SentinelX {__version__}"},
            {"name": "attack_version", "value": catalog.version},
        ],
    }
