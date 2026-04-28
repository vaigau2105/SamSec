# backend/app/services/mitre/coverage.py
"""
ATT&CK coverage calculator + ATT&CK Navigator layer generator.
Produces the JSON that can be imported directly into
https://mitre-attack.github.io/attack-navigator/
"""

import json
from collections import defaultdict
from typing import Any, Dict, List

from .ingestion import get_tactics

# Severity → heat score for the navigator heatmap
SEVERITY_SCORE: Dict[str, int] = {
    "critical": 100,
    "high":     80,
    "medium":   55,
    "low":      30,
    "info":     10,
}

SEVERITY_COLOR: Dict[str, str] = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#3b82f6",
    "info":     "#94a3b8",
}


# ──────────────────────────────────────────────────────────────
#  Coverage stats
# ──────────────────────────────────────────────────────────────

def calculate_coverage(enriched_findings: List[Dict]) -> Dict[str, Any]:
    """
    Aggregate technique coverage stats from enriched findings.
    Returns per-tactic and overall metrics.
    """
    tactic_map:     Dict[str, List[str]] = defaultdict(list)  # tactic → [technique_ids]
    technique_hits: Dict[str, Dict]      = {}                  # tid → {count, max_severity, findings}

    for finding in enriched_findings:
        sev   = finding.get("severity", "info").lower()
        score = SEVERITY_SCORE.get(sev, 10)

        for t in finding.get("mitre_techniques", []):
            tid = t["technique_id"]
            tac = t["tactic"]
            tactic_map[tac].append(tid)

            if tid not in technique_hits:
                technique_hits[tid] = {
                    "technique_id":   tid,
                    "technique_name": t["technique_name"],
                    "tactic":         tac,
                    "count":          0,
                    "max_score":      0,
                    "max_severity":   "info",
                    "findings":       [],
                    "confidence":     t.get("confidence", "medium"),
                }

            technique_hits[tid]["count"]    += 1
            technique_hits[tid]["findings"].append(finding.get("name", ""))
            if score > technique_hits[tid]["max_score"]:
                technique_hits[tid]["max_score"]    = score
                technique_hits[tid]["max_severity"] = sev

    # Per-tactic summary
    tactic_summary = []
    for tactic in get_tactics():
        tids   = list(dict.fromkeys(tactic_map.get(tactic, [])))
        tactic_summary.append({
            "tactic":          tactic,
            "technique_count": len(tids),
            "technique_ids":   tids,
        })

    total_techniques = len(technique_hits)
    covered_tactics  = sum(1 for t in tactic_summary if t["technique_count"] > 0)

    return {
        "total_techniques_covered": total_techniques,
        "total_tactics_covered":    covered_tactics,
        "total_tactics":            len(get_tactics()),
        "coverage_pct":             round(total_techniques / max(total_techniques, 1) * 100, 1),
        "tactic_summary":           tactic_summary,
        "technique_hits":           list(technique_hits.values()),
    }


# ──────────────────────────────────────────────────────────────
#  ATT&CK Navigator layer
# ──────────────────────────────────────────────────────────────

def generate_navigator_layer(
    enriched_findings: List[Dict],
    scan_name:   str = "SamSec Scan",
    target_url:  str = "",
) -> Dict[str, Any]:
    """
    Build a full ATT&CK Navigator v4 layer JSON.
    Import the result at https://mitre-attack.github.io/attack-navigator/
    """
    technique_scores: Dict[str, Dict] = {}

    for finding in enriched_findings:
        sev   = finding.get("severity", "info").lower()
        score = SEVERITY_SCORE.get(sev, 10)
        color = SEVERITY_COLOR.get(sev, "#94a3b8")

        for t in finding.get("mitre_techniques", []):
            tid = t["technique_id"]
            if tid not in technique_scores:
                technique_scores[tid] = {
                    "techniqueID": tid,
                    "score":       0,
                    "color":       "",
                    "comment":     "",
                    "enabled":     True,
                    "metadata":    [],
                    "_findings":   [],
                    "_max_sev":    "info",
                }
            entry = technique_scores[tid]
            if score > entry["score"]:
                entry["score"]    = score
                entry["color"]    = color
                entry["_max_sev"] = sev
            entry["_findings"].append(finding.get("name", "Unnamed"))

    # Finalise comments
    layer_techniques = []
    for tid, entry in technique_scores.items():
        findings_str = ", ".join(dict.fromkeys(entry["_findings"]))[:250]
        layer_techniques.append({
            "techniqueID": entry["techniqueID"],
            "score":       entry["score"],
            "color":       entry["color"],
            "comment":     f"[{entry['_max_sev'].upper()}] {findings_str}",
            "enabled":     True,
            "metadata":    [
                {"name": "tool",    "value": "SamSec"},
                {"name": "target",  "value": target_url or "unknown"},
            ],
        })

    layer = {
        "name":        scan_name,
        "versions": {
            "attack":    "14",
            "navigator": "4.9",
            "layer":     "4.5",
        },
        "domain":      "enterprise-attack",
        "description": (
            f"Generated by SamSec — {len(enriched_findings)} findings → "
            f"{len(layer_techniques)} ATT&CK techniques mapped. "
            f"Target: {target_url}"
        ),
        "filters": {
            "platforms": [
                "Linux", "Windows", "macOS",
                "Network", "Containers", "PRE",
            ],
        },
        "sorting":     3,  # sort by score descending
        "layout": {
            "layout":        "side",
            "aggregateFunction": "max",
            "showID":        True,
            "showName":      True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "gradient": {
            "colors":   ["#1e293b", "#fbbf24", "#ef4444"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"color": "#ef4444", "label": "Critical"},
            {"color": "#f97316", "label": "High"},
            {"color": "#eab308", "label": "Medium"},
            {"color": "#3b82f6", "label": "Low"},
            {"color": "#94a3b8", "label": "Info"},
        ],
        "techniques": layer_techniques,
        "metadata":   [
            {"name": "generated_by", "value": "SamSec"},
            {"name": "target",       "value": target_url},
        ],
    }

    return layer


def save_navigator_layer(
    layer: Dict,
    scan_id: str,
    reports_dir: str = "backend/reports",
) -> str:
    """Save navigator layer JSON next to the scan report."""
    import os
    out_dir  = os.path.join(reports_dir, scan_id)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "mitre_layer.json")
    with open(out_path, "w") as f:
        json.dump(layer, f, indent=2)
    return out_path
