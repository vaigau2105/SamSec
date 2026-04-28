# backend/app/services/mitre/ingestion.py
"""
MITRE ATT&CK data ingestion.
Downloads the enterprise ATT&CK STIX bundle from GitHub CDN,
caches it locally, and exposes helper accessors.
No external mitreattack-python dependency required — pure JSON parsing.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

CACHE_PATH = Path(__file__).resolve().parents[4] / "data" / "attack_cache.json"
CACHE_TTL  = 86_400 * 7   # refresh weekly


# ──────────────────────────────────────────────────────────────
#  Public API
# ──────────────────────────────────────────────────────────────

def load_attack_data(force_refresh: bool = False) -> Dict[str, Any]:
    """
    Return the full parsed ATT&CK STIX bundle (dict).
    Uses local cache when fresh; downloads otherwise.
    """
    if _cache_is_fresh() and not force_refresh:
        return json.loads(CACHE_PATH.read_text())

    print("[mitre] Downloading ATT&CK STIX bundle …")
    try:
        resp = requests.get(ATTACK_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(json.dumps(data))
        print(f"[mitre] Cached → {CACHE_PATH}")
        return data
    except Exception as exc:
        print(f"[mitre] Download failed: {exc}")
        if CACHE_PATH.exists():
            print("[mitre] Using stale cache as fallback")
            return json.loads(CACHE_PATH.read_text())
        return {"objects": []}


def get_techniques(force_refresh: bool = False) -> List[Dict]:
    """
    Return a clean list of ATT&CK techniques (non-revoked, non-deprecated).
    Each dict: id, name, tactics, description, platforms, url, sub_techniques
    """
    bundle = load_attack_data(force_refresh)
    objects = bundle.get("objects", [])

    # Build id → external_id map from attack-pattern objects
    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        attack_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None,
        )
        attack_url = next(
            (r.get("url", "") for r in ext_refs if r.get("source_name") == "mitre-attack"),
            "",
        )
        if not attack_id:
            continue

        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append({
            "id":            attack_id,
            "stix_id":       obj["id"],
            "name":          obj.get("name", ""),
            "tactics":       tactics,
            "description":   (obj.get("description") or "")[:400],
            "platforms":     obj.get("x_mitre_platforms", []),
            "url":           attack_url,
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
        })

    return techniques


def get_technique_by_id(technique_id: str) -> Optional[Dict]:
    for t in get_techniques():
        if t["id"].upper() == technique_id.upper():
            return t
    return None


def get_tactics() -> List[str]:
    """Return ordered list of tactic names."""
    TACTIC_ORDER = [
        "reconnaissance", "resource-development", "initial-access",
        "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact",
    ]
    return TACTIC_ORDER


# ──────────────────────────────────────────────────────────────
#  Internal helpers
# ──────────────────────────────────────────────────────────────

def _cache_is_fresh() -> bool:
    if not CACHE_PATH.exists():
        return False
    age = time.time() - CACHE_PATH.stat().st_mtime
    return age < CACHE_TTL
