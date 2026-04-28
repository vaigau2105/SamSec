# backend/app/api/mitre_routes.py
"""
MITRE ATT&CK API routes — add to main.py via app.include_router()

Add to backend/app/main.py:
    from backend.app.api.mitre_routes import router as mitre_router
    app.include_router(mitre_router)
"""

import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])

BASE_DIR    = Path(__file__).resolve().parents[3]
REPORTS_DIR = BASE_DIR / "backend" / "reports"


# ──────────────────────────────────────────────────────────────
#  GET /api/mitre/techniques
#  Returns the full ATT&CK technique list (cached locally)
# ──────────────────────────────────────────────────────────────

@router.get("/techniques")
def list_techniques(refresh: bool = False):
    """Return all ATT&CK techniques. Pass ?refresh=true to re-download."""
    try:
        from backend.app.services.mitre import get_techniques
        techniques = get_techniques(force_refresh=refresh)
        return {"count": len(techniques), "techniques": techniques}
    except Exception as exc:
        raise HTTPException(500, f"Failed to load ATT&CK data: {exc}")


# ──────────────────────────────────────────────────────────────
#  GET /api/mitre/techniques/{technique_id}
# ──────────────────────────────────────────────────────────────

@router.get("/techniques/{technique_id}")
def get_technique(technique_id: str):
    try:
        from backend.app.services.mitre import get_technique_by_id
        t = get_technique_by_id(technique_id)
        if not t:
            raise HTTPException(404, f"Technique {technique_id} not found")
        return t
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


# ──────────────────────────────────────────────────────────────
#  GET /api/mitre/report/{scan_id}
#  Returns the MITRE section from a completed scan report
# ──────────────────────────────────────────────────────────────

@router.get("/report/{scan_id}")
def get_mitre_report(scan_id: str):
    report_path = REPORTS_DIR / scan_id / "report.json"
    if not report_path.exists():
        raise HTTPException(404, "Report not found — scan may still be running")

    with open(report_path) as f:
        report = json.load(f)

    mitre = report.get("mitre")
    if not mitre or not mitre.get("has_mitre"):
        raise HTTPException(404, "No MITRE data in this report")

    return {
        "scan_id":    scan_id,
        "target_url": report.get("target_url"),
        "scan_date":  report.get("scan_date"),
        "mitre":      mitre,
        "vulnerabilities": [
            {
                "name":             v.get("name"),
                "severity":         v.get("severity"),
                "mitre_techniques": v.get("mitre_techniques", []),
            }
            for v in report.get("vulnerabilities", [])
            if v.get("mitre_techniques")
        ],
    }


# ──────────────────────────────────────────────────────────────
#  GET /api/mitre/navigator/{scan_id}
#  Returns the raw ATT&CK Navigator layer JSON
# ──────────────────────────────────────────────────────────────

@router.get("/navigator/{scan_id}")
def get_navigator_layer(scan_id: str):
    layer_path = REPORTS_DIR / scan_id / "mitre_layer.json"
    if not layer_path.exists():
        raise HTTPException(404, "Navigator layer not found for this scan")

    with open(layer_path) as f:
        layer = json.load(f)

    return JSONResponse(
        content=layer,
        headers={
            "Content-Disposition": f'attachment; filename="samsec_{scan_id}_mitre.json"',
        },
    )


# ──────────────────────────────────────────────────────────────
#  GET /api/mitre/coverage/{scan_id}
#  Returns tactic-level coverage summary for the UI heatmap
# ──────────────────────────────────────────────────────────────

@router.get("/coverage/{scan_id}")
def get_coverage(scan_id: str):
    report_path = REPORTS_DIR / scan_id / "report.json"
    if not report_path.exists():
        raise HTTPException(404, "Report not found")

    with open(report_path) as f:
        report = json.load(f)

    mitre = report.get("mitre", {})
    if not mitre.get("has_mitre"):
        raise HTTPException(404, "No MITRE coverage data for this scan")

    return {
        "scan_id":  scan_id,
        "coverage": mitre.get("coverage", {}),
    }


# ──────────────────────────────────────────────────────────────
#  POST /api/mitre/refresh-cache
#  Force re-download of ATT&CK data
# ──────────────────────────────────────────────────────────────

@router.post("/refresh-cache")
def refresh_cache():
    try:
        from backend.app.services.mitre import load_attack_data
        load_attack_data(force_refresh=True)
        return {"status": "ok", "message": "ATT&CK data refreshed successfully"}
    except Exception as exc:
        raise HTTPException(500, f"Refresh failed: {exc}")
