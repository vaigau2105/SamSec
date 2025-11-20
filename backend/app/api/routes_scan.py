# backend/app/api/routes_scan.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import os
import json
from ..models import enqueue_background_scan


router = APIRouter(prefix="/scans", tags=["Scans"])

class ScanRequest(BaseModel):
    name: Optional[str] = "samsec-scan"
    targets: List[str]

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "results"))

def result_path_for(job_id: str) -> str:
    return os.path.join(RESULTS_DIR, f"{job_id}.json")

@router.post("/", status_code=202)
def create_scan(payload: ScanRequest):
    if not payload.targets or len(payload.targets) == 0:
        raise HTTPException(400, "No targets provided")
    job_id = enqueue_background_scan(payload.targets)
    return {"success": True, "message": "Scan queued", "job_id": job_id}

@router.get("/{scan_id}")
def get_scan(scan_id: str):
    path = result_path_for(scan_id)
    if not os.path.exists(path):
        raise HTTPException(404, "Scan not found")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data
from fastapi.responses import FileResponse
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

@router.get("/{job_id}/report/pdf")
def get_pdf_report(job_id: str):
    file_path = RESULTS_DIR / f"{job_id}.pdf"
    if not file_path.exists():
        return {"error": "Report not found"}
    return FileResponse(file_path, media_type="application/pdf", filename=f"{job_id}.pdf")


@router.get("/{job_id}/report/html")
def get_html_report(job_id: str):
    file_path = RESULTS_DIR / f"{job_id}.html"
    if not file_path.exists():
        return {"error": "Report not found"}
    return FileResponse(file_path, media_type="text/html")
