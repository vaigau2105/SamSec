# backend/app/main.py

import json
import uuid
import asyncio
from datetime import datetime
from multiprocessing import Manager
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.app.services.scanner import run_full_scan
from backend.app.services.pipeline import (
    run_parallel_pipeline,
    run_single_scan_in_process,
)


# ─────────────────────────────────────────────
#  App
# ─────────────────────────────────────────────

app = FastAPI(
    title="SamSec API",
    description="Automated Vulnerability Scanning Platform",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
#  Paths
# ─────────────────────────────────────────────

BASE_DIR     = Path(__file__).resolve().parents[2]
FRONTEND_DIR = BASE_DIR / "frontend"
REPORTS_DIR  = BASE_DIR / "backend" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


# ─────────────────────────────────────────────
#  Shared state (multiprocessing-safe Manager dict)
# ─────────────────────────────────────────────

_manager       = Manager()
SCAN_STATUS    = _manager.dict()   # { scan_id: { status, progress, stage, ... } }
TARGETS_INDEX  = {}                 # { scan_id: metadata }  (in-process, not cross-process)


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def now_iso():
    return datetime.utcnow().isoformat()

def safe_id():
    return uuid.uuid4().hex[:12]


# ─────────────────────────────────────────────
#  Single-scan background runner
# ─────────────────────────────────────────────

def _bg_single_scan(scan_id: str, target_url: str):
    """Runs in FastAPI BackgroundTasks thread → spawns its own child process."""
    run_single_scan_in_process(scan_id, target_url, SCAN_STATUS)
    # Sync completed status back to TARGETS_INDEX
    st = SCAN_STATUS.get(scan_id, {})
    if scan_id in TARGETS_INDEX:
        TARGETS_INDEX[scan_id]["status"]  = st.get("status", "Unknown")
        TARGETS_INDEX[scan_id]["summary"] = st.get("summary", {})


# ─────────────────────────────────────────────
#  Bulk-scan background runner
# ─────────────────────────────────────────────

def _bg_bulk_scan(jobs: list):
    """Runs in BackgroundTasks thread → pool of child processes."""
    run_parallel_pipeline(jobs, SCAN_STATUS)
    for job in jobs:
        sid = job["scan_id"]
        st  = SCAN_STATUS.get(sid, {})
        if sid in TARGETS_INDEX:
            TARGETS_INDEX[sid]["status"]  = st.get("status", "Unknown")
            TARGETS_INDEX[sid]["summary"] = st.get("summary", {})


# ─────────────────────────────────────────────
#  Static pages
# ─────────────────────────────────────────────

@app.get("/")
def serve_home():
    return FileResponse(FRONTEND_DIR / "index.html")

@app.get("/scan")
def serve_scan():
    return FileResponse(FRONTEND_DIR / "scan.html")

@app.get("/reports")
def serve_reports():
    return FileResponse(FRONTEND_DIR / "reports.html")


# ─────────────────────────────────────────────
#  Request models
# ─────────────────────────────────────────────

class ScanRequest(BaseModel):
    target_url:  str
    target_name: str = "SamSec Target"
    group_name:  str = "Default"

class BulkScanRequest(BaseModel):
    urls:       List[str]
    group_name: str = "Bulk"


# ─────────────────────────────────────────────
#  API routes
# ─────────────────────────────────────────────

@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = safe_id()

    TARGETS_INDEX[scan_id] = {
        "id":          scan_id,
        "target_name": req.target_name,
        "target_url":  req.target_url,
        "group_name":  req.group_name,
        "scan_date":   now_iso(),
        "status":      "Queued",
        "vulnerabilities": [],
    }

    # Pre-seed status so /status endpoint works immediately
    SCAN_STATUS[scan_id] = {
        "status":   "Queued",
        "progress": 0,
        "stage":    "Waiting",
    }

    background_tasks.add_task(_bg_single_scan, scan_id, req.target_url)

    return {"status": "queued", "scan_id": scan_id}


@app.post("/api/bulk_scan")
async def bulk_scan(req: BulkScanRequest, background_tasks: BackgroundTasks):
    ids  = []
    jobs = []

    for url in req.urls:
        scan_id = safe_id()

        TARGETS_INDEX[scan_id] = {
            "id":          scan_id,
            "target_name": url,
            "target_url":  url,
            "group_name":  req.group_name,
            "scan_date":   now_iso(),
            "status":      "Queued",
            "vulnerabilities": [],
        }

        SCAN_STATUS[scan_id] = {
            "status":   "Queued",
            "progress": 0,
            "stage":    "Waiting",
        }

        jobs.append({"scan_id": scan_id, "target_url": url})
        ids.append(scan_id)

    background_tasks.add_task(_bg_bulk_scan, jobs)

    return {"scheduled": len(ids), "scan_ids": ids}


@app.get("/api/scan/{scan_id}/status")
def get_scan_status(scan_id: str):
    """
    Live polling endpoint. Returns real-time progress from the
    shared multiprocessing Manager dict.
    """
    st = SCAN_STATUS.get(scan_id)
    if not st:
        meta = TARGETS_INDEX.get(scan_id)
        if not meta:
            raise HTTPException(404, "Scan not found")
        return {"scan_id": scan_id, "status": meta.get("status", "Unknown"), "progress": 0}

    return {
        "scan_id":    scan_id,
        "status":     st.get("status", "Unknown"),
        "progress":   st.get("progress", 0),
        "stage":      st.get("stage", ""),
        "started_at": st.get("started_at"),
        "ended_at":   st.get("ended_at"),
        "summary":    st.get("summary", {}),
        "error":      st.get("error"),
    }


@app.get("/api/report/{scan_id}")
def get_report(scan_id: str):
    report_path = REPORTS_DIR / scan_id / "report.json"

    if not report_path.exists():
        st = SCAN_STATUS.get(scan_id, {})
        status = st.get("status", "")
        if status in ("Queued", "Running"):
            return {"status": "running", "progress": st.get("progress", 0), "stage": st.get("stage", "")}
        raise HTTPException(404, "Report not found")

    with open(report_path) as f:
        return json.load(f)


@app.get("/api/scans")
def list_scans():
    scans = []
    for scan_id, data in TARGETS_INDEX.items():
        # Sync live status from Manager dict if available
        live = SCAN_STATUS.get(scan_id, {})
        status = live.get("status") or data.get("status", "Unknown")

        scans.append({
            "scan_id":     scan_id,
            "target_name": data["target_name"],
            "target_url":  data["target_url"],
            "status":      status,
            "scan_date":   data["scan_date"],
            "progress":    live.get("progress", 100 if status == "Completed" else 0),
        })

    return {"total": len(scans), "scans": scans}


@app.delete("/api/scan/{scan_id}")
def delete_scan(scan_id: str):
    TARGETS_INDEX.pop(scan_id, None)
    SCAN_STATUS.pop(scan_id, None)
    return {"deleted": scan_id}