# backend/app/main.py

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.app.services.scanner import run_full_scan


# ------------------- APP ------------------

app = FastAPI(
    title="SamSec API",
    description="Automated Vulnerability Scanning Platform",
    version="1.0.0",
)

# ------------------- CORS ------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- PATHS ------------------

BASE_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIR = BASE_DIR / "frontend"
REPORTS_DIR = BASE_DIR / "backend" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ------------------- STATIC & FRONTEND ------------------

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
def serve_home():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/scan")
def serve_scan():
    return FileResponse(FRONTEND_DIR / "scan.html")


@app.get("/reports")
def serve_reports():
    return FileResponse(FRONTEND_DIR / "reports.html")


# ------------------- MEMORY STORAGE ------------------

TARGETS_INDEX = {}


def now_iso():
    return datetime.utcnow().isoformat()


def safe_id():
    return uuid.uuid4().hex[:12]


# ------------------- RUN SCANNERS ------------------

async def run_scanners(scan_id: str, target_url: str):

    outdir = REPORTS_DIR / scan_id
    outdir.mkdir(exist_ok=True)

    print(f"\n🚀 Running scanners for: {target_url}")

    try:
        result = run_full_scan(target_url)

        report = {
            "scan_id": scan_id,
            "target_url": target_url,
            "scan_date": now_iso(),
            "status": "Completed",
            "dns_data": result["dns_data"],
            "subdomains": result.get("subdomains", []),
            "alive_hosts": result.get("alive_hosts", []),
            "open_ports": result.get("open_ports", []),
            "dns_data": result.get("dns_data", {}),

            "vulnerabilities": result.get("vulnerabilities", []),

            "critical_count": result["summary"].get("Critical", 0),
            "high_count": result["summary"].get("High", 0),
            "medium_count": result["summary"].get("Medium", 0),
            "low_count": result["summary"].get("Low", 0),
            "info_count": result["summary"].get("Info", 0),
        }

        # SAVE REPORT
        with open(outdir / "report.json", "w") as f:
            json.dump(report, f, indent=4)

        # Update dashboard memory
        TARGETS_INDEX[scan_id]["status"] = "Completed"
        TARGETS_INDEX[scan_id]["summary"] = result["summary"]
        TARGETS_INDEX[scan_id]["vulnerabilities"] = result["vulnerabilities"]

        print(f"✅ Scan completed: {scan_id}")

    except Exception as e:
        print(f"❌ Scan failed: {e}")
        TARGETS_INDEX[scan_id]["status"] = "Failed"


# ------------------- API MODELS ------------------

class ScanRequest(BaseModel):
    target_url: str
    target_name: str = "SamSec Target"
    group_name: str = "Default"


class BulkScanRequest(BaseModel):
    urls: List[str]
    group_name: str = "Bulk"


# ------------------- API ROUTES ------------------

@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):

    scan_id = safe_id()

    TARGETS_INDEX[scan_id] = {
        "id": scan_id,
        "target_name": req.target_name,
        "target_url": req.target_url,
        "group_name": req.group_name,
        "scan_date": now_iso(),
        "status": "Queued",
        "vulnerabilities": []
    }

    background_tasks.add_task(run_scanners, scan_id, req.target_url)

    return {"status": "queued", "scan_id": scan_id}


@app.post("/api/bulk_scan")
async def bulk_scan(req: BulkScanRequest, background_tasks: BackgroundTasks):

    ids = []

    for url in req.urls:
        scan_id = safe_id()

        TARGETS_INDEX[scan_id] = {
            "id": scan_id,
            "target_name": url,
            "target_url": url,
            "group_name": req.group_name,
            "scan_date": now_iso(),
            "status": "Queued",
            "vulnerabilities": []
        }

        background_tasks.add_task(run_scanners, scan_id, url)
        ids.append(scan_id)

    return {"scheduled": len(ids), "scan_ids": ids}


@app.get("/api/report/{scan_id}")
def get_report(scan_id: str):

    report_path = REPORTS_DIR / scan_id / "report.json"

    if not report_path.exists():
        if scan_id in TARGETS_INDEX and TARGETS_INDEX[scan_id]["status"] == "Queued":
            return {"status": "running"}
        raise HTTPException(404, "Report not found")

    with open(report_path) as f:
        return json.load(f)


@app.get("/api/scans")
def list_scans():

    scans = []

    for scan_id, data in TARGETS_INDEX.items():
        scans.append({
            "scan_id": scan_id,
            "target_name": data["target_name"],
            "target_url": data["target_url"],
            "status": data["status"],
            "scan_date": data["scan_date"],
        })

    return {"total": len(scans), "scans": scans}
