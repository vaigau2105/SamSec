# backend/main.py
import os
import json
import uuid
import shutil
import asyncio
import subprocess
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
from pydantic import BaseModel
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from backend.app.api.routes_scan import router as scan_router
from backend.app.core.config import settings

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="SamSec API",
    description="Automated Vulnerability Scanning and Reporting Platform",
    version="1.0.0"
)


origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5500",
    "http://localhost:5500",

]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
# In-memory storage for scans
SCAN_RESULTS = {}

# Allow CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(scan_router, prefix="/api")

#######################
#  FRONTEND SERVING
#######################

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

# Serve static files (css, js, images)
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

# Serve the main index.html
@app.get("/", include_in_schema=False)
def serve_frontend():
    return FileResponse(FRONTEND_DIR / "index.html")

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="SamSec API")
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # backend/
FRONTEND_TEMPLATES = ROOT.parent / "frontend" / "templates"

templates = Jinja2Templates(directory=str(FRONTEND_TEMPLATES))

# In-memory index for demo; in production use a DB
TARGETS_INDEX = {}

class ScanRequest(BaseModel):
    target_name: str
    target_url: str
    group_name: str = "Default"

class BulkScanRequest(BaseModel):
    urls: list
    group_name: str = "Bulk Scan"

def safe_id():
    return uuid.uuid4().hex[:12]

def now_iso():
    return datetime.utcnow().isoformat()

@app.get("/api/scans")
async def list_scans():
    return {"scans": list(SCAN_RESULTS.keys())}

async def run_command(cmd, cwd=None, timeout=180):
    """Run command and collect stdout (non-blocking wrapper)"""
    proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=cwd)
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {"exit": -1, "error": "timeout", "stdout": "", "stderr": ""}
    return {"exit": proc.returncode, "stdout": stdout.decode('utf-8', errors='ignore'), "stderr": stderr.decode('utf-8', errors='ignore')}

async def run_scanners(scan_id: str, target_url: str):

    outdir = REPORTS_DIR / scan_id
    outdir.mkdir(exist_ok=True)
    # 1) subfinder
    subs_file = outdir / "subs.txt"
    sub_cmd = f"subfinder -silent -d {target_url} -o {subs_file}"
    await run_command(sub_cmd)

    # If subfinder found nothing, fallback to the root domain
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        subs_file.write_text(target_url + "\n")

    # 2) dnsx (resolve & responses)
    dns_json = outdir / "dns.json"
    dns_cmd = f"dnsx -l {subs_file} -json -resp -o {dns_json}"
    await run_command(dns_cmd)

    # 3) naabu (port scan)
    naabu_json = outdir / "naabu.json"
    naabu_cmd = f"naabu -l {subs_file} -json -o {naabu_json}"
    await run_command(naabu_cmd)

    # 4) httpx (probe for http endpoints)
    httpx_json = outdir / "httpx.json"
    httpx_cmd = f"httpx -l {subs_file} -json -o {httpx_json}"
    await run_command(httpx_cmd)

    # create a simple httpx hosts file for nuclei
    httpx_hosts = outdir / "httpx_hosts.txt"
    if httpx_json.exists():
        try:
            arr = []
            for line in httpx_json.read_text().splitlines():
                if not line.strip(): continue
                j = json.loads(line)
                if j.get("url"):
                    arr.append(j["url"])
            httpx_hosts.write_text("\n".join(arr))
        except Exception:
            pass

    # 5) nuclei (run templates) - may require a templates directory configured
    nuclei_json = outdir / "nuclei.json"
    if httpx_hosts.exists() and httpx_hosts.stat().st_size > 0:
        nuclei_cmd = f"nuclei -l {httpx_hosts} -json -o {nuclei_json}"
        await run_command(nuclei_cmd)
    else:
        nuclei_json.write_text("")

    # Combine results into a single summary JSON
    combined = {
        "scan_id": scan_id,
        "target_url": target_url,
        "scan_date": now_iso(),
        "status": "Completed",
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
        "vulnerabilities": []
    }

    # parse nuclei
    if nuclei_json.exists() and nuclei_json.stat().st_size > 0:
        for line in nuclei_json.read_text().splitlines():
            if not line.strip(): continue
            try:
                j = json.loads(line)
                sev = j.get("info", {}).get("severity", "info").capitalize()
                if sev == "Critical":
                    combined["critical_count"] += 1
                elif sev == "High":
                    combined["high_count"] += 1
                elif sev == "Medium":
                    combined["medium_count"] += 1
                elif sev == "Low":
                    combined["low_count"] += 1
                else:
                    combined["info_count"] += 1
                combined["vulnerabilities"].append({
                    "id": j.get("template-id"),
                    "name": j.get("info", {}).get("name"),
                    "severity": sev,
                    "description": j.get("info", {}).get("description"),
                    "matched": j.get("matches"),
                    "request": j.get("request"),
                    "host": j.get("host")
                })
            except Exception:
                continue

    # Save combined JSON
    report_file = outdir / "report.json"
    report_file.write_text(json.dumps(combined, indent=2))

    # Update in-memory index
    TARGETS_INDEX[scan_id] = {
        "id": scan_id,
        "target_name": target_url,
        "target_url": target_url,
        "scan_date": combined["scan_date"],
        "status": combined["status"],
        "critical_count": combined["critical_count"],
        "high_count": combined["high_count"],
        "medium_count": combined["medium_count"],
        "low_count": combined["low_count"],
        "info_count": combined["info_count"],
        "overall_severity": ("Critical" if combined["critical_count"] > 0 else "High" if combined["high_count"] > 0 else "Medium" if combined["medium_count"] > 0 else "Low"),
        "group_name": "Default",
        "vulnerabilities": combined["vulnerabilities"],
        "is_favorite": False,
        "scan_schedule": "once",
        "next_scan": ""
    }
    return report_file

def report_to_html(report_path: Path):
    """Create a simple HTML snippet for the target report to render in the UI"""
    try:
        j = json.loads(report_path.read_text())
    except Exception:
        return "<div class='p-6'>No report available</div>"

    total = j.get("critical_count",0)+j.get("high_count",0)+j.get("medium_count",0)+j.get("low_count",0)+j.get("info_count",0)
    html = f"""
    <div class="max-w-6xl mx-auto">
      <div class="mb-8">
        <div class="flex justify-between items-start mb-4">
          <div>
            <h1 class="text-3xl font-bold">{j.get('target_url')}</h1>
            <p class="text-slate-400 text-lg">{j.get('target_url')}</p>
            <p class="text-slate-500">Last scanned: {j.get('scan_date')}</p>
          </div>
          <div class="text-right">
            <div class="text-2xl font-bold">{'Critical' if j.get('critical_count',0)>0 else 'High' if j.get('high_count',0)>0 else 'Medium' if j.get('medium_count',0)>0 else 'Low'}</div>
            <div class="text-slate-400">{total} total issues found</div>
          </div>
        </div>
      </div>
      <div class="bg-slate-800 rounded-lg p-6">
        <h2 class="text-xl font-semibold mb-4">Vulnerability Summary</h2>
        <ul>
          <li>Critical: {j.get('critical_count',0)}</li>
          <li>High: {j.get('high_count',0)}</li>
          <li>Medium: {j.get('medium_count',0)}</li>
          <li>Low: {j.get('low_count',0)}</li>
          <li>Info: {j.get('info_count',0)}</li>
        </ul>
      </div>
      <div class="bg-slate-800 rounded-lg p-6 mt-6">
        <h2 class="text-xl font-semibold mb-4">Vulnerability Details</h2>
        <div class="space-y-4">
    """
    for v in j.get("vulnerabilities",[]):
        html += f"""
          <div class="vulnerability-item bg-slate-700 rounded-lg p-4 border-l-4 border-slate-600" data-severity="{v.get('severity')}">
            <div class="flex justify-between items-start mb-2">
              <h3 class="font-semibold text-lg">{v.get('name') or v.get('id')}</h3>
              <span class="px-3 py-1 rounded text-sm">{v.get('severity')}</span>
            </div>
            <p class="text-slate-300 mb-2">{v.get('description') or ''}</p>
            <p class="text-slate-400 text-sm mb-2"><strong>Host:</strong> {v.get('host')}</p>
          </div>
        """
    html += "</div></div></div>"
    return html

@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = safe_id()
    TARGETS_INDEX[scan_id] = {
        "id": scan_id,
        "target_name": req.target_name,
        "target_url": req.target_url,
        "scan_date": now_iso(),
        "status": "Queued",
        "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0,
        "overall_severity": "Low",
        "group_name": req.group_name,
        "vulnerabilities": [],
        "is_favorite": False,
        "scan_schedule": "once",
        "next_scan": ""
    }
    # run background scanning
    background_tasks.add_task(run_scanners, scan_id, req.target_url)
    return JSONResponse({"scan_id": scan_id}, status_code=202)

@app.get("/api/targets")
async def list_targets():
    # return list ordered by scan_date desc
    items = list(TARGETS_INDEX.values())
    items.sort(key=lambda x: x.get("scan_date",""), reverse=True)
    return JSONResponse(items)

@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    p = REPORTS_DIR / scan_id / "report.json"
    if not p.exists():
        # if queued but not finished, tell client
        if scan_id in TARGETS_INDEX and TARGETS_INDEX[scan_id]["status"] == "Queued":
            return JSONResponse({"detail": "Scan still running"}, status_code=202)
        raise HTTPException(status_code=404, detail="Report not found")
    html = report_to_html(p)
    return JSONResponse({"scan_id": scan_id, "html": html, "report": json.loads(p.read_text())})
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def create_pdf(report_path: Path, pdf_path: Path):
    j = json.loads(report_path.read_text())
    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, 750, f"Security Report - {j.get('target_url')}")
    c.setFont("Helvetica", 10)
    y = 720
    for k in ("critical_count","high_count","medium_count","low_count","info_count"):
        c.drawString(40, y, f"{k}: {j.get(k,0)}")
        y -= 16
    y -= 10
    c.drawString(40, y, "Vulnerabilities:")
    y -= 18
    for v in j.get("vulnerabilities", []):
        if y < 80:
            c.showPage()
            y = 750
        c.setFont("Helvetica-Bold", 11)
        c.drawString(48, y, f"- {v.get('name') or v.get('id')} [{v.get('severity')}]")
        y -= 14
        c.setFont("Helvetica", 9)
        c.drawString(56, y, (v.get('description') or '')[:120])
        y -= 18
    c.save()
@app.post("/api/rescan/{scan_id}")
async def api_rescan(scan_id: str, background_tasks: BackgroundTasks):
    target = TARGETS_INDEX.get(scan_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target["status"] = "Queued"
    background_tasks.add_task(run_scanners, scan_id, target["target_url"])
    return JSONResponse({"detail": "Rescan queued"}, status_code=202)

@app.post("/api/bulk_scan")
async def api_bulk_scan(req: BulkScanRequest, background_tasks: BackgroundTasks):
    if not req.urls:
        raise HTTPException(status_code=400, detail="No URLs provided")
    ids = []
    for url in req.urls:
        scan_id = safe_id()
        TARGETS_INDEX[scan_id] = {
            "id": scan_id,
            "target_name": url,
            "target_url": url,
            "scan_date": now_iso(),
            "status": "Queued",
            "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0,
            "overall_severity": "Low",
            "group_name": req.group_name,
            "vulnerabilities": [],
            "is_favorite": False,
            "scan_schedule": "once",
            "next_scan": ""
        }
        background_tasks.add_task(run_scanners, scan_id, url)
        ids.append(scan_id)
    return JSONResponse({"scheduled": len(ids), "ids": ids}, status_code=202)

# Basic UI route to serve the index
@app.get("/", response_class=JSONResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import pathlib

FRONTEND_DIR = pathlib.Path(__file__).resolve().parents[2] / "frontend"

@app.get("/", response_class=HTMLResponse)
def serve_home():
    return (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/scan", response_class=HTMLResponse)
def serve_scan():
    return (FRONTEND_DIR / "scan.html").read_text(encoding="utf-8")


@app.get("/reports", response_class=HTMLResponse)
def serve_reports():
    return (FRONTEND_DIR / "reports.html").read_text(encoding="utf-8")
