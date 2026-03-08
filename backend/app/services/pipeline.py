# backend/app/services/pipeline.py
"""
SamSec Parallel Scan Pipeline
Uses Python multiprocessing — each asset gets its own process (true parallelism).
Handles both sync and async run_full_scan safely inside child processes.
"""

import asyncio
import inspect
import json
import traceback
from datetime import datetime
from multiprocessing import Pool, current_process
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR    = Path(__file__).resolve().parents[3]
REPORTS_DIR = BASE_DIR / "backend" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

MAX_WORKERS  = 8
SCAN_TIMEOUT = 600  # seconds


# ──────────────────────────────────────────────────────────────
#  Helper: call run_full_scan regardless of sync / async
# ──────────────────────────────────────────────────────────────

def _call_run_full_scan(domain: str) -> Dict[str, Any]:
    """
    Import and call run_full_scan inside the child process.
    If it's a coroutine function (async def), run it with asyncio.run().
    If it's a regular function, call it directly.
    """
    # Import here — inside child process — to avoid pickling issues
    from backend.app.services.scanner import run_full_scan  # noqa

    result = run_full_scan(domain)

    # Handle async scanner
    if inspect.iscoroutine(result):
        result = asyncio.run(result)

    return result


# ──────────────────────────────────────────────────────────────
#  Per-asset worker  (top-level → picklable)
# ──────────────────────────────────────────────────────────────

def _scan_worker(args: tuple) -> Dict[str, Any]:
    """
    Runs entirely in a child process.
    args = (scan_id, target_url, shared_status_dict)
    """
    scan_id, target_url, shared_status = args
    pid = current_process().pid

    print(f"[PID {pid}] 🚀 Scanning {scan_id} → {target_url}")

    # ── Mark as Running ──
    shared_status[scan_id] = {
        "status":     "Running",
        "progress":   5,
        "stage":      "Initialising",
        "started_at": datetime.utcnow().isoformat(),
        "pid":        pid,
    }

    outdir = REPORTS_DIR / scan_id
    outdir.mkdir(exist_ok=True)

    def update(progress: int, stage: str):
        shared_status[scan_id] = {
            **shared_status[scan_id],
            "progress": progress,
            "stage":    stage,
        }

    try:
        update(10, "Running subfinder / httpx / naabu / nuclei")

        # ── THE FIX: use helper that handles sync & async ──
        result = _call_run_full_scan(target_url)

        # Sanity check
        if result is None:
            raise RuntimeError("run_full_scan returned None — check scanner.py for errors")
        if inspect.iscoroutine(result):
            raise RuntimeError("run_full_scan still returned a coroutine — asyncio.run() failed")

        update(80, "Normalising vulnerabilities")

        # ── Normalise nuclei vuln objects → flat schema ──
        raw_vulns: List[Dict] = result.get("vulnerabilities", [])
        normalised: List[Dict] = []

        for v in raw_vulns:
            if not isinstance(v, dict):
                continue

            info = v.get("info", {}) if isinstance(v.get("info"), dict) else {}

            classification = info.get("classification", {})
            if not isinstance(classification, dict):
                classification = {}

            cve_ids: List[str] = classification.get("cve-id") or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]

            remediation: str = (
                info.get("remediation")
                or info.get("fix")
                or v.get("remediation")
                or _default_remediation(info.get("severity") or v.get("severity") or "info")
            )

            normalised.append({
                "name":        info.get("name") or v.get("name") or v.get("template-id") or "Unknown",
                "severity":    (info.get("severity") or v.get("severity") or "info").capitalize(),
                "description": info.get("description") or v.get("description") or "",
                "cve_ids":     cve_ids,
                "remediation": remediation,
                "target":      v.get("host") or v.get("matched-at") or target_url,
                "template_id": v.get("template-id") or "",
                "tags":        info.get("tags") or [],
                "references":  info.get("reference") or [],
                "cvss_score":  classification.get("cvss-score"),
            })

        update(90, "Building report")

        # ── Recount severity ──
        summary: Dict[str, int] = {s: 0 for s in ("Critical", "High", "Medium", "Low", "Info")}
        for nv in normalised:
            sev = nv["severity"]
            summary[sev] = summary.get(sev, 0) + 1

        report = {
            "scan_id":         scan_id,
            "target_url":      target_url,
            "scan_date":       datetime.utcnow().isoformat(),
            "status":          "Completed",
            "subdomains":      result.get("subdomains", []),
            "alive_hosts":     result.get("alive_hosts", []),
            "open_ports":      result.get("open_ports", []),
            "dns_data":        result.get("dns_data", {}),
            "vulnerabilities": normalised,
            "summary":         summary,
            "critical_count":  summary["Critical"],
            "high_count":      summary["High"],
            "medium_count":    summary["Medium"],
            "low_count":       summary["Low"],
            "info_count":      summary["Info"],
        }

        with open(outdir / "report.json", "w") as f:
            json.dump(report, f, indent=4)

        shared_status[scan_id] = {
            **shared_status[scan_id],
            "status":   "Completed",
            "progress": 100,
            "stage":    "Done",
            "summary":  summary,
            "ended_at": datetime.utcnow().isoformat(),
        }

        print(f"[PID {pid}] ✅ Completed: {scan_id}")
        return {"scan_id": scan_id, "status": "Completed"}

    except Exception as exc:
        tb = traceback.format_exc()
        print(f"[PID {pid}] ❌ Failed: {scan_id}\n{tb}")

        shared_status[scan_id] = {
            **shared_status.get(scan_id, {}),
            "status":   "Failed",
            "progress": 0,
            "stage":    "Error",
            "error":    str(exc),
            "ended_at": datetime.utcnow().isoformat(),
        }

        with open(outdir / "error.txt", "w") as f:
            f.write(tb)

        return {"scan_id": scan_id, "status": "Failed", "error": str(exc)}


# ──────────────────────────────────────────────────────────────
#  Public API
# ──────────────────────────────────────────────────────────────

def run_parallel_pipeline(
    jobs: List[Dict[str, str]],
    shared_status: Dict,
    max_workers: int = MAX_WORKERS,
) -> List[Dict[str, Any]]:
    """Fan out all jobs across a multiprocessing Pool."""
    if not jobs:
        return []

    args = [(j["scan_id"], j["target_url"], shared_status) for j in jobs]
    effective_workers = min(max_workers, len(jobs))

    print(f"\n🔁 Pipeline: {len(jobs)} assets | {effective_workers} workers")

    with Pool(processes=effective_workers) as pool:
        results = pool.map(_scan_worker, args, chunksize=1)

    return results


def run_single_scan_in_process(
    scan_id: str,
    target_url: str,
    shared_status: Dict,
) -> None:
    """Run a single asset scan in the current thread (called from BackgroundTasks)."""
    _scan_worker((scan_id, target_url, shared_status))


# ──────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────

_REMEDIATION_MAP = {
    "critical": "Patch immediately. Isolate affected systems. Conduct full incident-response review.",
    "high":     "Apply vendor patches or mitigations within 24–72 hours. Restrict access until resolved.",
    "medium":   "Schedule a fix in the next sprint. Apply compensating controls in the meantime.",
    "low":      "Track and resolve in the next maintenance window. No immediate risk.",
    "info":     "Review for context. No immediate action required unless part of a broader attack surface.",
}

def _default_remediation(severity: str) -> str:
    return _REMEDIATION_MAP.get(str(severity).lower(), _REMEDIATION_MAP["info"])