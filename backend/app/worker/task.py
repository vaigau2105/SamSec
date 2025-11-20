# backend/app/worker/task.py
import os
import json
import uuid
import threading
from datetime import datetime
from typing import List, Dict, Any

from app.services.subfinder import run_subfinder
from app.services.httpx import run_httpx
from app.services.naabu import run_naabu
from app.services.nuclei import run_nuclei

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

def job_result_path(job_id: str) -> str:
    return os.path.join(RESULTS_DIR, f"{job_id}.json")

def write_progress(job_id: str, data: Dict[str, Any]):
    path = job_result_path(job_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def run_scan_job(job_id: str, targets: List[str]):
    """
    Orchestrates tools: subfinder -> httpx -> naabu -> nuclei
    Writes progress to results/<job_id>.json
    """
    meta = {
        "job_id": job_id,
        "status": "running",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "targets": targets,
        "started_at": datetime.utcnow().isoformat() + "Z"
    }
    combined = {"meta": meta, "subfinder": {}, "httpx": {}, "naabu": {}, "nuclei": {}}
    write_progress(job_id, combined)

    try:
        # 1) run subfinder for each target (fast)
        for t in targets:
            sres = run_subfinder(t)
            combined["subfinder"][t] = sres
            write_progress(job_id, combined)

        # 2) collect discovered hosts (unique)
        discovered = []
        for t, r in combined["subfinder"].items():
            discovered.extend(r.get("results", []))
        # fallback to original targets if none discovered
        hosts = list(dict.fromkeys(discovered)) or targets

        # limit hosts for demo-speed (first 25)
        hosts = hosts[:25]

        # 3) probe with httpx to detect alive URLs (fast)
        httpx_results = run_httpx(hosts)
        combined["httpx"] = httpx_results
        write_progress(job_id, combined)

        # 4) run naabu on the hosts (fast)
        naabu_results = run_naabu(hosts[:10])  # limit to first 10 for speed
        combined["naabu"] = naabu_results
        write_progress(job_id, combined)

        # 5) run nuclei on alive host URLs (choose hosts with httpx results)
        nuclei_results = {}
        alive_hosts = []
        for h, info in httpx_results.items():
            # httpx JSON items often contain 'url' or 'status_code'
            items = info.get("results", [])
            if items:
                # take the first url reported
                first = items[0]
                url = first.get("url") or first.get("input") or f"https://{h}"
                alive_hosts.append(url)

        if not alive_hosts:
            # fallback: create https://host for hosts
            alive_hosts = [("https://" + h) if not h.startswith("http") else h for h in hosts[:10]]

        # limit nuclei targets to first 10
        for url in alive_hosts[:10]:
            nres = run_nuclei(url)
            nuclei_results[url] = nres
            combined["nuclei"] = nuclei_results
            write_progress(job_id, combined)

        # finalize
        combined["meta"]["status"] = "finished"
        combined["meta"]["finished_at"] = datetime.utcnow().isoformat() + "Z"
        write_progress(job_id, combined)

    except Exception as e:
        combined["meta"]["status"] = "error"
        combined["meta"]["error"] = str(e)
        write_progress(job_id, combined)

def enqueue_background_scan(targets: List[str]) -> str:
    job_id = uuid.uuid4().hex[:12]
    meta = {
        "job_id": job_id,
        "status": "queued",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "targets": targets
    }
    path = job_result_path(job_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta}, f, indent=2)

    t = threading.Thread(target=run_scan_job, args=(job_id, targets), daemon=True)
    t.start()
    return job_id
