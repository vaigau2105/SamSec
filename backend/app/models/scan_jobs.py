import uuid
import json
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

def enqueue_background_scan(targets: list):
    """
    Fake scan that generates a demo report.
    """
    job_id = str(uuid.uuid4())

    report = {
        "job_id": job_id,
        "targets": targets,
        "status": "completed",
        "timestamp": datetime.utcnow().isoformat(),
        "findings": [
            {
                "severity": "high",
                "description": "Fake SQL Injection vulnerability",
                "target": targets[0]
            },
            {
                "severity": "medium",
                "description": "Fake Reflected XSS",
                "target": targets[0]
            }
        ]
    }

from backend.app.services.report_builder import generate_pdf_report

def enqueue_background_scan(targets: list):
    job_id = str(uuid.uuid4())

    report = {
        "job_id": job_id,
        "targets": targets,
        "status": "completed",
        "timestamp": datetime.utcnow().isoformat(),
        "findings": [
            {"severity": "high", "description": "Fake SQL Injection vulnerability", "target": targets[0]},
            {"severity": "medium", "description": "Fake Reflected XSS", "target": targets[0]}
        ]
    }

    generate_pdf_report(job_id, report)

    return job_id
