import redis
from rq import Worker, Queue, Connection
from app.core.database import SessionLocal
from backend.app.models.scan_jobs import Scan 

# Define which queues this worker should listen to
listen = ['default']

# Connect to the same Redis server
redis_conn = redis.Redis(host='localhost', port=6379)

def run_scan_job(scan_id: int, scan_payload: dict):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        scan.status = "running"
        db.commit()

        domain = scan_payload["targets"][0]

        # 1) Run Subfinder
        subfinder = _get_tool_instance("subfinder")
        subdomains = subfinder.run(domain)

        # Pick one found subdomain (or fallback to domain)
        target_for_nuclei = (
            subdomains["results"][0]["host"]
            if subdomains["results"]
            else domain
        )

        # 2) Run Nuclei
        nuclei = _get_tool_instance("nuclei")
        nuclei_results = nuclei.run(target_for_nuclei)

        scan.raw_results = {
            "subfinder": subdomains,
            "nuclei": nuclei_results
        }
        scan.result_summary = {
            "subdomains_found": len(subdomains["results"]),
            "vulnerabilities_found": len(nuclei_results["results"])
        }
        scan.status = "finished"
        db.commit()

    except Exception as e:
        scan.status = "error"
        db.commit()
        raise e

    finally:
        db.close()

TOOL_REGISTRY = {
    "subfinder": "app.services.subfinder:SubfinderTool",
    "nuclei": "app.services.nuclei:NucleiTool",
}
import importlib

def _get_tool_instance(path: str):
    module_path, class_name = path.split(":")
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls("/tmp/samsec")
