from rq import Queue
from redis import Redis
from app.core.config import settings
from app.worker.task import run_scan_job

# Connect to Redis
redis_conn = Redis.from_url(settings.REDIS_URL)

# Create queue
queue = Queue("scans", connection=redis_conn)

def enqueue_scan(scan_id: int, payload: dict):
    """
    Enqueue a scan job into Redis-RQ.
    """
    job = queue.enqueue(run_scan_job, scan_id, payload)
    return job.id
