from fastapi import APIRouter, HTTPException
from app.schemas.scan import ScanRequest, ScanResponse


# --- NEW IMPORTS ---
import redis
from rq import Queue
# ---------------------

# APIRouter is like a "mini-FastAPI" app
router = APIRouter()

# --- NEW: Connect to Redis ---
# This connects to the Redis server we started with Docker
redis_conn = redis.Redis(host='localhost', port=6379)
# Create a "queue" on that server. We can name it 'default'
q = Queue(connection=redis_conn)
# -----------------------------


@router.post("/scan-target", response_model=ScanResponse)
async def scan_target_endpoint(request: ScanRequest):
    """
    This endpoint NO LONGER runs the scan.
    It now ADDS THE JOB to the Redis queue.
    """
    try:
        target_to_scan = request.target
        
        # --- THIS IS THE CORE CHANGE ---
        # Instead of calling run_nuclei_scan...
        # We call queue.enqueue()
        # 1st arg: The function to run (as a string)
        # 2nd arg: The arguments for that function
        job = q.enqueue("app.worker.tasks.scan_target_task", target_to_scan)
        # -----------------------------

        # Return a "pending" response immediately
        return ScanResponse(
            status="pending",
            message="Scan successfully queued.",
            scan_id=job.id  # <-- We return the Job ID!
        )

    except Exception as e:
        # Catch-all for other unexpected errors
        raise HTTPException(status_code=500, detail=str(e))