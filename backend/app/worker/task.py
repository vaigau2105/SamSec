from app.services.scanner import run_nuclei_scan
import time

def scan_target_task(target: str):
    """
    This is the function the Redis Worker will run.
    It's the "job" itself.
    """
    print(f"WORKER: Starting scan on: {target}")
    try:
        # We call the *exact same service function* as before
        scan_output = run_nuclei_scan(target)
        
        # For now, we'll just print the output in the worker's terminal.
        # In the *next* step, we will save this 'scan_output' to our database.
        print(f"WORKER: Scan FINISHED for: {target}")
        print(scan_output)
        
        return scan_output
    
    except Exception as e:
        print(f"WORKER: Scan FAILED for: {target}")
        print(e)
        return str(e)