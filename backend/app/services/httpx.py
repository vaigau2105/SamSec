# backend/app/services/httpx.py
import subprocess
import json
from typing import Dict, Any, List

def run_httpx(hosts: List[str], timeout: int = 120) -> Dict[str, Any]:
    """
    Run httpx in WSL against a list of hosts (fast probe).
    Returns mapping host -> probe info (status_code, url, title etc).
    """
    # httpx supports reading from stdin list using -l, but here we call per host to keep parsing simple.
    probe_results = {}
    for h in hosts:
        # ensure scheme (httpx accepts host or url)
        target = h if h.startswith("http") else f"https://{h}"
        cmd = ["wsl", "httpx", "-silent", "-json", "-timeout", "10", "-u", target]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = proc.stdout or ""
            parsed = []
            for line in out.splitlines():
                if not line.strip():
                    continue
                try:
                    j = json.loads(line)
                    parsed.append(j)
                except Exception:
                    continue
            probe_results[h] = {"results": parsed, "raw": out, "rc": proc.returncode}
        except subprocess.TimeoutExpired:
            probe_results[h] = {"results": [], "raw": "", "rc": 124, "error": "timeout"}
        except Exception as e:
            probe_results[h] = {"results": [], "raw": "", "rc": -1, "error": str(e)}
    return probe_results
