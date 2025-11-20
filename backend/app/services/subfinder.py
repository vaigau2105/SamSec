# backend/app/services/subfinder.py
import subprocess
import json
from typing import Dict, Any, List

def run_subfinder(domain: str, timeout: int = 180) -> Dict[str, Any]:
    """
    Run subfinder in WSL (fast mode). Returns dict with 'results' (list of host strings)
    and raw stdout.
    """
    cmd = ["wsl", "subfinder", "-d", domain, "-silent", "-json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout or ""
        results: List[str] = []
        for line in out.splitlines():
            if not line.strip():
                continue
            try:
                j = json.loads(line)
                host = j.get("host") or j.get("subdomain") or j.get("name") or j.get("domain")
                if host:
                    results.append(host)
            except Exception:
                results.append(line.strip())
        # dedupe
        results = list(dict.fromkeys(results))
        return {"results": results, "raw": out, "rc": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"results": [], "raw": "", "rc": 124, "error": "timeout"}
    except Exception as e:
        return {"results": [], "raw": "", "rc": -1, "error": str(e)}
