# backend/app/services/nuclei.py
import subprocess
import json
from typing import Dict, Any, List

def run_nuclei(target: str, timeout: int = 240) -> Dict[str, Any]:
    """
    Run nuclei in WSL against a single target URL. Default templates (fast).
    Returns list of parsed nuclei JSON lines.
    """
    cmd = ["wsl", "nuclei", "-u", target, "-silent", "-json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout or ""
        findings = []
        for line in out.splitlines():
            if not line.strip():
                continue
            try:
                j = json.loads(line)
                findings.append(j)
            except Exception:
                continue
        return {"results": findings, "raw": out, "rc": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"results": [], "raw": "", "rc": 124, "error": "timeout"}
    except Exception as e:
        return {"results": [], "raw": "", "rc": -1, "error": str(e)}
