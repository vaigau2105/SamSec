# backend/app/services/naabu.py
import subprocess
import json
from typing import Dict, Any, List

def run_naabu(hosts: List[str], timeout: int = 180) -> Dict[str, Any]:
    """
    Run naabu in WSL for a list of hosts (fast). Returns mapping host -> list of ports found.
    """
    results = {}
    for h in hosts:
        cmd = ["wsl", "naabu", "-silent", "-json", "-host", h]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = proc.stdout or ""
            ports = []
            for line in out.splitlines():
                if not line.strip():
                    continue
                try:
                    j = json.loads(line)
                    port = j.get("port") or j.get("Port")
                    if port is not None:
                        ports.append(port)
                except Exception:
                    continue
            results[h] = {"ports": list(dict.fromkeys(ports)), "raw": out, "rc": proc.returncode}
        except subprocess.TimeoutExpired:
            results[h] = {"ports": [], "raw": "", "rc": 124, "error": "timeout"}
        except Exception as e:
            results[h] = {"ports": [], "raw": "", "rc": -1, "error": str(e)}
    return results
