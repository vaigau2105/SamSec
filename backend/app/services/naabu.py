# backend/app/services/naabu.py
import subprocess
import json
from typing import Dict, Any, List
from urllib.parse import urlparse


def run_naabu(hosts: List[str], timeout: int = 180) -> Dict[str, Any]:
    """
    Run naabu in WSL for a list of hosts.
    - Strips scheme/port before passing to naabu (it takes bare hostnames)
    - Skips localhost/127.x (naabu can't scan loopback from WSL)
    - Returns consistent schema: { host: { results: [...], ports: [...] } }
    """
    results = {}

    for h in hosts:
        # Parse and clean the host
        parsed    = urlparse(h if "://" in h else f"http://{h}")
        hostname  = parsed.hostname or h
        orig_port = parsed.port

        # Skip loopback — naabu inside WSL can't scan Windows localhost
        if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            results[h] = {
                "results": [{"host": hostname, "port": orig_port, "service": ""}] if orig_port else [],
                "ports":   [orig_port] if orig_port else [],
                "skipped": True,
                "reason":  "localhost — port recorded from URL",
            }
            continue

        cmd = [
            "wsl", "naabu",
            "-host",      hostname,
            "-top-ports", "1000",
            "-silent",
            "-json",
            "-timeout",   "10",
            "-rate",      "1000",
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out    = proc.stdout or ""
            stderr = proc.stderr or ""

            port_entries  = []
            port_numbers  = []

            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    j    = json.loads(line)
                    port = j.get("port") or j.get("Port")
                    if port is not None:
                        entry = {
                            "host":    j.get("ip") or j.get("host") or hostname,
                            "port":    int(port),
                            "service": j.get("service") or "",
                        }
                        port_entries.append(entry)
                        port_numbers.append(int(port))
                except Exception:
                    continue

            results[h] = {
                "results": port_entries,
                "ports":   list(dict.fromkeys(port_numbers)),
                "raw":     out,
                "rc":      proc.returncode,
            }

        except subprocess.TimeoutExpired:
            results[h] = {"results": [], "ports": [], "rc": 124, "error": "timeout"}
        except Exception as e:
            results[h] = {"results": [], "ports": [], "rc": -1, "error": str(e)}

    return results