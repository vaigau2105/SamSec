# backend/app/services/naabu.py
import json
from typing import Dict, Any, List
from urllib.parse import urlparse
from .tool_runner import run_tool


def run_naabu(hosts: List[str], timeout: int = 180) -> Dict[str, Any]:
    """Port scan a list of hosts. Skips loopback (Docker can't reach Windows localhost)."""
    results = {}

    for h in hosts:
        parsed   = urlparse(h if "://" in h else f"http://{h}")
        hostname = parsed.hostname or h
        port     = parsed.port

        # Skip loopback
        if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            results[h] = {
                "results": [{"host": hostname, "port": port, "service": ""}] if port else [],
                "ports":   [port] if port else [],
                "skipped": True,
            }
            continue

        out, err, rc = run_tool(
            "naabu",
            ["-host", hostname, "-top-ports", "1000", "-silent", "-json",
             "-timeout", "10", "-rate", "1000"],
            timeout=timeout,
        )

        entries = []
        ports   = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                j    = json.loads(line)
                p    = j.get("port") or j.get("Port")
                if p is not None:
                    entries.append({"host": j.get("ip") or hostname, "port": int(p), "service": j.get("service", "")})
                    ports.append(int(p))
            except Exception:
                continue

        results[h] = {"results": entries, "ports": list(dict.fromkeys(ports)), "rc": rc}

    return results