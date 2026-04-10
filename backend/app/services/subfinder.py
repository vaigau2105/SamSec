# backend/app/services/subfinder.py
import json
from typing import Dict, Any, List
from .tool_runner import run_tool


def run_subfinder(domain: str, timeout: int = 180) -> Dict[str, Any]:
    """Subdomain enumeration via subfinder."""
    out, err, rc = run_tool(
        "subfinder",
        ["-d", domain, "-silent", "-json"],
        timeout=timeout,
    )

    results: List[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j    = json.loads(line)
            host = j.get("host") or j.get("subdomain") or j.get("name") or j.get("domain")
            if host:
                results.append(host)
        except Exception:
            if line and "." in line:
                results.append(line)

    results = list(dict.fromkeys(results))  # dedupe, preserve order

    return {"results": results, "raw": out, "rc": rc}