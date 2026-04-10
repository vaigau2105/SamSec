# backend/app/services/httpx.py
import json
from typing import Dict, Any, List
from .tool_runner import run_tool_shell, run_tool


def run_httpx(hosts: List[str], timeout: int = 120) -> Dict[str, Any]:
    """Probe a list of hosts/URLs for liveness. Returns per-host results."""
    if not hosts:
        return {}

    # Normalise — keep full URLs, add http:// to bare hosts
    targets = [h if h.startswith("http") else f"http://{h}" for h in hosts]
    targets_input = "\n".join(targets)

    # Batch via stdin (one process for all hosts)
    out, err, rc = run_tool_shell(
        "httpx -silent -json -timeout 10 -no-color -follow-redirects",
        timeout=timeout,
        input_text=targets_input,
    )

    if out.strip() and "flag provided but not defined" not in err:
        return _parse_batch(out, hosts)

    # Fallback: per-host
    return _per_host(hosts, timeout)


def _parse_batch(out: str, original_hosts: List[str]) -> Dict[str, Any]:
    results = {h: {"results": [], "rc": 0} for h in original_hosts}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j   = json.loads(line)
            url = j.get("url") or j.get("input") or ""
            key = _match(url, original_hosts)
            if key:
                results[key]["results"].append(j)
            else:
                results[url] = {"results": [j], "rc": 0}
        except Exception:
            continue
    return results


def _match(url: str, hosts: List[str]) -> str:
    url_l = url.lower()
    for h in hosts:
        norm = h.lower().replace("https://", "").replace("http://", "").rstrip("/")
        if norm in url_l:
            return h
    return ""


def _per_host(hosts: List[str], timeout: int) -> Dict[str, Any]:
    results = {}
    for h in hosts:
        target = h if h.startswith("http") else f"http://{h}"
        out, err, rc = run_tool_shell(
            f"echo '{target}' | httpx -silent -json -timeout 10 -no-color -follow-redirects",
            timeout=timeout,
        )
        parsed = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed.append(json.loads(line))
            except Exception:
                continue
        results[h] = {"results": parsed, "raw": out, "rc": rc}
    return results