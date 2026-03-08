# backend/app/services/httpx.py
import subprocess
import json
from typing import Dict, Any, List


def run_httpx(hosts: List[str], timeout: int = 120) -> Dict[str, Any]:
    """
    Run httpx in WSL against a list of hosts.
    FIX: newer httpx uses -u not -target, and -json is correct (not -jsonl).
         We pass all hosts via stdin with -l to avoid per-host subprocess overhead.
    """
    if not hosts:
        return {}

    # Build input list — ensure https:// scheme
    targets = []
    for h in hosts:
        targets.append(h if h.startswith("http") else f"https://{h}")

    # Pass all targets via stdin using echo | httpx
    targets_str = "\n".join(targets)

    # httpx reads from stdin with no -u flag when piped
    cmd = ["wsl", "bash", "-c", f"echo '{targets_str}' | httpx -silent -json -timeout 10 -no-color"]

    probe_results: Dict[str, Any] = {h: {"results": [], "rc": 0} for h in hosts}

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out    = proc.stdout or ""
        stderr = proc.stderr or ""

        # If stdin pipe method fails, fall back to per-host -u flag
        if proc.returncode != 0 or (not out.strip() and stderr):
            return _run_httpx_per_host(hosts, timeout)

        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                j   = json.loads(line)
                url = j.get("url") or j.get("input") or ""
                # Match back to original host key
                matched_host = _match_host(url, hosts)
                if matched_host:
                    probe_results[matched_host]["results"].append(j)
                    probe_results[matched_host]["rc"] = proc.returncode
            except Exception:
                continue

    except subprocess.TimeoutExpired:
        return _run_httpx_per_host(hosts, timeout)
    except Exception:
        return _run_httpx_per_host(hosts, timeout)

    return probe_results


def _match_host(url: str, hosts: List[str]) -> str:
    """Find which original host a httpx result URL belongs to."""
    url_lower = url.lower()
    for h in hosts:
        h_clean = h.replace("https://", "").replace("http://", "").rstrip("/")
        if h_clean in url_lower:
            return h
    return ""


def _run_httpx_per_host(hosts: List[str], timeout: int) -> Dict[str, Any]:
    """Fallback: call httpx once per host using -u flag."""
    probe_results = {}

    for h in hosts:
        target = h if h.startswith("http") else f"https://{h}"

        # Try -u flag (newer httpx), fall back to positional arg
        for cmd in [
            ["wsl", "httpx", "-u", target, "-silent", "-json", "-timeout", "10", "-no-color"],
            ["wsl", "httpx",       target, "-silent", "-json", "-timeout", "10", "-no-color"],
        ]:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                out    = proc.stdout or ""
                stderr = proc.stderr or ""

                if "unknown flag" in stderr.lower() or "flag provided but not defined" in stderr:
                    continue  # try next cmd variant

                parsed = []
                for line in out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parsed.append(json.loads(line))
                    except Exception:
                        continue

                probe_results[h] = {"results": parsed, "raw": out, "rc": proc.returncode}
                break  # success — stop trying variants

            except subprocess.TimeoutExpired:
                probe_results[h] = {"results": [], "rc": 124, "error": "timeout"}
                break
            except Exception as e:
                probe_results[h] = {"results": [], "rc": -1, "error": str(e)}
                break
        else:
            probe_results[h] = {"results": [], "rc": -2, "error": "httpx: no working flag variant found"}

    return probe_results