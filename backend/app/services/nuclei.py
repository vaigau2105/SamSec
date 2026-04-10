# backend/app/services/nuclei.py
import json
from typing import Dict, Any, List
from .tool_runner import run_tool

NUCLEI_TAGS = [
    "sqli", "xss", "ssrf", "xxe", "ssti", "lfi", "rfi", "idor",
    "open-redirect", "csrf", "auth-bypass", "default-login",
    "exposure", "misconfig", "config", "backup", "debug",
    "headers", "cors", "csp", "ssl", "tls", "cve", "panel",
    "injection", "rce", "command-injection",
]

NUCLEI_TEMPLATE_PATHS = [
    "vulnerabilities/", "exposures/", "misconfiguration/",
    "technologies/", "default-logins/", "cves/",
]


def run_nuclei(target: str, timeout: int = 400) -> Dict[str, Any]:
    """Run nuclei with broad OWASP + CVE tag coverage."""
    if not target.startswith("http"):
        target = f"http://{target}"

    json_flag = _detect_json_flag()
    results   = []
    raw_all   = ""

    # Tag-based run
    tags_str  = ",".join(NUCLEI_TAGS)
    out, err, rc = run_tool(
        "nuclei",
        ["-u", target, "-silent", json_flag,
         "-tags", tags_str,
         "-timeout", "10", "-retries", "2",
         "-rate-limit", "50", "-no-color"],
        timeout=timeout,
    )
    raw_all += out
    results.extend(_parse(out))

    # Fallback to template paths if tags gave nothing
    if not results:
        for tpath in NUCLEI_TEMPLATE_PATHS:
            out, err, rc = run_tool(
                "nuclei",
                ["-u", target, "-silent", json_flag,
                 "-t", tpath, "-timeout", "10", "-no-color"],
                timeout=min(timeout, 120),
            )
            raw_all += out
            results.extend(_parse(out))

    return {"results": results, "raw": raw_all, "rc": rc, "count": len(results)}


def _detect_json_flag() -> str:
    out, err, _ = run_tool("nuclei", ["--help"], timeout=10)
    help_text   = out + err
    return "-jsonl" if "jsonl" in help_text else "-json"


def _parse(text: str) -> List[Dict]:
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
            if isinstance(j, dict):
                items.append(j)
        except Exception:
            continue
    return items