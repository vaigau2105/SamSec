# backend/app/services/nuclei.py
import subprocess
import json
import shlex
from typing import Dict, Any, List

# ─────────────────────────────────────────────────────────────
#  Template tags to use — covers OWASP Top 10 + common CVEs
#  These are standard nuclei community template tags
# ─────────────────────────────────────────────────────────────
NUCLEI_TAGS = [
    # OWASP Top 10
    "sqli", "xss", "ssrf", "xxe", "ssti", "lfi", "rfi", "idor",
    "open-redirect", "csrf",
    # Auth & session
    "auth-bypass", "default-login", "weak-password",
    # Exposure & misconfig
    "exposure", "misconfig", "config", "backup",
    "debug", "logs", "error", "info-disclosure",
    # Headers & TLS
    "headers", "cors", "csp", "ssl", "tls",
    # Common CVEs & panels
    "cve", "panel", "login",
    # Injection
    "injection", "rce", "command-injection",
]

# Template categories as paths (used if tags don't work)
NUCLEI_TEMPLATE_PATHS = [
    "vulnerabilities/",
    "exposures/",
    "misconfiguration/",
    "technologies/",
    "default-logins/",
    "takeovers/",
    "cves/",
]


def run_nuclei(target: str, timeout: int = 400, use_tags: bool = True) -> Dict[str, Any]:
    """
    Run nuclei against a single target.
    - Auto-detects correct JSON output flag (-jsonl vs -json)
    - Uses broad OWASP+CVE tags for maximum vulnerability coverage
    - Falls back to template paths if tags produce no results
    """
    # Ensure scheme
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{target}"

    # Detect which JSON flag nuclei accepts
    json_flag = _detect_json_flag()

    results = []
    raw_all = ""

    if use_tags:
        # Run with all tags in one shot (faster than per-tag)
        tags_str = ",".join(NUCLEI_TAGS)
        cmd = _build_cmd(target, json_flag, extra=["-tags", tags_str])
        out, err, rc = _run_cmd(cmd, timeout)
        raw_all += out
        parsed = _parse_jsonl(out)
        results.extend(parsed)

        # If tags gave nothing, try template paths
        if not results:
            for tpath in NUCLEI_TEMPLATE_PATHS:
                cmd = _build_cmd(target, json_flag, extra=["-t", tpath])
                out, err, rc = _run_cmd(cmd, min(timeout, 120))
                raw_all += out
                results.extend(_parse_jsonl(out))

    else:
        # Plain run — nuclei default templates
        cmd = _build_cmd(target, json_flag)
        out, err, rc = _run_cmd(cmd, timeout)
        raw_all = out
        results = _parse_jsonl(out)

    return {
        "results": results,
        "raw":     raw_all,
        "rc":      0,
        "count":   len(results),
    }


# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────

def _detect_json_flag() -> str:
    """Probe nuclei to find which JSON flag it accepts."""
    for flag in ["-jsonl", "-json"]:
        try:
            probe = subprocess.run(
                ["wsl", "nuclei", "--help"],
                capture_output=True, text=True, timeout=10
            )
            help_text = probe.stdout + probe.stderr
            if flag.lstrip("-") in help_text:
                return flag
        except Exception:
            pass
    # Default to -jsonl (nuclei v3 standard)
    return "-jsonl"


def _build_cmd(target: str, json_flag: str, extra: List[str] = None) -> List[str]:
    cmd = [
        "wsl", "nuclei",
        "-u",       target,
        "-silent",
        json_flag,
        "-timeout", "10",          # per-request timeout (seconds)
        "-retries", "2",
        "-rate-limit", "50",       # requests/sec — safe for local targets
        "-no-color",
    ]
    if extra:
        cmd.extend(extra)
    return cmd


def _run_cmd(cmd: List[str], timeout: int):
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 124
    except Exception as e:
        return "", str(e), -1


def _parse_jsonl(text: str) -> List[Dict]:
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
            if isinstance(j, dict):
                results.append(j)
        except Exception:
            continue
    return results