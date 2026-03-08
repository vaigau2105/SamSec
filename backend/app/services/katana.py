# backend/app/services/katana.py
"""
Katana web crawler — discovers endpoints, forms, JS files, parameters.
Falls back to a basic Python crawler if katana is not installed.
"""
import subprocess
import json
import re
import requests
from urllib.parse import urljoin, urlparse
from typing import Dict, Any, List
from collections import deque


# ─────────────────────────────────────────────────────────────
#  Main entry
# ─────────────────────────────────────────────────────────────

def run_katana(target: str, timeout: int = 180) -> Dict[str, Any]:
    """
    Crawl target and return discovered URLs/endpoints.
    Tries katana (WSL) first, falls back to Python BFS crawler.
    """
    if not target.startswith("http"):
        target = f"http://{target}"

    # Try katana in WSL
    result = _run_katana_wsl(target, timeout)
    if result["urls"]:
        return result

    # Fallback: Python BFS crawler
    print("[katana] WSL katana not available — using Python crawler fallback")
    return _python_crawler(target, max_pages=60, timeout=timeout)


# ─────────────────────────────────────────────────────────────
#  Katana via WSL
# ─────────────────────────────────────────────────────────────

def _run_katana_wsl(target: str, timeout: int) -> Dict[str, Any]:
    cmd = [
        "wsl", "katana",
        "-u",          target,
        "-silent",
        "-jsonl",
        "-depth",      "3",
        "-js-crawl",              # crawl JS files too
        "-automatic-form-fill",   # fill forms to discover more
        "-timeout",    "10",
        "-rate-limit", "50",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out    = proc.stdout or ""
        stderr = proc.stderr or ""

        if "command not found" in stderr or "executable file not found" in stderr:
            return {"urls": [], "error": "katana not installed"}

        urls = []
        endpoints = []

        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                j   = json.loads(line)
                url = j.get("endpoint") or j.get("url") or j.get("request", {}).get("endpoint", "")
                if url:
                    urls.append(url)
                    endpoints.append({
                        "url":    url,
                        "method": j.get("request", {}).get("method", "GET"),
                        "source": "katana",
                    })
            except Exception:
                # Plain URL line
                if line.startswith("http"):
                    urls.append(line)
                    endpoints.append({"url": line, "method": "GET", "source": "katana"})

        return {
            "urls":      list(dict.fromkeys(urls)),
            "endpoints": endpoints,
            "source":    "katana-wsl",
            "count":     len(urls),
        }

    except subprocess.TimeoutExpired:
        return {"urls": [], "error": "timeout", "source": "katana-wsl"}
    except Exception as e:
        return {"urls": [], "error": str(e), "source": "katana-wsl"}


# ─────────────────────────────────────────────────────────────
#  Python BFS crawler fallback
# ─────────────────────────────────────────────────────────────

def _python_crawler(base_url: str, max_pages: int = 60, timeout: int = 120) -> Dict[str, Any]:
    """
    Basic BFS crawler — discovers links, forms, and API endpoints.
    Stays within the same origin.
    """
    parsed_base = urlparse(base_url)
    origin      = f"{parsed_base.scheme}://{parsed_base.netloc}"

    visited:   set  = set()
    queue:     deque = deque([base_url])
    urls:      List[str] = []
    endpoints: List[Dict] = []
    forms:     List[Dict] = []

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 SamSec-Scanner/2.0"

    _href_re  = re.compile(r'href=["\']([^"\']+)["\']', re.I)
    _src_re   = re.compile(r'src=["\']([^"\']+)["\']', re.I)
    _action_re = re.compile(r'action=["\']([^"\']*)["\']', re.I)
    _api_re   = re.compile(r'["\`](\/api\/[^\s"\'`<>]+)', re.I)

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=8, allow_redirects=True, verify=False)
            content_type = resp.headers.get("content-type", "")
            if "text/html" not in content_type and "javascript" not in content_type:
                continue

            body = resp.text
            urls.append(url)
            endpoints.append({"url": url, "method": "GET", "status": resp.status_code, "source": "python-crawler"})

            # Extract hrefs
            for href in _href_re.findall(body):
                full = urljoin(url, href).split("?")[0].split("#")[0]
                if full.startswith(origin) and full not in visited:
                    queue.append(full)

            # Extract src (JS files)
            for src in _src_re.findall(body):
                full = urljoin(url, src)
                if full.startswith(origin) and full.endswith(".js") and full not in visited:
                    queue.append(full)

            # Extract form actions
            for action in _action_re.findall(body):
                full = urljoin(url, action) if action else url
                forms.append({"action": full, "source_page": url})

            # Extract API endpoints from JS/HTML
            for api in _api_re.findall(body):
                full = urljoin(origin, api)
                if full not in urls:
                    urls.append(full)
                    endpoints.append({"url": full, "method": "GET", "source": "api-extract"})

        except Exception:
            continue

    return {
        "urls":      list(dict.fromkeys(urls)),
        "endpoints": endpoints,
        "forms":     forms,
        "source":    "python-crawler",
        "count":     len(urls),
    }
