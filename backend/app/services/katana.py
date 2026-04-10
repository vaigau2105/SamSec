# backend/app/services/katana.py
"""
Katana web crawler.
Tries katana binary first, falls back to pure Python BFS crawler.
"""
import json
import re
import requests
from urllib.parse import urljoin, urlparse
from typing import Dict, Any, List
from collections import deque
from .tool_runner import run_tool


def run_katana(target: str, timeout: int = 180) -> Dict[str, Any]:
    if not target.startswith("http"):
        target = f"http://{target}"

    result = _katana_binary(target, timeout)
    if result["urls"]:
        return result

    print("[katana] binary not found — using Python crawler")
    return _python_crawler(target, max_pages=60)


def _katana_binary(target: str, timeout: int) -> Dict[str, Any]:
    out, err, rc = run_tool(
        "katana",
        ["-u", target, "-silent", "-jsonl",
         "-depth", "3", "-js-crawl",
         "-timeout", "10", "-rate-limit", "50"],
        timeout=timeout,
    )

    if "not found" in err or "executable" in err:
        return {"urls": [], "error": "not installed"}

    urls, endpoints = [], []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j   = json.loads(line)
            url = j.get("endpoint") or j.get("url") or j.get("request", {}).get("endpoint", "")
            if url:
                urls.append(url)
                endpoints.append({"url": url, "method": j.get("request", {}).get("method", "GET"), "source": "katana"})
        except Exception:
            if line.startswith("http"):
                urls.append(line)
                endpoints.append({"url": line, "method": "GET", "source": "katana"})

    return {"urls": list(dict.fromkeys(urls)), "endpoints": endpoints, "source": "katana", "count": len(urls)}


def _python_crawler(base_url: str, max_pages: int = 60) -> Dict[str, Any]:
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    visited:   set   = set()
    queue:     deque = deque([base_url])
    urls:      List[str]  = []
    endpoints: List[Dict] = []
    forms:     List[Dict] = []

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 SamSec-Scanner/2.0"
    session.verify = False

    href_re   = re.compile(r'href=["\']([^"\']+)["\']', re.I)
    src_re    = re.compile(r'src=["\']([^"\']+)["\']', re.I)
    action_re = re.compile(r'action=["\']([^"\']*)["\']', re.I)
    api_re    = re.compile(r'["\`](\/api\/[^\s"\'`<>]+)', re.I)

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=8, allow_redirects=True)
            ct   = resp.headers.get("content-type", "")
            if "text/html" not in ct and "javascript" not in ct:
                continue

            body = resp.text
            urls.append(url)
            endpoints.append({"url": url, "method": "GET", "status": resp.status_code, "source": "python-crawler"})

            for href in href_re.findall(body):
                full = urljoin(url, href).split("?")[0].split("#")[0]
                if full.startswith(origin) and full not in visited:
                    queue.append(full)

            for src in src_re.findall(body):
                full = urljoin(url, src)
                if full.startswith(origin) and full.endswith(".js") and full not in visited:
                    queue.append(full)

            for action in action_re.findall(body):
                full = urljoin(url, action) if action else url
                forms.append({"action": full, "source_page": url})

            for api in api_re.findall(body):
                full = urljoin(origin, api)
                if full not in urls:
                    urls.append(full)
                    endpoints.append({"url": full, "method": "GET", "source": "api-extract"})

        except Exception:
            continue

    return {"urls": list(dict.fromkeys(urls)), "endpoints": endpoints,
            "forms": forms, "source": "python-crawler", "count": len(urls)}