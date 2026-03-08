# backend/app/services/fingerprint.py
"""
Technology fingerprinting — detects frameworks, CMS, server software,
JavaScript libraries, security headers, and cookies.
Pure Python — no external tools required (uses HTTP headers + response body).
Also tries whatweb via WSL if available.
"""
import re
import subprocess
import json
import requests
from typing import Dict, Any, List
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────
#  Fingerprint signatures
# ─────────────────────────────────────────────────────────────

HEADER_SIGS: List[Dict] = [
    # Server
    {"header": "server",        "pattern": r"nginx",          "tech": "Nginx",          "category": "server"},
    {"header": "server",        "pattern": r"apache",         "tech": "Apache",         "category": "server"},
    {"header": "server",        "pattern": r"iis",            "tech": "IIS",            "category": "server"},
    {"header": "server",        "pattern": r"express",        "tech": "Express.js",     "category": "framework"},
    {"header": "server",        "pattern": r"gunicorn",       "tech": "Gunicorn",       "category": "server"},
    # Frameworks via headers
    {"header": "x-powered-by",  "pattern": r"php",            "tech": "PHP",            "category": "language"},
    {"header": "x-powered-by",  "pattern": r"asp\.net",       "tech": "ASP.NET",        "category": "framework"},
    {"header": "x-powered-by",  "pattern": r"express",        "tech": "Express.js",     "category": "framework"},
    {"header": "x-powered-by",  "pattern": r"next\.js",       "tech": "Next.js",        "category": "framework"},
    {"header": "x-generator",   "pattern": r"wordpress",      "tech": "WordPress",      "category": "cms"},
    {"header": "x-drupal",      "pattern": r".*",             "tech": "Drupal",         "category": "cms"},
]

BODY_SIGS: List[Dict] = [
    # CMS
    {"pattern": r"wp-content|wp-includes",               "tech": "WordPress",      "category": "cms"},
    {"pattern": r"Drupal\.settings|drupal\.js",          "tech": "Drupal",         "category": "cms"},
    {"pattern": r"Joomla!|joomla",                       "tech": "Joomla",         "category": "cms"},
    # JS Frameworks
    {"pattern": r"react(?:\.min)?\.js|__REACT",          "tech": "React",          "category": "js-framework"},
    {"pattern": r"angular(?:\.min)?\.js|ng-version",     "tech": "Angular",        "category": "js-framework"},
    {"pattern": r"vue(?:\.min)?\.js|Vue\.js",            "tech": "Vue.js",         "category": "js-framework"},
    {"pattern": r"jquery(?:\.min)?\.js",                 "tech": "jQuery",         "category": "js-library"},
    # Backend
    {"pattern": r"laravel_session|Laravel",              "tech": "Laravel",        "category": "framework"},
    {"pattern": r"django|csrfmiddlewaretoken",           "tech": "Django",         "category": "framework"},
    {"pattern": r"__NEXT_DATA__|_next/static",           "tech": "Next.js",        "category": "framework"},
    {"pattern": r"spring|springSecurityCheck",           "tech": "Spring",         "category": "framework"},
    # App identifiers
    {"pattern": r"OWASP Juice Shop",                     "tech": "OWASP Juice Shop","category": "app"},
    {"pattern": r"juice-shop|juiceshop",                 "tech": "OWASP Juice Shop","category": "app"},
    # Databases (error exposure)
    {"pattern": r"mysql_fetch|mysqli_",                  "tech": "MySQL (exposed)", "category": "database"},
    {"pattern": r"ORA-\d{5}",                            "tech": "Oracle DB (error exposed)", "category": "database"},
    {"pattern": r"Microsoft SQL Server",                 "tech": "MSSQL (error exposed)", "category": "database"},
]

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]


# ─────────────────────────────────────────────────────────────
#  Main entry
# ─────────────────────────────────────────────────────────────

def run_fingerprint(target: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Fingerprint a target URL. Returns tech stack, missing security headers,
    cookies analysis, and server info.
    """
    if not target.startswith("http"):
        target = f"http://{target}"

    technologies: List[Dict] = []
    missing_headers: List[str] = []
    present_headers: Dict[str, str] = {}
    cookies_info: List[Dict] = []
    server_info: str = ""

    try:
        session = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0 SamSec-Scanner/2.0"
        resp = session.get(target, timeout=timeout, allow_redirects=True, verify=False)

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        body          = resp.text[:50000]  # limit body scan

        # ── Header-based fingerprinting ──
        for sig in HEADER_SIGS:
            val = headers_lower.get(sig["header"], "")
            if val and re.search(sig["pattern"], val, re.I):
                _add_tech(technologies, sig["tech"], sig["category"])

        # ── Body-based fingerprinting ──
        for sig in BODY_SIGS:
            if re.search(sig["pattern"], body, re.I):
                _add_tech(technologies, sig["tech"], sig["category"])

        # ── Server header ──
        server_info = headers_lower.get("server", "") or headers_lower.get("x-powered-by", "")

        # ── Security header audit ──
        for h in SECURITY_HEADERS:
            if h in headers_lower:
                present_headers[h] = headers_lower[h]
            else:
                missing_headers.append(h)

        # ── Cookie security audit ──
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("missing SameSite flag")
            cookies_info.append({
                "name":   cookie.name,
                "issues": issues,
            })

    except requests.exceptions.SSLError:
        _add_tech(technologies, "SSL/TLS issue", "security")
    except Exception as e:
        pass

    # ── Whatweb via WSL (bonus if installed) ──
    whatweb_techs = _run_whatweb(target)
    for t in whatweb_techs:
        _add_tech(technologies, t, "whatweb")

    return {
        "technologies":      technologies,
        "server_info":       server_info,
        "missing_headers":   missing_headers,
        "present_headers":   present_headers,
        "cookies":           cookies_info,
        "tech_count":        len(technologies),
    }


# ─────────────────────────────────────────────────────────────
#  WhatWeb via WSL
# ─────────────────────────────────────────────────────────────

def _run_whatweb(target: str) -> List[str]:
    try:
        proc = subprocess.run(
            ["wsl", "whatweb", "--log-json=-", target],
            capture_output=True, text=True, timeout=30
        )
        out = proc.stdout or ""
        techs = []
        for line in out.splitlines():
            try:
                j = json.loads(line)
                plugins = j.get("plugins", {})
                for name in plugins:
                    techs.append(name)
            except Exception:
                continue
        return techs
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────
#  Helper
# ─────────────────────────────────────────────────────────────

def _add_tech(lst: List[Dict], tech: str, category: str):
    for item in lst:
        if item["tech"] == tech:
            return
    lst.append({"tech": tech, "category": category})
