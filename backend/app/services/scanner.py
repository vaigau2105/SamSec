# backend/app/services/scanner.py
"""
SamSec Full Scan Pipeline — v3
New tool chain:
  1. Recon        → subfinder (remote) or direct (local/IP)
  2. Fingerprint  → detect tech stack, headers, cookies
  3. Crawl        → katana / Python BFS crawler
  4. Nuclei       → template-based vuln scan (OWASP tags + CVEs)
  5. Active scan  → pure Python: SQLi, XSS, IDOR, CORS, JWT, headers...
  6. DNS          → samdns (remote only)
"""

import asyncio
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from .subfinder      import run_subfinder
from .httpx          import run_httpx
from .naabu          import run_naabu
from .nuclei         import run_nuclei
from .katana         import run_katana
from .fingerprint    import run_fingerprint
from .active_scanner import run_active_scan
from backend.app.tools.samdns import samdns_scan


# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────

def _is_local(target: str) -> bool:
    parsed   = urlparse(target if "://" in target else f"http://{target}")
    host     = parsed.hostname or ""
    port     = parsed.port
    local_re = re.compile(
        r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|::1)"
    )
    return bool(local_re.match(host)) or (port is not None and port not in (80, 443))


def _ensure_scheme(target: str) -> str:
    return target if "://" in target else f"http://{target}"


def _strip_scheme(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").rstrip("/")


def _severity_count(findings: List[Dict]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get("severity", "Info").capitalize()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _default_remediation(severity: str) -> str:
    m = {
        "critical": "Patch immediately. Isolate affected systems.",
        "high":     "Apply patches within 24-72 hours.",
        "medium":   "Schedule fix in next sprint.",
        "low":      "Address in next maintenance window.",
        "info":     "Review for context.",
    }
    return m.get(str(severity).lower(), m["info"])


def _normalise_nuclei(raw: List[Dict], fallback_url: str) -> List[Dict]:
    out = []
    for v in raw:
        if not isinstance(v, dict):
            continue
        info           = v.get("info", {}) if isinstance(v.get("info"), dict) else {}
        classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
        cve_ids        = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        out.append({
            "name":        info.get("name") or v.get("name") or v.get("template-id") or "Unknown",
            "severity":    (info.get("severity") or v.get("severity") or "info").capitalize(),
            "description": info.get("description") or v.get("description") or "",
            "cve_ids":     cve_ids,
            "remediation": info.get("remediation") or info.get("fix") or _default_remediation(info.get("severity") or "info"),
            "target":      v.get("host") or v.get("matched-at") or fallback_url,
            "template_id": v.get("template-id") or "",
            "tags":        info.get("tags") or [],
            "references":  info.get("reference") or [],
            "cvss_score":  classification.get("cvss-score"),
            "source":      "nuclei",
        })
    return out


# ─────────────────────────────────────────────────────────────
#  Main scanner
# ─────────────────────────────────────────────────────────────

def run_full_scan(domain: str) -> Dict[str, Any]:
    target_url  = _ensure_scheme(domain)
    is_local    = _is_local(target_url)
    domain_host = _strip_scheme(target_url).split(":")[0]

    print(f"\n{'='*55}")
    print(f"[SamSec] Target : {target_url}  (local={is_local})")
    print(f"{'='*55}\n")

    subdomains:   List[str]  = []
    alive_hosts:  List[str]  = []
    open_ports:   List[Dict] = []
    dns_data:     Dict       = {}
    all_findings: List[Dict] = []

    # ── STEP 1: RECON ──────────────────────────────────────────
    print("[1/6] Recon...")
    if is_local:
        subdomains  = [domain_host]
        alive_hosts = [target_url]
        parsed      = urlparse(target_url)
        if parsed.port:
            open_ports = [{"host": parsed.hostname, "port": parsed.port, "service": ""}]
        print("    Local target — skipping subfinder/naabu")
    else:
        sub_result = run_subfinder(domain_host)
        subdomains = sub_result.get("results", [])
        if domain_host not in subdomains:
            subdomains.insert(0, domain_host)
        subdomains = list(dict.fromkeys(subdomains))[:30]
        print(f"    Subdomains: {len(subdomains)}")

        httpx_result = run_httpx(subdomains)
        alive_hosts  = [h for h, d in httpx_result.items() if d.get("results")]
        if not alive_hosts:
            alive_hosts = [target_url]
        print(f"    Alive hosts: {len(alive_hosts)}")

        naabu_result = run_naabu(alive_hosts[:10])
        for h, d in naabu_result.items():
            open_ports.extend(d.get("results", []))

    # ── STEP 2: FINGERPRINT ────────────────────────────────────
    print("[2/6] Fingerprinting...")
    fp_result = run_fingerprint(target_url)
    techs     = fp_result.get("technologies", [])
    print(f"    Technologies detected: {[t['tech'] for t in techs]}")

    # Convert missing headers + cookie issues → findings
    for header in fp_result.get("missing_headers", []):
        sev = "Medium" if header in (
            "content-security-policy", "strict-transport-security", "x-frame-options"
        ) else "Low"
        all_findings.append({
            "name":        f"Missing Security Header: {header}",
            "severity":    sev,
            "description": f"The HTTP response is missing the {header} security header.",
            "remediation": f"Configure your web server to send the {header} header.",
            "target":      target_url,
            "cve_ids":     [],
            "source":      "fingerprint",
        })

    for cookie in fp_result.get("cookies", []):
        if cookie.get("issues"):
            all_findings.append({
                "name":        f"Insecure Cookie: {cookie['name']}",
                "severity":    "Medium",
                "description": f"Cookie '{cookie['name']}' is missing: {', '.join(cookie['issues'])}.",
                "remediation": "Set Secure, HttpOnly, and SameSite=Strict on all session cookies.",
                "target":      target_url,
                "cve_ids":     ["CWE-614"],
                "source":      "fingerprint",
            })

    # ── STEP 3: CRAWL ──────────────────────────────────────────
    print("[3/6] Crawling...")
    crawl_result = run_katana(target_url)
    crawled_urls = crawl_result.get("urls", [])
    print(f"    URLs discovered: {len(crawled_urls)}")

    # ── STEP 4: NUCLEI ─────────────────────────────────────────
    print("[4/6] Nuclei template scan...")
    nuclei_targets = list(dict.fromkeys(
        [target_url] + [u for u in crawled_urls if u.startswith(target_url)][:5]
    ))[:6]

    for url in nuclei_targets:
        print(f"    → {url}")
        nuk        = run_nuclei(url)
        normalised = _normalise_nuclei(nuk.get("results", []), url)
        all_findings.extend(normalised)
        if normalised:
            print(f"    ← {len(normalised)} findings")

    # ── STEP 5: ACTIVE SCAN ────────────────────────────────────
    print("[5/6] Active checks (SQLi / XSS / IDOR / CORS / JWT / headers)...")
    active = run_active_scan(target_url, crawl_urls=crawled_urls)
    active_findings = active.get("findings", [])
    all_findings.extend(active_findings)
    print(f"    Active findings: {len(active_findings)}")

    # ── STEP 6: DNS ────────────────────────────────────────────
    if not is_local:
        print("[6/6] DNS recon...")
        try:
            dns_data = asyncio.run(samdns_scan(domain_host))
        except Exception as e:
            print(f"    DNS error: {e}")
    else:
        print("[6/6] Skipping DNS (local target)")

    # ── Deduplication ──────────────────────────────────────────
    seen, deduped = set(), []
    for f in all_findings:
        key = (f.get("name", ""), f.get("target", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    summary = _severity_count(deduped)
    print(f"\n[SamSec] Done — {len(deduped)} findings | "
          f"C={summary['Critical']} H={summary['High']} M={summary['Medium']} "
          f"L={summary['Low']} I={summary['Info']}\n")

    return {
        "subdomains":      subdomains,
        "alive_hosts":     alive_hosts,
        "open_ports":      open_ports,
        "dns_data":        dns_data,
        "technologies":    techs,
        "vulnerabilities": deduped,
        "summary":         summary,
    }