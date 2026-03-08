# backend/app/services/active_scanner.py
"""
SamSec Active Scanner — pure Python vulnerability checks.
Covers OWASP Top 10 without needing external tools.
Designed to find real bugs in web apps like OWASP Juice Shop.
"""
import re
import requests
import urllib3
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, quote
from typing import Dict, Any, List, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────
#  Finding builder
# ─────────────────────────────────────────────────────────────

def _finding(name: str, severity: str, url: str, description: str,
             remediation: str, evidence: str = "", cve_ids: List[str] = None) -> Dict:
    return {
        "name":        name,
        "severity":    severity,
        "target":      url,
        "description": description,
        "remediation": remediation,
        "evidence":    evidence,
        "cve_ids":     cve_ids or [],
        "source":      "active-scanner",
    }


# ─────────────────────────────────────────────────────────────
#  Session factory
# ─────────────────────────────────────────────────────────────

def _session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 SamSec-Scanner/2.0"
    s.verify = False
    return s


# ─────────────────────────────────────────────────────────────
#  Main entry
# ─────────────────────────────────────────────────────────────

def run_active_scan(target: str, crawl_urls: List[str] = None, timeout: int = 8) -> Dict[str, Any]:
    """
    Run all active checks against target and its discovered URLs.
    Returns list of vulnerability findings.
    """
    if not target.startswith("http"):
        target = f"http://{target}"

    urls_to_test = list(dict.fromkeys([target] + (crawl_urls or [])))
    findings: List[Dict] = []

    s = _session()

    for url in urls_to_test[:50]:  # cap at 50 URLs
        try:
            # ── Passive checks (no payload, just observe) ──
            findings += _check_security_headers(url, s, timeout)
            findings += _check_sensitive_exposure(url, s, timeout)

            # ── Active checks (send payloads) ──
            findings += _check_sqli(url, s, timeout)
            findings += _check_xss_reflected(url, s, timeout)
            findings += _check_open_redirect(url, s, timeout)
            findings += _check_idor(url, s, timeout)

        except Exception:
            continue

    # ── Target-level checks (run once) ──
    findings += _check_cors(target, s, timeout)
    findings += _check_csrf(target, s, timeout)
    findings += _check_directory_listing(target, s, timeout)
    findings += _check_default_credentials(target, s, timeout)
    findings += _check_jwt_issues(target, s, timeout)
    findings += _check_ssrf_indicators(target, crawl_urls or [], s, timeout)

    # Deduplicate by (name + url)
    seen = set()
    unique = []
    for f in findings:
        key = (f["name"], f["target"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {
        "findings": unique,
        "count":    len(unique),
    }


# ─────────────────────────────────────────────────────────────
#  Security Header Checks
# ─────────────────────────────────────────────────────────────

REQUIRED_HEADERS = {
    "strict-transport-security": ("Missing HSTS Header", "Medium",
        "The Strict-Transport-Security header is not set, allowing downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "x-frame-options": ("Missing X-Frame-Options", "Medium",
        "Page can be embedded in iframes, enabling clickjacking attacks.",
        "Add: X-Frame-Options: DENY or SAMEORIGIN"),
    "x-content-type-options": ("Missing X-Content-Type-Options", "Low",
        "Browser may MIME-sniff responses, enabling content injection.",
        "Add: X-Content-Type-Options: nosniff"),
    "content-security-policy": ("Missing Content-Security-Policy", "Medium",
        "No CSP header detected, increasing XSS attack surface.",
        "Implement a restrictive Content-Security-Policy header."),
    "referrer-policy": ("Missing Referrer-Policy", "Low",
        "Browser may leak URL data in Referer headers.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin"),
}

def _check_security_headers(url: str, s: requests.Session, timeout: int) -> List[Dict]:
    findings = []
    try:
        resp    = s.get(url, timeout=timeout, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for header, (name, sev, desc, fix) in REQUIRED_HEADERS.items():
            if header not in headers:
                findings.append(_finding(name, sev, url, desc, fix))
    except Exception:
        pass
    return findings


# ─────────────────────────────────────────────────────────────
#  Sensitive Information Exposure
# ─────────────────────────────────────────────────────────────

SENSITIVE_PATTERNS = [
    (r"password\s*[:=]\s*['\"]?\w+",         "Password in Response",           "High"),
    (r"api[_\-]?key\s*[:=]\s*['\"]?[\w\-]+", "API Key Exposure",               "High"),
    (r"secret\s*[:=]\s*['\"]?[\w\-]+",        "Secret Exposure",                "High"),
    (r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
                                               "JWT Token in Response",         "Medium"),
    (r"-----BEGIN (?:RSA )?PRIVATE KEY",       "Private Key Exposure",          "Critical"),
    (r"mysql_fetch|mysqli_connect|pg_connect", "Database Error Disclosure",     "High"),
    (r"ORA-\d{5}|Microsoft OLE DB",            "Database Error Disclosure",     "High"),
    (r"stack trace|at [\w\.]+\([\w\.]+:\d+\)", "Stack Trace Disclosure",        "Medium"),
    (r"<b>Warning</b>.*PHP",                   "PHP Error Disclosure",          "Medium"),
]

def _check_sensitive_exposure(url: str, s: requests.Session, timeout: int) -> List[Dict]:
    findings = []
    try:
        resp = s.get(url, timeout=timeout, allow_redirects=True)
        body = resp.text[:30000]
        for pattern, name, sev in SENSITIVE_PATTERNS:
            m = re.search(pattern, body, re.I)
            if m:
                findings.append(_finding(
                    name, sev, url,
                    f"Sensitive data pattern found in response: {m.group(0)[:80]}",
                    "Remove sensitive data from HTTP responses. Use environment variables for secrets.",
                    evidence=m.group(0)[:120],
                ))
    except Exception:
        pass
    return findings


# ─────────────────────────────────────────────────────────────
#  SQL Injection
# ─────────────────────────────────────────────────────────────

SQLI_PAYLOADS = ["'", "''", "`", "1' OR '1'='1", "1 OR 1=1", "' OR 1=1--", "'; DROP TABLE--"]
SQLI_ERRORS = [
    r"sql syntax.*mysql", r"warning.*mysql_", r"unclosed quotation mark",
    r"quoted string not properly terminated", r"you have an error in your sql",
    r"ora-\d{5}", r"microsoft ole db", r"odbc.*driver", r"sqlite.*error",
    r"postgresql.*error", r"pg_query\(\)", r"syntax error.*near",
]

def _check_sqli(url: str, s: requests.Session, timeout: int) -> List[Dict]:
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query)
    if not params:
        return []

    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = {**{k: v[0] for k, v in params.items()}, param: payload}
            test_url    = url.split("?")[0] + "?" + urlencode(test_params)
            try:
                resp = s.get(test_url, timeout=timeout, allow_redirects=True)
                body = resp.text.lower()
                for pattern in SQLI_ERRORS:
                    if re.search(pattern, body, re.I):
                        findings.append(_finding(
                            "SQL Injection", "Critical", url,
                            f"SQL error triggered in parameter '{param}' with payload: {payload}",
                            "Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
                            evidence=f"Param: {param}, Payload: {payload}",
                            cve_ids=["CWE-89"],
                        ))
                        return findings  # one confirmed finding is enough
            except Exception:
                continue
    return findings


# ─────────────────────────────────────────────────────────────
#  Reflected XSS
# ─────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'><svg onload=alert(1)>",
]

def _check_xss_reflected(url: str, s: requests.Session, timeout: int) -> List[Dict]:
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query)
    if not params:
        return []

    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = {**{k: v[0] for k, v in params.items()}, param: payload}
            test_url    = url.split("?")[0] + "?" + urlencode(test_params)
            try:
                resp = s.get(test_url, timeout=timeout, allow_redirects=True)
                if payload.lower() in resp.text.lower():
                    # Check CSP — if present, XSS may be blocked
                    has_csp = "content-security-policy" in {k.lower() for k in resp.headers}
                    sev     = "High" if not has_csp else "Medium"
                    findings.append(_finding(
                        "Reflected XSS", sev, url,
                        f"Payload reflected unencoded in parameter '{param}'",
                        "HTML-encode all user-supplied output. Implement Content-Security-Policy.",
                        evidence=f"Param: {param}, Payload reflected: {payload[:60]}",
                        cve_ids=["CWE-79"],
                    ))
                    return findings
            except Exception:
                continue
    return findings


# ─────────────────────────────────────────────────────────────
#  Open Redirect
# ─────────────────────────────────────────────────────────────

REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "goto", "dest", "destination", "redir", "redirect_uri"]
REDIRECT_PAYLOAD = "https://evil.example.com"

def _check_open_redirect(url: str, s: requests.Session, timeout: int) -> List[Dict]:
    findings = []
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query)

    for param in list(params.keys()) + REDIRECT_PARAMS:
        test_params = {**{k: v[0] for k, v in params.items()}, param: REDIRECT_PAYLOAD}
        test_url    = url.split("?")[0] + "?" + urlencode(test_params)
        try:
            resp = s.get(test_url, timeout=timeout, allow_redirects=False)
            location = resp.headers.get("Location", "")
            if REDIRECT_PAYLOAD in location or "evil.example.com" in location:
                findings.append(_finding(
                    "Open Redirect", "Medium", url,
                    f"Parameter '{param}' causes redirect to external attacker-controlled URL.",
                    "Validate redirect destinations against an allowlist of trusted URLs.",
                    evidence=f"Location: {location}",
                    cve_ids=["CWE-601"],
                ))
                break
        except Exception:
            continue
    return findings


# ─────────────────────────────────────────────────────────────
#  CORS Misconfiguration
# ─────────────────────────────────────────────────────────────

def _check_cors(target: str, s: requests.Session, timeout: int) -> List[Dict]:
    findings = []
    try:
        resp = s.get(target, timeout=timeout,
                     headers={"Origin": "https://evil.example.com"}, allow_redirects=True)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            findings.append(_finding(
                "CORS Wildcard", "Medium", target,
                "Access-Control-Allow-Origin: * allows any origin to read responses.",
                "Restrict CORS to trusted origins. Never use wildcard with credentials.",
                evidence=f"ACAO: {acao}",
            ))
        elif "evil.example.com" in acao and acac.lower() == "true":
            findings.append(_finding(
                "CORS Misconfiguration — Origin Reflection + Credentials", "High", target,
                "Server reflects arbitrary Origin header and allows credentials. Attacker can read authenticated responses.",
                "Validate Origin against a strict allowlist. Never combine wildcard/reflection with Allow-Credentials: true.",
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                cve_ids=["CWE-942"],
            ))
        elif "evil.example.com" in acao:
            findings.append(_finding(
                "CORS Origin Reflection", "Medium", target,
                "Server reflects the supplied Origin header, potentially allowing cross-origin reads.",
                "Validate Origin against a strict allowlist of trusted domains.",
                evidence=f"ACAO: {acao}",
            ))
    except Exception:
        pass
    return findings


# ─────────────────────────────────────────────────────────────
#  CSRF Detection
# ─────────────────────────────────────────────────────────────

def _check_csrf(target: str, s: requests.Session, timeout: int) -> List[Dict]:
    findings = []
    try:
        resp = s.get(target, timeout=timeout, allow_redirects=True)
        body = resp.text.lower()
        # Look for forms without CSRF token
        forms     = re.findall(r"<form[^>]*>(.*?)</form>", body, re.I | re.S)
        csrf_keys = ["csrf", "token", "_token", "authenticity_token", "nonce"]
        for form in forms:
            has_csrf = any(k in form.lower() for k in csrf_keys)
            if not has_csrf and ("method" in form.lower()):
                findings.append(_finding(
                    "Potential CSRF — Missing Token in Form", "Medium", target,
                    "A form was detected without a visible CSRF token.",
                    "Add a per-session CSRF token to all state-changing forms. Validate server-side.",
                    cve_ids=["CWE-352"],
                ))
                break  # one finding per page
    except Exception:
        pass
    return findings


# ─────────────────────────────────────────────────────────────
#  Directory Listing
# ─────────────────────────────────────────────────────────────

LISTING_PATTERNS = [r"Index of /", r"Directory listing for", r"\[To Parent Directory\]"]

def _check_directory_listing(target: str, s: requests.Session, timeout: int) -> List[Dict]:
    findings = []
    paths = ["/", "/uploads/", "/files/", "/backup/", "/static/", "/assets/", "/data/"]
    for path in paths:
        try:
            url  = urljoin(target, path)
            resp = s.get(url, timeout=timeout, allow_redirects=True)
            for pattern in LISTING_PATTERNS:
                if re.search(pattern, resp.text, re.I):
                    findings.append(_finding(
                        "Directory Listing Enabled", "Medium", url,
                        f"Directory listing is enabled at {url}, exposing file structure.",
                        "Disable directory listing in your web server configuration (e.g., Options -Indexes in Apache).",
                        evidence=path,
                    ))
                    break
        except Exception:
            continue
    return findings


# ─────────────────────────────────────────────────────────────
#  Default Credentials
# ─────────────────────────────────────────────────────────────

DEFAULT_CREDS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "123456"),
    ("admin",  "admin123"),
    ("root",   "root"),
    ("test",   "test"),
    ("guest",  "guest"),
    ("admin",  ""),
]
LOGIN_PATHS = ["/login", "/admin", "/admin/login", "/user/login", "/auth/login", "/api/login", "/signin"]

def _check_default_credentials(target: str, s: requests.Session, timeout: int) -> List[Dict]:
    findings = []
    for path in LOGIN_PATHS:
        url = urljoin(target, path)
        try:
            probe = s.get(url, timeout=timeout, allow_redirects=True)
            if probe.status_code not in (200, 401, 403):
                continue
            body_lower = probe.text.lower()
            if "password" not in body_lower and "login" not in body_lower:
                continue

            for user, pwd in DEFAULT_CREDS:
                for payload in [
                    {"email": user, "password": pwd},
                    {"username": user, "password": pwd},
                    {"user": user, "pass": pwd},
                ]:
                    try:
                        r = s.post(url, json=payload, timeout=timeout, allow_redirects=True)
                        # Success indicators: redirect to dashboard, token in response, no "invalid" message
                        success_signs = ["token", "dashboard", "welcome", "logout", "profile"]
                        fail_signs    = ["invalid", "incorrect", "wrong", "failed", "error"]
                        body_l        = r.text.lower()
                        if (r.status_code in (200, 302) and
                                any(s in body_l for s in success_signs) and
                                not any(f in body_l for f in fail_signs)):
                            findings.append(_finding(
                                "Default Credentials Accepted", "Critical", url,
                                f"Login succeeded with default credentials: {user}/{pwd}",
                                "Change all default credentials immediately. Enforce strong password policy.",
                                evidence=f"user={user} pass={pwd} → {r.status_code}",
                            ))
                            return findings
                    except Exception:
                        continue
        except Exception:
            continue
    return findings


# ─────────────────────────────────────────────────────────────
#  IDOR (Insecure Direct Object Reference)
# ─────────────────────────────────────────────────────────────

def _check_idor(url: str, s: requests.Session, timeout: int) -> List[Dict]:
    """Check numeric ID params for IDOR by incrementing/decrementing."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    id_params = [k for k in params if re.search(r"id|uid|user|account|order|item", k, re.I)]
    for param in id_params:
        original_val = params[param][0]
        if not original_val.isdigit():
            continue
        try:
            orig_resp = s.get(url, timeout=timeout)
            # Try adjacent IDs
            for delta in [-1, 1, 2]:
                test_val    = str(int(original_val) + delta)
                test_params = {**{k: v[0] for k, v in params.items()}, param: test_val}
                test_url    = url.split("?")[0] + "?" + urlencode(test_params)
                test_resp   = s.get(test_url, timeout=timeout)
                # Different 200 response with similar length = likely IDOR
                if (test_resp.status_code == 200 and
                        orig_resp.status_code == 200 and
                        abs(len(test_resp.text) - len(orig_resp.text)) < 5000 and
                        test_resp.text != orig_resp.text):
                    findings.append(_finding(
                        "Potential IDOR", "High", url,
                        f"Parameter '{param}' with value '{test_val}' returns different user data (possible IDOR).",
                        "Implement server-side authorisation checks for all object references. Use UUIDs instead of sequential IDs.",
                        evidence=f"Param: {param}, original={original_val}, tested={test_val}",
                        cve_ids=["CWE-639"],
                    ))
                    break
        except Exception:
            continue
    return findings


# ─────────────────────────────────────────────────────────────
#  JWT Issues
# ─────────────────────────────────────────────────────────────

def _check_jwt_issues(target: str, s: requests.Session, timeout: int) -> List[Dict]:
    findings = []
    try:
        import base64, json as _json
        resp    = s.get(target, timeout=timeout, allow_redirects=True)
        cookies = {c.name: c.value for c in resp.cookies}
        headers = resp.headers

        # Look for JWT in cookies or Authorization header
        jwt_sources = list(cookies.values()) + [headers.get("authorization", "")]

        for val in jwt_sources:
            if not val:
                continue
            parts = val.replace("Bearer ", "").strip().split(".")
            if len(parts) != 3:
                continue
            try:
                # Decode header
                header_b64 = parts[0] + "=="
                header     = _json.loads(base64.b64decode(header_b64).decode("utf-8", errors="ignore"))
                alg        = header.get("alg", "")

                if alg.upper() == "NONE":
                    findings.append(_finding(
                        "JWT Algorithm None Attack", "Critical", target,
                        "JWT is signed with algorithm 'none', allowing token forgery.",
                        "Reject tokens with alg=none. Always enforce a strong signing algorithm (RS256, HS256).",
                        evidence=f"alg={alg}",
                        cve_ids=["CVE-2015-9235"],
                    ))
                elif alg.upper() == "HS256":
                    findings.append(_finding(
                        "JWT Uses Symmetric Algorithm (HS256)", "Low", target,
                        "JWT uses HS256 (symmetric). If the secret is weak, it can be brute-forced.",
                        "Use RS256 (asymmetric) for JWTs. Ensure the signing secret is long and random.",
                        evidence=f"alg={alg}",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


# ─────────────────────────────────────────────────────────────
#  SSRF Indicators
# ─────────────────────────────────────────────────────────────

SSRF_PARAMS = ["url", "uri", "src", "source", "href", "path", "dest", "destination",
               "redirect", "proxy", "callback", "fetch", "load", "file"]

def _check_ssrf_indicators(target: str, crawl_urls: List[str], s: requests.Session, timeout: int) -> List[Dict]:
    findings = []
    all_urls = [target] + crawl_urls[:20]

    for url in all_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        ssrf_params = [k for k in params if k.lower() in SSRF_PARAMS]
        for param in ssrf_params:
            try:
                test_params = {**{k: v[0] for k, v in params.items()}, param: "http://169.254.169.254/latest/meta-data/"}
                test_url    = url.split("?")[0] + "?" + urlencode(test_params)
                resp        = s.get(test_url, timeout=timeout)
                # AWS metadata or similar in response = confirmed SSRF
                if any(x in resp.text for x in ["ami-id", "instance-id", "hostname", "iam"]):
                    findings.append(_finding(
                        "Server-Side Request Forgery (SSRF)", "Critical", url,
                        f"Parameter '{param}' causes server to fetch internal/cloud metadata URLs.",
                        "Validate and restrict URLs the server is allowed to fetch. Block internal IP ranges.",
                        evidence=f"Param: {param} fetched AWS metadata",
                        cve_ids=["CWE-918"],
                    ))
            except Exception:
                continue
    return findings
