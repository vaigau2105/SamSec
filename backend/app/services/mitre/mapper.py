# backend/app/services/mitre/mapper.py
"""
Maps SamSec vulnerability findings → MITRE ATT&CK techniques.

Strategy (layered, highest confidence first):
  1. CVE-ID lookup  → technique via known CVE→ATT&CK mappings
  2. Template-ID    → technique via nuclei template name patterns
  3. Keyword match  → technique via finding name/description keywords
  4. Port/service   → technique via network service context
"""

from typing import Dict, List, Optional

# ──────────────────────────────────────────────────────────────
#  CVE → ATT&CK technique mappings  (curated high-signal list)
# ──────────────────────────────────────────────────────────────

CVE_TO_TECHNIQUE: Dict[str, Dict] = {
    "CVE-2021-44228": {"id": "T1190", "name": "Exploit Public-Facing Application",  "tactic": "initial-access"},
    "CVE-2021-45046": {"id": "T1190", "name": "Exploit Public-Facing Application",  "tactic": "initial-access"},
    "CVE-2017-0144":  {"id": "T1210", "name": "Exploitation of Remote Services",     "tactic": "lateral-movement"},
    "CVE-2021-26855": {"id": "T1190", "name": "Exploit Public-Facing Application",  "tactic": "initial-access"},
    "CVE-2019-11510": {"id": "T1190", "name": "Exploit Public-Facing Application",  "tactic": "initial-access"},
    "CVE-2020-1472":  {"id": "T1210", "name": "Exploitation of Remote Services",     "tactic": "lateral-movement"},
    "CVE-2021-34527": {"id": "T1068", "name": "Exploitation for Privilege Escalation","tactic": "privilege-escalation"},
    "CVE-2022-22965": {"id": "T1190", "name": "Exploit Public-Facing Application",  "tactic": "initial-access"},
    "CVE-2023-44487": {"id": "T1499", "name": "Endpoint Denial of Service",          "tactic": "impact"},
    "CVE-2014-6271":  {"id": "T1059.004", "name": "Unix Shell",                      "tactic": "execution"},
    "CVE-2021-21985": {"id": "T1210", "name": "Exploitation of Remote Services",     "tactic": "lateral-movement"},
    "CWE-89":         {"id": "T1190", "name": "Exploit Public-Facing Application",  "tactic": "initial-access"},
    "CWE-79":         {"id": "T1059.007", "name": "JavaScript",                      "tactic": "execution"},
    "CWE-352":        {"id": "T1185", "name": "Browser Session Hijacking",           "tactic": "collection"},
    "CWE-601":        {"id": "T1566.002", "name": "Spearphishing Link",              "tactic": "initial-access"},
    "CWE-918":        {"id": "T1090", "name": "Proxy",                               "tactic": "command-and-control"},
    "CWE-639":        {"id": "T1078", "name": "Valid Accounts",                      "tactic": "defense-evasion"},
    "CWE-942":        {"id": "T1557", "name": "Adversary-in-the-Middle",             "tactic": "collection"},
    "CWE-614":        {"id": "T1539", "name": "Steal Web Session Cookie",            "tactic": "credential-access"},
    "CVE-2015-9235":  {"id": "T1548", "name": "Abuse Elevation Control Mechanism",  "tactic": "privilege-escalation"},
}


# ──────────────────────────────────────────────────────────────
#  Keyword rules  (pattern, technique_id, name, tactic, confidence)
# ──────────────────────────────────────────────────────────────

KEYWORD_RULES: List[Dict] = [
    # Initial Access
    {"keywords": ["sqli", "sql injection", "sql error", "database error"],
     "id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "high"},
    {"keywords": ["default credential", "default login", "default password", "admin/admin"],
     "id": "T1078.001", "name": "Default Accounts", "tactic": "initial-access", "confidence": "high"},
    {"keywords": ["phishing", "spearphish", "open redirect"],
     "id": "T1566", "name": "Phishing", "tactic": "initial-access", "confidence": "medium"},

    # Execution
    {"keywords": ["xss", "cross-site scripting", "script injection", "javascript"],
     "id": "T1059.007", "name": "JavaScript", "tactic": "execution", "confidence": "high"},
    {"keywords": ["command injection", "rce", "remote code execution", "code injection"],
     "id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution", "confidence": "high"},
    {"keywords": ["ssti", "server-side template injection"],
     "id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution", "confidence": "high"},

    # Persistence
    {"keywords": ["backdoor", "webshell", "web shell", "php shell"],
     "id": "T1505.003", "name": "Web Shell", "tactic": "persistence", "confidence": "high"},
    {"keywords": ["cron", "scheduled task", "startup", "autorun"],
     "id": "T1053", "name": "Scheduled Task/Job", "tactic": "persistence", "confidence": "medium"},

    # Privilege Escalation
    {"keywords": ["privilege escalation", "sudo", "suid", "setuid", "privilege"],
     "id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "privilege-escalation", "confidence": "medium"},

    # Defense Evasion
    {"keywords": ["idor", "insecure direct object", "broken access"],
     "id": "T1078", "name": "Valid Accounts", "tactic": "defense-evasion", "confidence": "high"},
    {"keywords": ["directory traversal", "path traversal", "lfi", "local file inclusion"],
     "id": "T1083", "name": "File and Directory Discovery", "tactic": "discovery", "confidence": "high"},
    {"keywords": ["xxe", "xml external entity"],
     "id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution", "confidence": "medium"},

    # Credential Access
    {"keywords": ["brute force", "password spray", "credential stuffing", "login attempt"],
     "id": "T1110", "name": "Brute Force", "tactic": "credential-access", "confidence": "high"},
    {"keywords": ["jwt", "json web token", "token exposure", "bearer token"],
     "id": "T1528", "name": "Steal Application Access Token", "tactic": "credential-access", "confidence": "high"},
    {"keywords": ["cookie", "session", "session fixation", "session hijack"],
     "id": "T1539", "name": "Steal Web Session Cookie", "tactic": "credential-access", "confidence": "high"},
    {"keywords": ["api key", "secret key", "password in response", "credential exposure"],
     "id": "T1552", "name": "Unsecured Credentials", "tactic": "credential-access", "confidence": "high"},
    {"keywords": ["private key", "ssh key", "rsa key"],
     "id": "T1552.004", "name": "Private Keys", "tactic": "credential-access", "confidence": "high"},

    # Discovery
    {"keywords": ["directory listing", "open directory", "index of"],
     "id": "T1083", "name": "File and Directory Discovery", "tactic": "discovery", "confidence": "high"},
    {"keywords": ["port scan", "open port", "service discovery", "naabu", "nmap"],
     "id": "T1046", "name": "Network Service Discovery", "tactic": "discovery", "confidence": "high"},
    {"keywords": ["subdomain", "dns enumeration", "zone transfer"],
     "id": "T1590.002", "name": "DNS", "tactic": "reconnaissance", "confidence": "high"},
    {"keywords": ["version disclosure", "server banner", "technology fingerprint", "x-powered-by"],
     "id": "T1592", "name": "Gather Victim Host Information", "tactic": "reconnaissance", "confidence": "medium"},

    # Lateral Movement
    {"keywords": ["ssrf", "server-side request forgery", "internal network"],
     "id": "T1090.002", "name": "External Proxy", "tactic": "command-and-control", "confidence": "high"},
    {"keywords": ["smb", "445", "ms17", "eternalblue"],
     "id": "T1210", "name": "Exploitation of Remote Services", "tactic": "lateral-movement", "confidence": "high"},
    {"keywords": ["rdp", "3389", "remote desktop"],
     "id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "lateral-movement", "confidence": "high"},

    # Collection
    {"keywords": ["cors", "cross-origin", "access-control-allow-origin"],
     "id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "collection", "confidence": "high"},
    {"keywords": ["csrf", "cross-site request forgery", "missing csrf token"],
     "id": "T1185", "name": "Browser Session Hijacking", "tactic": "collection", "confidence": "high"},

    # Exfiltration / Impact
    {"keywords": ["data exposure", "sensitive data", "pii", "leak"],
     "id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration", "confidence": "medium"},
    {"keywords": ["denial of service", "dos", "ddos", "resource exhaustion"],
     "id": "T1499", "name": "Endpoint Denial of Service", "tactic": "impact", "confidence": "medium"},

    # Security Header specific
    {"keywords": ["missing hsts", "strict-transport-security", "hsts"],
     "id": "T1557.002", "name": "ARP Cache Poisoning", "tactic": "collection", "confidence": "low"},
    {"keywords": ["missing x-frame-options", "clickjack", "iframe"],
     "id": "T1185", "name": "Browser Session Hijacking", "tactic": "collection", "confidence": "medium"},
    {"keywords": ["missing content-security-policy", "csp", "content security policy"],
     "id": "T1059.007", "name": "JavaScript", "tactic": "execution", "confidence": "medium"},
    {"keywords": ["ssl", "tls", "certificate", "expired cert", "weak cipher"],
     "id": "T1557.002", "name": "ARP Cache Poisoning", "tactic": "collection", "confidence": "low"},
    {"keywords": ["rfi", "remote file inclusion"],
     "id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control", "confidence": "high"},
]


# ──────────────────────────────────────────────────────────────
#  Port → technique
# ──────────────────────────────────────────────────────────────

PORT_RULES: Dict[int, Dict] = {
    21:   {"id": "T1021.001", "name": "Remote Desktop Protocol",   "tactic": "lateral-movement"},
    22:   {"id": "T1021.004", "name": "SSH",                        "tactic": "lateral-movement"},
    23:   {"id": "T1021",     "name": "Remote Services",            "tactic": "lateral-movement"},
    25:   {"id": "T1071.003", "name": "Mail Protocols",             "tactic": "command-and-control"},
    53:   {"id": "T1590.002", "name": "DNS",                        "tactic": "reconnaissance"},
    80:   {"id": "T1190",     "name": "Exploit Public-Facing App",  "tactic": "initial-access"},
    443:  {"id": "T1190",     "name": "Exploit Public-Facing App",  "tactic": "initial-access"},
    445:  {"id": "T1210",     "name": "Exploitation of Remote Services", "tactic": "lateral-movement"},
    3306: {"id": "T1190",     "name": "Exploit Public-Facing App",  "tactic": "initial-access"},
    3389: {"id": "T1021.001", "name": "Remote Desktop Protocol",    "tactic": "lateral-movement"},
    5432: {"id": "T1190",     "name": "Exploit Public-Facing App",  "tactic": "initial-access"},
    6379: {"id": "T1190",     "name": "Exploit Public-Facing App",  "tactic": "initial-access"},
    8080: {"id": "T1190",     "name": "Exploit Public-Facing App",  "tactic": "initial-access"},
    27017:{"id": "T1190",     "name": "Exploit Public-Facing App",  "tactic": "initial-access"},
}


# ──────────────────────────────────────────────────────────────
#  Core mapper
# ──────────────────────────────────────────────────────────────

def map_finding_to_techniques(finding: Dict) -> List[Dict]:
    """
    Given a SamSec finding dict, return a list of matched ATT&CK techniques.
    Each result: { technique_id, technique_name, tactic, confidence, match_reason }
    """
    matched: Dict[str, Dict] = {}   # keyed by technique_id to deduplicate

    search_text = " ".join([
        str(finding.get("name", "")),
        str(finding.get("description", "")),
        str(finding.get("template_id", "")),
        str(finding.get("target", "")),
        str(finding.get("evidence", "")),
    ]).lower()

    # ── 1. CVE / CWE lookup (highest confidence) ──
    for cve_id in finding.get("cve_ids", []):
        key = cve_id.upper()
        if key in CVE_TO_TECHNIQUE:
            t = CVE_TO_TECHNIQUE[key]
            matched[t["id"]] = {
                "technique_id":   t["id"],
                "technique_name": t["name"],
                "tactic":         t["tactic"],
                "confidence":     "high",
                "match_reason":   f"CVE/CWE mapping: {cve_id}",
            }

    # ── 2. Keyword matching ──
    for rule in KEYWORD_RULES:
        hit_count = sum(1 for kw in rule["keywords"] if kw in search_text)
        if hit_count > 0:
            tid = rule["id"]
            confidence = rule["confidence"]
            if hit_count >= 2:
                confidence = "high"
            if tid not in matched:
                matched[tid] = {
                    "technique_id":   tid,
                    "technique_name": rule["name"],
                    "tactic":         rule["tactic"],
                    "confidence":     confidence,
                    "match_reason":   f"Keyword match: {rule['keywords'][0]}",
                }

    return list(matched.values())


def enrich_findings(findings: List[Dict]) -> List[Dict]:
    """Enrich a list of SamSec findings with MITRE ATT&CK data in-place."""
    for finding in findings:
        finding["mitre_techniques"] = map_finding_to_techniques(finding)
    return findings


def map_open_ports(open_ports: List[Dict]) -> List[Dict]:
    """
    Map open port findings from naabu to ATT&CK techniques.
    open_ports = [{"host": ..., "port": 22, "service": "ssh"}, ...]
    """
    port_findings = []
    seen = set()
    for entry in open_ports:
        port = entry.get("port")
        if port and port in PORT_RULES and port not in seen:
            seen.add(port)
            t = PORT_RULES[port]
            port_findings.append({
                "name":             f"Exposed Service on Port {port}",
                "severity":         "Info",
                "target":           entry.get("host", ""),
                "description":      f"Port {port} ({entry.get('service', 'unknown')}) is open and may be exploited.",
                "cve_ids":          [],
                "mitre_techniques": [{
                    "technique_id":   t["id"],
                    "technique_name": t["name"],
                    "tactic":         t["tactic"],
                    "confidence":     "medium",
                    "match_reason":   f"Open port {port}",
                }],
            })
    return port_findings
