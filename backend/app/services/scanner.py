from typing import Dict, Any
from .subfinder import run_subfinder
from .httpx import run_httpx
from .naabu import run_naabu
from .nuclei import run_nuclei
from backend.app.tools.samdns import samdns_scan

def run_full_scan(domain: str) -> Dict[str, Any]:
    print(f"[+] Running full scan on: {domain}")

    # 1. SUBFINDER
    sub_result = run_subfinder(domain)
    subdomains = sub_result.get("results", [])

    print(f"[+] Subdomains found: {len(subdomains)}")

    # ensure main domain is included
    if not subdomains:
        subdomains = [target.replace("https://","").replace("http://","")]

    # limit to avoid overload
    subdomains = subdomains[:30]

    # 2. HTTPX
    print("[+] Running httpx...")
    httpx_result = run_httpx(subdomains)

    # only alive ones
    alive_hosts = []
    for h, data in httpx_result.items():
        if data.get("results"):
            alive_hosts.append(h)

    print(f"[+] Alive hosts: {len(alive_hosts)}")

    # 3. NAABU
    print("[+] Running naabu...")
    naabu_result = run_naabu(alive_hosts)

    # 4. NUCLEI
    print("[+] Running nuclei...")
    nuclei_results = []
    for host in alive_hosts[:10]:   # limit for speed
        nuk = run_nuclei(host)
        if nuk.get("results"):
            nuclei_results.extend(nuk["results"])
    print("[+] Running SamDNS...")

    dns_data = asyncio.run(samdns_scan(target))

    # severity count
    severity_count = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for f in nuclei_results:
        sev = (f.get("info", {}).get("severity", "info")).capitalize()
        if sev in severity_count:
            severity_count[sev] += 1
        else:
            severity_count["Info"] += 1

    return {
        "subdomains": subdomains,
        "dns_data": dns_data,
        "alive_hosts": [],
        "ports": {},
        "vulnerabilities": [],
        "summary": {
    }
}