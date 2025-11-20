import asyncio
import subprocess
import dns.resolver
from typing import List, Dict


# -------------------------
# Run Subfinder
# -------------------------
async def run_subfinder(domain: str) -> List[str]:
    try:
        cmd = f"subfinder -silent -d {domain}"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await proc.communicate()
        if stderr:
            print("Subfinder Error:", stderr.decode())

        subdomains = stdout.decode().splitlines()
        return list(set(subdomains))  # unique values

    except Exception as e:
        print("ERROR: Subfinder failed:", e)
        return []


# -------------------------
# DNS Record Resolver
# -------------------------
async def resolve_record(domain: str, record: str):
    try:
        answers = dns.resolver.resolve(domain, record)
        return [str(r) for r in answers]
    except:
        return []


async def resolve_dns_of_list(subdomain_list: List[str]) -> Dict:
    results = {}

    for sub in subdomain_list:
        records = await resolve_all_records(sub)
        results[sub] = records

    return results


# -------------------------
# All Records for a domain
# -------------------------
async def resolve_all_records(domain: str) -> Dict:
    record_types = ["A", "AAAA", "NS", "MX", "TXT", "CNAME"]

    result = {}
    for r in record_types:
        result[r] = await resolve_record(domain, r)

    return result


# -------------------------
# Main SCAN FUNCTION
# -------------------------
async def samdns_scan(domain: str) -> Dict:
    # 1. Get subdomains using Subfinder
    subdomains = await run_subfinder(domain)

    # 2. Resolve DNS records for each
    dns_data = await resolve_dns_of_list(subdomains[:30])  
    # limit 30 to avoid slow scans

    # 3. Also get DNS of main domain
    root_records = await resolve_all_records(domain)

    return {
        "domain": domain,
        "root_dns": root_records,
        "subdomains_found": len(subdomains),
        "subdomains": subdomains[:30],
        "resolved_records": dns_data
    }


# -------------------------
# CLI for testing
# -------------------------
if __name__ == "__main__":
    domain = input("Enter domain: ").strip()
    result = asyncio.run(samdns_scan(domain))
    from pprint import pprint
    pprint(result)
