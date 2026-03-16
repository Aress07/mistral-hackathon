import requests
from langchain_core.tools import tool

@tool
def check_cve_database(package_name: str, version: str) -> str:
    """Checks the Open Source Vulnerability (OSV) database for known vulnerabilities of a specific package and version."""
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        }
    }
    
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        
        if "vulns" in data:
            cve_ids = set()
            for v in data["vulns"]:
                # OSV often lists CVEs in the aliases array
                aliases = v.get("aliases", [])
                for a in aliases:
                    if a.startswith("CVE-"):
                        cve_ids.add(a)
                # If no CVE alias but we have a GHSA or PYSEC ID, we can optionally use that
                if not cve_ids:
                    cve_ids.add(v["id"])
                    
            if cve_ids:
                return f"Found {len(data['vulns'])} known vulnerabilities for {package_name}@{version} in OSV database: {', '.join(cve_ids)}. Include these precise CVE IDs exactly in your Exploit Scenario text."
            
            return f"Found {len(data['vulns'])} vulnerabilities, but no explicit CVE IDs found."
            
        return f"No known vulnerabilities found for {package_name}@{version}. (Make sure that if you flag it anyway, note that it is unbacked by OSV)"
        
    except Exception as e:
        return f"Error querying OSV API: {e}. No CVEs could be retrieved."
