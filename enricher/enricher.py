import requests
import json
import os

CVE_DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "cve_database.json")

def get_cves_by_cwe(cwe_id):
    """Récupère les CVE depuis la base locale ou NVD API."""
    
    cwe_clean = cwe_id.split(":")[0].strip()
    print(f"🌐 Recherche CVE pour : {cwe_clean}")
    
    # 1. Chercher dans la base locale d'abord
    if os.path.exists(CVE_DB_FILE):
        with open(CVE_DB_FILE, "r", encoding="utf-8") as f:
            db = json.load(f)
        
        cves = db.get(cwe_clean, [])
        if cves:
            print(f"✅ {len(cves)} CVE(s) trouvé(s) depuis base locale")
            return cves[:5]
    
    # 2. Fallback NVD API si pas dans la base locale
    print(f"⚠️  CWE non trouvé localement — appel NVD API...")
    return _fetch_nvd_api(cwe_clean)


def _fetch_nvd_api(cwe_clean):
    """Appelle NVD API en fallback."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cweId": cwe_clean, "resultsPerPage": 5}
    
    try:
        response = requests.get(url, params=params, timeout=15)
        if not response.text.strip():
            return []
        
        data = response.json()
        cves = []
        
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cves.append({
                "id":          cve["id"],
                "cwe":         cwe_clean,
                "description": cve["descriptions"][0]["value"][:300],
                "severity":    cve.get("metrics", {})
                                  .get("cvssMetricV31", [{}])[0]
                                  .get("cvssData", {})
                                  .get("baseSeverity", "UNKNOWN"),
                "published":   cve.get("published", "")[:10]
            })
        
        return cves
        
    except Exception as e:
        print(f"⚠️  Erreur NVD API : {e}")
        return []


if __name__ == "__main__":
    cves = get_cves_by_cwe("CWE-89")
    print(f"\n✅ {len(cves)} CVE(s) :\n")
    for cve in cves:
        print(f"  🆔 {cve['id']} — {cve.get('severity', 'UNKNOWN')}")
        print(f"  💬 {cve.get('description', '')[:100]}")
        print()