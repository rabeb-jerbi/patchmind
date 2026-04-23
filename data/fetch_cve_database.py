import requests
import json
import os
import time

OUTPUT_FILE = "data/cve_database.json"

TARGET_CWES = [
    "CWE-89",  "CWE-79",  "CWE-22",  "CWE-78",
    "CWE-95",  "CWE-327", "CWE-276", "CWE-502",
    "CWE-20",  "CWE-798", "CWE-732", "CWE-400",
    "CWE-611", "CWE-918", "CWE-307", "CWE-352"
]

def _parse_cves(data, cwe_id):
    """Parse les CVE depuis la réponse NVD."""
    cves = []
    
    for item in data.get("vulnerabilities", []):
        cve     = item["cve"]
        metrics = cve.get("metrics", {})
        
        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
        cvss_v2  = metrics.get("cvssMetricV2",  [{}])[0].get("cvssData", {})
        
        if cvss_v31:
            cvss    = cvss_v31
            version = "3.1"
        elif cvss_v30:
            cvss    = cvss_v30
            version = "3.0"
        elif cvss_v2:
            cvss    = cvss_v2
            version = "2.0"
        else:
            cvss    = {}
            version = "N/A"
        
        score    = cvss.get("baseScore", 0.0)
        severity = cvss.get("baseSeverity", "UNKNOWN")
        
        if version == "2.0" and severity == "UNKNOWN" and score > 0:
            if score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        
        refs = []
        for ref in cve.get("references", []):
            url_ref = ref.get("url", "")
            if "github.com" in url_ref:
                refs.append(url_ref)
        
        cves.append({
            "id":           cve["id"],
            "cwe":          cwe_id,
            "description":  cve["descriptions"][0]["value"][:300],
            "cvss_version": version,
            "cvss_score":   score,
            "severity":     severity,
            "published":    cve.get("published", "")[:10],
            "github_refs":  refs[:3]
        })
    
    cves.sort(key=lambda x: x["cvss_score"], reverse=True)
    return cves


def fetch_cves_for_cwe(cwe_id, max_results=20):
    """Récupère les CVE depuis NVD — essai avec CRITICAL, HIGH, puis sans filtre."""
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    for severity_filter in ["CRITICAL", "HIGH", None]:
        params = {
            "cweId":          cwe_id,
            "resultsPerPage": max_results
        }
        if severity_filter:
            params["cvssV3Severity"] = severity_filter
        
        try:
            response = requests.get(url, params=params, timeout=15)
            
            if not response.text.strip():
                continue
            
            data = response.json()
            cves = _parse_cves(data, cwe_id)
            
            if cves:
                label = severity_filter or "aucun filtre"
                print(f"  ✅ {len(cves)} CVE(s) trouvé(s) (filtre: {label})")
                return cves
            
            # Attendre entre les requêtes
            time.sleep(3)
            
        except Exception as e:
            print(f"  ⚠️  Erreur ({severity_filter}) : {e}")
            time.sleep(3)
            continue
    
    return []


def build_cve_database():
    """Construit la base CVE locale."""
    
    print("🔨 Construction de la base CVE...\n")
    
    database = {}
    total    = 0
    
    for cwe_id in TARGET_CWES:
        print(f"📌 Récupération CVE pour {cwe_id}...")
        cves = fetch_cves_for_cwe(cwe_id)
        database[cwe_id] = cves
        total += len(cves)
        
        # Rate limit NVD
        time.sleep(6)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(database, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Base CVE sauvegardée : {total} CVE au total")
    print(f"📁 Fichier : {OUTPUT_FILE}")
    
    print(f"\n📊 Résumé :")
    for cwe, cves in database.items():
        if cves:
            scores = [c["cvss_score"] for c in cves if c["cvss_score"] > 0]
            avg    = round(sum(scores) / len(scores), 1) if scores else 0
            print(f"  {cwe} : {len(cves)} CVE(s) — Score moyen : {avg}")
        else:
            print(f"  {cwe} : 0 CVE(s)")
    
    return database


if __name__ == "__main__":
    build_cve_database()