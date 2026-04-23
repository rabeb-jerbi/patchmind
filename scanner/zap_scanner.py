"""
scanner/zap_scanner.py
Détecte les vulnérabilités runtime via OWASP ZAP.
Nécessite ZAP en cours d'exécution ou en mode daemon.
"""
import subprocess
import json
import os
import time
import requests as req

ZAP_API_KEY = os.getenv("ZAP_API_KEY", "patchmind-zap-key")
ZAP_HOST    = os.getenv("ZAP_HOST", "http://localhost")
ZAP_PORT    = os.getenv("ZAP_PORT", "8090")
ZAP_URL     = f"{ZAP_HOST}:{ZAP_PORT}"

# Mapping severité ZAP → niveau
RISK_MAP = {
    "3": "HIGH",
    "2": "MEDIUM",
    "1": "LOW",
    "0": "INFO"
}

# Mapping alertes ZAP → CWE
ZAP_CWE_MAP = {
    "SQL Injection":                    "CWE-89",
    "Cross Site Scripting":             "CWE-79",
    "Path Traversal":                   "CWE-22",
    "Remote OS Command Injection":      "CWE-78",
    "Server Side Request Forgery":      "CWE-918",
    "Cross-Site Request Forgery":       "CWE-352",
    "Open Redirect":                    "CWE-601",
    "Insecure Direct Object Reference": "CWE-863",
    "Missing Anti-clickjacking Header": "CWE-693",
    "Information Disclosure":           "CWE-200",
    "Weak Authentication":              "CWE-287",
    "Session Fixation":                 "CWE-384",
    "Insecure Cookie":                  "CWE-614",
    "Directory Browsing":               "CWE-548",
    "LDAP Injection":                   "CWE-90",
    "XML External Entity":              "CWE-611",
    "Buffer Overflow":                  "CWE-120",
}


def is_zap_running():
    """Vérifie si ZAP est en cours d'exécution."""
    try:
        resp = req.get(f"{ZAP_URL}/JSON/core/view/version/",
                       params={"apikey": ZAP_API_KEY}, timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def start_zap_daemon():
    """Lance ZAP en mode daemon si disponible."""
    zap_paths = [
        r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
        r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
        "/usr/share/zaproxy/zap.sh",
        "/opt/homebrew/bin/zap.sh",
    ]
    for zap_path in zap_paths:
        if os.path.exists(zap_path):
            subprocess.Popen([
                zap_path, "-daemon",
                "-port", ZAP_PORT,
                "-config", f"api.key={ZAP_API_KEY}",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true"
            ])
            print(f"  🚀 ZAP lancé sur le port {ZAP_PORT}")
            time.sleep(15)  # Attendre démarrage
            return True
    return False


def run_zap(target_url, scan_type="passive"):
    """
    Lance un scan ZAP sur une URL cible.
    scan_type: 'passive' (rapide) ou 'active' (complet mais lent)
    """
    findings = []

    if not target_url or not target_url.startswith("http"):
        print("  ⚠️  ZAP : URL cible invalide")
        return []

    # Vérifier/démarrer ZAP
    if not is_zap_running():
        print("  🚀 Démarrage de ZAP...")
        if not start_zap_daemon():
            print("  ⚠️  ZAP non installé — scan DAST ignoré")
            return _zap_not_available_warning(target_url)

    print(f"  🌐 ZAP scan {'actif' if scan_type=='active' else 'passif'} sur {target_url}")

    try:
        params = {"apikey": ZAP_API_KEY}

        # 1. Spider (crawl)
        print("    🕷️  Spider en cours...")
        spider = req.get(f"{ZAP_URL}/JSON/spider/action/scan/",
                         params={**params, "url": target_url}).json()
        spider_id = spider.get("scan", "0")
        _wait_for_scan(f"{ZAP_URL}/JSON/spider/view/status/",
                       {"apikey": ZAP_API_KEY, "scanId": spider_id})

        if scan_type == "active":
            # 2. Active scan
            print("    ⚔️  Scan actif en cours (peut prendre plusieurs minutes)...")
            ascan = req.get(f"{ZAP_URL}/JSON/ascan/action/scan/",
                            params={**params, "url": target_url}).json()
            ascan_id = ascan.get("scan", "0")
            _wait_for_scan(f"{ZAP_URL}/JSON/ascan/view/status/",
                           {"apikey": ZAP_API_KEY, "scanId": ascan_id},
                           timeout=300)

        # 3. Récupérer les alertes
        alerts_resp = req.get(f"{ZAP_URL}/JSON/core/view/alerts/",
                               params={**params, "baseurl": target_url}).json()
        alerts = alerts_resp.get("alerts", [])

        for alert in alerts:
            risk   = alert.get("risk", "").upper()
            if risk == "INFORMATIONAL":
                continue  # Ignorer les infos
            name   = alert.get("alert", "")
            cwe_id = _detect_cwe_from_alert(name, alert.get("cweid", ""))
            findings.append({
                "tool":        "zap",
                "type":        "DAST",
                "cwe":         cwe_id,
                "severity":    risk,
                "rule":        name,
                "url":         alert.get("url", ""),
                "description": alert.get("description", "")[:200],
                "solution":    alert.get("solution", "")[:200],
                "message":     f"ZAP [{risk}] : {name}",
                "file":        alert.get("url", ""),
                "line":        0,
                "evidence":    alert.get("evidence", "")[:100],
            })

        print(f"  🌐 ZAP : {len(findings)} alerte(s) trouvée(s)")

    except Exception as e:
        print(f"  ❌ ZAP erreur : {e}")

    return findings


def _wait_for_scan(url, params, timeout=120):
    """Attend la fin d'un scan ZAP."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = req.get(url, params=params, timeout=10).json()
            progress = int(resp.get("status", "0"))
            if progress >= 100:
                return
        except Exception:
            pass
        time.sleep(3)


def _detect_cwe_from_alert(alert_name, cweid):
    """Détecte le CWE depuis le nom de l'alerte ZAP."""
    if cweid and cweid != "0":
        return f"CWE-{cweid}"
    for name, cwe in ZAP_CWE_MAP.items():
        if name.lower() in alert_name.lower():
            return cwe
    return "CWE-693"


def _zap_not_available_warning(target_url):
    """Retourne un avertissement si ZAP n'est pas disponible."""
    return [{
        "tool":        "zap",
        "type":        "INFO",
        "cwe":         "N/A",
        "severity":    "INFO",
        "message":     "OWASP ZAP non installé — scan DAST non effectué",
        "description": f"Installez ZAP pour scanner {target_url} en mode dynamique",
        "file":        "",
        "line":        0,
    }]