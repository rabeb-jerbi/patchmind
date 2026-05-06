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


# ── File-based DAST patterns ──────────────────────────────────────────────────

_DAST_RULES = [
    {
        "id":       "xss-sink",
        "pattern":  r'(?:document\.write|innerHTML|outerHTML)\s*[+]?=',
        "cwe":      "CWE-79",
        "severity": "HIGH",
        "message":  "XSS sink détecté : écriture non sécurisée dans le DOM",
        "description": "L'écriture directe dans le DOM sans encodage permet à un attaquant d'injecter du code JavaScript malveillant.",
        "solution": "Utilisez textContent au lieu de innerHTML. Encodez toutes les données avant insertion dans le DOM.",
    },
    {
        "id":       "eval-injection",
        "pattern":  r'\beval\s*\(|\bnew\s+Function\s*\(',
        "cwe":      "CWE-95",
        "severity": "HIGH",
        "message":  "Injection via eval() — exécution de code dynamique non sécurisée",
        "description": "L'utilisation d'eval() avec des données non contrôlées permet l'exécution de code arbitraire.",
        "solution": "Évitez eval() avec des données utilisateur. Utilisez JSON.parse() pour les données JSON.",
    },
    {
        "id":       "open-redirect",
        "pattern":  r'(?:window\.location|location\.href|location\.replace)\s*=\s*(?:req|request|param|url|redirect)',
        "cwe":      "CWE-601",
        "severity": "MEDIUM",
        "message":  "Redirection ouverte potentielle vers une URL non validée",
        "description": "Une redirection vers une URL contrôlée par l'utilisateur permet de diriger des victimes vers des sites malveillants.",
        "solution": "Validez et limitez les URLs de redirection à une liste blanche.",
    },
    {
        "id":       "ssrf-risk",
        "pattern":  r'(?:fetch|axios\.get|requests\.get|urllib\.request\.urlopen)\s*\(\s*(?:req|request|params?|url)',
        "cwe":      "CWE-918",
        "severity": "HIGH",
        "message":  "SSRF potentiel : requête HTTP construite depuis des données utilisateur",
        "description": "La construction dynamique d'URLs pour des requêtes HTTP côté serveur peut permettre d'accéder à des ressources internes.",
        "solution": "Validez et limitez les URLs cibles. Utilisez une liste blanche de domaines autorisés.",
    },
    {
        "id":       "sensitive-storage",
        "pattern":  r'localStorage\.setItem\s*\([^,]+,\s*(?:[^)]*(?:token|password|secret|key|auth)[^)]*)\)',
        "cwe":      "CWE-312",
        "severity": "MEDIUM",
        "message":  "Données sensibles stockées dans localStorage",
        "description": "Le stockage de tokens ou mots de passe dans localStorage expose ces données aux scripts de la page (XSS).",
        "solution": "Utilisez des cookies HttpOnly et Secure pour les tokens d'authentification.",
    },
    {
        "id":       "hardcoded-url",
        "pattern":  r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+',
        "cwe":      "CWE-547",
        "severity": "LOW",
        "message":  "URL de serveur local codée en dur",
        "description": "Les URLs locales codées en dur empêchent le bon fonctionnement en production et révèlent l'architecture interne.",
        "solution": "Utilisez des variables d'environnement pour configurer les URLs de services.",
    },
    {
        "id":       "sql-concat",
        "pattern":  r'(?:execute|query|cursor\.execute)\s*\(\s*["\'].*?["\'\s]*\+',
        "cwe":      "CWE-89",
        "severity": "HIGH",
        "message":  "Concaténation de chaîne dans une requête SQL — injection SQL probable",
        "description": "La construction de requêtes SQL par concaténation permet à un attaquant de modifier la logique de la requête.",
        "solution": "Utilisez des requêtes paramétrées ou un ORM.",
    },
    {
        "id":       "cmd-injection",
        "pattern":  r'(?:subprocess\.(?:call|run|Popen)|os\.system|os\.popen)\s*\([^)]*(?:req|request|param|input|user)',
        "cwe":      "CWE-78",
        "severity": "CRITICAL",
        "message":  "Injection de commande OS potentielle via entrée utilisateur",
        "description": "L'exécution de commandes système avec des paramètres utilisateur non validés permet l'exécution de commandes arbitraires.",
        "solution": "Évitez shell=True. Validez et assainissez toute entrée avant utilisation dans des commandes.",
    },
]

_WEB_EXTS = {'.html', '.htm', '.js', '.jsx', '.ts', '.tsx', '.php', '.py', '.rb', '.go', '.java', '.vue', '.svelte'}


def _regex_dast_scan(work_dir):
    """Scan DAST par analyse statique de patterns web dans les fichiers sources."""
    import re as _re
    findings = []
    compiled = [(r, _re.compile(r["pattern"], _re.IGNORECASE)) for r in _DAST_RULES]

    for root, dirs, files in os.walk(work_dir):
        dirs[:] = [d for d in dirs if d not in ('node_modules', 'venv', '__pycache__', '.git', 'dist', 'build')]
        for fname in files:
            if os.path.splitext(fname)[1].lower() not in _WEB_EXTS:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as fh:
                    lines = fh.readlines()
            except Exception:
                continue

            # CSRF check: HTML forms without csrf token
            if fname.endswith(('.html', '.htm', '.php')):
                content = ''.join(lines)
                for m in _re.finditer(r'<form[^>]*>(.*?)</form>', content, _re.IGNORECASE | _re.DOTALL):
                    form_body = m.group(1)
                    if 'csrf' not in form_body.lower() and 'token' not in form_body.lower():
                        lineno = content[:m.start()].count('\n') + 1
                        findings.append({
                            "tool": "zap", "type": "DAST",
                            "cwe": "CWE-352:CSRF Token Absent",
                            "severity": "MEDIUM",
                            "message": f"Formulaire HTML sans protection CSRF dans {fname}",
                            "description": "Les formulaires sans token CSRF permettent à un attaquant d'effectuer des actions au nom d'un utilisateur authentifié.",
                            "solution": "Ajoutez un champ CSRF caché à chaque formulaire : <input type='hidden' name='csrf_token' value='...'>",
                            "explanation": "Un formulaire sans protection CSRF peut être soumis depuis n'importe quel site tiers, permettant des attaques de type Cross-Site Request Forgery.",
                            "file": fpath, "line": lineno, "rule": "zap-csrf-missing",
                        })

            seen_lines = set()
            for rule, pat in compiled:
                for lineno, line in enumerate(lines, 1):
                    key = (rule["id"], lineno)
                    if key in seen_lines:
                        continue
                    if pat.search(line):
                        seen_lines.add(key)
                        findings.append({
                            "tool": "zap", "type": "DAST",
                            "cwe": rule["cwe"] + ":" + rule["message"],
                            "severity": rule["severity"],
                            "message": rule["message"] + f" ({fname}:{lineno})",
                            "description": rule["description"],
                            "solution": rule["solution"],
                            "explanation": rule["description"],
                            "file": fpath, "line": lineno, "rule": "zap-" + rule["id"],
                        })

    return findings[:30]


def run_zap_on_file(work_dir):
    """
    Lance ZAP sur les fichiers uploadés.
    Essaie de démarrer un serveur HTTP local pour le scan ZAP.
    Si ZAP n'est pas disponible, utilise l'analyse statique de patterns DAST.
    """
    import threading as _th
    import socketserver as _ss
    import http.server as _hs
    import random

    if not is_zap_running() and not start_zap_daemon():
        print("  ⚠️  ZAP non disponible — scan DAST par analyse de patterns")
        return _regex_dast_scan(work_dir)

    # Start a temporary HTTP file server
    port = random.randint(19100, 19999)
    orig_dir = os.getcwd()
    try:
        os.chdir(work_dir)
        handler = _hs.SimpleHTTPRequestHandler
        handler.log_message = lambda *a: None
        httpd = _ss.TCPServer(("127.0.0.1", port), handler)
        t = _th.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            results = run_zap(f"http://127.0.0.1:{port}", scan_type="passive")
        finally:
            httpd.shutdown()
    except Exception as e:
        print(f"  ⚠️  ZAP serveur local : {e} — fallback patterns")
        results = _regex_dast_scan(work_dir)
    finally:
        os.chdir(orig_dir)

    return results