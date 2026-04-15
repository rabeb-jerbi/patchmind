"""
fetch_cvefixes_v2.py — Récupère des CVE réels depuis OSV API
pour TOUS les langages supportés par PatchMind et TOUS les CWE Semgrep.
Lance depuis la racine : python fetch_cvefixes_v2.py
"""
import requests
import json
import os
import time
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
RAG_FILE     = os.path.join("data", "rag_examples.json")

HEADERS_GITHUB = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
} if GITHUB_TOKEN else {}

# ── Packages par écosystème ───────────────────────────────────────────────────
ECOSYSTEMS = {
    "PyPI": [
        "django", "flask", "sqlalchemy", "requests", "pillow",
        "cryptography", "paramiko", "twisted", "werkzeug", "aiohttp",
        "bottle", "tornado", "fastapi", "pyyaml", "lxml", "jinja2",
        "urllib3", "httpx", "pymysql", "psycopg2"
    ],
    "npm": [
        "express", "lodash", "axios", "react", "angular", "vue",
        "jquery", "moment", "sequelize", "mongoose", "passport",
        "jsonwebtoken", "bcrypt", "multer", "helmet", "cors",
        "serialize-javascript", "node-fetch", "marked", "sanitize-html"
    ],
    "Maven": [
        "org.springframework:spring-core",
        "org.springframework.security:spring-security-core",
        "com.fasterxml.jackson.core:jackson-databind",
        "org.apache.struts:struts2-core",
        "org.apache.commons:commons-collections",
        "log4j:log4j",
        "org.hibernate:hibernate-core",
        "com.google.guava:guava"
    ],
    "Packagist": [
        "laravel/laravel", "symfony/symfony", "codeigniter/framework",
        "guzzlehttp/guzzle", "monolog/monolog", "twig/twig",
        "doctrine/orm", "nesbot/carbon"
    ],
    "Go": [
        "github.com/gin-gonic/gin",
        "github.com/gorilla/mux",
        "github.com/labstack/echo",
        "github.com/beego/beego",
        "golang.org/x/crypto",
        "golang.org/x/net"
    ],
    "RubyGems": [
        "rails", "devise", "activerecord", "sinatra",
        "nokogiri", "rack", "omniauth", "paperclip"
    ],
}

# ── Mapping CWE depuis les mots-clés ─────────────────────────────────────────
CWE_KEYWORDS = {
    "CWE-89":  ["sql injection", "sql", "query injection", "database injection"],
    "CWE-79":  ["xss", "cross-site scripting", "html injection", "script injection"],
    "CWE-22":  ["path traversal", "directory traversal", "file traversal", "zip slip"],
    "CWE-78":  ["command injection", "os command", "shell injection", "rce"],
    "CWE-94":  ["code injection", "remote code execution", "arbitrary code", "eval injection"],
    "CWE-502": ["deserialization", "unsafe deserialization", "pickle", "object injection"],
    "CWE-327": ["weak crypto", "md5", "sha1", "weak hash", "insecure hash"],
    "CWE-330": ["weak random", "predictable random", "insecure random", "prng"],
    "CWE-798": ["hardcoded credential", "hardcoded password", "hardcoded secret", "hardcoded key"],
    "CWE-611": ["xxe", "xml external entity", "xml injection"],
    "CWE-918": ["ssrf", "server-side request forgery", "request forgery"],
    "CWE-352": ["csrf", "cross-site request forgery"],
    "CWE-434": ["file upload", "unrestricted upload", "arbitrary file"],
    "CWE-601": ["open redirect", "url redirect", "redirect vulnerability"],
    "CWE-400": ["denial of service", "dos", "resource exhaustion", "memory exhaustion"],
    "CWE-20":  ["input validation", "improper validation", "missing validation"],
    "CWE-200": ["information disclosure", "information leak", "sensitive information"],
    "CWE-209": ["error message", "stack trace", "debug information", "verbose error"],
    "CWE-312": ["cleartext", "plaintext password", "unencrypted"],
    "CWE-321": ["hardcoded key", "hardcoded secret key", "static key"],
    "CWE-326": ["weak encryption", "insufficient key", "weak key"],
    "CWE-362": ["race condition", "toctou", "time of check"],
    "CWE-732": ["file permission", "world writable", "insecure permission"],
    "CWE-862": ["missing authorization", "missing auth", "unauthorized access"],
    "CWE-863": ["incorrect authorization", "improper authorization", "access control"],
    "CWE-916": ["weak password hash", "unsalted hash", "password storage"],
    "CWE-190": ["integer overflow", "integer underflow", "arithmetic overflow"],
    "CWE-307": ["brute force", "rate limit", "account lockout"],
    "CWE-95":  ["eval", "exec injection", "dynamic code"],
    "CWE-90":  ["ldap injection", "ldap"],
    "CWE-643": ["xpath injection", "xpath"],
}

# Extension par écosystème pour détecter les fichiers pertinents
ECOSYSTEM_EXTENSIONS = {
    "PyPI":      [".py"],
    "npm":       [".js", ".jsx", ".ts", ".tsx"],
    "Maven":     [".java"],
    "Packagist": [".php"],
    "Go":        [".go"],
    "RubyGems":  [".rb"],
}


# ── Fonctions ─────────────────────────────────────────────────────────────────

def detect_cwe(text):
    """Détecte le CWE depuis le texte d'une vulnérabilité."""
    text_lower = text.lower()
    # Chercher d'abord mention directe CWE-XXX
    import re
    direct = re.findall(r'cwe-(\d+)', text_lower)
    if direct:
        cwe = f"CWE-{direct[0]}"
        if cwe in CWE_KEYWORDS:
            return cwe
    # Sinon chercher par mots-clés
    for cwe, keywords in CWE_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return cwe
    return None


def fetch_osv(package, ecosystem, max_vulns=15):
    """Récupère des vulnérabilités depuis OSV API."""
    try:
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"ecosystem": ecosystem, "name": package}},
            timeout=15
        )
        if resp.status_code != 200:
            return []
        return resp.json().get("vulns", [])[:max_vulns]
    except Exception as e:
        print(f"    ⚠️  OSV error: {e}")
        return []


def fetch_github_fix(commit_url, extensions):
    """Récupère before/after d'un commit GitHub."""
    if not GITHUB_TOKEN:
        return None, None
    try:
        api_url = commit_url.replace(
            "https://github.com/",
            "https://api.github.com/repos/"
        ).replace("/commit/", "/commits/")

        resp = requests.get(api_url, headers=HEADERS_GITHUB, timeout=15)
        if resp.status_code != 200:
            return None, None
        data = resp.json()

        for f in data.get("files", []):
            fname = f.get("filename", "")
            patch = f.get("patch", "")
            # Vérifier l'extension du fichier
            if not any(fname.endswith(ext) for ext in extensions):
                continue
            if not patch or len(patch) > 2000:
                continue

            before, after = [], []
            for line in patch.split("\n"):
                if line.startswith("-") and not line.startswith("---"):
                    before.append(line[1:])
                elif line.startswith("+") and not line.startswith("+++"):
                    after.append(line[1:])

            # Garder uniquement des exemples courts et significatifs
            before_code = "\n".join(before[:8]).strip()
            after_code  = "\n".join(after[:8]).strip()

            if (before_code and after_code and
                len(before_code) > 10 and len(after_code) > 10 and
                before_code != after_code):
                return before_code, after_code

        return None, None
    except Exception:
        return None, None


def run():
    # Charger la base RAG existante
    if os.path.exists(RAG_FILE):
        with open(RAG_FILE, "r", encoding="utf-8") as f:
            db = json.load(f)
        total_before = sum(len(v) for v in db.values())
        print(f"📂 Base RAG chargée : {total_before} exemples")
    else:
        db = {}
        print("📂 Nouvelle base RAG")

    added_total = 0
    skipped     = 0
    no_fix      = 0

    for ecosystem, packages in ECOSYSTEMS.items():
        extensions = ECOSYSTEM_EXTENSIONS.get(ecosystem, [".py"])
        print(f"\n{'='*50}")
        print(f"🌐 Écosystème : {ecosystem} ({len(packages)} packages)")
        print(f"{'='*50}")

        for package in packages:
            print(f"\n  📌 {package}")
            vulns = fetch_osv(package, ecosystem)
            if not vulns:
                print(f"    → Aucune vulnérabilité OSV")
                continue
            print(f"    → {len(vulns)} vulnérabilité(s) trouvée(s)")

            for vuln in vulns:
                vid      = vuln.get("id", "")
                summary  = vuln.get("summary", "") or ""
                details  = vuln.get("details",  "") or ""
                text     = summary + " " + details

                cwe = detect_cwe(text)
                if not cwe:
                    skipped += 1
                    continue

                # Vérifier si on a déjà assez d'exemples pour ce CWE
                existing = db.get(cwe, [])
                osv_count = sum(1 for e in existing if e.get("source") in ["osv+github", "osv"])
                if osv_count >= 15:
                    skipped += 1
                    continue

                # Chercher commit GitHub
                refs = vuln.get("references", [])
                got_fix = False
                for ref in refs:
                    url = ref.get("url", "")
                    if "github.com" in url and "/commit/" in url:
                        before, after = fetch_github_fix(url, extensions)
                        if before and after:
                            # Vérifier pas de doublon
                            existing_keys = {e.get("vulnerable","")[:60] for e in existing}
                            if before[:60] not in existing_keys:
                                existing.append({
                                    "cwe":         cwe,
                                    "source":      "osv+github",
                                    "cve_id":      vid,
                                    "ecosystem":   ecosystem,
                                    "package":     package,
                                    "description": summary[:200],
                                    "vulnerable":  before,
                                    "fixed":       after
                                })
                                db[cwe] = existing
                                added_total += 1
                                got_fix = True
                                print(f"    ✅ {vid} → {cwe} ({ecosystem})")
                            break
                        time.sleep(0.3)  # Rate limit GitHub API

                if not got_fix:
                    # Sauvegarder quand même avec description comme exemple
                    if summary and len(summary) > 30:
                        no_fix += 1

            time.sleep(0.5)  # Rate limit OSV API

    # Sauvegarder
    with open(RAG_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

    total_after = sum(len(v) for v in db.values())
    print(f"\n{'='*50}")
    print(f"✅ RÉSULTAT FINAL")
    print(f"{'='*50}")
    print(f"  Exemples ajoutés  : {added_total}")
    print(f"  Sans CWE détecté  : {skipped}")
    print(f"  Sans fix GitHub   : {no_fix}")
    print(f"  Total base RAG    : {total_after} exemples pour {len(db)} CWE")
    print(f"  Fichier           : {RAG_FILE}")
    print(f"\nDétail par CWE :")
    for cwe in sorted(db.keys()):
        exs = db[cwe]
        osv = sum(1 for e in exs if e.get("source") == "osv+github")
        man = sum(1 for e in exs if e.get("source") == "manual")
        loc = sum(1 for e in exs if e.get("source") == "local")
        print(f"  {cwe:12s}: {len(exs):3d} total  ({osv} osv, {man} manual, {loc} local)")


if __name__ == "__main__":
    if not GITHUB_TOKEN:
        print("⚠️  GITHUB_TOKEN non défini — les fixes GitHub ne seront pas récupérés")
        print("    Ajoutez dans .env : GITHUB_TOKEN=votre_token")
        print("    (Créez un token sur https://github.com/settings/tokens)\n")
    run()