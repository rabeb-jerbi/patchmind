import os
import re
import json
import hashlib
import time
import sys

from groq import Groq
from dotenv import load_dotenv

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rag.rag import search_similar_fixes, get_cwe_description

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# ── Rotation de modèles gratuits ─────────────────────────────────────────────
MODELS = [
    "llama-3.3-70b-versatile",        # Principal — production stable
    "llama-3.1-8b-instant",           # Rapide — fallback rate limit
    "meta-llama/llama-4-scout-17b-16e-instruct",  # Llama 4 Scout — preview
    "qwen/qwen-3-32b",                # Qwen 3 — bon alternatif
]
_model_index = [0]  # Index courant (liste pour mutabilité)

def _get_next_model():
    """Retourne le modèle courant et passe au suivant si rate limit."""
    return MODELS[_model_index[0] % len(MODELS)]

def _rotate_model():
    """Passe au modèle suivant."""
    _model_index[0] = (_model_index[0] + 1) % len(MODELS)
    print(f"🔄 Rotation → {MODELS[_model_index[0]]}")

# ── Cache ─────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_FILE = os.path.join(BASE_DIR, "data", "patch_cache.json")

def _load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_cache(cache):
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️  Cache save error: {e}")

def _cache_key(cwe, lang, code_snippet):
    """Clé unique : CWE + langage + hash du snippet vulnérable."""
    normalized = re.sub(r'\s+', ' ', code_snippet.strip())
    content    = f"{cwe}::{lang}::{normalized}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]

def _extract_vuln_snippet(code, line_num, context=5):
    """Extrait les lignes autour de la vulnérabilité."""
    lines = code.split('\n')
    start = max(0, line_num - context - 1)
    end   = min(len(lines), line_num + context)
    return '\n'.join(lines[start:end])

def get_from_cache(cwe, lang, code, line):
    """Cherche un patch dans le cache. Retourne le patch ou None."""
    cache   = _load_cache()
    snippet = _extract_vuln_snippet(code, line)
    key     = _cache_key(cwe, lang, snippet)
    entry   = cache.get(key)
    if entry:
        # Incrémenter le compteur de hits
        entry["hits"] = entry.get("hits", 0) + 1
        _save_cache(cache)
        print(f"⚡ Cache HIT — patch réutilisé ({cwe} {lang}) — économie ~20s + 1 appel LLM")
        return entry["fixed_code"]
    return None

def save_to_cache(cwe, lang, code, line, fixed_code):
    """Sauvegarde un patch validé dans le cache."""
    cache   = _load_cache()
    snippet = _extract_vuln_snippet(code, line)
    key     = _cache_key(cwe, lang, snippet)
    cache[key] = {
        "cwe":        cwe,
        "lang":       lang,
        "fixed_code": fixed_code,
        "snippet":    snippet[:200],
        "hits":       0,
        "saved_at":   time.strftime("%Y-%m-%d %H:%M:%S")
    }
    _save_cache(cache)
    print(f"💾 Patch mis en cache : {cwe} ({lang})")

def get_cache_stats():
    """Retourne les statistiques du cache."""
    cache      = _load_cache()
    total_hits = sum(e.get("hits", 0) for e in cache.values())
    by_cwe     = {}
    for entry in cache.values():
        cwe = entry.get("cwe", "unknown")
        by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
    return {
        "total_entries":   len(cache),
        "total_hits":      total_hits,
        "llm_calls_saved": total_hits,
        "time_saved_sec":  total_hits * 20,
        "by_cwe":          by_cwe
    }

# ── Règles par langage ────────────────────────────────────────────────────────
LANGUAGE_RULES = {
    "python": """
- CWE-89  : utilise les paramètres préparés (?, %s)
- CWE-79  : utilise markupsafe.escape() ou render_template_string
- CWE-22  : utilise os.path.basename() + os.path.realpath()
- CWE-78  : utilise subprocess avec shell=False
- CWE-95  : utilise ast.literal_eval()
- CWE-327 : remplace MD5/SHA1 par SHA-256
- CWE-502 : remplace pickle par json
""",
    "javascript": """
- CWE-89  : utilise des requêtes préparées (?, $1) ou ORM
- CWE-79  : utilise DOMPurify.sanitize() ou textContent
- CWE-22  : utilise path.resolve() + vérification du chemin
- CWE-78  : utilise execFile() au lieu de exec()
- CWE-327 : utilise crypto.createHash('sha256')
- CWE-502 : valide avec JSON.parse() + try/catch
""",
    "java": """
- CWE-89  : utilise PreparedStatement
- CWE-79  : utilise OWASP Java HTML Sanitizer
- CWE-22  : utilise Paths.get().normalize()
- CWE-78  : utilise ProcessBuilder avec liste
- CWE-327 : utilise MessageDigest SHA-256
- CWE-502 : utilise ObjectInputStream avec whitelist
""",
    "php": """
- CWE-89  : utilise PDO avec prepare/execute
- CWE-79  : utilise htmlspecialchars()
- CWE-22  : utilise realpath() + basename()
- CWE-78  : utilise escapeshellarg()
- CWE-327 : utilise password_hash() avec PASSWORD_BCRYPT
""",
    "go": """
- CWE-89  : utilise db.Query avec placeholders (?)
- CWE-79  : utilise html/template
- CWE-22  : utilise filepath.Clean()
- CWE-78  : utilise exec.Command avec args séparés
""",
    "ruby": """
- CWE-89  : utilise des requêtes paramétrées ActiveRecord (?, :name)
- CWE-79  : utilise html_escape() ou ERB::Util.html_escape()
- CWE-22  : utilise File.expand_path + vérification du préfixe
- CWE-78  : utilise system() avec liste d'args
""",
    "kotlin": """
- CWE-89  : utilise PreparedStatement ou Room avec @Query paramétré
- CWE-79  : utilise HtmlCompat.fromHtml() ou encodeHtml()
- CWE-22  : utilise File.canonicalPath + vérification du préfixe
- CWE-78  : utilise ProcessBuilder avec liste d'args
- CWE-327 : utilise MessageDigest.getInstance("SHA-256")
""",
    "swift": """
- CWE-89  : utilise des requêtes préparées SQLite3 ou CoreData
- CWE-79  : utilise addingPercentEncoding ou HTMLString
- CWE-22  : utilise URL.standardized + vérifier le préfixe autorisé
- CWE-327 : utilise CryptoKit SHA256 au lieu de MD5/SHA1
- CWE-798 : utilise Keychain au lieu de variables hardcodées
""",
    "rust": """
- CWE-89  : utilise sqlx avec requêtes paramétrées (bind)
- CWE-22  : utilise std::fs::canonicalize() + vérifier le préfixe
- CWE-78  : utilise std::process::Command avec args séparés
- CWE-327 : utilise sha2 crate au lieu de md5
- CWE-798 : utilise std::env::var() pour les secrets
""",
    "default": """
- Applique les meilleures pratiques de sécurité pour ce langage
- Utilise les paramètres préparés pour les requêtes SQL
- Échappe les sorties HTML
- Valide et sanitise toutes les entrées utilisateur
"""
}

# ── Génération ────────────────────────────────────────────────────────────────

def generate_patch(vuln, _attempt=0):
    """
    Génère un patch avec 3 niveaux :
    1. Cache → instantané, 0 appel LLM
    2. RAG   → exemples similaires
    3. LLM   → Groq Llama 3.3 (si pas en cache)
    """
    MAX_GLOBAL_RETRIES = 3
    if _attempt >= MAX_GLOBAL_RETRIES:
        print(f"❌ Abandon après {MAX_GLOBAL_RETRIES} tentatives globales.")
        return ""
    print(f"🤖 Génération patch pour : {vuln['cwe']}")

    try:
        with open(vuln["file"], "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except FileNotFoundError:
        print(f"❌ Fichier non trouvé : {vuln['file']}")
        return ""

    lang = vuln.get("language", "python")
    cwe  = vuln["cwe"].split(":")[0].strip()
    line = vuln.get("line", 0)

    # ── 1. Cache lookup ───────────────────────────────────────────────────────
    cached = get_from_cache(cwe, lang, code, line)
    if cached:
        return cached

    # ── 2. RAG ────────────────────────────────────────────────────────────────
    lang_rules  = LANGUAGE_RULES.get(lang, LANGUAGE_RULES["default"])
    cwe_info    = get_cwe_description(vuln["cwe"])
    cwe_context = ""
    if cwe_info:
        cwe_context = f"""
## Description officielle MITRE
- Nom        : {cwe_info['name']}
- Sévérité   : {cwe_info['severity']}
- Description: {cwe_info['description'][:300]}
"""

    print(f"🔍 Recherche d'exemples similaires...")
    fixes    = search_similar_fixes(code, vuln["cwe"])
    examples = ""
    for i, fix in enumerate(fixes, 1):
        examples += f"\nExemple {i} ({fix['cwe']}) :\n  Vulnérable : {fix['vulnerable']}\n  Corrigé    : {fix['fixed']}\n"
    print(f"✅ {len(fixes)} exemple(s) trouvé(s) via RAG")

    # ── 3. LLM ────────────────────────────────────────────────────────────────
    prompt = f"""Tu es un expert en sécurité {lang}. Corrige cette vulnérabilité.

## Règles importantes pour {lang}
{lang_rules}

## Vulnérabilité détectée
- CWE      : {vuln['cwe']}
- Fichier  : {vuln['file']}
- Ligne    : {vuln['line']}
- Sévérité : {vuln['severity']}
- Message  : {vuln['message']}
{cwe_context}

## Exemples réels de corrections similaires
{examples}

## Code vulnérable à corriger
```{lang}
{code}
```

## Ta tâche
1. Inspire-toi des exemples et de la description officielle MITRE
2. Corrige UNIQUEMENT la vulnérabilité détectée
3. Ne change rien d'autre
4. Retourne UNIQUEMENT le code corrigé complet, sans explication
"""

    for _ in range(len(MODELS) * 2):  # Essayer tous les modèles x2
        model = _get_next_model()
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1
            )
            fixed_code = response.choices[0].message.content
            # Supprimer les balises markdown quel que soit le langage
            fixed_code = re.sub(r"^```[a-zA-Z0-9+#]*\n?", "", fixed_code.strip())
            fixed_code = re.sub(r"\n?```$", "", fixed_code).strip()
            return fixed_code

        except Exception as e:
            if "429" in str(e) or "rate_limit" in str(e).lower():
                print(f"⏳ Rate limit sur {model} — rotation modèle...")
                _rotate_model()
                time.sleep(5)
            else:
                raise e

    print("❌ Tous les modèles en rate limit — attente 60s...")
    time.sleep(60)
    return generate_patch(vuln, _attempt + 1)


TEST_FRAMEWORK = {
    "python":     "pytest",
    "javascript": "jest",
    "typescript": "jest",
    "java":       "junit",
    "kotlin":     "junit",
    "php":        "phpunit",
    "go":         "go test",
    "ruby":       "rspec",
    "rust":       "cargo test",
    "swift":      "xctest",
    "default":    "pytest",
}

TOOL_HINTS = {
    "python":     "bandit, safety, semgrep",
    "javascript": "eslint-plugin-security, retire.js, npm audit",
    "java":       "SpotBugs, OWASP Dependency-Check, Checkmarx",
    "php":        "RIPS, phpstan, psalm",
    "go":         "gosec, nancy, govulncheck",
    "ruby":       "brakeman, bundler-audit",
    "rust":       "cargo-audit, cargo-geiger",
    "default":    "OWASP ZAP, Snyk, SonarQube",
}

def generate_suggestions(vuln, fixed_code):
    """
    Second LLM call — returns {tools: [...], test_code: str}.
    Falls back to {} on any error to avoid blocking the pipeline.
    """
    lang      = vuln.get("language", "python")
    cwe       = vuln["cwe"].split(":")[0].strip()
    framework = TEST_FRAMEWORK.get(lang, TEST_FRAMEWORK["default"])
    hints     = TOOL_HINTS.get(lang, TOOL_HINTS["default"])

    prompt = f"""You are a security expert. Given this patched vulnerability, return ONLY valid JSON.

Vulnerability: {cwe} in {lang} at line {vuln.get('line',0)}
Fixed code snippet (first 300 chars): {fixed_code[:300]}
Already used scanners: Semgrep, GitLeaks, Snyk/OSV
Known tools for {lang}: {hints}
Test framework: {framework}

Return ONLY this JSON (no markdown, no explanation):
{{
  "tools": [
    {{"name": "ToolName", "description": "One sentence what it does", "url": "https://...", "install_cmd": "pip install toolname", "run_cmd": "toolname scan ."}}
  ],
  "test_code": "// {framework} test that verifies the {cwe} vulnerability is fixed\\n..."
}}

Rules:
- Suggest 2-3 tools NOT already listed above that are relevant for {cwe} in {lang}
- install_cmd: the exact shell command to install the tool (pip install / npm install)
- run_cmd: a safe read-only scan command (no destructive options)
- test_code must be a real {framework} unit test for this specific vulnerability
- Return ONLY JSON, no preamble
"""
    for _ in range(len(MODELS)):
        model = _get_next_model()
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=800,
            )
            raw = resp.choices[0].message.content.strip()
            raw = re.sub(r"^```[a-zA-Z0-9]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw).strip()
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
        except Exception as e:
            if "429" in str(e) or "rate_limit" in str(e).lower():
                _rotate_model()
                time.sleep(3)
            else:
                return {}
    return {}


if __name__ == "__main__":
    print("📊 Stats cache :", get_cache_stats())
    vuln = {
        "file":     "test_vuln.py",
        "line":     7,
        "severity": "ERROR",
        "cwe":      "CWE-89",
        "language": "python",
        "message":  "SQL Injection detected"
    }
    fixed = generate_patch(vuln)
    print("\n✅ Code corrigé :\n")
    print(fixed)