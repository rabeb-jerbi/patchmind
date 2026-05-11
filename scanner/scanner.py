import subprocess
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from scanner.cwe_resolver import resolve_cwe as _resolve_cwe
except ImportError:
    def _resolve_cwe(f): return f.get("cwe", "CWE-UNKNOWN")

def _resolve_semgrep() -> str:
    """
    Resolve the semgrep executable path using multiple strategies:
    1. SEMGREP_PATH environment variable
    2. Local venv (Windows)
    3. Local venv (Linux/Mac)
    4. shutil.which("semgrep")
    Returns empty string if not found.
    """
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # 1 — explicit override
    env_path = os.environ.get("SEMGREP_PATH", "")
    if env_path and os.path.isfile(env_path):
        return env_path

    # 2/3 — local venv candidates
    candidates = [
        os.path.join(_root, "venv", "Scripts", "semgrep.exe"),   # Windows
        os.path.join(_root, "venv", "bin", "semgrep"),             # Linux/Mac
        os.path.join(_root, ".venv", "Scripts", "semgrep.exe"),
        os.path.join(_root, ".venv", "bin", "semgrep"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c

    # 4 — PATH
    found = shutil.which("semgrep")
    if found:
        return found

    return ""

SEMGREP_PATH = _resolve_semgrep()

# Extensions supportées par langage
SUPPORTED_EXTENSIONS = {
    "python":     [".py"],
    "javascript": [".js", ".jsx", ".mjs"],
    "typescript": [".ts", ".tsx"],
    "java":       [".java"],
    "php":        [".php"],
    "go":         [".go"],
    "ruby":       [".rb"],
    "c":          [".c", ".h"],
    "cpp":        [".cpp", ".cc", ".cxx", ".hpp"],
    "kotlin":     [".kt"],
    "swift":      [".swift"],
    "rust":       [".rs"],
    "scala":      [".scala"],
    "dockerfile": ["Dockerfile"],
    "yaml":       [".yml", ".yaml"],
}

ALL_EXTENSIONS = [ext for exts in SUPPORTED_EXTENSIONS.values() for ext in exts]

def detect_language(file_path):
    """Détecte le langage d'un fichier."""
    ext = os.path.splitext(file_path)[1].lower()
    filename = os.path.basename(file_path)
    
    for lang, extensions in SUPPORTED_EXTENSIONS.items():
        if ext in extensions or filename in extensions:
            return lang
    return "unknown"

def is_supported_file(file_path):
    """Vérifie si le fichier est supporté."""
    ext = os.path.splitext(file_path)[1].lower()
    filename = os.path.basename(file_path)
    return ext in ALL_EXTENSIONS or filename in ALL_EXTENSIONS

def run_scan(file_path):
    """
    Lance Semgrep sur un fichier et retourne les vulnérabilités.
    Retourne [] si Semgrep est absent ou si le fichier n'est pas supporté.
    Ne lève jamais d'exception.
    """
    if not is_supported_file(file_path):
        return []

    if not SEMGREP_PATH:
        print("⚠️  Semgrep introuvable — scan SAST ignoré. "
              "Installez Semgrep : pip install semgrep  "
              "ou définissez SEMGREP_PATH.")
        return []

    lang = detect_language(file_path)
    print(f"🔍 Scan de : {os.path.basename(file_path)} ({lang})")

    try:
        result = subprocess.run(
            [SEMGREP_PATH, "--config=auto", "--json", file_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=120,
        )
    except FileNotFoundError:
        print(f"⚠️  Semgrep introuvable à '{SEMGREP_PATH}' — scan ignoré.")
        return []
    except subprocess.TimeoutExpired:
        print(f"⚠️  Semgrep timeout sur {os.path.basename(file_path)}")
        return []
    except Exception as exc:
        print(f"⚠️  Semgrep erreur : {exc}")
        return []

    output = result.stdout.strip()
    if not output:
        return []

    json_start = output.find('{')
    if json_start == -1:
        return []

    try:
        data = json.loads(output[json_start:])
    except json.JSONDecodeError:
        print(f"⚠️  Semgrep sortie JSON invalide pour {os.path.basename(file_path)}")
        return []

    vulnerabilities = []
    for finding in data.get("results", []):
        try:
            extra   = finding.get("extra", {})
            meta    = extra.get("metadata", {})
            cwe_raw = meta.get("cwe", "")
            if isinstance(cwe_raw, list):
                cwe_raw = cwe_raw[0] if cwe_raw else ""
            else:
                cwe_raw = str(cwe_raw) if cwe_raw else ""
            vuln = {
                "file":     finding.get("path", ""),
                "line":     finding.get("start", {}).get("line", 0),
                "rule":     finding.get("check_id", ""),
                "severity": extra.get("severity", "MEDIUM"),
                "message":  extra.get("message", ""),
                "cwe":      cwe_raw,
                "language": lang,
            }
            vuln["cwe"] = _resolve_cwe(vuln)
            vulnerabilities.append(vuln)
        except Exception:
            continue

    return vulnerabilities


def scan_directory(directory_path):
    """Scanne tous les fichiers supportés dans un dossier."""
    
    all_vulns = []
    scanned   = 0
    
    for root, dirs, files in os.walk(directory_path):
        dirs[:] = [d for d in dirs if d not in [
            'venv', '.git', '__pycache__', 
            'node_modules', '.env', 'dist', 'build'
        ]]
        
        for filename in files:
            filepath = os.path.join(root, filename)
            if is_supported_file(filepath):
                vulns = run_scan(filepath)
                all_vulns.extend(vulns)
                scanned += 1
    
    print(f"📊 {scanned} fichier(s) scannés — {len(all_vulns)} vulnérabilité(s) trouvée(s)")
    return all_vulns


if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "test_vuln.py"
    
    if os.path.isdir(target):
        results = scan_directory(target)
    else:
        results = run_scan(target)
    
    print(f"\n✅ {len(results)} vulnérabilité(s) :\n")
    for v in results:
        print(f"  📁 {v['file']} ({v['language']})")
        print(f"  📍 Ligne     : {v['line']}")
        print(f"  🏷️  CWE       : {v['cwe']}")
        print(f"  ⚠️  Sévérité  : {v['severity']}")
        print()