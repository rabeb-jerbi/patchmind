# -*- coding: utf-8 -*-
import subprocess
import json
import os

import shutil
SEMGREP_PATH = shutil.which("semgrep") or "semgrep"
# Extensions supportÃ©es par langage
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
    """DÃ©tecte le langage d'un fichier."""
    ext = os.path.splitext(file_path)[1].lower()
    filename = os.path.basename(file_path)
    
    for lang, extensions in SUPPORTED_EXTENSIONS.items():
        if ext in extensions or filename in extensions:
            return lang
    return "unknown"

def is_supported_file(file_path):
    """VÃ©rifie si le fichier est supportÃ©."""
    ext = os.path.splitext(file_path)[1].lower()
    filename = os.path.basename(file_path)
    return ext in ALL_EXTENSIONS or filename in ALL_EXTENSIONS

def run_scan(file_path):
    """Lance Semgrep sur un fichier et retourne les vulnÃ©rabilitÃ©s."""
    
    if not is_supported_file(file_path):
        return []
    
    lang = detect_language(file_path)
    print(f"ðŸ” Scan de : {os.path.basename(file_path)} ({lang})")
    
    result = subprocess.run(
        [SEMGREP_PATH, "--config=auto", "--json", file_path],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )
    
    output = result.stdout.strip()
    if not output:
        return []
    
    json_start = output.find('{')
    if json_start == -1:
        return []
    
    data = json.loads(output[json_start:])
    
    vulnerabilities = []
    for finding in data.get("results", []):
        vuln = {
            "file":     finding["path"],
            "line":     finding["start"]["line"],
            "rule":     finding["check_id"],
            "severity": finding["extra"]["severity"],
            "message":  finding["extra"]["message"],
            "cwe":      finding["extra"]["metadata"].get("cwe", ["UNKNOWN"])[0],
            "language": lang
        }
        vulnerabilities.append(vuln)
    
    return vulnerabilities


def scan_directory(directory_path):
    """Scanne tous les fichiers supportÃ©s dans un dossier."""
    
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
    
    print(f"ðŸ“Š {scanned} fichier(s) scannÃ©s â€” {len(all_vulns)} vulnÃ©rabilitÃ©(s) trouvÃ©e(s)")
    return all_vulns


if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "test_vuln.py"
    
    if os.path.isdir(target):
        results = scan_directory(target)
    else:
        results = run_scan(target)
    
    print(f"\nâœ… {len(results)} vulnÃ©rabilitÃ©(s) :\n")
    for v in results:
        print(f"  ðŸ“ {v['file']} ({v['language']})")
        print(f"  ðŸ“ Ligne     : {v['line']}")
        print(f"  ðŸ·ï¸  CWE       : {v['cwe']}")
        print(f"  âš ï¸  SÃ©vÃ©ritÃ©  : {v['severity']}")
        print()
