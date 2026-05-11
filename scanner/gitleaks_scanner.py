"""
scanner/gitleaks_scanner.py
Détecte les secrets hardcodés (API keys, passwords, tokens)
via GitLeaks ou par patterns regex si GitLeaks non installé.
"""
import subprocess
import json
import os
import re

# Patterns regex de secours si GitLeaks non installé
SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
    "AWS_SECRET_KEY": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "GITHUB_TOKEN":   r"ghp_[a-zA-Z0-9]{36}",
    "GOOGLE_API_KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "STRIPE_KEY":     r"sk_live_[0-9a-zA-Z]{24}",
    "JWT_SECRET":     r"(?i)(jwt.?secret|secret.?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "HARDCODED_PASS": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
    "HARDCODED_KEY":  r"(?i)(api.?key|apikey|api_token)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "PRIVATE_KEY":    r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "GENERIC_SECRET": r"(?i)(secret|token)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
}

def run_gitleaks(path):
    """Lance GitLeaks sur un repo ou dossier."""
    findings = []

    # Essayer GitLeaks d'abord
    try:
        report_path = os.path.join(os.path.dirname(path), "gitleaks_report.json")
        result = subprocess.run(
            ["gitleaks", "detect", "--source", path,
             "--report-format", "json",
             "--report-path", report_path,
             "--no-git"],
            capture_output=True, text=True, timeout=60
        )
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            os.remove(report_path)
            for item in (raw if isinstance(raw, list) else []):
                findings.append({
                    "tool":        "gitleaks",
                    "type":        "SECRET",
                    "cwe":         "CWE-798",
                    "severity":    "HIGH",
                    "rule":        item.get("RuleID", "secret"),
                    "secret":      item.get("Secret", "")[:20] + "...",
                    "file":        item.get("File", ""),
                    "line":        item.get("StartLine", 0),
                    "description": f"Secret détecté : {item.get('Description', item.get('RuleID',''))}",
                    "message":     f"Secret hardcodé trouvé : {item.get('RuleID','')}",
                })
            print(f"  🔑 GitLeaks : {len(findings)} secret(s) trouvé(s)")
            return findings
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  ⚠️  GitLeaks non installé — scan par regex")

    # Fallback : scan regex
    findings = _regex_scan(path)
    print(f"  🔑 Regex scan : {len(findings)} secret(s) trouvé(s)")
    return findings


def _regex_scan(path):
    """Scan regex sur tous les fichiers supportés."""
    findings = []
    EXTENSIONS = {'.py','.js','.ts','.jsx','.tsx','.java','.php',
                  '.go','.rb','.cpp','.c','.env','.yml','.yaml',
                  '.json','.xml','.properties','.cfg','.conf'}

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in
                   ['.git','node_modules','venv','__pycache__','dist','build']]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except Exception:
                continue

            for i, line in enumerate(lines, 1):
                # Ignorer les commentaires et les tests
                stripped = line.strip()
                if stripped.startswith(('#','//','*','<!--')):
                    continue
                if 'test' in fname.lower() or 'example' in fname.lower():
                    continue

                for rule, pattern in SECRET_PATTERNS.items():
                    if re.search(pattern, line):
                        # Éviter les faux positifs évidents
                        if any(fp in line.lower() for fp in
                               ['os.getenv','os.environ','process.env',
                                'System.getenv','getenv','placeholder',
                                'your_key_here','example','xxxx']):
                            continue
                        findings.append({
                            "tool":        "regex",
                            "type":        "SECRET",
                            "cwe":         "CWE-798",
                            "severity":    "HIGH",
                            "rule":        rule,
                            "file":        os.path.relpath(fpath, path),
                            "line":        i,
                            "description": f"Secret potentiel détecté : {rule}",
                            "message":     f"Valeur secrète hardcodée ({rule})",
                        })
                        break  # Une seule alerte par ligne
    return findings