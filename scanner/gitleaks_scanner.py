"""
scanner/gitleaks_scanner.py
Détecte les secrets hardcodés via GitLeaks ou regex fallback.
Supporte maintenant fichier OU dossier.
"""
import subprocess
import json
import os
import re
import tempfile
import uuid


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

SUPPORTED_SECRET_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php",
    ".go", ".rb", ".cpp", ".c", ".env", ".yml", ".yaml",
    ".json", ".xml", ".properties", ".cfg", ".conf"
}

IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"
}


def run_gitleaks(path):
    """Lance GitLeaks sur un fichier ou dossier."""
    path = os.path.realpath(path)
    findings = []

    try:
        report_path = os.path.join(
            tempfile.gettempdir(),
            f"patchmind_gitleaks_{uuid.uuid4().hex}.json"
        )

        result = subprocess.run(
            [
                "gitleaks", "detect",
                "--source", path,
                "--report-format", "json",
                "--report-path", report_path,
                "--no-git",
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        if os.path.exists(report_path):
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            finally:
                try:
                    os.remove(report_path)
                except OSError:
                    pass

            for item in (raw if isinstance(raw, list) else []):
                findings.append({
                    "tool": "gitleaks",
                    "type": "SECRET",
                    "cwe": "CWE-798",
                    "severity": "HIGH",
                    "rule": item.get("RuleID", "secret"),
                    "secret": (item.get("Secret", "")[:20] + "...") if item.get("Secret") else "",
                    "file": item.get("File", ""),
                    "line": item.get("StartLine", 0),
                    "description": f"Secret détecté : {item.get('Description', item.get('RuleID', ''))}",
                    "message": f"Secret hardcodé trouvé : {item.get('RuleID', '')}",
                    "source": "gitleaks",
                    "patchable": False,
                })

            print(f"  🔑 GitLeaks : {len(findings)} secret(s) trouvé(s)")
            return findings

        # GitLeaks peut retourner 0 finding sans fichier report.
        if result.returncode == 0:
            print("  🔑 GitLeaks : 0 secret(s) trouvé(s)")
            return []

    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  ⚠️  GitLeaks non installé ou timeout — scan par regex")
    except Exception as exc:
        print(f"  ⚠️  GitLeaks erreur — fallback regex : {exc}")

    findings = _regex_scan(path)
    print(f"  🔑 Regex scan : {len(findings)} secret(s) trouvé(s)")
    return findings


def _iter_target_files(path):
    """Retourne les fichiers à scanner depuis un fichier OU dossier."""
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        if ext in SUPPORTED_SECRET_EXTENSIONS:
            yield path
        return

    if not os.path.isdir(path):
        return

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SUPPORTED_SECRET_EXTENSIONS:
                continue

            if "_patched" in fname or "_temp_check" in fname:
                continue

            yield os.path.join(root, fname)


def _regex_scan(path):
    """Scan regex sur un fichier ou tous les fichiers supportés d'un dossier."""
    findings = []
    base_dir = path if os.path.isdir(path) else os.path.dirname(path)

    for fpath in _iter_target_files(path):
        fname = os.path.basename(fpath)

        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            continue

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            if stripped.startswith(("#", "//", "*", "<!--")):
                continue

            for rule, pattern in SECRET_PATTERNS.items():
                if re.search(pattern, line):
                    if any(fp in line.lower() for fp in [
                        "os.getenv", "os.environ", "process.env",
                        "System.getenv", "getenv", "placeholder",
                        "your_key_here", "example", "xxxx"
                    ]):
                        continue

                    findings.append({
                        "tool": "regex",
                        "type": "SECRET",
                        "cwe": "CWE-798",
                        "severity": "HIGH",
                        "rule": rule,
                        "file": os.path.relpath(fpath, base_dir) if base_dir else fpath,
                        "line": i,
                        "description": f"Secret potentiel détecté : {rule}",
                        "message": f"Valeur secrète hardcodée ({rule})",
                        "source": "gitleaks",
                        "patchable": False,
                    })
                    break

    return findings