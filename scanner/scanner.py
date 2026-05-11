import subprocess
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scanner.cwe_resolver import resolve_cwe as _resolve_cwe
except ImportError:
    def _resolve_cwe(f):
        return f.get("cwe", "CWE-UNKNOWN")


def _resolve_semgrep() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    env_path = os.environ.get("SEMGREP_PATH", "")
    if env_path and os.path.isfile(env_path):
        return env_path

    candidates = [
        os.path.join(root, "venv", "Scripts", "semgrep.exe"),
        os.path.join(root, "venv", "Scripts", "pysemgrep.exe"),
        os.path.join(root, "venv", "bin", "semgrep"),
        os.path.join(root, ".venv", "Scripts", "semgrep.exe"),
        os.path.join(root, ".venv", "Scripts", "pysemgrep.exe"),
        os.path.join(root, ".venv", "bin", "semgrep"),
    ]

    for path in candidates:
        if os.path.isfile(path):
            return path

    return shutil.which("semgrep") or ""


SEMGREP_PATH = _resolve_semgrep()


SUPPORTED_EXTENSIONS = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".mjs"],
    "typescript": [".ts", ".tsx"],
    "java": [".java"],
    "php": [".php"],
    "go": [".go"],
    "ruby": [".rb"],
    "c": [".c", ".h"],
    "cpp": [".cpp", ".cc", ".cxx", ".hpp"],
    "kotlin": [".kt"],
    "swift": [".swift"],
    "rust": [".rs"],
    "scala": [".scala"],
    "dockerfile": ["Dockerfile"],
    "yaml": [".yml", ".yaml"],
}

ALL_EXTENSIONS = [ext for exts in SUPPORTED_EXTENSIONS.values() for ext in exts]


def detect_language(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    filename = os.path.basename(file_path)

    for lang, extensions in SUPPORTED_EXTENSIONS.items():
        if ext in extensions or filename in extensions:
            return lang

    return "unknown"


def is_supported_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    filename = os.path.basename(file_path)
    return ext in ALL_EXTENSIONS or filename in ALL_EXTENSIONS


def _normalize_severity(raw):
    raw = str(raw or "MEDIUM").upper()

    severity_map = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "INFO": "LOW",
        "INFORMATIONAL": "LOW",
        "NOTE": "LOW",
    }

    normalized = severity_map.get(raw, raw)

    if normalized not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return "MEDIUM"

    return normalized


def _extract_json_from_semgrep_output(output):
    if not output:
        return None

    json_start = output.find("{")
    if json_start == -1:
        return None

    try:
        return json.loads(output[json_start:])
    except json.JSONDecodeError:
        return None


def run_scan(file_path):
    """
    Lance Semgrep sur un fichier et retourne les vulnérabilités patchables.
    Retourne [] si Semgrep est absent, cassé ou si le fichier n'est pas supporté.
    """

    if not is_supported_file(file_path):
        return []

    if not SEMGREP_PATH:
        print(
            "⚠️ Semgrep introuvable — scan SAST ignoré. "
            "Installez Semgrep : pip install semgrep ou définissez SEMGREP_PATH."
        )
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
        print(f"⚠️ Semgrep introuvable à '{SEMGREP_PATH}' — scan ignoré.")
        return []
    except subprocess.TimeoutExpired:
        print(f"⚠️ Semgrep timeout sur {os.path.basename(file_path)}")
        return []
    except Exception as exc:
        msg = str(exc)
        if "pkg_resources" in msg:
            print("⚠️ Semgrep erreur : pkg_resources manquant. Essayez : python -m pip install 'setuptools<81'")
        else:
            print(f"⚠️ Semgrep erreur : {exc}")
        return []

    combined_output = (result.stdout or "").strip()

    if not combined_output:
        stderr = (result.stderr or "").strip()
        if "pkg_resources" in stderr:
            print("⚠️ Semgrep erreur : pkg_resources manquant. Essayez : python -m pip install 'setuptools<81'")
        elif stderr:
            print(f"⚠️ Semgrep stderr : {stderr[:300]}")
        return []

    data = _extract_json_from_semgrep_output(combined_output)

    if data is None:
        print(f"⚠️ Semgrep sortie JSON invalide pour {os.path.basename(file_path)}")
        return []

    vulnerabilities = []

    for finding in data.get("results", []):
        try:
            extra = finding.get("extra", {}) or {}
            meta = extra.get("metadata", {}) or {}

            cwe_raw = meta.get("cwe", "")
            if isinstance(cwe_raw, list):
                cwe_raw = cwe_raw[0] if cwe_raw else ""
            else:
                cwe_raw = str(cwe_raw) if cwe_raw else ""

            message = extra.get("message", "") or finding.get("check_id", "Semgrep finding")
            severity = _normalize_severity(extra.get("severity", "MEDIUM"))

            vuln = {
                "scanner": "semgrep",
                "source": "semgrep",
                "type": "SAST",
                "category": "code",
                "patchable": True,

                "file": finding.get("path", file_path),
                "line": finding.get("start", {}).get("line", 0),
                "rule": finding.get("check_id", ""),
                "severity": severity,
                "message": message,
                "cwe": cwe_raw,
                "language": lang,

                "raw": finding,
            }

            vuln["cwe"] = _resolve_cwe(vuln)
            vulnerabilities.append(vuln)

        except Exception as exc:
            print(f"⚠️ Semgrep finding ignoré : {exc}")
            continue

    print(f"  ✅ Semgrep : {len(vulnerabilities)} vulnérabilité(s) patchable(s)")
    return vulnerabilities


def scan_directory(directory_path):
    all_vulns = []
    scanned = 0

    for root, dirs, files in os.walk(directory_path):
        dirs[:] = [
            d for d in dirs
            if d not in ["venv", ".git", "__pycache__", "node_modules", ".env", "dist", "build"]
        ]

        for filename in files:
            filepath = os.path.join(root, filename)
            if is_supported_file(filepath):
                all_vulns.extend(run_scan(filepath))
                scanned += 1

    print(f"📊 {scanned} fichier(s) scannés — {len(all_vulns)} vulnérabilité(s) trouvée(s)")
    return all_vulns


if __name__ == "__main__":
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
        print(f"  🔧 Patchable : {v['patchable']}")
        print()