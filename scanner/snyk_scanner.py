"""
scanner/snyk_scanner.py
Détecte les dépendances vulnérables via Snyk CLI ou OSV API (fallback).
"""
import subprocess
import json
import os
import requests

# Fichiers de dépendances par langage
DEPENDENCY_FILES = {
    "python":     ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py"],
    "javascript": ["package.json", "yarn.lock", "package-lock.json"],
    "java":       ["pom.xml", "build.gradle"],
    "php":        ["composer.json"],
    "go":         ["go.mod"],
    "ruby":       ["Gemfile", "Gemfile.lock"],
}

ECOSYSTEM_MAP = {
    "requirements.txt": "PyPI",
    "Pipfile":          "PyPI",
    "pyproject.toml":   "PyPI",
    "package.json":     "npm",
    "package-lock.json":"npm",
    "yarn.lock":        "npm",
    "pom.xml":          "Maven",
    "build.gradle":     "Maven",
    "composer.json":    "Packagist",
    "go.mod":           "Go",
    "Gemfile":          "RubyGems",
}


def run_snyk(path):
    """Lance Snyk sur un projet ou fallback OSV."""
    findings = []

    # Chercher les fichiers de dépendances
    dep_files = _find_dependency_files(path)
    if not dep_files:
        print("  ⚠️  Aucun fichier de dépendances trouvé")
        return []

    print(f"  📦 Fichiers détectés : {[os.path.basename(f) for f in dep_files]}")

    # Essayer Snyk d'abord
    snyk_ok = _try_snyk(path, findings)
    if snyk_ok:
        return findings

    # Fallback : OSV API
    print("  ⚠️  Snyk non disponible — scan OSV API")
    for dep_file in dep_files:
        _scan_with_osv(dep_file, findings)

    print(f"  📦 Snyk/OSV : {len(findings)} vulnérabilité(s) de dépendances")
    return findings


def _find_dependency_files(path):
    """Trouve tous les fichiers de dépendances."""
    found = []
    all_dep_files = [f for files in DEPENDENCY_FILES.values() for f in files]
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in
                   ['node_modules','venv','.git','__pycache__']]
        for fname in files:
            if fname in all_dep_files:
                found.append(os.path.join(root, fname))
    return found


def _try_snyk(path, findings):
    """Essaie de lancer Snyk CLI."""
    try:
        result = subprocess.run(
            ["snyk", "test", "--json", "--all-projects", path],
            capture_output=True, text=True, timeout=120
        )
        data = json.loads(result.stdout) if result.stdout else {}
        vulns = data.get("vulnerabilities", [])
        for v in vulns:
            findings.append({
                "tool":        "snyk",
                "type":        "DEPENDENCY",
                "cwe":         v.get("identifiers", {}).get("CWE", ["CWE-1035"])[0],
                "severity":    v.get("severity", "medium").upper(),
                "package":     v.get("packageName", ""),
                "version":     v.get("version", ""),
                "fix_version": v.get("fixedIn", [""])[0] if v.get("fixedIn") else "",
                "cve":         v.get("identifiers", {}).get("CVE", [""])[0],
                "description": v.get("title", ""),
                "message":     f"Dépendance vulnérable : {v.get('packageName')} {v.get('version')}",
                "file":        v.get("from", [""])[0],
                "line":        0,
            })
        return len(vulns) > 0
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return False


def _scan_with_osv(dep_file, findings):
    """Scan via OSV API pour un fichier de dépendances."""
    fname    = os.path.basename(dep_file)
    ecosystem = ECOSYSTEM_MAP.get(fname, "PyPI")
    packages = _parse_dependencies(dep_file, ecosystem)

    for pkg_name, pkg_version in packages[:20]:  # Max 20 packages
        try:
            resp = requests.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"ecosystem": ecosystem, "name": pkg_name},
                      "version": pkg_version} if pkg_version else
                     {"package": {"ecosystem": ecosystem, "name": pkg_name}},
                timeout=10
            )
            vulns = resp.json().get("vulns", [])
            for v in vulns[:3]:  # Max 3 vulns par package
                summary = v.get("summary", "")
                severity = "HIGH"
                for s in v.get("database_specific", {}).get("severity", []):
                    if isinstance(s, str):
                        severity = s.upper()
                        break
                findings.append({
                    "tool":        "osv",
                    "type":        "DEPENDENCY",
                    "cwe":         "CWE-1035",
                    "severity":    severity,
                    "package":     pkg_name,
                    "version":     pkg_version,
                    "fix_version": _get_fix_version(v),
                    "cve":         v.get("id", ""),
                    "description": summary[:200],
                    "message":     f"Dépendance vulnérable : {pkg_name} {pkg_version}",
                    "file":        os.path.basename(dep_file),
                    "line":        0,
                })
        except Exception:
            continue


def _parse_dependencies(dep_file, ecosystem):
    """Parse un fichier de dépendances."""
    packages = []
    try:
        with open(dep_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        if ecosystem == "PyPI" and "requirements" in dep_file:
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '>=' in line or '==' in line:
                    parts = line.replace('>=','==').split('==')
                    packages.append((parts[0].strip(), parts[1].strip() if len(parts)>1 else ""))
                elif line and not line.startswith('-'):
                    packages.append((line, ""))

        elif ecosystem == "npm":
            import json as _json
            try:
                data = _json.loads(content)
                for pkg, ver in {**data.get("dependencies",{}),
                                  **data.get("devDependencies",{})}.items():
                    packages.append((pkg, ver.lstrip('^~>=').split('.')[0] if ver else ""))
            except Exception:
                pass

    except Exception:
        pass
    return packages[:30]


def _get_fix_version(vuln):
    """Extrait la version corrigée depuis une entrée OSV."""
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev:
                    return ev["fixed"]
    return ""