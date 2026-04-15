"""
scanner/unified_scanner.py
Orchestre tous les scanners : Semgrep + GitLeaks + Snyk/OSV + ZAP
"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.scanner         import run_scan
from scanner.gitleaks_scanner import run_gitleaks
from scanner.snyk_scanner    import run_snyk
from scanner.zap_scanner     import run_zap


def run_full_scan(file_paths, target_url=None, enable_zap=False):
    """
    Lance tous les scanners sur les fichiers donnés.

    file_paths  : liste de fichiers ou 1 dossier racine
    target_url  : URL de l'app pour ZAP (optionnel)
    enable_zap  : activer le scan DAST ZAP

    Retourne dict avec tous les résultats.
    """
    results = {
        "semgrep":   [],   # Vulnérabilités code (SAST)
        "gitleaks":  [],   # Secrets hardcodés
        "snyk":      [],   # Dépendances vulnérables
        "zap":       [],   # Vulnérabilités runtime (DAST)
        "summary":   {}
    }

    # Déterminer le dossier racine
    if file_paths:
        root = os.path.dirname(file_paths[0]) if len(file_paths) == 1 else \
               os.path.commonpath(file_paths)
    else:
        return results

    print("\n" + "="*50)
    print("🔍 SCAN UNIFIÉ PATCHMIND")
    print("="*50)

    # ── 1. Semgrep SAST ──────────────────────────────────
    print("\n📋 [1/4] Semgrep SAST...")
    all_semgrep = []
    seen = set()
    for fp in file_paths:
        vulns = run_scan(fp)
        for v in vulns:
            key = (v["line"], v["cwe"].split(":")[0], v["file"])
            if key not in seen:
                seen.add(key)
                all_semgrep.append(v)
    results["semgrep"] = all_semgrep
    print(f"  ✅ {len(all_semgrep)} vulnérabilité(s) code")

    # ── 2. GitLeaks ──────────────────────────────────────
    print("\n🔑 [2/4] GitLeaks — secrets...")
    results["gitleaks"] = run_gitleaks(root)

    # ── 3. Snyk / OSV ────────────────────────────────────
    print("\n📦 [3/4] Snyk — dépendances...")
    results["snyk"] = run_snyk(root)

    # ── 4. ZAP DAST ──────────────────────────────────────
    print("\n🌐 [4/4] OWASP ZAP — runtime...")
    if enable_zap and target_url:
        results["zap"] = run_zap(target_url, scan_type="passive")
    else:
        print("  ⏭️  ZAP ignoré (désactivé ou pas d'URL)")

    # ── Résumé ───────────────────────────────────────────
    total = (len(results["semgrep"]) + len(results["gitleaks"]) +
             len(results["snyk"])    + len(results["zap"]))

    results["summary"] = {
        "total":    total,
        "semgrep":  len(results["semgrep"]),
        "gitleaks": len(results["gitleaks"]),
        "snyk":     len(results["snyk"]),
        "zap":      len(results["zap"]),
        "critical": sum(1 for r in _all_results(results)
                       if r.get("severity","").upper() in ["CRITICAL","HIGH"]),
    }

    print("\n" + "="*50)
    print("📊 RÉSUMÉ")
    print("="*50)
    print(f"  Semgrep (SAST)    : {results['summary']['semgrep']} vulnérabilité(s)")
    print(f"  GitLeaks (secrets): {results['summary']['gitleaks']} secret(s)")
    print(f"  Snyk (deps)       : {results['summary']['snyk']} dépendance(s) vulnérable(s)")
    print(f"  ZAP (DAST)        : {results['summary']['zap']} alerte(s)")
    print(f"  TOTAL             : {total} problème(s) détecté(s)")
    print(f"  HIGH/CRITICAL     : {results['summary']['critical']}")

    return results


def _all_results(results):
    return (results["semgrep"] + results["gitleaks"] +
            results["snyk"]    + results["zap"])