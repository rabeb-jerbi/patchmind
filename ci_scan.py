"""
ci_scan.py — Script CI/CD pour GitHub Actions
Lance PatchMind en mode non-interactif et génère un rapport JSON.
Place à la racine du projet à analyser.
"""
import argparse
import json
import os
import sys
from datetime import datetime

# Ajouter le chemin de PatchMind (si installé séparément)
PATCHMIND_PATH = os.getenv("PATCHMIND_PATH", os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PATCHMIND_PATH)


def run_ci_scan(path, output_file="results.json", fail_on_critical=True):
    """Lance un scan PatchMind en mode CI."""
    print(f"🛡️  PatchMind CI Scan — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📁 Chemin : {path}")

    results = {
        "timestamp":          datetime.now().isoformat(),
        "scanned_path":       path,
        "total_vulns":        0,
        "patches_validated":  0,
        "patches_rejected":   0,
        "success_rate":       0,
        "critical_rejected":  0,
        "vulnerabilities":    [],
        "status":             "completed"
    }

    try:
        from scanner.scanner import run_scan
        from generator.generator import generate_patch
        from validator.validator import validate_patch
        from intelligence import predict_risk

        # Collecter les fichiers
        file_paths = []
        EXTENSIONS = {'.py','.js','.ts','.java','.php','.go','.rb','.cpp','.c','.kt','.swift','.rs'}
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ['node_modules','venv','.git','__pycache__','dist','build']]
            for f in files:
                if os.path.splitext(f)[1].lower() in EXTENSIONS:
                    file_paths.append(os.path.join(root, f))

        print(f"📋 {len(file_paths)} fichier(s) à analyser")

        # Prédiction de risque rapide
        risk = predict_risk(file_paths)
        results["risk_prediction"] = risk
        print(f"⚡ Risque estimé : {risk['level']} ({risk['score']}/100)")

        # Scan + patch
        all_vulns = []
        seen = set()
        for fp in file_paths[:50]:  # Max 50 fichiers en CI
            vulns = run_scan(fp)
            for v in vulns:
                key = (v["line"], v["cwe"].split(":")[0], v["file"])
                if key not in seen:
                    seen.add(key)
                    all_vulns.append(v)

        results["total_vulns"] = len(all_vulns)
        print(f"🔍 {len(all_vulns)} vulnérabilité(s) détectée(s)")

        validated = 0
        rejected  = 0
        critical_rejected = 0

        for vuln in all_vulns[:30]:  # Max 30 en CI pour éviter timeout
            try:
                orig_path = vuln["file"]
                base, ext = os.path.splitext(orig_path)
                patched   = base + "_patched" + ext
                src       = patched if os.path.exists(patched) else orig_path
                vt        = vuln.copy(); vt["file"] = orig_path
                fixed_code = generate_patch(vt)
                ok, _  = validate_patch(src, fixed_code, vuln)
                if ok:
                    validated += 1
                else:
                    rejected += 1
                    sev = vuln.get("severity","").upper()
                    if "CRITICAL" in sev or "ERROR" in sev:
                        critical_rejected += 1
                results["vulnerabilities"].append({
                    "cwe":      vuln["cwe"].split(":")[0],
                    "file":     os.path.relpath(vuln["file"], path),
                    "line":     vuln["line"],
                    "severity": vuln.get("severity",""),
                    "fixed":    ok
                })
            except Exception as e:
                print(f"⚠️  Erreur sur {vuln.get('file','?')}: {e}")
                rejected += 1

        results["patches_validated"]  = validated
        results["patches_rejected"]   = rejected
        results["critical_rejected"]  = critical_rejected
        results["success_rate"]       = round(validated / len(all_vulns) * 100, 1) if all_vulns else 100

        print(f"\n📊 Résultats :")
        print(f"   ✅ Validés   : {validated}")
        print(f"   ❌ Rejetés   : {rejected}")
        print(f"   📈 Success   : {results['success_rate']}%")
        print(f"   🚨 Critiques : {critical_rejected}")

    except ImportError as e:
        print(f"⚠️  PatchMind non disponible : {e}")
        results["status"] = "patchmind_not_found"
    except Exception as e:
        print(f"❌ Erreur : {e}")
        results["status"] = "error"
        results["error"]  = str(e)

    # Sauvegarder
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n💾 Résultats sauvegardés : {output_file}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PatchMind CI Scanner")
    parser.add_argument("--path",   default=".", help="Chemin du projet à analyser")
    parser.add_argument("--output", default="results.json", help="Fichier de sortie JSON")
    parser.add_argument("--no-fail-critical", action="store_true", help="Ne pas échouer sur critiques")
    args = parser.parse_args()

    results = run_ci_scan(args.path, args.output)
    if results.get("critical_rejected", 0) > 0 and not args.no_fail_critical:
        sys.exit(1)