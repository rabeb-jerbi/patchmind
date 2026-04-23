import sys
import os
import time

os.environ["TOKENIZERS_PARALLELISM"] = "false"

from scanner.scanner import run_scan
from enricher.enricher import get_cves_by_cwe
from generator.generator import generate_patch
from validator.validator import validate_patch
from metrics.metrics import PatchMindMetrics

def run_pipeline(file_path):
    """Pipeline complet PatchMind."""
    
    print("=" * 60)
    print("🔒 PATCHMIND - Automated Vulnerability Remediation")
    print("=" * 60)
    
    metrics = PatchMindMetrics()
    _base, _ext = os.path.splitext(file_path)
    patched_file = _base + "_patched" + _ext
    
    # ÉTAPE 1 : Scanner
    print("\n📌 ÉTAPE 1 : Scan du fichier...")
    t0            = time.time()
    vulns         = run_scan(file_path)
    scan_duration = time.time() - t0
    
    if not vulns:
        print("✅ Aucune vulnérabilité trouvée !")
        return
    
    # Dédupliquer
    seen         = set()
    unique_vulns = []
    for v in vulns:
        key = (v["line"], v["cwe"].split(":")[0])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)
    
    print(f"⚠️  {len(unique_vulns)} vulnérabilité(s) unique(s) détectée(s)")
    print(f"⏱️  Scan terminé en {scan_duration:.1f}s")
    
    results_summary = []
    
    for i, vuln in enumerate(unique_vulns, 1):
        
        # ÉTAPE 2 : Enrichissement NVD
        print(f"\n{'=' * 60}")
        print(f"🔍 Vulnérabilité {i}/{len(unique_vulns)}")
        print(f"   CWE      : {vuln['cwe']}")
        print(f"   Fichier  : {vuln['file']}:{vuln['line']}")

        print(f"\n📌 ÉTAPE 2 : Enrichissement NVD...")
        cwe_clean = vuln['cwe'].split(":")[0].strip()
        t0        = time.time()
        cves      = get_cves_by_cwe(cwe_clean)
        nvd_dur   = time.time() - t0

        # Calculer la sévérité CVSS
        known_cves = [c for c in cves if c.get("severity") != "UNKNOWN"]
        if known_cves:
            top_cve      = max(known_cves, key=lambda x: x.get("cvss_score", 0))
            cvss_display = f"{top_cve.get('severity')} (CVSS {top_cve.get('cvss_score')})"
        else:
            cvss_display = vuln['severity']

        print(f"   Sévérité : {cvss_display}")
        metrics.start_vuln(vuln)

        if cves:
            if known_cves:
                print(f"✅ {len(cves)} CVE(s) — Score max : {top_cve.get('cvss_score')} ({top_cve.get('severity')}) — {nvd_dur:.1f}s")
            else:
                print(f"✅ {len(cves)} CVE(s) — Sévérité UNKNOWN (vieux CVE) — {nvd_dur:.1f}s")
        else:
            print(f"⚠️  Aucun CVE trouvé — {nvd_dur:.1f}s")
        metrics.record_stage("nvd", nvd_dur)
        
        # ÉTAPE 3+4 : RAG + Génération
        print(f"\n📌 ÉTAPE 3+4 : RAG + Génération patch...")
        t0          = time.time()
        source_file = patched_file if os.path.exists(patched_file) else file_path
        vuln_temp   = vuln.copy()
        vuln_temp["file"] = source_file
        fixed_code  = generate_patch(vuln_temp)
        gen_dur     = time.time() - t0
        print(f"⏱️  Génération en {gen_dur:.1f}s")
        metrics.record_stage("generation", gen_dur)
        
        # ÉTAPE 5 : Validation
        print(f"\n📌 ÉTAPE 5 : Validation...")
        t0      = time.time()
        success, results = validate_patch(source_file, fixed_code, vuln)
        val_dur = time.time() - t0
        print(f"⏱️  Validation en {val_dur:.1f}s")
        metrics.record_stage("validation", val_dur)
        
        metrics.end_vuln(success)
        results_summary.append({"vuln": vuln, "success": success})
    
    # Résumé final
    print(f"\n{'=' * 60}")
    print(f"📊 RÉSUMÉ FINAL")
    print(f"{'=' * 60}")
    
    total   = len(results_summary)
    success = sum(1 for r in results_summary if r["success"])
    failed  = total - success
    
    print(f"  Total vulnérabilités : {total}")
    print(f"  ✅ Patches validés   : {success}")
    print(f"  ❌ Patches rejetés   : {failed}")
    print(f"  📈 Success rate      : {(success/total)*100:.1f}%")
    
    metrics.finalize()
    
    print(f"\n🎉 PatchMind terminé !")


if __name__ == "__main__":
    file_path = "test_all_vulns.py"
    run_pipeline(file_path)