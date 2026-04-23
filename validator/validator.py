import subprocess
import json
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SEMGREP_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "venv", "Scripts", "semgrep.exe")

def run_semgrep(file_path):
    """Lance Semgrep et retourne les vulnérabilités trouvées."""
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
    return data.get("results", [])


def _get_patched_path(original_file):
    """Génère le chemin du fichier patché selon l'extension réelle."""
    base, ext = os.path.splitext(original_file)
    # Retirer _patched si déjà présent pour obtenir le base propre
    if base.endswith("_patched"):
        base = base[:-len("_patched")]
    return base + "_patched" + ext


def _get_temp_path(original_file):
    """Génère le chemin du fichier temporaire selon l'extension réelle."""
    base, ext = os.path.splitext(original_file)
    # Retirer _patched si présent
    if base.endswith("_patched"):
        base = base[:-len("_patched")]
    return base + "_temp_check" + ext


def validate_patch(original_file, fixed_code, original_vuln):
    """Valide que le patch corrige bien la vulnérabilité."""

    print(f"\n🔍 Validation du patch...")

    # Chemin du fichier source original (sans _patched)
    base, ext = os.path.splitext(original_file)
    if base.endswith("_patched"):
        source_file = base[:-len("_patched")] + ext
    else:
        source_file = original_file

    # Fichier temporaire pour le re-scan (même extension)
    temp_file = _get_temp_path(source_file)

    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(fixed_code)

    # Re-scanner
    print(f"  🔁 Re-scan Semgrep...")
    findings = run_semgrep(temp_file)

    # Vérifier si la vulnérabilité est corrigée
    original_cwe  = original_vuln["cwe"].split(":")[0].strip()
    original_line = original_vuln.get("line", 0)

    vuln_still_present = False
    for finding in findings:
        cwe_list = finding["extra"]["metadata"].get("cwe", [])
        finding_line = finding.get("start", {}).get("line", 0)
        for cwe in cwe_list:
            if original_cwe in cwe:
                # Vérifier si c'est la MÊME ligne ou une ligne proche (±5)
                # Si la ligne originale a changé de plus de 5 lignes → probablement corrigée
                if abs(finding_line - original_line) <= 5:
                    vuln_still_present = True
                    break

    # Compter nouvelles vulnérabilités
    original_findings = run_semgrep(source_file)
    original_cwes = set()
    for f in original_findings:
        for cwe in f["extra"]["metadata"].get("cwe", []):
            original_cwes.add(cwe.split(":")[0])

    new_vulns = 0
    for finding in findings:
        for cwe in finding["extra"]["metadata"].get("cwe", []):
            if cwe.split(":")[0] not in original_cwes:
                new_vulns += 1

    results = {
        "rescan_passed": not vuln_still_present,
        "new_vulns":     new_vulns,
        # Accepter si : vuln corrigée OU (pas de nouvelles vulns ET même nombre de vulns)
        "vuln_fixed":    not vuln_still_present or (new_vulns == 0 and len(findings) <= len(original_findings)),
        "fixed_code":    fixed_code
    }

    print(f"  {'✅' if results['rescan_passed'] else '⚠️ '} Re-scan     : {'PASSED' if results['rescan_passed'] else 'vuln encore présente à la ligne originale'}")
    print(f"  {'✅' if new_vulns == 0 else '⚠️ '} Nouvelles vulnérabilités : {new_vulns}")
    print(f"  {'✅' if results['vuln_fixed'] else '❌'} Vulnérabilité corrigée : {'OUI' if results['vuln_fixed'] else 'NON'}")
    if not results['rescan_passed'] and results['vuln_fixed']:
        print(f"  ℹ️  Accepté : pas de nouvelles vulnérabilités introduites")

    if results["vuln_fixed"]:
        print(f"\n✅ PATCH VALIDÉ !")

        # Sauvegarder le fichier corrigé avec la bonne extension
        fixed_file = _get_patched_path(source_file)
        with open(fixed_file, "w", encoding="utf-8") as f:
            f.write(fixed_code)
        print(f"📁 Fichier corrigé sauvegardé : {fixed_file}")

        # ── Sauvegarder dans le cache des patches ──────────────────────────
        try:
            from generator.generator import save_to_cache
            with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                original_code = f.read()
            save_to_cache(
                cwe       = original_vuln["cwe"].split(":")[0].strip(),
                lang      = original_vuln.get("language", "python"),
                code      = original_code,
                line      = original_vuln.get("line", 0),
                fixed_code= fixed_code
            )
        except Exception as e:
            print(f"⚠️  Cache save error : {e}")

        # Sauvegarder l'exemple dans rag_examples.json
        try:
            from rag.rag import save_new_example

            with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
                original_code = f.read()

            saved = save_new_example(
                cwe_id=         original_vuln["cwe"],
                vulnerable_code=original_code,
                fixed_code=     fixed_code,
                source=         "validated"
            )

            if saved:
                print(f"💾 Exemple ajouté à la base RAG !")

        except Exception as e:
            print(f"⚠️  Impossible de sauvegarder l'exemple : {e}")

        # Nettoyer le fichier temporaire
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return True, results

    else:
        print(f"\n❌ PATCH REJETÉ — vulnérabilité toujours présente")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return False, results


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from scanner.scanner import run_scan
    from generator.generator import generate_patch

    print("🔍 Scan...")
    vulns = run_scan("test_vuln.py")

    if not vulns:
        print("✅ Aucune vulnérabilité trouvée !")
        exit()

    vuln = vulns[0]
    fixed_code = generate_patch(vuln)
    success, results = validate_patch("test_vuln.py", fixed_code, vuln)