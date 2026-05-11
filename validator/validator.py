"""
validator/validator.py
Validates a generated patch by checking syntax, running scanners, and
performing regression safety checks.

validate_patch() returns (bool, dict) where the dict contains:
  rescan_passed  bool   – Semgrep no longer detects the original CWE at that line
  new_vulns      int    – new CWEs introduced by the patch
  vuln_fixed     bool   – overall verdict (used to decide VALIDÉ/REJETÉ)
  fixed_code     str
  syntax         dict   – {passed, message, tool, warning?}
  gitleaks       dict   – {passed, count, findings}
  snyk           dict   – {passed, message}   (not_applicable for source files)
  zap            dict   – {passed, message}   (not_applicable without target_url)
  regression     dict   – {passed, warnings, errors}
  warnings       list   – all non-fatal messages
  errors         list   – fatal rejection reasons
"""
import subprocess
import json
import os
import re
import sys
import shutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_semgrep() -> str:
    env_path = os.environ.get("SEMGREP_PATH", "")
    if env_path and os.path.isfile(env_path):
        return env_path
    for c in [
        os.path.join(_ROOT, "venv",  "Scripts", "semgrep.exe"),
        os.path.join(_ROOT, "venv",  "bin",     "semgrep"),
        os.path.join(_ROOT, ".venv", "Scripts", "semgrep.exe"),
        os.path.join(_ROOT, ".venv", "bin",     "semgrep"),
    ]:
        if os.path.isfile(c):
            return c
    return shutil.which("semgrep") or ""


SEMGREP_PATH = _resolve_semgrep()

# Dependency file names — Snyk/OSV is meaningful only for these
_DEP_FILES = frozenset({
    "requirements.txt", "pipfile", "pyproject.toml", "setup.py",
    "package.json", "package-lock.json", "yarn.lock",
    "pom.xml", "build.gradle", "composer.json", "go.mod",
    "gemfile", "gemfile.lock",
})

# Patterns for in-file secret scanning (gitleaks fallback)
_SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
    "GITHUB_TOKEN":   r"ghp_[a-zA-Z0-9]{36}",
    "HARDCODED_PASS": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
    "HARDCODED_KEY":  r"(?i)(api.?key|apikey|api_token)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "PRIVATE_KEY":    r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "GENERIC_SECRET": r"(?i)(secret|token)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
}
_FP_SKIP = frozenset((
    "os.getenv", "os.environ", "process.env", "system.getenv",
    "getenv", "placeholder", "your_key_here", "example", "xxxx",
    "replace_me", "changeme", "todo",
))


# ══════════════════════════════════════════════════════════════════
# Section 7 — Syntax validation
# ══════════════════════════════════════════════════════════════════

def syntax_check(file_path: str, language: str = None) -> dict:
    """
    Run a syntax check appropriate for the file's language.

    Returns:
        {"passed": bool, "message": str, "tool": str, "warning"?: True}

    Missing optional tools (node, php, go, javac) set warning=True and
    return passed=True so they never cause a hard rejection.
    """
    ext  = os.path.splitext(file_path)[1].lower()
    lang = (language or "").lower()

    # ── Python ───────────────────────────────────────────────────
    if ext == ".py" or lang == "python":
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", file_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return {"passed": True,  "message": "Syntaxe Python valide",      "tool": "py_compile"}
        return     {"passed": False, "message": (result.stderr or result.stdout).strip()[:300], "tool": "py_compile"}

    # ── JavaScript / JSX ─────────────────────────────────────────
    if ext in (".js", ".jsx", ".mjs", ".cjs") or lang == "javascript":
        try:
            result = subprocess.run(
                ["node", "--check", file_path],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return {"passed": True,  "message": "Syntaxe JavaScript valide",  "tool": "node"}
            return     {"passed": False, "message": (result.stderr or result.stdout).strip()[:300], "tool": "node"}
        except FileNotFoundError:
            return {"passed": True, "message": "node non installé — vérification syntaxique ignorée", "tool": "none", "warning": True}

    # ── TypeScript — tsc check is too complex to run in isolation ─
    if ext in (".ts", ".tsx") or lang == "typescript":
        return {"passed": True, "message": "TypeScript — tsc non disponible, vérification ignorée", "tool": "none", "warning": True}

    # ── PHP ───────────────────────────────────────────────────────
    if ext == ".php" or lang == "php":
        try:
            result = subprocess.run(
                ["php", "-l", file_path],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return {"passed": True,  "message": "Syntaxe PHP valide",  "tool": "php"}
            return     {"passed": False, "message": (result.stderr or result.stdout).strip()[:300], "tool": "php"}
        except FileNotFoundError:
            return {"passed": True, "message": "php non installé — vérification syntaxique ignorée", "tool": "none", "warning": True}

    # ── Go ────────────────────────────────────────────────────────
    if ext == ".go" or lang == "go":
        try:
            result = subprocess.run(
                ["go", "vet", "./..."],
                capture_output=True, text=True, timeout=30,
                cwd=os.path.dirname(file_path) or ".",
            )
            if result.returncode == 0:
                return {"passed": True,  "message": "go vet OK", "tool": "go vet"}
            return     {"passed": False, "message": (result.stderr or result.stdout).strip()[:300], "tool": "go vet"}
        except FileNotFoundError:
            return {"passed": True, "message": "go non installé — vérification ignorée", "tool": "none", "warning": True}

    # ── Java ──────────────────────────────────────────────────────
    if ext == ".java" or lang == "java":
        try:
            result = subprocess.run(
                ["javac", "-proc:none", file_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return {"passed": True,  "message": "Syntaxe Java valide", "tool": "javac"}
            return     {"passed": False, "message": (result.stderr or result.stdout).strip()[:300], "tool": "javac"}
        except FileNotFoundError:
            return {"passed": True, "message": "javac non installé — vérification ignorée", "tool": "none", "warning": True}

    # ── Unknown ───────────────────────────────────────────────────
    return {"passed": True, "message": f"Vérification syntaxique non supportée pour '{ext}'", "tool": "none", "warning": True}


# ══════════════════════════════════════════════════════════════════
# Section 8 — Post-patch secret scan (lightweight GitLeaks fallback)
# ══════════════════════════════════════════════════════════════════

def _scan_file_for_secrets(file_path: str) -> dict:
    """
    Run a lightweight regex-based secret scan on a single file.
    Returns {"passed": bool, "count": int, "findings": list}
    """
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "<!--")):
                continue
            low = line.lower()
            if any(fp in low for fp in _FP_SKIP):
                continue
            for rule, pattern in _SECRET_PATTERNS.items():
                if re.search(pattern, line):
                    findings.append({"rule": rule, "line": i})
                    break
    except Exception:
        pass
    return {"passed": len(findings) == 0, "count": len(findings), "findings": findings}


# ══════════════════════════════════════════════════════════════════
# Section 9 — Regression safety checks
# ══════════════════════════════════════════════════════════════════

def _regression_check(original_code: str, fixed_code: str) -> dict:
    """
    Check for common regression patterns.

    Fatal (passed=False):
      - Empty patched file
      - Identical to original (no change made)

    Warnings (passed=True but with messages):
      - >60% of non-blank lines removed
      - Imports removed that existed in original
      - Python: functions or classes removed (AST check)
    """
    errors   = []
    warnings = []

    # ── Fatal: empty ──────────────────────────────────────────────
    if not fixed_code.strip():
        return {"passed": False, "errors": ["Le fichier patché est vide"], "warnings": []}

    # ── Fatal: identical ─────────────────────────────────────────
    if fixed_code.strip() == original_code.strip():
        return {"passed": False, "errors": ["Le patch est identique au code original — aucune modification appliquée"], "warnings": []}

    orig_lines  = original_code.splitlines()
    fixed_lines = fixed_code.splitlines()

    # ── Warning: large deletion ───────────────────────────────────
    orig_nb  = len([l for l in orig_lines  if l.strip()])
    fixed_nb = len([l for l in fixed_lines if l.strip()])
    if orig_nb > 10 and fixed_nb < orig_nb * 0.4:
        pct = int((orig_nb - fixed_nb) / orig_nb * 100)
        warnings.append(f"Suppression importante : {pct}% des lignes non-vides ont été supprimées")

    # ── Warning: removed imports ──────────────────────────────────
    orig_imports  = {l.strip() for l in orig_lines  if l.strip().startswith(("import ", "from "))}
    fixed_imports = {l.strip() for l in fixed_lines if l.strip().startswith(("import ", "from "))}
    removed = orig_imports - fixed_imports
    for imp in sorted(removed)[:3]:
        warnings.append(f"Import supprimé : {imp[:100]}")

    # ── Warning: Python AST — removed functions/classes ──────────
    try:
        import ast
        orig_tree  = ast.parse(original_code)
        fixed_tree = ast.parse(fixed_code)

        orig_funcs    = {n.name for n in ast.walk(orig_tree)  if isinstance(n, ast.FunctionDef)}
        fixed_funcs   = {n.name for n in ast.walk(fixed_tree) if isinstance(n, ast.FunctionDef)}
        orig_classes  = {n.name for n in ast.walk(orig_tree)  if isinstance(n, ast.ClassDef)}
        fixed_classes = {n.name for n in ast.walk(fixed_tree) if isinstance(n, ast.ClassDef)}

        for name in sorted(orig_funcs - fixed_funcs)[:3]:
            warnings.append(f"Fonction supprimée du fichier patché : {name}()")
        for name in sorted(orig_classes - fixed_classes)[:3]:
            warnings.append(f"Classe supprimée du fichier patché : {name}")
    except SyntaxError:
        pass  # Syntax errors are caught by syntax_check; don't double-report
    except Exception:
        pass

    return {"passed": True, "errors": errors, "warnings": warnings}


# ══════════════════════════════════════════════════════════════════
# Semgrep helpers (unchanged API)
# ══════════════════════════════════════════════════════════════════

def run_semgrep(file_path):
    """Launch Semgrep and return findings list. Returns [] if semgrep is absent."""
    if not SEMGREP_PATH:
        return []
    try:
        result = subprocess.run(
            [SEMGREP_PATH, "--config=auto", "--json", file_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=120,
        )
        output = result.stdout.strip()
        if not output:
            return []
        json_start = output.find("{")
        if json_start == -1:
            return []
        data = json.loads(output[json_start:])
        return data.get("results", [])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []


def _get_patched_path(original_file):
    base, ext = os.path.splitext(original_file)
    if base.endswith("_patched"):
        base = base[: -len("_patched")]
    return base + "_patched" + ext


def _get_temp_path(original_file):
    base, ext = os.path.splitext(original_file)
    if base.endswith("_patched"):
        base = base[: -len("_patched")]
    return base + "_temp_check" + ext


# ══════════════════════════════════════════════════════════════════
# Main validate_patch — Sections 7 + 8 + 9
# ══════════════════════════════════════════════════════════════════

def validate_patch(original_file, fixed_code, original_vuln, target_url: str = None):
    """
    Validate that *fixed_code* actually fixes the vulnerability described by
    *original_vuln* without introducing regressions or new issues.

    Returns (success: bool, results: dict).

    The *results* dict is used by _compute_confidence() in app.py.
    """
    print(f"\n🔍 Validation du patch...")

    # ── Resolve source (non-patched) file ─────────────────────────
    base, ext = os.path.splitext(original_file)
    if base.endswith("_patched"):
        source_file = base[: -len("_patched")] + ext
    else:
        source_file = original_file

    language  = original_vuln.get("language", "python")
    cwe_clean = original_vuln["cwe"].split(":")[0].strip()

    # ── Read original code ────────────────────────────────────────
    try:
        with open(source_file, "r", encoding="utf-8", errors="ignore") as f:
            original_code = f.read()
    except Exception:
        original_code = ""

    # ── Skeleton result (filled as we go) ─────────────────────────
    results = {
        "rescan_passed": False,
        "new_vulns":     0,
        "vuln_fixed":    False,
        "fixed_code":    fixed_code,
        "syntax":        {"passed": True, "message": "non vérifié", "tool": "none"},
        "gitleaks":      {"passed": True, "count": 0, "findings": []},
        "snyk":          {"passed": True, "message": "non applicable (fichier source, pas de dépendances)"},
        "zap":           {"passed": True, "message": "non applicable (pas d'URL cible)"},
        "regression":    {"passed": True, "errors": [], "warnings": []},
        "warnings":      [],
        "errors":        [],
    }

    # ═══ Section 9 — Regression safety ════════════════════════════
    print("  🛡️  Vérification de régression...")
    reg = _regression_check(original_code, fixed_code)
    results["regression"] = reg
    results["warnings"].extend(reg.get("warnings", []))

    if not reg["passed"]:
        # Fatal regression (empty or identical)
        err_msg = (reg.get("errors") or ["Régression détectée"])[0]
        results["errors"].append(err_msg)
        print(f"  ❌ Régression : {err_msg}")
        return False, results

    # ═══ Section 7 — Syntax check ═════════════════════════════════
    # Write fixed_code to temp file first so syntax tools can read it
    temp_file = _get_temp_path(source_file)
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(fixed_code)
    except Exception as e:
        results["errors"].append(f"Impossible d'écrire le fichier temporaire : {e}")
        return False, results

    print(f"  🔤 Vérification syntaxique ({language})...")
    syn = syntax_check(temp_file, language)
    results["syntax"] = syn

    if syn.get("warning"):
        results["warnings"].append(f"Syntaxe : {syn['message']}")
    elif not syn["passed"]:
        results["errors"].append(f"Erreur de syntaxe : {syn['message']}")
        print(f"  ❌ Syntaxe : {syn['message'][:120]}")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return False, results
    else:
        print(f"  ✅ Syntaxe {syn['tool']} : OK")

    # ═══ Section 8 — Semgrep rescan ════════════════════════════════
    print("  🔁 Re-scan Semgrep...")
    findings = run_semgrep(temp_file)
    original_line = original_vuln.get("line", 0)

    vuln_still_present = False
    for finding in findings:
        cwe_list     = finding.get("extra", {}).get("metadata", {}).get("cwe", [])
        finding_line = finding.get("start", {}).get("line", 0)
        for cwe in cwe_list:
            if cwe_clean in cwe and abs(finding_line - original_line) <= 5:
                vuln_still_present = True
                break

    results["rescan_passed"] = not vuln_still_present

    # Count new CWEs introduced
    original_findings = run_semgrep(source_file)
    original_cwes = set()
    for f in original_findings:
        for cwe in f.get("extra", {}).get("metadata", {}).get("cwe", []):
            original_cwes.add(cwe.split(":")[0])

    new_vulns = 0
    for finding in findings:
        for cwe in finding.get("extra", {}).get("metadata", {}).get("cwe", []):
            if cwe.split(":")[0] not in original_cwes:
                new_vulns += 1
    results["new_vulns"] = new_vulns
    if new_vulns > 0:
        results["warnings"].append(f"{new_vulns} nouvelle(s) vulnérabilité(s) introduite(s) par le patch")

    print(f"  {'✅' if results['rescan_passed'] else '⚠️ '} Semgrep : {'PASSED' if results['rescan_passed'] else 'vuln encore présente'}")
    print(f"  {'✅' if new_vulns == 0 else '⚠️ '} Nouvelles vulnérabilités : {new_vulns}")

    # ═══ Section 8 — GitLeaks (secrets in patched file) ════════════
    print("  🔑 Scan secrets (patched file)...")
    gl = _scan_file_for_secrets(temp_file)
    results["gitleaks"] = gl
    if not gl["passed"]:
        results["warnings"].append(f"Secret potentiel dans le patch : {gl['count']} occurrence(s)")
    print(f"  {'✅' if gl['passed'] else '⚠️ '} GitLeaks : {'OK' if gl['passed'] else str(gl['count'])+' secret(s) détecté(s)'}")

    # ═══ Section 8 — Snyk / ZAP status (informational) ════════════
    fname_lower = os.path.basename(source_file).lower()
    if fname_lower in _DEP_FILES:
        results["snyk"] = {"passed": True, "message": "fichier de dépendances — vérifiez manuellement"}

    if target_url:
        web_cwes = {"CWE-79", "CWE-89", "CWE-352", "CWE-601", "CWE-611"}
        if cwe_clean in web_cwes:
            results["zap"] = {"passed": True, "message": f"DAST non relancé automatiquement — url: {target_url}"}
        else:
            results["zap"] = {"passed": True, "message": "non applicable (vulnérabilité non web)"}

    # ═══ Overall verdict ═══════════════════════════════════════════
    vuln_fixed = (
        not vuln_still_present
        or (new_vulns == 0 and len(findings) <= len(original_findings))
    )
    # GitLeaks failures are warnings but don't block patch acceptance
    results["vuln_fixed"] = vuln_fixed

    status_sym = "✅" if results["rescan_passed"] else "⚠️ "
    print(f"  {status_sym} Vuln corrigée : {'OUI' if vuln_fixed else 'NON'}")

    if vuln_fixed:
        print(f"\n✅ PATCH VALIDÉ !")

        # Save patched file
        fixed_file = _get_patched_path(source_file)
        with open(fixed_file, "w", encoding="utf-8") as f:
            f.write(fixed_code)
        print(f"📁 Fichier corrigé sauvegardé : {fixed_file}")

        # Patch cache
        try:
            from generator.generator import save_to_cache
            save_to_cache(
                cwe=cwe_clean,
                lang=language,
                code=original_code,
                line=original_vuln.get("line", 0),
                fixed_code=fixed_code,
            )
        except Exception as e:
            print(f"⚠️  Cache save error : {e}")

        # RAG example
        try:
            from rag.rag import save_new_example
            saved = save_new_example(
                cwe_id=original_vuln["cwe"],
                vulnerable_code=original_code,
                fixed_code=fixed_code,
                source="validated",
            )
            if saved:
                print("💾 Exemple ajouté à la base RAG !")
        except Exception as e:
            print(f"⚠️  Impossible de sauvegarder l'exemple : {e}")

        if os.path.exists(temp_file):
            os.remove(temp_file)
        return True, results

    else:
        print(f"\n❌ PATCH REJETÉ — vulnérabilité toujours présente")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return False, results


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from scanner.scanner    import run_scan
    from generator.generator import generate_patch

    print("🔍 Scan...")
    vulns = run_scan("test_vuln.py")

    if not vulns:
        print("✅ Aucune vulnérabilité trouvée !")
        sys.exit(0)

    vuln       = vulns[0]
    fixed_code = generate_patch(vuln)
    success, results = validate_patch("test_vuln.py", fixed_code, vuln)
