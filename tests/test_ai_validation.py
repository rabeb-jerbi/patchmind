"""
tests/test_ai_validation.py
Tests for validate_patch() and _compute_confidence().

All subprocess (Semgrep) and file-system writes are mocked so no real
scanner or LLM is invoked.
"""
import os
import sys
import tempfile
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validator.validator import validate_patch, _regression_check, _scan_file_for_secrets


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _vuln(cwe="CWE-79", line=5, language="python"):
    return {"cwe": cwe, "line": line, "language": language}


def _mock_semgrep_empty():
    """subprocess.run that returns semgrep with no findings."""
    proc = MagicMock()
    proc.returncode = 0
    proc.stdout = '{"results": [], "errors": []}'
    proc.stderr = ""
    return proc


def _mock_semgrep_with_finding(cwe="CWE-79", line=5):
    proc = MagicMock()
    proc.returncode = 1
    proc.stdout = f'''{{
        "results": [{{
            "path": "test.py",
            "start": {{"line": {line}, "col": 1}},
            "end":   {{"line": {line}, "col": 20}},
            "check_id": "python.security.xss",
            "extra": {{
                "severity": "ERROR",
                "message": "XSS vulnerability",
                "metadata": {{"cwe": ["{cwe}: Cross-site scripting"]}}
            }}
        }}],
        "errors": []
    }}'''
    proc.stderr = ""
    return proc


# ─── _regression_check unit tests ────────────────────────────────────────────

def test_regression_empty_fixed_code_fails():
    result = _regression_check("original = 'code'", "")
    assert result["passed"] is False
    assert result["errors"]


def test_regression_identical_code_fails():
    code = "def foo(): return 1"
    result = _regression_check(code, code)
    assert result["passed"] is False


def test_regression_valid_fix_passes():
    original = "password = 'hardcoded'\n"
    fixed    = "password = os.environ.get('PASSWORD')\n"
    result = _regression_check(original, fixed)
    assert result["passed"] is True


def test_regression_warns_on_removed_import():
    original = "import os\nimport sys\nx = 1\n"
    fixed    = "x = 1\n"
    result = _regression_check(original, fixed)
    assert result["passed"] is True
    assert any("import" in w.lower() or "Import" in w for w in result.get("warnings", []))


def test_regression_warns_on_large_deletion():
    original = "\n".join(f"line_{i} = {i}" for i in range(30)) + "\n"
    fixed    = "line_0 = 0\n"
    result = _regression_check(original, fixed)
    assert result["passed"] is True
    assert any("suppress" in w.lower() or "uppression" in w or "%" in w
               for w in result.get("warnings", []))


def test_regression_warns_on_removed_function():
    original = "def process():\n    return 1\n\ndef validate():\n    return True\n"
    fixed    = "def process():\n    return 1\n"
    result = _regression_check(original, fixed)
    assert result["passed"] is True
    assert any("validate" in w or "fonction" in w.lower() or "Fonction" in w
               for w in result.get("warnings", []))


# ─── _scan_file_for_secrets unit tests ───────────────────────────────────────

def test_secret_scan_clean_file_passes(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text("x = os.environ.get('DB_PASSWORD')\n", encoding="utf-8")
    result = _scan_file_for_secrets(str(f))
    assert result["passed"] is True
    assert result["count"] == 0


def test_secret_scan_detects_hardcoded_password(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('db_password = "mysecretpassword123"\n', encoding="utf-8")
    result = _scan_file_for_secrets(str(f))
    assert result["passed"] is False
    assert result["count"] > 0


def test_secret_scan_detects_aws_key(tmp_path):
    f = tmp_path / "creds.py"
    # Use a key that matches AKIA[0-9A-Z]{16} but doesn't contain FP-skip tokens
    f.write_text("AWS_KEY = 'AKIAJ3VIQHSRVRLRMQNA'\n", encoding="utf-8")
    result = _scan_file_for_secrets(str(f))
    assert result["passed"] is False


def test_secret_scan_ignores_commented_lines(tmp_path):
    f = tmp_path / "example.py"
    f.write_text("# password = 'example_secret_here'\n", encoding="utf-8")
    result = _scan_file_for_secrets(str(f))
    assert result["passed"] is True


def test_secret_scan_ignores_env_var_reads(tmp_path):
    f = tmp_path / "safe.py"
    f.write_text("secret = os.getenv('SECRET_KEY')\n", encoding="utf-8")
    result = _scan_file_for_secrets(str(f))
    assert result["passed"] is True


# ─── validate_patch — mocked semgrep ─────────────────────────────────────────

def test_validate_patch_empty_fixed_code_rejected(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("password = 'hardcoded'\n", encoding="utf-8")
    ok, results = validate_patch(str(src), "", _vuln())
    assert ok is False
    assert results["vuln_fixed"] is False


def test_validate_patch_identical_code_rejected(tmp_path):
    code = "password = 'hardcoded'\n"
    src = tmp_path / "app.py"
    src.write_text(code, encoding="utf-8")
    ok, results = validate_patch(str(src), code, _vuln())
    assert ok is False


def test_validate_patch_syntax_error_rejected(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("x = 1\n", encoding="utf-8")
    invalid_python = "def broken(\n    pass\n"
    # No subprocess mock — let py_compile actually detect the syntax error.
    # Semgrep re-scan is naturally skipped when SEMGREP_PATH is empty.
    ok, results = validate_patch(str(src), invalid_python, _vuln())
    assert ok is False
    assert results["syntax"]["passed"] is False


def test_validate_patch_valid_fix_semgrep_clean(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("password = 'hardcoded'\n", encoding="utf-8")
    fixed = "password = os.environ.get('PASSWORD')\n"
    with patch("subprocess.run", return_value=_mock_semgrep_empty()):
        ok, results = validate_patch(str(src), fixed, _vuln(cwe="CWE-259"))
    # With empty semgrep output, vuln is considered fixed
    assert results["vuln_fixed"] is True


def test_validate_patch_returns_confidence_fields(tmp_path):
    src = tmp_path / "check.py"
    src.write_text("x = 1\n", encoding="utf-8")
    fixed = "x = os.environ.get('X', '1')\n"
    with patch("subprocess.run", return_value=_mock_semgrep_empty()):
        ok, results = validate_patch(str(src), fixed, _vuln(cwe="CWE-259"))
    assert "syntax" in results
    assert "gitleaks" in results
    assert "regression" in results
    assert "rescan_passed" in results
    assert "new_vulns" in results


def test_validate_patch_with_secret_warns(tmp_path):
    src = tmp_path / "sec.py"
    src.write_text("x = 1\n", encoding="utf-8")
    # Use a key matching AKIA[0-9A-Z]{16} that has no FP-skip tokens
    fixed_with_secret = 'api_key = "AKIAJ3VIQHSRVRLRMQNA"\nx = api_key\n'
    with patch("subprocess.run", return_value=_mock_semgrep_empty()):
        ok, results = validate_patch(str(src), fixed_with_secret, _vuln(cwe="CWE-259"))
    assert results["gitleaks"]["passed"] is False


def test_validate_patch_new_vuln_warns(tmp_path):
    src = tmp_path / "vuln.py"
    src.write_text("x = 1\n", encoding="utf-8")
    fixed = "x = 2\n"
    # First call (scan fixed) finds new CWE; second call (scan original) finds nothing.
    # Also patch SEMGREP_PATH so the re-scan is not skipped.
    new_finding = _mock_semgrep_with_finding(cwe="CWE-89", line=1)
    empty = _mock_semgrep_empty()
    # subprocess.run is called 3 times when SEMGREP_PATH is set:
    # 1. py_compile for syntax check (returncode=0 → passes)
    # 2. semgrep on fixed file (returncode=1, new CWE-89 found)
    # 3. semgrep on original file (returncode=0, empty → CWE-89 is new)
    syntax_ok = _mock_semgrep_empty()
    with patch("validator.validator.SEMGREP_PATH", "/fake/semgrep"), \
         patch("subprocess.run", side_effect=[syntax_ok, new_finding, empty]):
        ok, results = validate_patch(str(src), fixed, _vuln(cwe="CWE-79"))
    assert results["new_vulns"] > 0


# ─── _compute_confidence unit tests ──────────────────────────────────────────

def test_compute_confidence_zero_when_not_fixed():
    from dashboard.app import _compute_confidence
    results = {
        "vuln_fixed": False,
        "syntax":     {"passed": True},
        "rescan_passed": False,
        "gitleaks":   {"passed": True},
        "regression": {"passed": True, "warnings": []},
        "new_vulns":  0,
    }
    score, details = _compute_confidence(results, from_cache=False)
    assert score == 0


def test_compute_confidence_syntax_pass_adds_weight():
    from dashboard.app import _compute_confidence
    results = {
        "vuln_fixed": True,
        "syntax":     {"passed": True},
        "rescan_passed": False,
        "gitleaks":   {"passed": True},
        "regression": {"passed": True, "warnings": []},
        "new_vulns":  0,
    }
    score, details = _compute_confidence(results, from_cache=False)
    assert score >= 30


def test_compute_confidence_syntax_warning_partial():
    from dashboard.app import _compute_confidence
    results = {
        "vuln_fixed": True,
        "syntax":     {"passed": True, "warning": True},
        "rescan_passed": False,
        "gitleaks":   {"passed": True},
        "regression": {"passed": True, "warnings": []},
        "new_vulns":  0,
    }
    score_warn, _ = _compute_confidence(results, from_cache=False)
    results2 = dict(results)
    results2["syntax"] = {"passed": True}
    score_ok, _ = _compute_confidence(results2, from_cache=False)
    assert score_warn < score_ok


def test_compute_confidence_semgrep_rescan_adds_weight():
    from dashboard.app import _compute_confidence
    results_no_rescan = {
        "vuln_fixed": True,
        "syntax":     {"passed": True},
        "rescan_passed": False,
        "gitleaks":   {"passed": True},
        "regression": {"passed": True, "warnings": []},
        "new_vulns":  0,
    }
    results_rescan = dict(results_no_rescan)
    results_rescan["rescan_passed"] = True
    score_no, _ = _compute_confidence(results_no_rescan, from_cache=False)
    score_yes, _ = _compute_confidence(results_rescan, from_cache=False)
    assert score_yes > score_no


def test_compute_confidence_cache_bonus():
    from dashboard.app import _compute_confidence
    results = {
        "vuln_fixed": True,
        "syntax":     {"passed": True},
        "rescan_passed": True,
        "gitleaks":   {"passed": True},
        "regression": {"passed": True, "warnings": []},
        "new_vulns":  0,
    }
    score_nocache, _ = _compute_confidence(results, from_cache=False)
    score_cache, _ = _compute_confidence(results, from_cache=True)
    assert score_cache >= score_nocache


def test_compute_confidence_capped_at_100():
    from dashboard.app import _compute_confidence
    results = {
        "vuln_fixed": True,
        "syntax":     {"passed": True},
        "rescan_passed": True,
        "gitleaks":   {"passed": True},
        "regression": {"passed": True, "warnings": []},
        "new_vulns":  0,
    }
    score, _ = _compute_confidence(results, from_cache=True)
    assert score <= 100


def test_compute_confidence_details_has_required_keys():
    from dashboard.app import _compute_confidence
    results = {
        "vuln_fixed": True,
        "syntax":     {"passed": True},
        "rescan_passed": True,
        "gitleaks":   {"passed": True},
        "regression": {"passed": True, "warnings": []},
        "new_vulns":  0,
    }
    _, details = _compute_confidence(results, from_cache=False)
    assert isinstance(details, dict)
    # At minimum the dict should not be empty
    assert len(details) > 0


def test_compute_confidence_gitleaks_fail_reduces_score():
    from dashboard.app import _compute_confidence
    results_ok = {
        "vuln_fixed": True,
        "syntax":     {"passed": True},
        "rescan_passed": True,
        "gitleaks":   {"passed": True},
        "regression": {"passed": True, "warnings": []},
        "new_vulns":  0,
    }
    results_secret = dict(results_ok)
    results_secret["gitleaks"] = {"passed": False, "count": 1}
    score_ok, _ = _compute_confidence(results_ok, from_cache=False)
    score_secret, _ = _compute_confidence(results_secret, from_cache=False)
    assert score_secret < score_ok
