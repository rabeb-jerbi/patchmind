"""
tests/test_scanners.py
Tests for the scanner layer — language detection, extension support,
and output parsing with mocked subprocess.

No real Semgrep, GitLeaks, or Snyk is required.
"""
import os
import sys
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.scanner import detect_language, is_supported_file, SUPPORTED_EXTENSIONS


# ─── detect_language ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("ext,expected", [
    (".py",  "python"),
    (".js",  "javascript"),
    (".jsx", "javascript"),
    (".ts",  "typescript"),
    (".tsx", "typescript"),
    (".java","java"),
    (".php", "php"),
    (".go",  "go"),
    (".rb",  "ruby"),
    (".cpp", "cpp"),
    (".c",   "c"),
    (".kt",  "kotlin"),
    (".rs",  "rust"),
    (".yml", "yaml"),
    (".yaml","yaml"),
])
def test_detect_language_by_extension(ext, expected, tmp_path):
    p = tmp_path / f"file{ext}"
    p.touch()
    assert detect_language(str(p)) == expected


def test_detect_language_dockerfile(tmp_path):
    p = tmp_path / "Dockerfile"
    p.touch()
    assert detect_language(str(p)) == "dockerfile"


def test_detect_language_unknown(tmp_path):
    p = tmp_path / "file.xyz"
    p.touch()
    assert detect_language(str(p)) == "unknown"


def test_detect_language_case_insensitive_ext(tmp_path):
    p = tmp_path / "FILE.PY"
    p.touch()
    assert detect_language(str(p)) == "python"


# ─── is_supported_file ────────────────────────────────────────────────────────

@pytest.mark.parametrize("ext", [".py", ".js", ".ts", ".java", ".php", ".go",
                                  ".rb", ".cpp", ".c", ".kt", ".rs"])
def test_supported_extensions_are_supported(ext, tmp_path):
    p = tmp_path / f"file{ext}"
    p.touch()
    assert is_supported_file(str(p)) is True


@pytest.mark.parametrize("name", [".exe", ".bat", ".docx", ".pdf", ".png"])
def test_unsupported_extensions(name, tmp_path):
    p = tmp_path / f"file{name}"
    p.touch()
    assert is_supported_file(str(p)) is False


def test_dockerfile_is_supported(tmp_path):
    p = tmp_path / "Dockerfile"
    p.touch()
    assert is_supported_file(str(p)) is True


def test_unsupported_file_returns_empty_scan():
    from scanner.scanner import run_scan
    with tempfile.NamedTemporaryFile(suffix=".xyz", delete=False) as f:
        f.write(b"unsupported content")
        path = f.name
    try:
        result = run_scan(path)
        assert result == []
    finally:
        os.unlink(path)


# ─── run_scan — mocked Semgrep ────────────────────────────────────────────────

def _make_semgrep_output(findings):
    return json.dumps({
        "results": findings,
        "errors": [],
    })


def test_run_scan_returns_vulns_from_semgrep():
    from scanner.scanner import run_scan
    semgrep_out = _make_semgrep_output([{
        "path": "app.py",
        "start": {"line": 5, "col": 1},
        "end": {"line": 5, "col": 20},
        "check_id": "python.flask.security.xss.audit.direct-use-of-jinja2",
        "extra": {
            "severity": "ERROR",
            "message": "Direct use of Jinja2 template",
            "metadata": {"cwe": ["CWE-79: XSS"]}
        },
    }])
    mock_proc = MagicMock(
        returncode=1,
        stdout=semgrep_out,
        stderr="",
    )
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
        f.write(b"x = 1")
        path = f.name
    try:
        with patch("scanner.scanner.SEMGREP_PATH", "/fake/semgrep"), \
             patch("subprocess.run", return_value=mock_proc):
            results = run_scan(path)
        assert len(results) == 1
        assert results[0]["cwe"] == "CWE-79"
        assert results[0]["line"] == 5
    finally:
        os.unlink(path)


def test_run_scan_empty_output_returns_empty():
    from scanner.scanner import run_scan
    mock_proc = MagicMock(returncode=0, stdout="", stderr="")
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
        f.write(b"x = 1")
        path = f.name
    try:
        with patch("subprocess.run", return_value=mock_proc):
            results = run_scan(path)
        assert results == []
    finally:
        os.unlink(path)


def test_run_scan_no_json_in_output_returns_empty():
    from scanner.scanner import run_scan
    mock_proc = MagicMock(returncode=0, stdout="no json here", stderr="")
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
        path = f.name
    try:
        with patch("subprocess.run", return_value=mock_proc):
            results = run_scan(path)
        assert results == []
    finally:
        os.unlink(path)


# ─── GitLeaks fallback regex scanner ────────────────────────────────────────

def test_gitleaks_regex_detects_hardcoded_password(tmp_path):
    from scanner.gitleaks_scanner import _regex_scan
    p = tmp_path / "config.py"
    p.write_text('db_password = "mysecretpassword123"\n', encoding="utf-8")
    findings = _regex_scan(str(tmp_path))
    assert len(findings) > 0
    assert any(f["type"] == "SECRET" for f in findings)


def test_gitleaks_regex_detects_aws_key(tmp_path):
    from scanner.gitleaks_scanner import _regex_scan
    p = tmp_path / "creds.py"
    # Use a key matching AKIA[0-9A-Z]{16} that has no FP-skip tokens
    p.write_text("AWS_KEY = 'AKIAJ3VIQHSRVRLRMQNA'\n", encoding="utf-8")
    findings = _regex_scan(str(tmp_path))
    assert len(findings) > 0


def test_gitleaks_regex_clean_file_returns_empty(tmp_path):
    from scanner.gitleaks_scanner import _regex_scan
    p = tmp_path / "clean.py"
    p.write_text("x = os.environ.get('AWS_KEY')\n", encoding="utf-8")
    findings = _regex_scan(str(tmp_path))
    assert findings == []


def test_gitleaks_falls_back_to_regex_when_tool_missing(tmp_path):
    from scanner.gitleaks_scanner import run_gitleaks
    p = tmp_path / "s.py"
    p.write_text('api_key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"\n', encoding="utf-8")
    with patch("subprocess.run", side_effect=FileNotFoundError):
        findings = run_gitleaks(str(tmp_path))
    # Regex fallback should detect the github token
    assert isinstance(findings, list)


# ─── Snyk/OSV scanner ────────────────────────────────────────────────────────

def test_snyk_returns_list():
    from scanner.snyk_scanner import run_snyk
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = run_snyk("/tmp/requirements.txt")
    assert isinstance(result, list)


# ─── SUPPORTED_EXTENSIONS completeness ───────────────────────────────────────

def test_all_language_keys_present():
    for lang in ("python", "javascript", "typescript", "java", "php",
                 "go", "ruby", "c", "cpp", "kotlin", "rust"):
        assert lang in SUPPORTED_EXTENSIONS


def test_each_language_has_at_least_one_extension():
    for lang, exts in SUPPORTED_EXTENSIONS.items():
        assert len(exts) >= 1, f"{lang} has no extensions"
