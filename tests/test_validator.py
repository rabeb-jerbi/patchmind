"""
tests/test_validator.py
Unit tests for validator/validator.py.

External tools (semgrep, gitleaks) and subprocess calls are mocked
so tests run without real scanners installed.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ast
import tempfile
import textwrap
import pytest
from unittest.mock import patch, MagicMock

from validator.validator import (
    syntax_check,
    _regression_check,
    _scan_file_for_secrets,
)


# ─── syntax_check — Python ───────────────────────────────────────────────────

def _write_tmp(content: str, suffix: str = ".py") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def test_syntax_check_valid_python():
    path = _write_tmp("x = 1\nprint(x)\n")
    try:
        r = syntax_check(path, "python")
        assert r["passed"] is True
        assert r["tool"] == "py_compile"
        assert "warning" not in r
    finally:
        os.unlink(path)


def test_syntax_check_invalid_python():
    path = _write_tmp("def bad(:\n    pass\n")
    try:
        r = syntax_check(path, "python")
        assert r["passed"] is False
        assert r["tool"] == "py_compile"
        assert len(r["message"]) > 0
    finally:
        os.unlink(path)


def test_syntax_check_valid_python_by_extension():
    path = _write_tmp("a = [1, 2, 3]\n")
    try:
        r = syntax_check(path)
        assert r["passed"] is True
    finally:
        os.unlink(path)


# ─── syntax_check — JavaScript (mocked) ──────────────────────────────────────

def test_syntax_check_js_success():
    path = _write_tmp("const x = 1;", suffix=".js")
    try:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_result.stdout = ""
        with patch("subprocess.run", return_value=mock_result):
            r = syntax_check(path, "javascript")
        assert r["passed"] is True
        assert r["tool"] == "node"
    finally:
        os.unlink(path)


def test_syntax_check_js_error():
    path = _write_tmp("const x = {{{;", suffix=".js")
    try:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "SyntaxError: Unexpected token"
        mock_result.stdout = ""
        with patch("subprocess.run", return_value=mock_result):
            r = syntax_check(path, "javascript")
        assert r["passed"] is False
    finally:
        os.unlink(path)


def test_syntax_check_js_node_missing():
    path = _write_tmp("const x = 1;", suffix=".js")
    try:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            r = syntax_check(path, "javascript")
        assert r["passed"] is True
        assert r.get("warning") is True
    finally:
        os.unlink(path)


# ─── syntax_check — TypeScript always warns ───────────────────────────────────

def test_syntax_check_typescript_warns():
    path = _write_tmp("const x: number = 1;", suffix=".ts")
    try:
        r = syntax_check(path)
        assert r["passed"] is True
        assert r.get("warning") is True
    finally:
        os.unlink(path)


# ─── syntax_check — PHP missing tool ─────────────────────────────────────────

def test_syntax_check_php_missing():
    path = _write_tmp("<?php echo 'hi'; ?>", suffix=".php")
    try:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            r = syntax_check(path, "php")
        assert r["passed"] is True
        assert r.get("warning") is True
    finally:
        os.unlink(path)


# ─── syntax_check — unknown extension ────────────────────────────────────────

def test_syntax_check_unknown_extension():
    path = _write_tmp("hello", suffix=".xyz")
    try:
        r = syntax_check(path)
        assert r["passed"] is True
        assert r.get("warning") is True
    finally:
        os.unlink(path)


# ─── _regression_check ───────────────────────────────────────────────────────

def test_regression_empty_patch_rejected():
    r = _regression_check("x = 1\n", "   ")
    assert r["passed"] is False
    assert r["errors"]


def test_regression_identical_patch_rejected():
    code = "x = 1\n"
    r = _regression_check(code, code)
    assert r["passed"] is False
    assert "identique" in r["errors"][0].lower()


def test_regression_valid_fix_passes():
    orig = "password = 'hardcoded'\n"
    fixed = "import os\npassword = os.getenv('PASSWORD')\n"
    r = _regression_check(orig, fixed)
    assert r["passed"] is True


def test_regression_large_deletion_warning():
    orig = "\n".join(f"line_{i} = {i}" for i in range(50))
    fixed = "x = 1"
    r = _regression_check(orig, fixed)
    assert r["passed"] is True
    assert any("suppression" in w.lower() or "%" in w for w in r["warnings"])


def test_regression_removed_import_warning():
    orig = "import os\nimport sys\nx = 1\n"
    fixed = "x = 1\n"
    r = _regression_check(orig, fixed)
    assert r["passed"] is True
    warning_text = " ".join(r["warnings"]).lower()
    assert "import" in warning_text


def test_regression_removed_function_warning():
    orig = textwrap.dedent("""\
        def helper():
            pass
        def main():
            helper()
    """)
    fixed = textwrap.dedent("""\
        def main():
            pass
    """)
    r = _regression_check(orig, fixed)
    assert r["passed"] is True
    assert any("helper" in w for w in r["warnings"])


def test_regression_removed_class_warning():
    orig = textwrap.dedent("""\
        class MyService:
            def run(self):
                pass
        x = MyService()
    """)
    fixed = "x = None\n"
    r = _regression_check(orig, fixed)
    assert r["passed"] is True
    assert any("MyService" in w for w in r["warnings"])


def test_regression_no_warnings_clean_fix():
    orig = "password = 'secret'\n"
    fixed = "password = os.environ.get('PWD')\n"
    r = _regression_check(orig, fixed)
    assert r["passed"] is True
    assert r["errors"] == []


# ─── _scan_file_for_secrets ───────────────────────────────────────────────────

def test_scan_secrets_clean_file():
    path = _write_tmp("x = 1\nprint(x)\n")
    try:
        r = _scan_file_for_secrets(path)
        assert r["passed"] is True
        assert r["count"] == 0
    finally:
        os.unlink(path)


def test_scan_secrets_detects_hardcoded_password():
    path = _write_tmp('password = "mysupersecret123"\n')
    try:
        r = _scan_file_for_secrets(path)
        assert r["passed"] is False
        assert r["count"] > 0
    finally:
        os.unlink(path)


def test_scan_secrets_detects_aws_key():
    path = _write_tmp("key = 'AKIAJ3VIQHSRVRLRMQNA'\n")
    try:
        r = _scan_file_for_secrets(path)
        assert r["passed"] is False
    finally:
        os.unlink(path)


def test_scan_secrets_skips_env_var_reads():
    path = _write_tmp("password = os.getenv('PASSWORD')\n")
    try:
        r = _scan_file_for_secrets(path)
        assert r["passed"] is True
    finally:
        os.unlink(path)


def test_scan_secrets_skips_comments():
    path = _write_tmp("# password = 'supersecret'\n")
    try:
        r = _scan_file_for_secrets(path)
        assert r["passed"] is True
    finally:
        os.unlink(path)


def test_scan_secrets_returns_finding_structure():
    path = _write_tmp('api_key = "abcdefghij1234567890"\n')
    try:
        r = _scan_file_for_secrets(path)
        if not r["passed"]:
            finding = r["findings"][0]
            assert "rule" in finding
            assert "line" in finding
    finally:
        os.unlink(path)
