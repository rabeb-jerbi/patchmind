"""
tests/test_confidence.py
Unit tests for _compute_confidence() in dashboard/app.py.
No Flask context needed — function is imported directly.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from dashboard.app import _compute_confidence


# ─── Helper: build a validation_results dict ─────────────────────────────────

def _vr(
    vuln_fixed=True,
    rescan_passed=True,
    new_vulns=0,
    syntax_passed=True,
    syntax_warning=False,
    gitleaks_passed=True,
    gitleaks_count=0,
    reg_passed=True,
    reg_warnings=None,
    errors=None,
):
    return {
        "vuln_fixed":    vuln_fixed,
        "rescan_passed": rescan_passed,
        "new_vulns":     new_vulns,
        "syntax": {
            "passed":  syntax_passed,
            "message": "ok" if syntax_passed else "SyntaxError",
            "tool":    "py_compile",
            **({"warning": True} if syntax_warning else {}),
        },
        "gitleaks": {
            "passed": gitleaks_passed,
            "count":  gitleaks_count,
        },
        "regression": {
            "passed":   reg_passed,
            "warnings": reg_warnings or [],
            "errors":   errors or [],
        },
        "errors":   errors or [],
        "warnings": [],
    }


# ─── vuln_fixed=False → score 0 ───────────────────────────────────────────────

def test_not_fixed_returns_zero():
    score, details = _compute_confidence(_vr(vuln_fixed=False), False, "CWE-79", "x=1")
    assert score == 0


def test_not_fixed_details_have_failed_semgrep():
    _, details = _compute_confidence(_vr(vuln_fixed=False), False, "CWE-79", "x=1")
    assert "failed" in details.get("semgrep", "")


# ─── perfect conditions → maximum score ──────────────────────────────────────

def test_perfect_score_is_capped_at_100():
    score, _ = _compute_confidence(_vr(), False, "CWE-79", "x=1")
    assert score <= 100


def test_all_passing_no_cache_gives_high_score():
    score, _ = _compute_confidence(_vr(), False, "CWE-79", "x=1")
    # syntax(30) + semgrep(30) + gitleaks(20) + regression(20) + no_new_vulns(5) = 105 → capped 100
    assert score == 100


# ─── syntax contribution ─────────────────────────────────────────────────────

def test_syntax_tool_warning_gives_partial_credit():
    vr = _vr(syntax_passed=True, syntax_warning=True)
    score, details = _compute_confidence(vr, False, "CWE-79", "x=1")
    assert "warning" in details["syntax"]
    # 15 (syntax) + 30 (semgrep) + 20 (gl) + 20 (reg) + 5 (no new) = 90
    assert score == 90


def test_syntax_failed_gives_zero_syntax_credit():
    vr = _vr(vuln_fixed=True, syntax_passed=False)
    score, details = _compute_confidence(vr, False, "CWE-79", "x=1")
    assert "failed" in details["syntax"]
    # 0 (syntax) + 30 (semgrep) + 20 (gl) + 20 (reg) + 5 (no new) = 75
    assert score == 75


# ─── semgrep contribution ─────────────────────────────────────────────────────

def test_semgrep_not_passed_gives_partial_credit():
    vr = _vr(rescan_passed=False)
    score, details = _compute_confidence(vr, False, "CWE-79", "x=1")
    assert "warning" in details["semgrep"]
    # 30 (syn) + 10 (semgrep partial) + 20 (gl) + 20 (reg) + 5 (no new) = 85
    assert score == 85


# ─── gitleaks contribution ────────────────────────────────────────────────────

def test_gitleaks_failed_reduces_score():
    vr = _vr(gitleaks_passed=False, gitleaks_count=2)
    score, details = _compute_confidence(vr, False, "CWE-79", "x=1")
    assert "warning" in details["gitleaks"]
    # 30 (syn) + 30 (semgrep) + 5 (gl partial) + 20 (reg) + 5 (no new) = 90
    assert score == 90


# ─── regression contribution ─────────────────────────────────────────────────

def test_regression_warnings_reduce_score():
    vr = _vr(reg_warnings=["Some warning"])
    score, details = _compute_confidence(vr, False, "CWE-79", "x=1")
    assert "warning" in details["lint"]
    # 30 (syn) + 30 (semgrep) + 20 (gl) + 10 (reg partial) + 5 (no new) = 95
    assert score == 95


def test_regression_failed_gives_zero_lint_credit():
    vr = {**_vr(), "regression": {"passed": False, "warnings": [], "errors": ["Empty"]}}
    score, details = _compute_confidence(vr, False, "CWE-79", "x=1")
    assert "failed" in details["lint"]


# ─── bonuses ──────────────────────────────────────────────────────────────────

def test_new_vulns_removes_bonus():
    # Use syntax_warning=True so base=15+30+20+20=85, staying below the 100 cap.
    # With no_new_vulns bonus: 85+5=90. Without: 85. Difference = 5.
    score_with_new, _ = _compute_confidence(_vr(new_vulns=1, syntax_warning=True), False, "CWE-79", "x=1")
    score_clean, _    = _compute_confidence(_vr(new_vulns=0, syntax_warning=True), False, "CWE-79", "x=1")
    assert score_with_new == score_clean - 5


def test_cache_hit_adds_bonus():
    # Use syntax_warning=True so scores stay below 100 and the cache bonus is visible.
    # no_cache: 85+5=90; cache: 85+5+5=95. Difference = 5.
    vr = _vr(syntax_warning=True)
    score_cache, details = _compute_confidence(vr, True, "CWE-79", "x=1")
    score_no_cache, _    = _compute_confidence(vr, False, "CWE-79", "x=1")
    assert score_cache == score_no_cache + 5
    assert details["consensus"] == "cache"


# ─── details structure ────────────────────────────────────────────────────────

def test_details_has_all_keys():
    _, details = _compute_confidence(_vr(), False, "CWE-79", "x=1")
    for key in ("syntax", "semgrep", "gitleaks", "lint", "consensus"):
        assert key in details


def test_consensus_single_model_label():
    _, details = _compute_confidence(_vr(), False, "CWE-79", "x=1")
    assert details["consensus"] == "single model"


def test_consensus_with_info():
    consensus = {"badge": "3/3", "patches": {"groq": "x", "gpt": "x", "claude": "x"}}
    _, details = _compute_confidence(_vr(), False, "CWE-79", "x=1", consensus)
    assert "3" in details["consensus"]


# ─── score cap ───────────────────────────────────────────────────────────────

def test_score_never_exceeds_100():
    # cache + no new vulns + all passing would exceed 100 without cap
    score, _ = _compute_confidence(_vr(), True, "CWE-79", "x=1")
    assert score <= 100


def test_score_never_negative():
    # worst case: nothing passes
    vr = _vr(
        vuln_fixed=True,
        rescan_passed=False,
        new_vulns=5,
        syntax_passed=False,
        gitleaks_passed=False,
        gitleaks_count=3,
        reg_warnings=["warn"],
    )
    score, _ = _compute_confidence(vr, False, "CWE-79", "x=1")
    assert score >= 0
