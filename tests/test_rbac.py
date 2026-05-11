"""tests/test_rbac.py — RBAC unit tests (no Flask context needed)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from rbac import has_permission, role_level, ROLES, PERMISSIONS


# ─── role_level ───────────────────────────────────────────────────────────────

def test_role_levels_ordered():
    assert role_level("viewer") < role_level("analyst")
    assert role_level("analyst") < role_level("dev")
    assert role_level("dev") < role_level("admin")


def test_role_level_invalid():
    assert role_level("superuser") == -1
    assert role_level("") == -1
    assert role_level("ADMIN") == -1  # case-sensitive


def test_all_roles_have_levels():
    for r in ROLES:
        assert role_level(r) >= 0


# ─── has_permission — viewer ──────────────────────────────────────────────────

def test_viewer_can_view_dashboard():
    assert has_permission("viewer", "view_dashboard")


def test_viewer_can_comment():
    assert has_permission("viewer", "comment_vuln")


def test_viewer_cannot_run_scan():
    assert not has_permission("viewer", "run_scan")


def test_viewer_cannot_manage_users():
    assert not has_permission("viewer", "manage_users")


def test_viewer_cannot_download_patch():
    assert not has_permission("viewer", "download_patch")


def test_viewer_cannot_manage_projects():
    assert not has_permission("viewer", "manage_projects")


def test_viewer_cannot_view_audit():
    assert not has_permission("viewer", "view_audit")


# ─── has_permission — analyst ─────────────────────────────────────────────────

def test_analyst_can_run_scan():
    assert has_permission("analyst", "run_scan")


def test_analyst_can_download_patch():
    assert has_permission("analyst", "download_patch")


def test_analyst_can_export_report():
    assert has_permission("analyst", "export_report")


def test_analyst_can_flag_false_positive():
    assert has_permission("analyst", "false_positive")


def test_analyst_cannot_manage_users():
    assert not has_permission("analyst", "manage_users")


def test_analyst_cannot_assign_vuln():
    assert not has_permission("analyst", "assign_vuln")


def test_analyst_cannot_manage_projects():
    assert not has_permission("analyst", "manage_projects")


# ─── has_permission — dev ─────────────────────────────────────────────────────

def test_dev_can_manage_projects():
    assert has_permission("dev", "manage_projects")


def test_dev_can_assign_vuln():
    assert has_permission("dev", "assign_vuln")


def test_dev_cannot_manage_users():
    assert not has_permission("dev", "manage_users")


def test_dev_cannot_view_audit():
    assert not has_permission("dev", "view_audit")


# ─── has_permission — admin ───────────────────────────────────────────────────

def test_admin_can_manage_users():
    assert has_permission("admin", "manage_users")


def test_admin_can_view_audit():
    assert has_permission("admin", "view_audit")


def test_admin_can_view_ciso():
    assert has_permission("admin", "view_ciso")


def test_admin_can_manage_settings():
    assert has_permission("admin", "manage_settings")


def test_admin_has_all_permissions():
    for perm in PERMISSIONS:
        assert has_permission("admin", perm), f"admin should have {perm}"


# ─── has_permission — edge cases ─────────────────────────────────────────────

def test_invalid_role_has_no_permissions():
    for perm in PERMISSIONS:
        assert not has_permission("ghost", perm)


def test_unknown_permission_always_false():
    for role in ROLES:
        assert not has_permission(role, "nonexistent_perm")


def test_empty_role():
    assert not has_permission("", "run_scan")


def test_permission_matrix_completeness():
    """Every defined role should appear in at least one permission set."""
    all_roles_in_perms = set()
    for allowed in PERMISSIONS.values():
        all_roles_in_perms.update(allowed)
    for r in ROLES:
        assert r in all_roles_in_perms, f"role {r!r} not in any permission"
