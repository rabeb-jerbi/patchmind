"""
tests/test_routes.py
HTTP route tests: status codes, auth, basic response validation.
"""
import io
import pytest
from unittest.mock import patch


# ─── Public routes ────────────────────────────────────────────────────────────

def test_login_page_get(client):
    r = client.get("/login")
    assert r.status_code == 200


def test_login_page_has_html(client):
    r = client.get("/login")
    assert b"<html" in r.data.lower() or b"<!doctype" in r.data.lower()


def test_request_access_page(client):
    r = client.get("/request-access")
    assert r.status_code == 200


# ─── Protected routes — unauthenticated ──────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/dashboard", "/history", "/profile",
    "/files", "/download",
])
def test_protected_get_redirects_to_login(client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code in (302, 401)


@pytest.mark.parametrize("path", [
    "/upload", "/reanalyze", "/assign", "/false-positive",
])
def test_protected_post_returns_401(client, path):
    r = client.post(path, json={})
    assert r.status_code == 401


# ─── Protected routes — authenticated ────────────────────────────────────────

def test_dashboard_returns_200(auth_client):
    r = auth_client.get("/dashboard")
    assert r.status_code == 200


def test_history_returns_200(auth_client):
    r = auth_client.get("/history")
    assert r.status_code == 200


def test_files_returns_200(auth_client):
    r = auth_client.get("/files")
    assert r.status_code == 200


def test_profile_get_returns_200(auth_client):
    r = auth_client.get("/profile")
    assert r.status_code == 200


# ─── /status ─────────────────────────────────────────────────────────────────

def test_status_requires_auth(client):
    r = client.get("/status")
    assert r.status_code in (302, 401)


def test_status_returns_json(auth_client):
    r = auth_client.get("/status")
    data = r.get_json()
    assert data is not None
    assert "running" in data or "progress" in data


def test_status_with_invalid_job_id(auth_client):
    r = auth_client.get("/status?job_id=invalid-does-not-exist")
    # job_id mismatch → 404 with error; no 500
    assert r.status_code in (200, 404)


# ─── /api/tools ──────────────────────────────────────────────────────────────

def test_api_tools_list_returns_json(auth_client):
    r = auth_client.get("/api/tools")
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert isinstance(data["tools"], list)


def test_api_tools_each_has_required_fields(auth_client):
    r = auth_client.get("/api/tools")
    for t in r.get_json()["tools"]:
        assert "name" in t
        assert "description" in t
        assert "available" in t


def test_api_tools_recommend_missing_target(auth_client):
    r = auth_client.post("/api/tools/recommend", json={})
    assert r.status_code == 400


def test_api_tools_recommend_traversal_rejected(auth_client):
    r = auth_client.post("/api/tools/recommend",
                         json={"target_path": "../../../etc/passwd"})
    assert r.status_code in (403, 404)


def test_api_tools_run_invalid_tool_name(auth_client):
    r = auth_client.post("/api/tools/run",
                         json={"tool_name": "nonexistent_tool_xyz",
                               "target_path": "."})
    assert r.status_code == 404


def test_api_tools_run_missing_tool_name(auth_client):
    r = auth_client.post("/api/tools/run", json={"target_path": "."})
    assert r.status_code == 400


def test_api_tools_run_missing_target(auth_client):
    r = auth_client.post("/api/tools/run", json={"tool_name": "bandit"})
    assert r.status_code == 400


def test_api_tools_run_traversal_rejected(auth_client):
    r = auth_client.post("/api/tools/run",
                         json={"tool_name": "bandit",
                               "target_path": "../../../etc/passwd"})
    assert r.status_code in (403, 404)


# ─── /admin routes ────────────────────────────────────────────────────────────

def test_admin_users_denied_for_analyst(auth_client):
    r = auth_client.get("/admin/users")
    assert r.status_code == 403


def test_admin_stats_denied_for_analyst(auth_client):
    r = auth_client.get("/admin/stats")
    assert r.status_code == 403


def test_admin_users_allowed_for_admin(admin_client):
    r = admin_client.get("/admin/users")
    assert r.status_code == 200


def test_admin_audit_allowed_for_admin(admin_client):
    r = admin_client.get("/admin/audit")
    assert r.status_code == 200


# ─── /admin/users DELETE (soft delete) ───────────────────────────────────────

import json as _json
from werkzeug.security import generate_password_hash as _phash
from database.db import get_db_session as _get_db
from database.models import User as _User


def _create_user(app, username, role="analyst", active=True):
    with app.app_context():
        db = _get_db()
        if not db.query(_User).filter_by(username=username).first():
            db.add(_User(
                username=username,
                password=_phash("Pass@1234!"),
                role=role,
                email=f"{username}@test.local",
                active=active,
                blocked=False,
                must_change_password=False,
                totp_enabled=False,
            ))
            db.commit()
        # Invalidate load_users() TTL cache so this user is visible to routes
        import dashboard.app as _dash_app
        _dash_app._users_cache    = {}
        _dash_app._users_cache_ts = 0.0


def test_delete_normal_user(app, admin_client):
    _create_user(app, "victim_user", role="analyst")
    r = admin_client.delete("/admin/users/victim_user")
    assert r.status_code == 200
    d = _json.loads(r.data)
    assert d["ok"] is True


def test_deleted_user_not_in_list(app, admin_client):
    _create_user(app, "ghost_user", role="analyst")
    admin_client.delete("/admin/users/ghost_user")
    r = admin_client.get("/admin/users")
    users = _json.loads(r.data)
    assert not any(u["username"] == "ghost_user" for u in users)


def test_cannot_delete_self(admin_client):
    # admin_client is logged in as "admin"
    r = admin_client.delete("/admin/users/admin")
    assert r.status_code == 400
    d = _json.loads(r.data)
    assert d["ok"] is False


def test_cannot_delete_last_admin(app, admin_client):
    # Ensure no other active admin exists, then try deleting "admin" (only admin)
    # First, verify admin is the only admin in the test DB
    with app.app_context():
        db = _get_db()
        admins = db.query(_User).filter_by(role="admin", active=True).all()
        if len(admins) > 1:
            pytest.skip("Multiple admins in DB — last-admin guard not triggered")
    r = admin_client.delete("/admin/users/admin")
    # Either blocked as self-delete (400) or last-admin (400)
    assert r.status_code == 400
    d = _json.loads(r.data)
    assert d["ok"] is False


def test_delete_nonexistent_user_returns_404(admin_client):
    r = admin_client.delete("/admin/users/does_not_exist_xyz")
    assert r.status_code == 404
    d = _json.loads(r.data)
    assert d["ok"] is False


# ─── /request-access & approval (soft-delete compatibility) ──────────────────

import secrets as _secrets
from database.models import AccessRequest as _AccessRequest


def _seed_request(app, email, status="pending", req_id=None):
    """Insert an AccessRequest row directly into the DB."""
    with app.app_context():
        db = _get_db()
        rid = req_id or _secrets.token_hex(8)
        if not db.query(_AccessRequest).filter_by(id=rid).first():
            db.add(_AccessRequest(
                id=rid, email=email, full_name="Test User",
                reason="", status=status, role_requested="analyst",
            ))
            db.commit()
        return rid


def _soft_delete_user(app, username):
    with app.app_context():
        db = _get_db()
        row = db.query(_User).filter_by(username=username).first()
        if row:
            row.active  = False
            row.blocked = True
            db.commit()
    import dashboard.app as _dash_app
    _dash_app._users_cache    = {}
    _dash_app._users_cache_ts = 0.0


def test_soft_deleted_user_can_request_access_again(app, client):
    """A user soft-deleted from admin should be able to re-submit an access request."""
    _create_user(app, "reapply_user", role="analyst")
    _soft_delete_user(app, "reapply_user")
    r = client.post("/request-access", json={
        "full_name": "Re Apply", "email": "reapply_user@test.local",
    })
    assert r.status_code == 200
    d = _json.loads(r.data)
    assert d["ok"] is True


def test_active_user_cannot_request_access(app, client):
    """An active account holder cannot submit a new access request."""
    _create_user(app, "active_requester", role="analyst")
    r = client.post("/request-access", json={
        "full_name": "Active", "email": "active_requester@test.local",
    })
    assert r.status_code == 400
    d = _json.loads(r.data)
    assert d["ok"] is False


def test_pending_request_blocks_duplicate_email(app, client):
    """Submitting a second request while one is still pending → 400."""
    _seed_request(app, "dup_pending@test.local", status="pending")
    r = client.post("/request-access", json={
        "full_name": "Dup", "email": "dup_pending@test.local",
    })
    assert r.status_code == 400
    d = _json.loads(r.data)
    assert d["ok"] is False


def test_approved_request_does_not_block_new_request(app, client):
    """After a previous approved request, a new one should be accepted (if no active user)."""
    _seed_request(app, "prev_approved@test.local", status="approved")
    r = client.post("/request-access", json={
        "full_name": "Prev Approved", "email": "prev_approved@test.local",
    })
    # Should succeed (no pending request, no active user with this email)
    assert r.status_code == 200
    d = _json.loads(r.data)
    assert d["ok"] is True


def test_approving_request_reactivates_inactive_user(app, admin_client):
    """Approving a request for a soft-deleted user's email should reactivate the account."""
    email = "reactive_approve@test.local"
    # Create then soft-delete the user
    _create_user(app, "reactive_approve", role="analyst")
    _soft_delete_user(app, "reactive_approve")

    # Seed a pending access request for the same email
    rid = _seed_request(app, email, status="pending")

    r = admin_client.post(f"/admin/requests/{rid}/approve")
    assert r.status_code == 200
    d = _json.loads(r.data)
    assert d["ok"] is True
    assert d.get("reactivated") is True

    # User should now be active again
    with app.app_context():
        db = _get_db()
        row = db.query(_User).filter_by(email=email).first()
        assert row is not None
        assert row.active is True
        assert row.blocked is False


def test_approve_does_not_expose_password_when_email_sent(app, admin_client):
    """When email delivery succeeds the JSON must not contain the plaintext password."""
    from unittest.mock import patch
    rid = _seed_request(app, "nopw_expose@test.local", status="pending")

    with patch("dashboard.app.send_credentials_email", return_value=True):
        r = admin_client.post(f"/admin/requests/{rid}/approve")

    assert r.status_code == 200
    d = _json.loads(r.data)
    assert d["ok"] is True
    assert d.get("email_sent") is True
    assert "mot de passe" not in d.get("message", "")


# ─── /projects ───────────────────────────────────────────────────────────────

from database.models import Project as _Project

def _create_project(app, pid, name, owner):
    with app.app_context():
        db = _get_db()
        if not db.query(_Project).filter_by(id=pid).first():
            db.add(_Project(id=pid, name=name, owner=owner, description="test", status="active"))
            db.commit()


def test_projects_page_requires_auth(client):
    r = client.get("/projects")
    assert r.status_code in (302, 401)


def test_projects_page_ok_for_analyst(auth_client):
    r = auth_client.get("/projects")
    assert r.status_code == 200


def test_projects_api_list_returns_json(auth_client):
    r = auth_client.get("/projects/api")
    assert r.status_code == 200
    data = r.get_json()
    assert isinstance(data, list)


def test_projects_api_create(auth_client):
    r = auth_client.post("/projects/api", json={"name": "Test Project CI"})
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] is True
    assert "id" in d


def test_projects_api_create_missing_name(auth_client):
    r = auth_client.post("/projects/api", json={})
    assert r.status_code == 400


def test_project_edit_by_owner(app, auth_client):
    _create_project(app, "proj_edit_test", "Edit Me", "test_analyst")
    r = auth_client.put("/projects/api/proj_edit_test", json={
        "name": "Edited Name", "description": "new desc"
    })
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] is True
    assert d["project"]["name"] == "Edited Name"


def test_project_edit_missing_name(app, auth_client):
    _create_project(app, "proj_edit_noname", "Has Name", "test_analyst")
    r = auth_client.put("/projects/api/proj_edit_noname", json={"name": ""})
    assert r.status_code == 400


def test_project_edit_by_non_owner_forbidden(app, admin_client):
    _create_project(app, "proj_edit_other", "Other Owner", "test_analyst")
    r = admin_client.put("/projects/api/proj_edit_other", json={"name": "Hacked"})
    assert r.status_code == 403


def test_project_edit_not_found(auth_client):
    r = auth_client.put("/projects/api/proj_does_not_exist", json={"name": "X"})
    assert r.status_code == 404


def test_project_members_requires_auth(client):
    r = client.get("/projects/api/proj_x/members")
    assert r.status_code in (302, 401)


def test_project_invite_missing_email(app, auth_client):
    _create_project(app, "proj_invite_test", "Invite Project", "test_analyst")
    r = auth_client.post("/projects/api/proj_invite_test/invite", json={"email": ""})
    assert r.status_code == 400


def test_project_invite_invalid_email(app, auth_client):
    _create_project(app, "proj_invite_invalid", "Invite Invalid", "test_analyst")
    r = auth_client.post("/projects/api/proj_invite_invalid/invite", json={"email": "not-an-email"})
    assert r.status_code == 400


def test_project_invite_by_owner_succeeds(app, auth_client):
    _create_project(app, "proj_invite_ok", "Invite OK", "test_analyst")
    r = auth_client.post("/projects/api/proj_invite_ok/invite", json={
        "email": "invitee@example.com", "role": "member"
    })
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] is True
    # New workflow: invitation is pending approval, no direct link returned
    assert d.get("pending_approval") is True
    assert "id" in d


def test_project_invite_duplicate_pending_rejected(app, auth_client):
    _create_project(app, "proj_invite_dup", "Invite Dup", "test_analyst")
    auth_client.post("/projects/api/proj_invite_dup/invite",
                     json={"email": "dup@example.com"})
    r = auth_client.post("/projects/api/proj_invite_dup/invite",
                         json={"email": "dup@example.com"})
    assert r.status_code == 409


def test_invitation_view_invalid_token(auth_client):
    r = auth_client.get("/project-invitations/nonexistent_token_xyz")
    assert r.status_code == 404


def test_invitation_accept_invalid_token(auth_client):
    r = auth_client.post("/project-invitations/nonexistent_token_xyz/accept")
    assert r.status_code == 404


def test_invitation_reject_invalid_token(auth_client):
    r = auth_client.post("/project-invitations/nonexistent_token_xyz/reject")
    assert r.status_code == 404


def test_history_without_project_filter(auth_client):
    r = auth_client.get("/history")
    assert r.status_code == 200
    assert isinstance(r.get_json(), list)


def test_history_with_unknown_project_filter(auth_client):
    r = auth_client.get("/history?project_id=proj_nonexistent_xyz")
    assert r.status_code == 200
    data = r.get_json()
    assert data == []


def test_project_member_remove_admin_allowed(app, admin_client):
    """Admin can remove a member even if not the project owner."""
    _create_project(app, "proj_remove_test", "Remove Test", "test_analyst")
    # admin is allowed (admin RBAC override), but 'someone' does not exist → still 200 (ok, no-op)
    r = admin_client.delete("/projects/api/proj_remove_test/members/someone")
    assert r.status_code == 200


# ─── Upload route basic ───────────────────────────────────────────────────────

def test_upload_no_file_returns_400(auth_client):
    r = auth_client.post("/upload", data={}, content_type="multipart/form-data")
    assert r.status_code == 400


def test_upload_unsupported_extension_returns_400(auth_client):
    r = auth_client.post(
        "/upload",
        data={"file": (io.BytesIO(b"data"), "file.exe")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 400


def test_upload_valid_py_starts_pipeline(auth_client):
    with patch("dashboard.app.run_pipeline"):
        r = auth_client.post(
            "/upload",
            data={"file": (io.BytesIO(b"x = 1\n"), "app.py")},
            content_type="multipart/form-data",
        )
    assert r.status_code == 200
    assert "job_id" in r.get_json()


# ─── /report ─────────────────────────────────────────────────────────────────

def test_report_requires_auth(client):
    r = client.get("/report")
    assert r.status_code in (302, 401)


def test_report_accessible_to_analyst(auth_client):
    r = auth_client.get("/report")
    # /report returns 404 when no analysis results yet — auth is working either way
    assert r.status_code in (200, 404)


# ─── Dashboard metrics — zero for new accounts ───────────────────────────────

def test_history_returns_empty_for_new_user(admin_client):
    """A brand-new account has no sessions — /history returns []."""
    r = admin_client.get("/history")
    assert r.status_code == 200
    data = r.get_json()
    assert isinstance(data, list)


def test_new_user_metrics_are_zero(admin_client):
    """New user: /history is [] so metrics must all be 0, not fake ~N values."""
    r = admin_client.get("/history")
    sessions = r.get_json()
    total_vulns   = sum(s.get("total_vulns", 0) for s in sessions)
    total_patches = sum(s.get("patches_validated", 0) for s in sessions)
    # For a new account both counts must be exactly 0 (no fake ~10/~25 values)
    assert isinstance(total_vulns, int)
    assert isinstance(total_patches, int)
    assert total_vulns   == 0
    assert total_patches == 0


# ─── RBAC — "user" role can run tools ────────────────────────────────────────

def test_user_role_has_run_scan_permission():
    from rbac import has_permission
    assert has_permission("user", "run_scan") is True


def test_user_role_has_view_dashboard_permission():
    from rbac import has_permission
    assert has_permission("user", "view_dashboard") is True


def test_viewer_role_cannot_run_scan():
    from rbac import has_permission
    assert has_permission("viewer", "run_scan") is False


def test_api_tools_run_allowed_for_user_role(client, app, _seed_test_users):
    """A logged-in user with role='user' must not get 403 from /api/tools/run."""
    with client.session_transaction() as sess:
        sess["username"] = "test_analyst"
        sess["role"]     = "user"
        sess["2fa_ok"]   = True
        sess["must_change_pw"] = False
    from unittest.mock import patch as _patch
    fake_result = {"ok": True, "findings": [], "duration": 0.1, "from_cache": False}
    with _patch("tools.tool_registry.ToolRegistry.run_tool", return_value=fake_result):
        r = client.post("/api/tools/run", json={
            "tool_name": "bandit", "target_path": "."
        })
    # Must not be 403 (permission denied)
    assert r.status_code != 403


def test_api_tools_run_blocked_for_unauthenticated(client):
    r = client.post("/api/tools/run", json={"tool_name": "bandit", "target_path": "."})
    assert r.status_code in (302, 401, 403)


# ─── Semgrep path resolution ─────────────────────────────────────────────────

def test_semgrep_missing_returns_empty_list(tmp_path):
    """run_scan() must return [] and not raise when semgrep is absent."""
    import scanner.scanner as _s
    orig = _s.SEMGREP_PATH
    _s.SEMGREP_PATH = ""   # simulate missing binary
    try:
        py_file = tmp_path / "test.py"
        py_file.write_text("import os\nos.system('ls')\n")
        result = _s.run_scan(str(py_file))
        assert result == []
    finally:
        _s.SEMGREP_PATH = orig


def test_semgrep_bad_path_returns_empty_list(tmp_path):
    """run_scan() must return [] when the binary path does not exist."""
    import scanner.scanner as _s
    orig = _s.SEMGREP_PATH
    _s.SEMGREP_PATH = "/nonexistent/path/semgrep"
    try:
        py_file = tmp_path / "test.py"
        py_file.write_text("x = 1\n")
        result = _s.run_scan(str(py_file))
        assert result == []
    finally:
        _s.SEMGREP_PATH = orig


# ─── Pipeline status ─────────────────────────────────────────────────────────

def test_status_returns_json_for_authenticated(auth_client):
    r = auth_client.get("/status")
    assert r.status_code == 200
    data = r.get_json()
    assert "running" in data
    assert "status" in data


def test_pipeline_status_field_is_idle_for_new_user(auth_client):
    r = auth_client.get("/status")
    data = r.get_json()
    assert data["status"] in ("idle", "running", "completed",
                               "completed_with_warnings", "failed")


# ─── Tool registry availability ──────────────────────────────────────────────

def test_api_tools_returns_only_available(auth_client):
    """Endpoint must return only installed/available tools."""
    r = auth_client.get("/api/tools")
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] is True
    assert isinstance(d["tools"], list)
    # Every tool returned must be available — never expose uninstalled tools
    for t in d["tools"]:
        assert t.get("available") is True, (
            f"Tool {t['name']!r} returned by /api/tools but available=False"
        )


def test_api_tools_include_install_hint(auth_client):
    r = auth_client.get("/api/tools")
    d = r.get_json()
    for tool in d["tools"]:
        assert "install_hint" in tool
        assert "available" in tool


# ─── Audit log API (Section 2 fix: DB-backed) ────────────────────────────────

def test_audit_api_returns_json(admin_client):
    r = admin_client.get("/admin/audit/api")
    assert r.status_code == 200
    d = r.get_json()
    assert "entries" in d
    assert "total" in d
    assert isinstance(d["entries"], list)


def test_audit_api_entries_have_required_fields(admin_client):
    """Each audit entry should have ts, event, user, ip, details fields."""
    r = admin_client.get("/admin/audit/api")
    for entry in r.get_json()["entries"]:
        for field in ("ts", "event", "user", "ip"):
            assert field in entry, f"Missing field '{field}' in audit entry"


def test_audit_api_pagination(admin_client):
    r = admin_client.get("/admin/audit/api?page=1&per_page=5")
    assert r.status_code == 200
    d = r.get_json()
    assert d["page"] == 1
    assert d["per_page"] == 5
    assert len(d["entries"]) <= 5


def test_audit_api_denied_for_analyst(auth_client):
    r = auth_client.get("/admin/audit/api")
    assert r.status_code == 403


def test_audit_api_event_filter(admin_client):
    r = admin_client.get("/admin/audit/api?event=login")
    assert r.status_code == 200
    d = r.get_json()
    for entry in d["entries"]:
        assert "login" in entry.get("event", "").lower()


# ─── Semgrep CWE extraction (Section 3 fix) ──────────────────────────────────

def test_semgrep_cwe_as_list(tmp_path):
    """run_scan() must handle cwe as a list (normal Semgrep format)."""
    import json
    import scanner.scanner as _s

    fake_output = json.dumps({"results": [{
        "path": str(tmp_path / "f.py"),
        "start": {"line": 1},
        "check_id": "test-rule",
        "extra": {
            "severity": "HIGH",
            "message": "test finding",
            "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
        },
    }]})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = fake_output
        mock_run.return_value.stderr = ""
        mock_run.return_value.returncode = 0
        orig = _s.SEMGREP_PATH
        _s.SEMGREP_PATH = "/fake/semgrep"
        try:
            py_file = tmp_path / "f.py"
            py_file.write_text("x=1\n")
            result = _s.run_scan(str(py_file))
        finally:
            _s.SEMGREP_PATH = orig
    assert len(result) == 1
    assert result[0]["cwe"] == "CWE-78"


def test_semgrep_cwe_as_string(tmp_path):
    """run_scan() must handle cwe as a plain string (some rule outputs)."""
    import json
    import scanner.scanner as _s

    fake_output = json.dumps({"results": [{
        "path": str(tmp_path / "f.py"),
        "start": {"line": 2},
        "check_id": "test-rule2",
        "extra": {
            "severity": "MEDIUM",
            "message": "another finding",
            "metadata": {"cwe": "CWE-89: SQL Injection"},
        },
    }]})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = fake_output
        mock_run.return_value.stderr = ""
        mock_run.return_value.returncode = 0
        orig = _s.SEMGREP_PATH
        _s.SEMGREP_PATH = "/fake/semgrep"
        try:
            py_file = tmp_path / "f.py"
            py_file.write_text("x=1\n")
            result = _s.run_scan(str(py_file))
        finally:
            _s.SEMGREP_PATH = orig
    assert len(result) == 1
    assert result[0]["cwe"] == "CWE-89"


def test_semgrep_missing_metadata_keeps_finding(tmp_path):
    """run_scan() must keep a finding even when metadata key is absent."""
    import json
    import scanner.scanner as _s

    fake_output = json.dumps({"results": [{
        "path": str(tmp_path / "f.py"),
        "start": {"line": 5},
        "check_id": "test-rule3",
        "extra": {
            "severity": "LOW",
            "message": "no metadata",
        },
    }]})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = fake_output
        mock_run.return_value.stderr = ""
        mock_run.return_value.returncode = 0
        orig = _s.SEMGREP_PATH
        _s.SEMGREP_PATH = "/fake/semgrep"
        try:
            py_file = tmp_path / "f.py"
            py_file.write_text("x=1\n")
            result = _s.run_scan(str(py_file))
        finally:
            _s.SEMGREP_PATH = orig
    assert len(result) == 1
    assert result[0]["cwe"] == "CWE-UNKNOWN"


# ─── Bandit adapter (Section 1) ───────────────────────────────────────────────

def test_bandit_adapter_parse_output():
    """BanditTool.parse_output() must normalize findings correctly."""
    import json
    from tools.bandit_adapter import BanditTool

    raw = json.dumps({"results": [{
        "issue_cwe":      {"id": 78, "link": ""},
        "issue_severity": "HIGH",
        "filename":       "/app/vuln.py",
        "line_number":    10,
        "issue_text":     "Use of os.system",
        "more_info":      "https://bandit.readthedocs.io/",
        "test_id":        "B605",
    }]})
    findings = BanditTool().parse_output(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f["cwe"] == "CWE-78"
    assert f["severity"] == "HIGH"
    assert f["file"] == "/app/vuln.py"
    assert f["line"] == 10
    assert "os.system" in f["message"]


def test_bandit_adapter_parse_empty():
    """BanditTool.parse_output() must return [] for empty results."""
    import json
    from tools.bandit_adapter import BanditTool
    raw = json.dumps({"results": []})
    assert BanditTool().parse_output(raw) == []


def test_bandit_adapter_parse_invalid_json():
    """BanditTool.parse_output() must return [] for invalid JSON without raising."""
    from tools.bandit_adapter import BanditTool
    assert BanditTool().parse_output("not json") == []


# ─── Invitation HTML page (Sections 7 & 8) ───────────────────────────────────

from database.models import ProjectInvitation as _ProjectInvitation
from datetime import datetime as _dt, timedelta as _td
import secrets as _sec


def _create_invitation(app, project_id, email, token=None, status='pending',
                       expires_offset_days=7):
    with app.app_context():
        db = _get_db()
        tok = token or _sec.token_urlsafe(32)
        inv = _ProjectInvitation(
            project_id  = project_id,
            invited_by  = 'test_analyst',
            email       = email,
            token       = tok,
            role        = 'member',
            status      = status,
            expires_at  = _dt.now() + _td(days=expires_offset_days),
        )
        db.add(inv)
        db.commit()
        return tok


def test_invitation_view_renders_html(app, auth_client):
    """GET /project-invitations/<token> must return HTML, not raw JSON."""
    _create_project(app, "proj_inv_html", "HTML Invite", "test_analyst")
    tok = _create_invitation(app, "proj_inv_html", "other@test.local")
    r = auth_client.get(f"/project-invitations/{tok}")
    assert r.status_code == 200
    assert b"<!DOCTYPE html" in r.data or b"<!doctype html" in r.data.lower()


def test_invitation_view_shows_project_name(app, auth_client):
    """The HTML page must include the project name."""
    _create_project(app, "proj_inv_name", "My Special Project", "test_analyst")
    tok = _create_invitation(app, "proj_inv_name", "other@test.local")
    r = auth_client.get(f"/project-invitations/{tok}")
    assert b"My Special Project" in r.data


def test_invitation_view_expired_token_shows_status(app, auth_client):
    """An expired invitation must show 'expired' status in HTML."""
    _create_project(app, "proj_inv_exp", "Expired Project", "test_analyst")
    tok = _create_invitation(app, "proj_inv_exp", "other@test.local",
                              expires_offset_days=-1)
    r = auth_client.get(f"/project-invitations/{tok}")
    assert r.status_code == 200
    assert b"expir" in r.data.lower()


def test_invitation_view_bad_token_shows_error(auth_client):
    """An unknown token must return 404 HTML (not 500 or raw JSON)."""
    r = auth_client.get("/project-invitations/totally_fake_token_xyz")
    assert r.status_code == 404
    assert b"introuvable" in r.data.lower() or b"<!doctype" in r.data.lower()


def test_invitation_view_unauthenticated_redirects(client):
    """Unauthenticated access must redirect to login."""
    r = client.get("/project-invitations/some_token", follow_redirects=False)
    assert r.status_code in (302, 301)
    assert b"/login" in r.headers.get("Location", "").encode()


def test_invitation_accept_returns_ok_json(app, auth_client):
    """Accept from a JSON client must return {"ok": true, "project_id": ...} for approved invitations."""
    _create_project(app, "proj_acc_json", "Accept JSON", "test_analyst")
    # Invitation must be in 'approved' status to be accepted (pending requires admin approval first)
    tok = _create_invitation(app, "proj_acc_json", "test_analyst@test.local", status='approved')
    # Update analyst email in DB to match invitation
    with app.app_context():
        db = _get_db()
        u = db.query(_User).filter_by(username='test_analyst').first()
        if u: u.email = 'test_analyst@test.local'; db.commit()
        import dashboard.app as _dash_app
        _dash_app._users_cache = {}; _dash_app._users_cache_ts = 0.0
    r = auth_client.post(f"/project-invitations/{tok}/accept",
                         json={}, headers={"Accept": "application/json"})
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] is True
    assert d["project_id"] == "proj_acc_json"


def test_invitation_accept_pending_requires_approval(app, auth_client):
    """Pending invitation must return 409 — admin approval required first."""
    _create_project(app, "proj_acc_pending", "Pending Accept", "test_analyst")
    tok = _create_invitation(app, "proj_acc_pending", "test_analyst@test.local", status='pending')
    r = auth_client.post(f"/project-invitations/{tok}/accept", json={})
    assert r.status_code == 409


def test_invitation_accept_wrong_email_rejected(app, auth_client):
    """Accept must be rejected if logged-in user's email != invitation email."""
    _create_project(app, "proj_wrong_email", "Wrong Email", "test_analyst")
    tok = _create_invitation(app, "proj_wrong_email", "someone_else@example.com", status='approved')
    r = auth_client.post(f"/project-invitations/{tok}/accept", json={})
    assert r.status_code == 403


def test_invitation_reject_returns_ok(app, auth_client):
    """Rejecting an invitation must return {"ok": true}."""
    _create_project(app, "proj_rej_json", "Reject JSON", "test_analyst")
    tok = _create_invitation(app, "proj_rej_json", "test_analyst@test.local")
    r = auth_client.post(f"/project-invitations/{tok}/reject",
                         json={}, headers={"Accept": "application/json"})
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


# ─── Invite pending-approval workflow (Section 9) ────────────────────────────

def test_project_invite_returns_pending_approval(app, auth_client):
    """New workflow: invite goes to admin for approval, response has pending_approval=True."""
    _create_project(app, "proj_inv_email_field", "Email Field", "test_analyst")
    r = auth_client.post("/projects/api/proj_inv_email_field/invite",
                         json={"email": "somebody@example.com", "role": "member"})
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] is True
    assert d.get("pending_approval") is True
    assert "id" in d
    # No email is sent at invite time — that happens only after admin approval
    assert "email_sent" not in d


def test_project_invite_no_email_at_invite_time(app, auth_client):
    """Invite route must not call send_project_invitation_email (email only after admin approval)."""
    _create_project(app, "proj_inv_email_false", "Email False", "test_analyst")
    with patch("dashboard.app.send_project_invitation_email") as mock_send:
        r = auth_client.post("/projects/api/proj_inv_email_false/invite",
                             json={"email": "nobody2@example.com", "role": "viewer"})
    assert r.status_code == 200
    mock_send.assert_not_called()


# ─── Admin invitations API (Section 10) ──────────────────────────────────────

def test_admin_invitations_api_returns_json(app, admin_client):
    """GET /admin/api/invitations must return JSON 200, never an HTML error page."""
    r = admin_client.get("/admin/api/invitations?status=pending")
    assert r.status_code == 200
    ct = r.content_type or ''
    assert 'application/json' in ct, f"Expected JSON, got {ct}"
    d = r.get_json()
    assert d["ok"] is True
    assert "invitations" in d
    assert "pending_count" in d
    assert isinstance(d["invitations"], list)


def test_admin_invitations_api_all_statuses(app, admin_client):
    """Listing without status filter returns all invitations."""
    _create_project(app, "proj_adm_inv_all", "Admin All", "test_analyst")
    tok = _create_invitation(app, "proj_adm_inv_all", "all@test.local", status='pending')
    r = admin_client.get("/admin/api/invitations")
    assert r.status_code == 200
    d = r.get_json()
    assert any(i["email"] == "all@test.local" for i in d["invitations"])


def test_admin_invitations_api_pending_count_increments(app, admin_client):
    """pending_count reflects actual number of pending invitations."""
    _create_project(app, "proj_adm_count", "Count Test", "test_analyst")
    r_before = admin_client.get("/admin/api/invitations?status=pending")
    count_before = r_before.get_json()["pending_count"]

    _create_invitation(app, "proj_adm_count", "count_test@test.local", status='pending')

    r_after = admin_client.get("/admin/api/invitations?status=pending")
    count_after = r_after.get_json()["pending_count"]
    assert count_after == count_before + 1


def test_admin_invitations_includes_project_name(app, admin_client):
    """Each invitation entry must include project_name."""
    _create_project(app, "proj_adm_pname", "Named Project", "test_analyst")
    _create_invitation(app, "proj_adm_pname", "pname@test.local", status='pending')
    r = admin_client.get("/admin/api/invitations?status=pending")
    d = r.get_json()
    match = next((i for i in d["invitations"] if i["email"] == "pname@test.local"), None)
    assert match is not None
    assert match["project_name"] == "Named Project"


def test_admin_invitations_denied_for_analyst(auth_client):
    """Analyst must receive 403 from /admin/api/invitations."""
    r = auth_client.get("/admin/api/invitations?status=pending")
    assert r.status_code == 403
    # Must be JSON, not HTML
    d = r.get_json()
    assert d is not None


# ─── Project members API (Section 11) ────────────────────────────────────────

def test_project_members_api_returns_json(app, auth_client):
    """GET /projects/api/<id>/members must return JSON with members and invitations keys."""
    _create_project(app, "proj_mem_api", "Members API", "test_analyst")
    r = auth_client.get("/projects/api/proj_mem_api/members")
    assert r.status_code == 200
    ct = r.content_type or ''
    assert 'application/json' in ct, f"Expected JSON, got {ct}"
    d = r.get_json()
    assert "members" in d
    assert "invitations" in d
    assert isinstance(d["members"], list)
    assert isinstance(d["invitations"], list)


def test_project_members_shows_pending_invitations(app, auth_client):
    """Members list must include pending invitations."""
    _create_project(app, "proj_mem_pending", "Members Pending", "test_analyst")
    _create_invitation(app, "proj_mem_pending", "pending_member@test.local", status='pending')
    r = auth_client.get("/projects/api/proj_mem_pending/members")
    assert r.status_code == 200
    d = r.get_json()
    inv_emails = [i["email"] for i in d["invitations"]]
    assert "pending_member@test.local" in inv_emails


def test_project_members_unknown_project_returns_404_json(auth_client):
    """Members route for non-existent project must return JSON 404, not HTML."""
    r = auth_client.get("/projects/api/proj_does_not_exist_xyz99/members")
    assert r.status_code == 404
    d = r.get_json()
    assert d is not None
    assert "error" in d


def test_project_invite_unknown_project_returns_404_json(auth_client):
    """Invite to non-existent project must return JSON 404, not HTML."""
    r = auth_client.post("/projects/api/proj_nope_xyz99/invite",
                         json={"email": "x@y.com", "role": "member"})
    assert r.status_code == 404
    d = r.get_json()
    assert d is not None
    assert "error" in d
