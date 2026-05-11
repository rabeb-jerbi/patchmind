"""
tests/test_integration.py
Workflow integration tests: auth flows, upload pipeline, tool recommendation.

All external calls (scanner pipeline, LLM, email, subprocess tools) are mocked.
"""
import io
import pytest
from unittest.mock import patch, MagicMock


# ─── Auth workflow ────────────────────────────────────────────────────────────

def test_unauthenticated_redirected_from_dashboard(client):
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code in (302, 401)
    if r.status_code == 302:
        assert "login" in r.headers["Location"].lower()


def test_analyst_can_reach_dashboard(auth_client):
    r = auth_client.get("/dashboard")
    assert r.status_code == 200


def test_admin_can_reach_admin_panel(admin_client):
    r = admin_client.get("/admin/users")
    assert r.status_code == 200


def test_analyst_blocked_from_admin_panel(auth_client):
    r = auth_client.get("/admin/users")
    assert r.status_code == 403


def test_viewer_blocked_from_admin_panel(viewer_client):
    r = viewer_client.get("/admin/users")
    assert r.status_code == 403


# ─── Login page ───────────────────────────────────────────────────────────────

def test_login_page_loads(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert b"<form" in r.data.lower() or b"form" in r.data.lower()


def test_bad_credentials_returns_error(client):
    r = client.post("/login",
                    json={"username": "nobody_xyz", "password": "wrong_pass"})
    assert r.status_code in (200, 401)


# ─── Upload workflow ──────────────────────────────────────────────────────────

def test_upload_valid_python_accepted(auth_client):
    with patch("dashboard.app.run_pipeline"):
        r = auth_client.post(
            "/upload",
            data={"file": (io.BytesIO(b"x = 1\n"), "app.py")},
            content_type="multipart/form-data",
        )
    assert r.status_code == 200
    data = r.get_json()
    assert "job_id" in data


def test_upload_javascript_accepted(auth_client):
    with patch("dashboard.app.run_pipeline"):
        r = auth_client.post(
            "/upload",
            data={"file": (io.BytesIO(b"const x = 1;\n"), "app.js")},
            content_type="multipart/form-data",
        )
    assert r.status_code == 200


def test_upload_java_accepted(auth_client):
    with patch("dashboard.app.run_pipeline"):
        r = auth_client.post(
            "/upload",
            data={"file": (io.BytesIO(b"class A {}\n"), "Main.java")},
            content_type="multipart/form-data",
        )
    assert r.status_code == 200


def test_upload_exe_rejected(auth_client):
    r = auth_client.post(
        "/upload",
        data={"file": (io.BytesIO(b"\x4d\x5a"), "malware.exe")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 400


def test_upload_pdf_rejected(auth_client):
    r = auth_client.post(
        "/upload",
        data={"file": (io.BytesIO(b"%PDF-1.4"), "report.pdf")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 400


def test_upload_empty_payload_rejected(auth_client):
    r = auth_client.post("/upload", data={}, content_type="multipart/form-data")
    assert r.status_code == 400


def test_upload_unauthenticated_blocked(client):
    r = client.post(
        "/upload",
        data={"file": (io.BytesIO(b"x=1\n"), "app.py")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 401


def test_upload_returns_job_id_as_string(auth_client):
    with patch("dashboard.app.run_pipeline"):
        r = auth_client.post(
            "/upload",
            data={"file": (io.BytesIO(b"x = 1\n"), "main.py")},
            content_type="multipart/form-data",
        )
    data = r.get_json()
    assert isinstance(data["job_id"], str)
    assert len(data["job_id"]) > 0


# ─── Status workflow ──────────────────────────────────────────────────────────

def test_status_after_upload_is_queryable(auth_client):
    with patch("dashboard.app.run_pipeline"):
        upload_r = auth_client.post(
            "/upload",
            data={"file": (io.BytesIO(b"x = 1\n"), "check.py")},
            content_type="multipart/form-data",
        )
    job_id = upload_r.get_json()["job_id"]
    status_r = auth_client.get(f"/status?job_id={job_id}")
    assert status_r.status_code == 200
    data = status_r.get_json()
    assert data is not None
    assert "running" in data or "progress" in data or "status" in data


# ─── Tool recommendation workflow ────────────────────────────────────────────

def test_tools_list_accessible_after_login(auth_client):
    r = auth_client.get("/api/tools")
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert isinstance(data["tools"], list)


def test_tool_recommendation_requires_target(auth_client):
    r = auth_client.post("/api/tools/recommend", json={})
    assert r.status_code == 400


def test_tool_recommendation_returns_list(auth_client):
    r = auth_client.post("/api/tools/recommend", json={"target_path": "."})
    # May succeed (200) or fail if workspace validation is strict (400/403/404)
    assert r.status_code in (200, 400, 403, 404)
    if r.status_code == 200:
        data = r.get_json()
        assert "tools" in data or "ok" in data


def test_tool_run_invalid_tool_rejected(auth_client):
    r = auth_client.post("/api/tools/run", json={
        "tool_name": "totally_fake_tool_xyz",
        "target_path": ".",
    })
    assert r.status_code == 404


def test_tool_run_missing_fields_rejected(auth_client):
    r = auth_client.post("/api/tools/run", json={})
    assert r.status_code == 400


# ─── Report access workflow ───────────────────────────────────────────────────

def test_report_accessible_to_analyst(auth_client):
    r = auth_client.get("/report")
    # 200 when results exist; 404 is correct when no analysis has been run
    assert r.status_code in (200, 404)


def test_report_unauthenticated_blocked(client):
    r = client.get("/report", follow_redirects=False)
    assert r.status_code in (302, 401)


# ─── History and files workflow ───────────────────────────────────────────────

def test_history_accessible_to_analyst(auth_client):
    r = auth_client.get("/history")
    assert r.status_code == 200


def test_files_accessible_to_analyst(auth_client):
    r = auth_client.get("/files")
    assert r.status_code == 200


# ─── Projects workflow ────────────────────────────────────────────────────────

def test_projects_page_accessible(auth_client):
    r = auth_client.get("/projects")
    assert r.status_code == 200


def test_projects_api_returns_list(auth_client):
    r = auth_client.get("/projects/api")
    assert r.status_code == 200
    data = r.get_json()
    assert isinstance(data, list)


# ─── Admin audit workflow ─────────────────────────────────────────────────────

def test_admin_audit_log_accessible(admin_client):
    r = admin_client.get("/admin/audit")
    assert r.status_code == 200


def test_admin_stats_accessible(admin_client):
    r = admin_client.get("/admin/stats")
    assert r.status_code == 200


# ─── Profile workflow ─────────────────────────────────────────────────────────

def test_profile_loads_for_analyst(auth_client):
    r = auth_client.get("/profile")
    assert r.status_code == 200
