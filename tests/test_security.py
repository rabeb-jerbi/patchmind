"""
tests/test_security.py
HTTP security tests: headers, auth enforcement, RBAC, session config.
"""
import pytest


# ─── Unauthenticated access ───────────────────────────────────────────────────

def test_dashboard_requires_auth(client):
    r = client.get("/dashboard")
    assert r.status_code in (302, 401)


def test_dashboard_redirect_goes_to_login(client):
    r = client.get("/dashboard")
    if r.status_code == 302:
        assert "/login" in r.headers["Location"]


def test_admin_page_requires_auth(client):
    r = client.get("/admin", follow_redirects=False)
    assert r.status_code in (302, 401, 403)


def test_api_tools_requires_auth(client):
    r = client.get("/api/tools")
    assert r.status_code == 401


def test_api_tools_recommend_requires_auth(client):
    r = client.post("/api/tools/recommend", json={"target_path": "."})
    assert r.status_code == 401


def test_api_tools_run_requires_auth(client):
    r = client.post("/api/tools/run", json={"tool_name": "bandit", "target_path": "."})
    assert r.status_code == 401


def test_upload_requires_auth(client):
    r = client.post("/upload")
    assert r.status_code == 401


def test_download_requires_auth(client):
    r = client.get("/download")
    assert r.status_code in (302, 401)


def test_history_requires_auth(client):
    r = client.get("/history")
    assert r.status_code in (302, 401)


def test_profile_requires_auth(client):
    r = client.get("/profile")
    assert r.status_code in (302, 401)


# ─── Secure HTTP headers ─────────────────────────────────────────────────────

def test_x_content_type_options_header(client):
    r = client.get("/login")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"


def test_x_frame_options_header(client):
    r = client.get("/login")
    assert r.headers.get("X-Frame-Options") == "DENY"


def test_referrer_policy_header(client):
    r = client.get("/login")
    assert "referrer-policy" in {k.lower() for k in r.headers.keys()}


def test_security_headers_present_on_api(client, auth_client):
    r = auth_client.get("/api/tools")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"


# ─── Session cookie config ────────────────────────────────────────────────────

def test_session_cookie_httponly(app):
    assert app.config.get("SESSION_COOKIE_HTTPONLY") is True


def test_session_cookie_samesite(app):
    samesite = app.config.get("SESSION_COOKIE_SAMESITE")
    assert samesite in ("Lax", "Strict", "None")


def test_session_lifetime_is_set(app):
    from datetime import timedelta
    assert app.permanent_session_lifetime <= timedelta(hours=24)


# ─── RBAC enforcement via HTTP ────────────────────────────────────────────────

def test_admin_endpoint_blocks_analyst(auth_client):
    r = auth_client.get("/admin/users")
    assert r.status_code == 403


def test_admin_endpoint_allows_admin(admin_client):
    r = admin_client.get("/admin/users")
    assert r.status_code == 200


def test_viewer_cannot_run_tool(viewer_client):
    r = viewer_client.post("/api/tools/run",
                           json={"tool_name": "bandit", "target_path": "."})
    # 403 (permission denied) or 404 (tool not found) — both are acceptable rejections
    assert r.status_code in (403, 404)


# ─── Login page ───────────────────────────────────────────────────────────────

def test_login_page_returns_200(client):
    r = client.get("/login")
    assert r.status_code == 200


def test_login_page_contains_form(client):
    r = client.get("/login")
    assert b"form" in r.data.lower() or b"input" in r.data.lower()


# ─── JSON API auth responses ──────────────────────────────────────────────────

def test_unauthenticated_json_post_returns_401_json(client):
    r = client.post("/api/tools/run",
                    json={"tool_name": "bandit", "target_path": "."},
                    content_type="application/json")
    assert r.status_code == 401
    data = r.get_json()
    assert data is not None
    assert "error" in data


def test_unauthenticated_json_get_returns_401_json(client):
    r = client.get("/api/tools",
                   content_type="application/json")
    assert r.status_code == 401
    data = r.get_json()
    assert data is not None
