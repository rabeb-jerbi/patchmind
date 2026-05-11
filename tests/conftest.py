"""
tests/conftest.py
Shared fixtures for the PatchMind test suite.

Environment variables MUST be set before the Flask app is imported,
because app.py calls init_schema() at module level.
"""
import os
import sys
import io
import tempfile
import zipfile

# ── env vars FIRST — before any app import ──────────────────────────────────
_db_fd, _db_path = tempfile.mkstemp(suffix=".db", prefix="patchmind_test_")
os.close(_db_fd)

os.environ.setdefault("PATCHMIND_SECRET", "test-secret-for-pytest-32-chars!!")
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"
os.environ["TESTING"] = "True"

# ── sys.path ─────────────────────────────────────────────────────────────────
_PATCHMIND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PATCHMIND not in sys.path:
    sys.path.insert(0, _PATCHMIND)

# ── imports after env setup ──────────────────────────────────────────────────
import pytest
from werkzeug.security import generate_password_hash

from dashboard.app import app as _flask_app
from database.db import get_db_session
from database.models import User


# ─────────────────────────────────────────────────────────────────────────────
# App / client fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def app():
    """Session-scoped Flask application."""
    _flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
    })
    yield _flask_app
    # Clean up test DB file
    try:
        os.unlink(_db_path)
    except OSError:
        pass


@pytest.fixture
def client(app):
    """Fresh test client per test function."""
    with app.test_client() as c:
        yield c


# ─────────────────────────────────────────────────────────────────────────────
# User fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def analyst_creds():
    return {"username": "test_analyst", "role": "analyst", "password": "Test@1234!"}


@pytest.fixture(scope="session")
def admin_creds():
    return {"username": "admin", "role": "admin", "password": "Admin@2026!"}


@pytest.fixture(scope="session")
def viewer_creds():
    return {"username": "test_viewer", "role": "viewer", "password": "Viewer@1234!"}


@pytest.fixture(scope="session")
def _seed_test_users(app, analyst_creds, viewer_creds):
    """Create test users in DB (once per session)."""
    with app.app_context():
        db = get_db_session()
        for creds in (analyst_creds, viewer_creds):
            if not db.query(User).filter_by(username=creds["username"]).first():
                db.add(User(
                    username=creds["username"],
                    password=generate_password_hash(creds["password"]),
                    role=creds["role"],
                    full_name=creds["username"].replace("_", " ").title(),
                    email=f"{creds['username']}@test.local",
                    active=True,
                    blocked=False,
                    must_change_password=False,
                    totp_enabled=False,
                ))
        db.commit()


@pytest.fixture
def auth_client(client, analyst_creds, _seed_test_users):
    """Pre-authenticated client as analyst."""
    with client.session_transaction() as sess:
        sess["username"] = analyst_creds["username"]
        sess["role"] = analyst_creds["role"]
        sess["2fa_ok"] = True
        sess["must_change_pw"] = False
    return client


@pytest.fixture
def admin_client(client, admin_creds):
    """Pre-authenticated client as admin."""
    with client.session_transaction() as sess:
        sess["username"] = admin_creds["username"]
        sess["role"] = admin_creds["role"]
        sess["2fa_ok"] = True
        sess["must_change_pw"] = False
    return client


@pytest.fixture
def viewer_client(client, viewer_creds, _seed_test_users):
    """Pre-authenticated client as viewer."""
    with client.session_transaction() as sess:
        sess["username"] = viewer_creds["username"]
        sess["role"] = viewer_creds["role"]
        sess["2fa_ok"] = True
        sess["must_change_pw"] = False
    return client


# ─────────────────────────────────────────────────────────────────────────────
# Rate-limiter reset (prevents 429s during test runs)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_rate_store():
    """Clear the in-memory rate-limit store before every test."""
    from dashboard.app import _rate_store
    _rate_store.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Upload / file fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def py_file_bytes():
    return b"x = 1\nprint(x)\n"


@pytest.fixture
def zip_bytes(py_file_bytes):
    """A valid ZIP containing one .py file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.py", py_file_bytes.decode())
    return buf.getvalue()


@pytest.fixture
def traversal_zip_bytes():
    """ZIP with a path-traversal entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../../evil.py", "evil = True")
        zf.writestr("safe.py", "x = 1")
    return buf.getvalue()


@pytest.fixture
def dangerous_zip_bytes():
    """ZIP containing a .exe file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("malware.exe", b"\x4d\x5a")
        zf.writestr("safe.py", "x = 1")
    return buf.getvalue()
