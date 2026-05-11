"""
tests/test_database.py
Integration tests for the SQLAlchemy DB layer.

Each test uses an isolated in-memory SQLite database so tests are
fully independent and leave no files on disk.
"""
import os
import sys
import json
import tempfile
import pytest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from database.db import Base
from database.models import (
    User, Project, AccessRequest,
    Metric, AuditLog, Comment,
    VulnAssignment, FalsePositive, ToolExecution,
)


# ─── Session fixture ─────────────────────────────────────────────────────────

@pytest.fixture
def db():
    """Fresh in-memory SQLite session per test."""
    engine = create_engine(
        "sqlite:///:memory:", echo=False,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _user(username="alice", role="analyst", email="alice@example.com"):
    return User(
        username=username,
        password="hashed_pw",
        role=role,
        full_name=username.title(),
        email=email,
    )


# ─── User model ──────────────────────────────────────────────────────────────

def test_user_create_and_retrieve(db):
    db.add(_user()); db.commit()
    found = db.query(User).filter_by(username="alice").first()
    assert found is not None
    assert found.role == "analyst"


def test_user_unique_username(db):
    db.add(_user()); db.commit()
    db.add(_user())
    with pytest.raises(IntegrityError):
        db.commit()


def test_user_to_dict_has_required_keys(db):
    u = _user(); db.add(u); db.commit()
    d = u.to_dict()
    for key in ("role", "full_name", "email", "active", "blocked",
                "must_change_password", "totp_enabled"):
        assert key in d, f"missing key: {key}"


def test_user_from_dict_roundtrip(db):
    data = {
        "password": "pw", "role": "admin",
        "full_name": "Bob Admin", "email": "bob@example.com",
        "lang": "en", "active": True, "blocked": False,
        "must_change_password": False, "totp_secret": None,
        "totp_enabled": False, "created_at": datetime.now().isoformat(),
    }
    u = User.from_dict("bob", data)
    db.add(u); db.commit()
    found = db.query(User).filter_by(username="bob").first()
    assert found.role == "admin"
    assert found.email == "bob@example.com"


def test_user_update_from_dict(db):
    u = _user(); db.add(u); db.commit()
    u.update_from_dict({"role": "admin", "email": "new@example.com"})
    db.commit()
    found = db.query(User).filter_by(username="alice").first()
    assert found.role == "admin"
    assert found.email == "new@example.com"


def test_user_extra_fields_stored_in_json(db):
    data = {
        "password": "pw", "role": "analyst",
        "department": "SecOps", "avatar": "pic.png",
    }
    u = User.from_dict("carol", data)
    db.add(u); db.commit()
    found = db.query(User).filter_by(username="carol").first()
    assert found.extra.get("department") == "SecOps"


def test_user_default_active_and_not_blocked(db):
    u = _user("dave"); db.add(u); db.commit()
    found = db.query(User).filter_by(username="dave").first()
    # Defaults: active may be None or True; blocked should be falsy
    assert not found.blocked


# ─── Project model ────────────────────────────────────────────────────────────

@pytest.fixture
def db_with_owner(db):
    db.add(User(username="owner", password="pw", role="analyst")); db.commit()
    return db


def test_project_create(db_with_owner):
    p = Project(id="proj_001", name="Test Project", owner="owner")
    db_with_owner.add(p); db_with_owner.commit()
    found = db_with_owner.query(Project).filter_by(id="proj_001").first()
    assert found.name == "Test Project"


def test_project_to_dict_has_members(db_with_owner):
    p = Project(id="proj_002", name="P2", owner="owner",
                members=["alice", "bob"], tags=["web"])
    db_with_owner.add(p); db_with_owner.commit()
    d = p.to_dict()
    assert d["members"] == ["alice", "bob"]
    assert d["tags"] == ["web"]


def test_project_from_dict(db_with_owner):
    data = {
        "name": "P3", "owner": "owner", "description": "desc",
        "department": "IT", "status": "active",
        "created_at": datetime.now().isoformat(),
        "tags": [], "members": [],
    }
    p = Project.from_dict("proj_003", data)
    db_with_owner.add(p); db_with_owner.commit()
    found = db_with_owner.query(Project).filter_by(id="proj_003").first()
    assert found.owner == "owner"


# ─── AccessRequest model ──────────────────────────────────────────────────────

def test_access_request_default_status_is_pending(db):
    r = AccessRequest(id="req_001", email="x@x.com",
                      full_name="X User", role_requested="analyst")
    db.add(r); db.commit()
    found = db.query(AccessRequest).filter_by(id="req_001").first()
    assert found.status == "pending"


def test_access_request_to_dict(db):
    r = AccessRequest(id="req_002", email="y@y.com", full_name="Y")
    db.add(r); db.commit()
    d = r.to_dict()
    assert "email" in d
    assert "status" in d


# ─── Metric model ─────────────────────────────────────────────────────────────

def test_metric_create_and_retrieve(db):
    db.add(User(username="ana", password="pw", role="analyst")); db.commit()
    m = Metric(username="ana", session_data={"total_vulns": 5, "validated": 3})
    db.add(m); db.commit()
    found = db.query(Metric).filter_by(username="ana").first()
    assert found.session_data["total_vulns"] == 5


def test_metric_to_dict_includes_timestamp(db):
    db.add(User(username="ana2", password="pw", role="analyst")); db.commit()
    m = Metric(username="ana2", timestamp=datetime.now(),
               session_data={"total_vulns": 1})
    db.add(m); db.commit()
    d = m.to_dict()
    assert "timestamp" in d


# ─── AuditLog model ──────────────────────────────────────────────────────────

def test_audit_log_create(db):
    log = AuditLog(event="login", user="alice", ip="127.0.0.1",
                   details={"browser": "Firefox"})
    db.add(log); db.commit()
    found = db.query(AuditLog).filter_by(event="login").first()
    assert found.user == "alice"


def test_audit_log_to_dict(db):
    log = AuditLog(event="logout", user="bob")
    db.add(log); db.commit()
    d = log.to_dict()
    assert "event" in d
    assert "user" in d
    assert "details" in d


# ─── Comment model ────────────────────────────────────────────────────────────

def test_comment_create_and_to_dict(db):
    c = Comment(vuln_key="app.py:42:CWE-89", username="alice",
                text="Needs review")
    db.add(c); db.commit()
    d = c.to_dict()
    assert d["vuln_key"] == "app.py:42:CWE-89"
    assert d["text"] == "Needs review"


# ─── VulnAssignment ───────────────────────────────────────────────────────────

def test_vuln_assignment_create(db):
    a = VulnAssignment(vuln_key="app.py:10:CWE-79", assignee="bob",
                       status="open")
    db.add(a); db.commit()
    found = db.query(VulnAssignment).filter_by(assignee="bob").first()
    assert found.status == "open"


# ─── FalsePositive ────────────────────────────────────────────────────────────

def test_false_positive_create(db):
    fp = FalsePositive(vuln_key="app.py:5:CWE-22", reason="Test file",
                       reported_by="alice")
    db.add(fp); db.commit()
    found = db.query(FalsePositive).filter_by(vuln_key="app.py:5:CWE-22").first()
    assert found.reported_by == "alice"


def test_false_positive_unique_vuln_key(db):
    db.add(FalsePositive(vuln_key="a:1:CWE-1")); db.commit()
    db.add(FalsePositive(vuln_key="a:1:CWE-1"))
    with pytest.raises(IntegrityError):
        db.commit()


# ─── ToolExecution ────────────────────────────────────────────────────────────

def test_tool_execution_create(db):
    db.add(User(username="runner", password="pw", role="analyst")); db.commit()
    te = ToolExecution(
        username="runner", tool_name="bandit",
        target_path="/tmp/test.py", status="success",
        findings_count=3, findings_json=[{"severity": "HIGH"}],
        cache_key="abc123", duration_ms=250,
    )
    db.add(te); db.commit()
    found = db.query(ToolExecution).filter_by(tool_name="bandit").first()
    assert found.findings_count == 3
    assert found.status == "success"


def test_tool_execution_to_dict(db):
    te = ToolExecution(tool_name="trivy", status="failed",
                       findings_json=[], cache_key="xyz")
    db.add(te); db.commit()
    d = te.to_dict()
    assert "tool_name" in d
    assert "findings" in d
    assert "status" in d


# ─── Multiple models coexist in same DB ──────────────────────────────────────

def test_all_models_create_in_single_db(db):
    """Smoke test: all model types can coexist in one schema."""
    db.add(User(username="multi_user", password="pw", role="analyst"))
    db.commit()
    db.add(Project(id="mp_001", name="Multi", owner="multi_user"))
    db.add(Metric(username="multi_user", session_data={}))
    db.add(AuditLog(event="test", user="multi_user"))
    db.add(Comment(vuln_key="x:1:CWE-0", username="multi_user", text="ok"))
    db.commit()
    assert db.query(User).count() >= 1
    assert db.query(Project).count() >= 1
    assert db.query(Metric).count() >= 1
    assert db.query(AuditLog).count() >= 1
    assert db.query(Comment).count() >= 1
