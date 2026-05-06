"""
tests/test_database.py
Integration tests for the SQLAlchemy DB layer.

Run from patchmind/ directory:
    python -m pytest tests/test_database.py -v

Each test class uses an isolated in-memory SQLite database so tests are
fully independent and leave no files on disk.
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.db import Base
from database.models import (
    User, Project, AccessRequest,
    Metric, AuditLog, Comment,
    VulnAssignment, FalsePositive, ToolExecution,
)


# ─── Helper: spin up an in-memory DB for each test class ─────────────────────

def _make_session():
    engine = create_engine("sqlite:///:memory:", echo=False,
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


# ─── User model ──────────────────────────────────────────────────────────────

class TestUserModel(unittest.TestCase):

    def setUp(self):
        self.db = _make_session()

    def tearDown(self):
        self.db.close()

    def _make_user(self, username="alice", role="analyst"):
        return User(
            username=username,
            password="hashed_pw",
            role=role,
            full_name="Alice Dupont",
            email="alice@example.com",
        )

    def test_create_and_retrieve(self):
        u = self._make_user()
        self.db.add(u); self.db.commit()
        found = self.db.query(User).filter_by(username="alice").first()
        self.assertIsNotNone(found)
        self.assertEqual(found.role, "analyst")

    def test_unique_username(self):
        self.db.add(self._make_user()); self.db.commit()
        self.db.add(self._make_user())
        from sqlalchemy.exc import IntegrityError
        with self.assertRaises(IntegrityError):
            self.db.commit()

    def test_to_dict_keys(self):
        u = self._make_user()
        self.db.add(u); self.db.commit()
        d = u.to_dict()
        for key in ("role", "full_name", "email", "active", "blocked",
                    "must_change_password", "totp_enabled"):
            self.assertIn(key, d)

    def test_from_dict_roundtrip(self):
        original = {
            "password": "pw",
            "role": "admin",
            "full_name": "Bob",
            "email": "bob@example.com",
            "lang": "en",
            "active": True,
            "blocked": False,
            "must_change_password": False,
            "totp_secret": None,
            "totp_enabled": False,
            "created_at": datetime.now().isoformat(),
        }
        u = User.from_dict("bob", original)
        self.db.add(u); self.db.commit()
        found = self.db.query(User).filter_by(username="bob").first()
        self.assertEqual(found.role, "admin")
        self.assertEqual(found.email, "bob@example.com")

    def test_update_from_dict(self):
        u = self._make_user()
        self.db.add(u); self.db.commit()
        u.update_from_dict({"role": "admin", "email": "new@example.com"})
        self.db.commit()
        found = self.db.query(User).filter_by(username="alice").first()
        self.assertEqual(found.role, "admin")
        self.assertEqual(found.email, "new@example.com")

    def test_extra_fields_stored_in_json(self):
        data = {
            "password": "pw", "role": "analyst",
            "department": "SecOps", "avatar": "pic.png",
        }
        u = User.from_dict("carol", data)
        self.db.add(u); self.db.commit()
        found = self.db.query(User).filter_by(username="carol").first()
        self.assertEqual(found.extra.get("department"), "SecOps")


# ─── Project model ────────────────────────────────────────────────────────────

class TestProjectModel(unittest.TestCase):

    def setUp(self):
        self.db = _make_session()
        # seed a user so FK is satisfied
        self.db.add(User(username="owner", password="pw", role="analyst"))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_create_project(self):
        p = Project(id="proj_001", name="Test Project", owner="owner")
        self.db.add(p); self.db.commit()
        found = self.db.query(Project).filter_by(id="proj_001").first()
        self.assertEqual(found.name, "Test Project")

    def test_to_dict_has_members(self):
        p = Project(id="proj_002", name="P2", owner="owner",
                    members=["alice", "bob"], tags=["web"])
        self.db.add(p); self.db.commit()
        d = p.to_dict()
        self.assertEqual(d["members"], ["alice", "bob"])
        self.assertEqual(d["tags"], ["web"])

    def test_from_dict(self):
        data = {"name": "P3", "owner": "owner", "description": "desc",
                "department": "IT", "status": "active",
                "created_at": datetime.now().isoformat(),
                "tags": [], "members": []}
        p = Project.from_dict("proj_003", data)
        self.db.add(p); self.db.commit()
        found = self.db.query(Project).filter_by(id="proj_003").first()
        self.assertEqual(found.owner, "owner")


# ─── AccessRequest model ─────────────────────────────────────────────────────

class TestAccessRequestModel(unittest.TestCase):

    def setUp(self):
        self.db = _make_session()

    def tearDown(self):
        self.db.close()

    def test_create_request(self):
        r = AccessRequest(id="req_001", email="x@x.com",
                          full_name="X User", role_requested="analyst")
        self.db.add(r); self.db.commit()
        found = self.db.query(AccessRequest).filter_by(id="req_001").first()
        self.assertEqual(found.status, "pending")

    def test_to_dict(self):
        r = AccessRequest(id="req_002", email="y@y.com", full_name="Y")
        self.db.add(r); self.db.commit()
        d = r.to_dict()
        self.assertIn("email", d)
        self.assertIn("status", d)


# ─── Metric model ─────────────────────────────────────────────────────────────

class TestMetricModel(unittest.TestCase):

    def setUp(self):
        self.db = _make_session()
        self.db.add(User(username="ana", password="pw", role="analyst"))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_create_metric(self):
        m = Metric(username="ana", session_data={"total_vulns": 5, "validated": 3})
        self.db.add(m); self.db.commit()
        found = self.db.query(Metric).filter_by(username="ana").first()
        self.assertEqual(found.session_data["total_vulns"], 5)

    def test_to_dict_includes_timestamp(self):
        m = Metric(username="ana", timestamp=datetime.now(),
                   session_data={"total_vulns": 1})
        self.db.add(m); self.db.commit()
        d = m.to_dict()
        self.assertIn("timestamp", d)


# ─── AuditLog model ───────────────────────────────────────────────────────────

class TestAuditLogModel(unittest.TestCase):

    def setUp(self):
        self.db = _make_session()

    def tearDown(self):
        self.db.close()

    def test_create_entry(self):
        log = AuditLog(event="login", user="alice", ip="127.0.0.1",
                       details={"browser": "Firefox"})
        self.db.add(log); self.db.commit()
        found = self.db.query(AuditLog).filter_by(event="login").first()
        self.assertEqual(found.user, "alice")

    def test_to_dict(self):
        log = AuditLog(event="logout", user="bob")
        self.db.add(log); self.db.commit()
        d = log.to_dict()
        self.assertIn("event", d)
        self.assertIn("user", d)
        self.assertIn("details", d)


# ─── Comment model ────────────────────────────────────────────────────────────

class TestCommentModel(unittest.TestCase):

    def setUp(self):
        self.db = _make_session()

    def tearDown(self):
        self.db.close()

    def test_create_and_to_dict(self):
        c = Comment(vuln_key="app.py:42:CWE-89", username="alice", text="Needs review")
        self.db.add(c); self.db.commit()
        d = c.to_dict()
        self.assertEqual(d["vuln_key"], "app.py:42:CWE-89")
        self.assertEqual(d["text"], "Needs review")


# ─── VulnAssignment ───────────────────────────────────────────────────────────

class TestVulnAssignment(unittest.TestCase):

    def setUp(self):
        self.db = _make_session()

    def tearDown(self):
        self.db.close()

    def test_create_assignment(self):
        a = VulnAssignment(vuln_key="app.py:10:CWE-79", assignee="bob", status="open")
        self.db.add(a); self.db.commit()
        found = self.db.query(VulnAssignment).filter_by(assignee="bob").first()
        self.assertEqual(found.status, "open")


# ─── FalsePositive ────────────────────────────────────────────────────────────

class TestFalsePositive(unittest.TestCase):

    def setUp(self):
        self.db = _make_session()

    def tearDown(self):
        self.db.close()

    def test_create_fp(self):
        fp = FalsePositive(vuln_key="app.py:5:CWE-22", reason="Test file",
                           reported_by="alice")
        self.db.add(fp); self.db.commit()
        found = self.db.query(FalsePositive).filter_by(vuln_key="app.py:5:CWE-22").first()
        self.assertEqual(found.reported_by, "alice")

    def test_unique_vuln_key(self):
        self.db.add(FalsePositive(vuln_key="a:1:CWE-1")); self.db.commit()
        self.db.add(FalsePositive(vuln_key="a:1:CWE-1"))
        from sqlalchemy.exc import IntegrityError
        with self.assertRaises(IntegrityError):
            self.db.commit()


# ─── ToolExecution ────────────────────────────────────────────────────────────

class TestToolExecution(unittest.TestCase):

    def setUp(self):
        self.db = _make_session()
        self.db.add(User(username="runner", password="pw", role="analyst"))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_create_execution(self):
        te = ToolExecution(
            username="runner", tool_name="bandit",
            target_path="/tmp/test.py", status="success",
            findings_count=3, findings_json=[{"severity": "HIGH"}],
            cache_key="abc123", duration_ms=250,
        )
        self.db.add(te); self.db.commit()
        found = self.db.query(ToolExecution).filter_by(tool_name="bandit").first()
        self.assertEqual(found.findings_count, 3)
        self.assertEqual(found.status, "success")

    def test_to_dict(self):
        te = ToolExecution(tool_name="trivy", status="failed",
                           findings_json=[], cache_key="xyz")
        self.db.add(te); self.db.commit()
        d = te.to_dict()
        self.assertIn("tool_name", d)
        self.assertIn("findings", d)
        self.assertIn("status", d)


# ─── Migration script (idempotency) ──────────────────────────────────────────

class TestMigrationIdempotency(unittest.TestCase):
    """
    Smoke test: running migrate_users() twice on the same data must not
    raise or duplicate rows.
    """

    def test_migrate_users_idempotent(self):
        import json, tempfile, os
        from database.init_db import init_schema
        from database.db import get_db_session

        # Point to a temp DB
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "test.db")
            os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

            # Re-import to pick up new URL
            import importlib, database.db as _db_mod
            importlib.reload(_db_mod)
            from database.db import init_db
            init_db(f"sqlite:///{db_path}")
            init_schema()

            # Build a minimal users.json
            users_data = {
                "testuser": {
                    "password": "pw",
                    "role": "analyst",
                    "full_name": "Test User",
                    "email": "t@t.com",
                    "active": True,
                    "blocked": False,
                    "must_change_password": False,
                    "totp_enabled": False,
                    "created_at": datetime.now().isoformat(),
                }
            }
            users_file = os.path.join(tmp, "users.json")
            with open(users_file, "w") as f:
                json.dump(users_data, f)

            db = get_db_session()
            # Run migration twice
            for _ in range(2):
                from scripts.import_json_to_db import migrate_users
                # Patch DATA_DIR to our temp dir
                import scripts.import_json_to_db as mig
                original_data_dir = mig.DATA_DIR
                mig.DATA_DIR = tmp
                try:
                    migrate_users(db)
                finally:
                    mig.DATA_DIR = original_data_dir

            count = db.query(User).filter_by(username="testuser").count()
            self.assertEqual(count, 1)

            del os.environ["DATABASE_URL"]


if __name__ == "__main__":
    unittest.main()
