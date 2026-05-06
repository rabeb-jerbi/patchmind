"""
scripts/import_json_to_db.py
One-time migration: import runtime JSON files → SQLite database.

Usage (from patchmind/ directory):
    python scripts/import_json_to_db.py

Safe to re-run — skips records that already exist (by primary key / username).
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.init_db import init_schema
from database.db      import get_db_session
from database.models  import (User, Project, AccessRequest,
                               Metric, AuditLog, Comment,
                               VulnAssignment, FalsePositive)

BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR  = os.path.join(BASE_DIR, "data")
USERS_DIR = os.path.join(DATA_DIR, "users")

_stats: dict = {}


def _load(path: str, default):
    """Load JSON file, return *default* on missing/corrupted file."""
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"  ⚠️  Skipped corrupted file {path}: {e}")
        return default


# ══════════════════════════════════════════════════════════════════
# Users
# ══════════════════════════════════════════════════════════════════

def migrate_users(db) -> None:
    print("\n👥 Migrating users.json …")
    users_json = _load(os.path.join(DATA_DIR, "users.json"), {})
    added = skipped = 0
    for username, data in users_json.items():
        if db.query(User).filter_by(username=username).first():
            skipped += 1
            continue
        user = User.from_dict(username, data)
        db.add(user)
        added += 1
    db.commit()
    _stats["users"] = {"added": added, "skipped": skipped}
    print(f"  ✅ {added} added, {skipped} already present")


# ══════════════════════════════════════════════════════════════════
# Projects
# ══════════════════════════════════════════════════════════════════

def migrate_projects(db) -> None:
    print("\n📁 Migrating projects.json …")
    projects_json = _load(os.path.join(DATA_DIR, "projects.json"), {})
    added = skipped = 0
    for pid, data in projects_json.items():
        if db.query(Project).filter_by(id=pid).first():
            skipped += 1
            continue
        # Ensure owner exists in DB
        owner = data.get("owner", "")
        if owner and not db.query(User).filter_by(username=owner).first():
            print(f"  ⚠️  Owner '{owner}' not found — skipping project {pid}")
            skipped += 1
            continue
        proj = Project.from_dict(pid, data)
        db.add(proj)
        added += 1
    db.commit()
    _stats["projects"] = {"added": added, "skipped": skipped}
    print(f"  ✅ {added} added, {skipped} already present")


# ══════════════════════════════════════════════════════════════════
# Access Requests
# ══════════════════════════════════════════════════════════════════

def migrate_requests(db) -> None:
    print("\n📬 Migrating requests.json …")
    reqs_json = _load(os.path.join(DATA_DIR, "requests.json"), [])
    if not isinstance(reqs_json, list):
        reqs_json = list(reqs_json.values()) if isinstance(reqs_json, dict) else []
    added = skipped = 0
    from datetime import datetime
    for i, req in enumerate(reqs_json):
        rid = req.get("id") or f"req_{i:06d}"
        if db.query(AccessRequest).filter_by(id=rid).first():
            skipped += 1
            continue
        created = req.get("created_at")
        if isinstance(created, str):
            try:   created = datetime.fromisoformat(created)
            except ValueError: created = datetime.utcnow()
        reviewed = req.get("reviewed_at")
        if isinstance(reviewed, str):
            try:   reviewed = datetime.fromisoformat(reviewed)
            except ValueError: reviewed = None
        row = AccessRequest(
            id             = rid,
            email          = req.get("email", ""),
            full_name      = req.get("full_name", req.get("name", "")),
            reason         = req.get("reason", ""),
            status         = req.get("status", "pending"),
            role_requested = req.get("role", req.get("role_requested", "analyst")),
            created_at     = created or datetime.utcnow(),
            reviewed_by    = req.get("reviewed_by"),
            reviewed_at    = reviewed,
            username       = req.get("username"),
        )
        db.add(row)
        added += 1
    db.commit()
    _stats["requests"] = {"added": added, "skipped": skipped}
    print(f"  ✅ {added} added, {skipped} already present")


# ══════════════════════════════════════════════════════════════════
# Per-user session metrics
# ══════════════════════════════════════════════════════════════════

def migrate_metrics(db) -> None:
    print("\n📊 Migrating per-user metrics …")
    added = skipped = 0
    if not os.path.isdir(USERS_DIR):
        print("  ℹ️  No users/ directory found — skipping")
        return

    for username in os.listdir(USERS_DIR):
        metrics_path = os.path.join(USERS_DIR, username, "metrics.json")
        data = _load(metrics_path, {})
        sessions = data.get("sessions", [])
        for sess in sessions:
            from datetime import datetime
            ts_str = sess.get("timestamp", "")
            try:   ts = datetime.fromisoformat(ts_str)
            except (ValueError, TypeError): ts = datetime.utcnow()
            row = Metric(username=username, timestamp=ts, session_data=sess)
            db.add(row)
            added += 1
    db.commit()
    _stats["metrics"] = {"added": added, "skipped": skipped}
    print(f"  ✅ {added} session record(s) migrated")


# ══════════════════════════════════════════════════════════════════
# Audit log
# ══════════════════════════════════════════════════════════════════

def migrate_audit_log(db) -> None:
    print("\n📋 Migrating audit_log.json …")
    entries = _load(os.path.join(DATA_DIR, "audit_log.json"), [])
    if not isinstance(entries, list):
        entries = []
    # If DB already has entries, skip to avoid duplicates
    if db.query(AuditLog).count() > 0:
        print("  ℹ️  Audit log already has rows — skipping")
        _stats["audit_log"] = {"added": 0, "skipped": len(entries)}
        return
    from datetime import datetime
    added = 0
    for entry in entries:
        ts_str = entry.get("ts", entry.get("timestamp", ""))
        try:   ts = datetime.fromisoformat(ts_str)
        except (ValueError, TypeError): ts = datetime.utcnow()
        row = AuditLog(
            ts      = ts,
            event   = entry.get("event", ""),
            user    = entry.get("user", ""),
            ip      = entry.get("ip", ""),
            details = entry.get("details", {}),
        )
        db.add(row)
        added += 1
        if added % 500 == 0:
            db.commit()
    db.commit()
    _stats["audit_log"] = {"added": added, "skipped": 0}
    print(f"  ✅ {added} entries migrated")


# ══════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════

def run_migration() -> None:
    print("=" * 55)
    print("  PatchMind — JSON → SQLite Migration")
    print("=" * 55)

    init_schema()
    db = get_db_session()

    migrate_users(db)
    migrate_projects(db)
    migrate_requests(db)
    migrate_metrics(db)
    migrate_audit_log(db)

    print("\n" + "=" * 55)
    print("  Migration Summary")
    print("=" * 55)
    for table, counts in _stats.items():
        print(f"  {table:<20} added={counts['added']}  skipped={counts['skipped']}")

    print("\n✅ Migration complete.")
    print("\nNext steps:")
    print("  1. Start PatchMind normally — it will use the new DB.")
    print("  2. Verify data in data/patchmind.db with any SQLite viewer.")
    print("  3. Keep JSON files as backup until verified.")


if __name__ == "__main__":
    run_migration()
