"""
database/init_db.py
Create all tables and seed the default admin user if the DB is empty.

    python -m database.init_db          # from patchmind/ directory
    from database.init_db import init_schema
    init_schema()
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db     import init_db, get_db_session, get_engine, Base
from database.models import (  # noqa – ensure all models are registered
    User, Project, ProjectMember, ProjectInvitation,
    AccessRequest, Metric, AuditLog, Comment,
    VulnAssignment, FalsePositive, ToolExecution,
)


def init_schema(db_url: str = None) -> None:
    """Create all tables (idempotent — safe to call on every startup)."""
    init_db(db_url)
    Base.metadata.create_all(get_engine())
    _migrate_schema(get_engine())
    _seed_admin()
    print("[OK] Database schema ready.")


# ── Schema migrations (ALTER TABLE for columns added after initial release) ──

def _migrate_schema(engine) -> None:
    """Add new columns to existing tables without destroying data.

    Safe to run on every startup — skips columns that already exist.
    Uses SQLAlchemy inspect so it works for any supported backend.
    """
    from sqlalchemy import inspect as sa_inspect, text

    inspector = sa_inspect(engine)
    tables = inspector.get_table_names()

    # project_invitations: approval-workflow columns (added in phase 3)
    if 'project_invitations' in tables:
        _ensure_columns(engine, inspector, 'project_invitations', [
            ('approved_by',           'VARCHAR(50)'),
            ('approved_at',           'DATETIME'),
            ('rejected_at',           'DATETIME'),
            ('rejection_reason',      'TEXT DEFAULT ""'),
            ('cancelled_at',          'DATETIME'),
            ('cancelled_by',          'VARCHAR(50)'),
            ('invited_existing_user', 'BOOLEAN'),
            ('credentials_sent',      'BOOLEAN DEFAULT 0'),
            ('provisioned_username',  'VARCHAR(50)'),
        ])


def _ensure_columns(engine, inspector, table: str, columns: list) -> None:
    """Add each (name, type) column if it is absent from the table."""
    from sqlalchemy import text

    existing = {c['name'] for c in inspector.get_columns(table)}
    missing  = [(n, t) for n, t in columns if n not in existing]
    if not missing:
        return

    with engine.begin() as conn:
        for col_name, col_type in missing:
            conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {col_name} {col_type}'))
    print(f"[MIGRATE] Added {len(missing)} column(s) to '{table}': "
          + ", ".join(n for n, _ in missing))


def _seed_admin() -> None:
    """Insert default admin user if the users table is empty."""
    db = get_db_session()
    if db.query(User).count() > 0:
        return

    try:
        from werkzeug.security import generate_password_hash
        import pyotp
        totp_secret = pyotp.random_base32()
    except ImportError:
        generate_password_hash = lambda p: p  # pragma: no cover
        totp_secret = None

    admin = User(
        username             = "admin",
        password             = generate_password_hash("Admin@2026!"),
        role                 = "admin",
        full_name            = "Administrator",
        active               = True,
        totp_secret          = totp_secret,
        totp_enabled         = False,
    )
    db.add(admin)
    db.commit()
    print("[OK] Default admin user created (password: Admin@2026!)")


if __name__ == "__main__":
    init_schema()
