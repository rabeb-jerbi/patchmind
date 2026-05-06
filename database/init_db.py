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
from database.models import User  # noqa – ensure model is registered


def init_schema(db_url: str = None) -> None:
    """Create all tables (idempotent — safe to call on every startup)."""
    init_db(db_url)
    Base.metadata.create_all(get_engine())
    _seed_admin()
    print("✅ Database schema ready.")


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
    print("✅ Default admin user created (password: Admin@2026!)")


if __name__ == "__main__":
    init_schema()
