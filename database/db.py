"""
database/db.py
SQLAlchemy engine and session management.

Usage in app.py:
    from database.db import init_db, get_db_session, close_db_session
    init_db()                       # call once at startup
    db = get_db_session()           # get a thread-local session
    db.query(User).all()
    close_db_session()              # call in teardown_appcontext
"""
import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

_engine       = None
_SessionFactory = None
Session       = None   # scoped (thread-local) session proxy

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_URL = f"sqlite:///{os.path.join(BASE_DIR, 'data', 'patchmind.db')}"


def init_db(db_url: str = None) -> None:
    """Create engine and session factory.  Call once at application start."""
    global _engine, _SessionFactory, Session

    url = db_url or os.environ.get("DATABASE_URL", _DEFAULT_URL)

    connect_args = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    _engine = create_engine(
        url,
        echo=False,
        pool_pre_ping=True,
        connect_args=connect_args,
    )

    # Enable WAL mode for SQLite so reads don't block writes
    if url.startswith("sqlite"):
        @event.listens_for(_engine, "connect")
        def _set_wal(conn, _):
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")

    _SessionFactory = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
    Session = scoped_session(_SessionFactory)


def get_db_session():
    """Return the thread-local session (creates one if needed)."""
    if Session is None:
        raise RuntimeError("Database not initialised — call init_db() first")
    return Session()


def close_db_session(exception=None) -> None:
    """Remove the thread-local session.  Register as Flask teardown."""
    if Session is not None:
        Session.remove()


def get_engine():
    return _engine
